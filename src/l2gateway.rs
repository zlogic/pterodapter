use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::pin::pin;
use std::task::Poll;
use std::time::Duration;
use std::{error, fmt, net::Ipv6Addr};
use std::{future, io};

use log::{debug, info, trace, warn};
use tokio::io::unix::AsyncFd;
use tokio::{runtime, sync::oneshot};

use crate::logger::fmt_slice_hex;
use crate::uplink::UplinkService as _;
use crate::{ip, pcap, uplink};

// Maximum ethernet frame size, the ethernet header will be reused for PPP headers.
const MAX_PACKET_SIZE: usize = 1500;
// Limit the packet size to IPv6 minimum, any packet that exceeds this size will be rejected with an
// ICMPv6 Packet Too Big message.
// This prevents jumbo frames which will be rejected by the uplink.
const PATH_MTU: usize = 1280;
const L2_ETHERNET_HEADER_SIZE: usize = 6 + 6 + 2;

pub struct Config {
    pub listen_interface: String,
    pub set_mtu: bool,
    pub nat64_prefix: Ipv6Addr,
    pub dns64_domains: Vec<String>,
}

pub struct Server {
    listen_interface: String,
    set_mtu: bool,
    dns64_domains: Vec<String>,
    nat64_prefix: ip::Nat64Prefix,
    raw_read_buffer: [u8; MAX_PACKET_SIZE],
    raw_write_buffer: [u8; MAX_PACKET_SIZE],
    uplink_read_buffer: [u8; MAX_PACKET_SIZE],
    uplink_write_buffer: [u8; MAX_PACKET_SIZE],
}

impl Server {
    pub fn new(config: Config) -> Server {
        let raw_read_buffer = [0u8; MAX_PACKET_SIZE];
        let raw_write_buffer = [0u8; MAX_PACKET_SIZE];
        let uplink_read_buffer = [0u8; MAX_PACKET_SIZE];
        let uplink_write_buffer = [0u8; MAX_PACKET_SIZE];
        Server {
            listen_interface: config.listen_interface,
            set_mtu: config.set_mtu,
            dns64_domains: config.dns64_domains,
            nat64_prefix: ip::Nat64Prefix::new(config.nat64_prefix),
            raw_read_buffer,
            raw_write_buffer,
            uplink_read_buffer,
            uplink_write_buffer,
        }
    }

    pub fn run(
        &mut self,
        rt: runtime::Runtime,
        uplink: uplink::UplinkServiceType,
        shutdown_receiver: oneshot::Receiver<()>,
        pcap_sender: Option<pcap::PcapSender>,
    ) -> Result<(), L2GatewayError> {
        let network = ip::Network::new(
            Some(self.nat64_prefix),
            self.dns64_domains.clone(),
            ip::DnsDetection::Port,
            Some(PATH_MTU),
        )?;

        let result = rt.block_on(self.run_process(shutdown_receiver, uplink, network, pcap_sender));
        rt.shutdown_timeout(Duration::from_secs(60));
        result
    }

    async fn run_process(
        &mut self,
        shutdown_receiver: oneshot::Receiver<()>,
        mut uplink: uplink::UplinkServiceType,
        network: ip::Network,
        pcap_sender: Option<pcap::PcapSender>,
    ) -> Result<(), L2GatewayError> {
        let mtu = if self.set_mtu {
            Some(MAX_PACKET_SIZE)
        } else {
            None
        };
        let socket = match RawSocket::new(self.listen_interface.as_str(), mtu).await {
            Ok(socket) => socket,
            Err(err) => {
                log::error!("Failed to open raw IPv6 socket: {err}");
                return Err(err);
            }
        };
        if let Err(err) = socket.set_nat64_filter(&self.nat64_prefix) {
            warn!("Failed to enable BPF filter, will rely on a less efficient packet filter: {err}")
        }

        let mut packet_filter =
            PacketFilter::new(network, self.nat64_prefix, socket.if_mac(), pcap_sender);

        info!("Started server");

        let mut shutdown_command = pin!(shutdown_receiver);
        let mut shutdown = false;
        let uplink_reserved_header_size = uplink.reserved_header_bytes();
        loop {
            let uplink_is_connected = uplink.is_connected();
            if shutdown && !uplink_is_connected {
                debug!("Shutdown completed");
                return Ok(());
            }
            let (shutdown_requested, raw_packet, uplink_event) = {
                let ignore_uplink = shutdown && !uplink_is_connected;
                let mut uplink_event = None;
                let mut raw_packet = None;
                let mut shutdown_requested = shutdown;
                let mut receive_uplink_event =
                    pin!(uplink.wait_event(&mut self.uplink_read_buffer));
                future::poll_fn(|cx| {
                    if uplink_event.is_none() {
                        uplink_event = if !ignore_uplink {
                            let uplink_event = receive_uplink_event.as_mut().poll(cx);
                            match uplink_event {
                                Poll::Ready(cmd) => Some(cmd),
                                Poll::Pending => None,
                            }
                        } else {
                            // Avoid waking if uplink/VPN is already shut down.
                            None
                        };
                    }
                    shutdown_requested =
                        shutdown_requested || shutdown_command.as_mut().poll(cx).is_ready();
                    if raw_packet.is_none() {
                        raw_packet = match socket.poll_recv(cx, &mut self.raw_read_buffer) {
                            Poll::Ready(result) => Some(result),
                            Poll::Pending => None,
                        };
                    }
                    if uplink_event.is_some() || raw_packet.is_some() || shutdown_requested {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
                (shutdown_requested, raw_packet, uplink_event)
            };
            // Process all ready events.
            if shutdown_requested {
                shutdown = true;
                if let Err(err) = uplink.terminate().await {
                    warn!("Failed to terminate uplink/VPN client connection: {err}");
                }
            }
            let uplink_action = match uplink_event {
                Some(Ok(())) => match uplink.read_packet(&mut self.uplink_read_buffer).await {
                    Ok(data) => {
                        let read_bytes = data.len();

                        match packet_filter.process_uplink_packet(
                            &mut self.uplink_read_buffer[uplink_reserved_header_size..],
                            read_bytes,
                            &mut self.uplink_write_buffer,
                        ) {
                            Ok(action) => action,
                            Err(err) => {
                                warn!("Failed to forward uplink/VPN packet to raw socket: {err}");
                                UplinkRoutingAction::Drop
                            }
                        }
                    }
                    Err(err) => {
                        warn!("Failed to read packet from uplink/VPN: {err}");
                        UplinkRoutingAction::Drop
                    }
                },
                Some(Err(err)) => {
                    warn!("Uplink/VPN reported an error status: {err}");
                    UplinkRoutingAction::Drop
                }
                None => UplinkRoutingAction::Drop,
            };
            let (uplink_reply, uplink_send_to_raw) = uplink_action.into_packets();
            let raw_action = match raw_packet {
                Some(Ok(read_bytes)) => {
                    let result = packet_filter.process_raw_packet(
                        &mut self.raw_read_buffer,
                        read_bytes,
                        &mut self.raw_write_buffer,
                    );
                    match result {
                        Ok(action) => action,
                        Err(err) => {
                            warn!("Failed to process raw packet: {err}");
                            RawRoutingAction::Drop
                        }
                    }
                }
                Some(Err(err)) => {
                    warn!("Failed to read raw packet: {err}");
                    RawRoutingAction::Drop
                }
                None => RawRoutingAction::Drop,
            };
            let (raw_reply, raw_send_to_uplink) = raw_action.into_packets();
            // TODO: remove this debug code
            if log::log_enabled!(log::Level::Trace) {
                if let Some(packet) = raw_reply {
                    let packet = ip::IpPacket::from_data(&packet[L2_ETHERNET_HEADER_SIZE..])
                        .expect("raw reply");
                    trace!("Sending reply:\n{packet}")
                }
                if !raw_send_to_uplink.is_empty() {
                    let packet = ip::IpPacket::from_data(raw_send_to_uplink).expect("send to vpn");
                    trace!("Sending packet to VPN:\n{packet}")
                }
            }
            let (uplink_event, sent_raw_response, forwarded_raw_packet) = {
                let send_slices_to_uplink = [uplink_reply, raw_send_to_uplink];
                let mut process_uplink_events = pin!(uplink.process_events(&send_slices_to_uplink));
                let mut sent_raw_response = None;
                let mut forwarded_raw_packet = None;
                let mut uplink_event = None;
                future::poll_fn(|cx| {
                    if uplink_event.is_none() {
                        uplink_event = match process_uplink_events.as_mut().poll(cx) {
                            Poll::Ready(result) => Some(result),
                            Poll::Pending => None,
                        };
                    }
                    if sent_raw_response.is_none() {
                        sent_raw_response = if let Some(raw_reply_data) = &raw_reply {
                            match socket.poll_send(cx, raw_reply_data) {
                                Poll::Ready(result) => Some(result),
                                Poll::Pending => None,
                            }
                        } else {
                            Some(Ok(0))
                        }
                    }
                    if forwarded_raw_packet.is_none() {
                        forwarded_raw_packet = if let Some(uplink_packet) = &uplink_send_to_raw {
                            match socket.poll_send(cx, uplink_packet) {
                                Poll::Ready(result) => Some(result),
                                Poll::Pending => None,
                            }
                        } else {
                            Some(Ok(0))
                        }
                    }
                    if uplink_event.is_some()
                        && sent_raw_response.is_some()
                        && forwarded_raw_packet.is_some()
                    {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
                (uplink_event, sent_raw_response, forwarded_raw_packet)
            };
            if let Some(Err(err)) = sent_raw_response {
                warn!("Failed to send raw socket response: {err}");
            }
            if let Some(Err(err)) = forwarded_raw_packet {
                warn!("Failed to forward message to raw socket: {err}");
            }
            if let Some(Err(err)) = uplink_event {
                warn!("Failed to process uplink/VPN lifecycle events: {err}");
            }
            if !uplink_is_connected && uplink.is_connected() {
                let client_ip = match &uplink {
                    uplink::UplinkServiceType::FortiVPN(forti_service) => {
                        forti_service.cookie_client_ip()
                    }
                };
                packet_filter.update_ip(uplink.ip_configuration(), client_ip);
            } else if uplink_is_connected && !uplink.is_connected() {
                packet_filter.update_ip(None, None);
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
struct MacAddr([u8; 6]);

impl MacAddr {
    fn from_data(data: &[u8]) -> MacAddr {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(data);
        MacAddr(mac)
    }

    fn as_slice(&self) -> &[u8; 6] {
        &self.0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

#[derive(PartialEq, Eq)]
struct EtherType(u16);

impl EtherType {
    const IPV4: EtherType = EtherType(0x0800);
    const IPV6: EtherType = EtherType(0x86DD);

    fn from_data(data: &[u8]) -> EtherType {
        let mut et = [0u8; 2];
        et.copy_from_slice(data);
        EtherType(u16::from_be_bytes(et))
    }

    fn to_u16(&self) -> u16 {
        self.0
    }
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::IPV4 => write!(f, "IPv4"),
            Self::IPV6 => write!(f, "IPv6"),
            _ => write!(f, "Unknown EtherType {:#04x}", self.0),
        }
    }
}

struct PacketFilter {
    network: ip::Network,
    nat64_prefix: ip::Nat64Prefix,
    pcap_sender: Option<pcap::PcapSender>,
    client_ip: Option<Ipv6Addr>,
    client_mac: Option<MacAddr>,
    vpn_real_ip: Option<IpAddr>,
    server_mac: MacAddr,
}

impl PacketFilter {
    fn new(
        network: ip::Network,
        nat64_prefix: ip::Nat64Prefix,
        server_mac: MacAddr,
        pcap_sender: Option<pcap::PcapSender>,
    ) -> PacketFilter {
        PacketFilter {
            network,
            nat64_prefix,
            pcap_sender,
            client_ip: None,
            client_mac: None,
            vpn_real_ip: None,
            server_mac,
        }
    }

    fn update_ip(&mut self, configuration: Option<(IpAddr, &[IpAddr])>, client_ip: Option<IpAddr>) {
        let (internal_addr, dns_addrs): (Option<IpAddr>, &[IpAddr]) =
            if let Some((internal_addr, dns_addrs)) = configuration {
                (Some(internal_addr), dns_addrs)
            } else {
                (None, &[])
            };
        self.network
            .update_ip_configuration(internal_addr, dns_addrs);
        self.vpn_real_ip = internal_addr;

        let client_ip = match client_ip {
            Some(IpAddr::V6(client_ip)) => Some(client_ip),
            Some(IpAddr::V4(_)) | None => None,
        };
        if client_ip != self.client_ip {
            self.client_ip = client_ip;
            self.client_mac = None;
        }
    }

    fn process_raw_packet<'a>(
        &mut self,
        in_buf: &'a mut [u8],
        data_len: usize,
        out_buf: &'a mut [u8],
    ) -> Result<RawRoutingAction<'a>, L2GatewayError> {
        let data = &in_buf[..data_len];
        trace!("Received ethernet frame\n{}", fmt_slice_hex(data));
        if data.len() < L2_ETHERNET_HEADER_SIZE {
            return Err("Not enough data in ethernet frame".into());
        }
        let dst_mac = MacAddr::from_data(&data[0..6]);
        let src_mac = MacAddr::from_data(&data[6..12]);
        let ether_type = EtherType::from_data(&data[12..14]);
        if ether_type != EtherType::IPV6 {
            debug!(
                "Received unsupported EtherType: {ether_type}\n{}",
                fmt_slice_hex(data),
            );
            return Err("Received unsupported EtherType".into());
        }
        if dst_mac != self.server_mac {
            debug!(
                "Ethernet frame has destination {dst_mac}, should be {}",
                self.server_mac
            );
            return Ok(RawRoutingAction::Drop);
        }
        if let Some(client_mac) = &self.client_mac
            && &src_mac != client_mac
        {
            debug!("Ethernet frame has source {src_mac}, should be {client_mac}");
            return Ok(RawRoutingAction::Drop);
        }

        let data = &data[L2_ETHERNET_HEADER_SIZE..];
        if let Some(pcap_sender) = &mut self.pcap_sender {
            pcap_sender.send_packet(data);
        }
        let ip_packet = match ip::IpPacket::from_data(data) {
            Ok(packet) => packet,
            Err(err) => {
                warn!(
                    "Failed to parse IP packet from ethernet frame: {}\n{}",
                    err,
                    fmt_slice_hex(data),
                );
                return Err("Failed to parse IP packet from ethernet frame".into());
            }
        };
        trace!(
            "Decoded IP packet from {ether_type} ethernet frame {src_mac} -> {dst_mac} {ip_packet}"
        );
        let header = ip_packet.to_header();
        if !self.nat64_prefix.matches_addr(header.dst_addr()) {
            debug!(
                "Packet destination {} doesn't match NAT64 prefix",
                header.dst_addr()
            );
            return Ok(RawRoutingAction::Drop);
        }
        // Register client MAC for additional authentication, and to send back replies.
        if self.client_ip.is_some() && self.client_mac.is_none() {
            self.client_mac = Some(src_mac);
        }

        match self
            .network
            .translate_packet_from_client(ip_packet, header, out_buf)
        {
            Ok(ip::RoutingActionClient::Forward(buf)) => {
                let vpn_real_ip = match self.vpn_real_ip {
                    Some(vpn_real_ip) => vpn_real_ip,
                    None => {
                        return Err(
                            "VPN real IP is not configured, cannot translate packet source IP"
                                .into(),
                        );
                    }
                };
                if let Err(err) = ip::IpPacket::update_src_addr(buf, vpn_real_ip) {
                    warn!("Failed to update packet source IP: {err}");
                    return Err("Failed to update packet source IP".into());
                }
                Ok(RawRoutingAction::Forward(buf))
            }
            Ok(ip::RoutingActionClient::ReturnToSender(buf, msg_len)) => {
                // Prepend Ethernet headers.
                buf.copy_within(..msg_len, L2_ETHERNET_HEADER_SIZE);
                buf[0..6].copy_from_slice(src_mac.as_slice());
                buf[6..12].copy_from_slice(dst_mac.as_slice());
                buf[12..14].copy_from_slice(&EtherType::IPV6.to_u16().to_be_bytes());
                Ok(RawRoutingAction::ReturnToSender(
                    &buf[..L2_ETHERNET_HEADER_SIZE + msg_len],
                ))
            }
            Ok(ip::RoutingActionClient::Drop) => Ok(RawRoutingAction::Drop),
            Err(err) => {
                warn!("Failed to NAT packet from client: {err}");
                Err("Failed to NAT packet from client".into())
            }
        }
    }

    fn process_uplink_packet<'a>(
        &mut self,
        in_buf: &'a mut [u8],
        data_len: usize,
        out_buf: &'a mut [u8],
    ) -> Result<UplinkRoutingAction<'a>, L2GatewayError> {
        if data_len == 0 {
            return Ok(UplinkRoutingAction::Drop);
        }
        trace!(
            "Received packet from uplink/VPN\n{}",
            fmt_slice_hex(&in_buf[..data_len])
        );
        let ip_packet = match ip::IpPacket::from_data(&in_buf[..data_len]) {
            Ok(packet) => packet,
            Err(err) => {
                warn!(
                    "Failed to decode IP packet from uplink/VPN: {}\n{}",
                    err,
                    fmt_slice_hex(&in_buf[..data_len]),
                );
                return Err("Failed to decode IP packet from uplink/VPN".into());
            }
        };
        trace!("Decoded IP packet from uplink/VPN {ip_packet}");
        let ip_header = ip_packet.to_header();

        match self
            .network
            .translate_packet_from_uplink(ip_header, in_buf, data_len, out_buf)
        {
            Ok(ip::RoutingActionUplink::Forward(buf, data_len)) => {
                trace!(
                    "Forwarding response to raw socket: {}",
                    fmt_slice_hex(&buf[..data_len])
                );
                if let Some(pcap_sender) = &mut self.pcap_sender {
                    pcap_sender.send_packet(&buf[..data_len]);
                }
                let client_ip = match self.client_ip {
                    Some(client_ip) => IpAddr::V6(client_ip),
                    None => return Err("No client IP address found for uplink/VPN packet".into()),
                };
                if let Err(err) = ip::IpPacket::update_dst_addr(&mut buf[..data_len], client_ip) {
                    warn!("Failed to update packet destination IP: {err}");
                    return Err("Failed to update packet destination IP".into());
                }
                let dst_mac = match &self.client_mac {
                    Some(client_mac) => client_mac,
                    None => return Err("No client MAC address found for uplink/VPN packet".into()),
                };
                let ethernet_len = L2_ETHERNET_HEADER_SIZE + data_len;
                if ethernet_len > buf.len() {
                    // This sometimes happens when FortiVPN returns a zero-padded packet.
                    warn!(
                        "Slice doesn't have capacity for ethernet headers, message length is {ethernet_len}, buffer has {}",
                        buf.len()
                    );
                    return Err("Slice doesn't have capacity for ethernet headers".into());
                }
                // Prepend Ethernet headers.
                buf.copy_within(..data_len, 14);
                buf[0..6].copy_from_slice(dst_mac.as_slice());
                buf[6..12].copy_from_slice(self.server_mac.as_slice());
                buf[12..14].copy_from_slice(&EtherType::IPV6.to_u16().to_be_bytes());

                trace!(
                    "Sending ethernet frame: {}",
                    fmt_slice_hex(&buf[..ethernet_len])
                );
                Ok(UplinkRoutingAction::Forward(&buf[..ethernet_len]))
            }
            Ok(ip::RoutingActionUplink::ReturnToSender(buf)) => {
                Ok(UplinkRoutingAction::ReturnToSender(buf))
            }
            Ok(ip::RoutingActionUplink::Drop) => Ok(UplinkRoutingAction::Drop),
            Err(err) => {
                warn!("Failed to NAT packet from uplink/VPN: {err}");
                Err("Failed to NAT packet from uplink/VPN".into())
            }
        }
    }
}

enum RawRoutingAction<'a> {
    Forward(&'a [u8]),
    ReturnToSender(&'a [u8]),
    Drop,
}

impl<'a> RawRoutingAction<'a> {
    fn into_packets(self) -> (Option<&'a [u8]>, &'a [u8]) {
        match self {
            RawRoutingAction::Forward(data) => (None, data),
            RawRoutingAction::ReturnToSender(data) => (Some(data), &[]),
            RawRoutingAction::Drop => (None, &[]),
        }
    }
}

enum UplinkRoutingAction<'a> {
    Forward(&'a [u8]),
    ReturnToSender(&'a [u8]),
    Drop,
}

impl<'a> UplinkRoutingAction<'a> {
    fn into_packets(self) -> (&'a [u8], Option<&'a [u8]>) {
        match self {
            UplinkRoutingAction::Forward(data) => (&[], Some(data)),
            UplinkRoutingAction::ReturnToSender(data) => (data, None),
            UplinkRoutingAction::Drop => (&[], None),
        }
    }
}

struct RawSocket {
    socket: AsyncFd<std::os::unix::io::RawFd>,
    mac: MacAddr,
    if_index: libc::c_int,
}

impl RawSocket {
    async fn new(listen_interface: &str, mtu: Option<usize>) -> Result<RawSocket, L2GatewayError> {
        let protocol = u16::from_be(libc::ETH_P_IPV6 as u16) as libc::c_int;
        let socket = match unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, protocol) } {
            0 => return Err(io::Error::last_os_error().into()),
            fd => fd as std::os::unix::io::RawFd,
        };
        let (mac, if_index) = RawSocket::iface_config(socket, listen_interface)?;
        if let Some(mtu) = mtu {
            match RawSocket::set_mtu(socket, listen_interface, mtu) {
                Ok(true) => {
                    info!("Updated MTU to {mtu}")
                }
                Ok(false) => {
                    debug!("MTU is already up to date")
                }
                Err(err) => {
                    warn!("Failed to update MTU: {err}")
                }
            }
        }
        let socket = AsyncFd::new(socket)?;
        let socket = RawSocket {
            socket,
            mac,
            if_index,
        };
        if let Err(err) =
            socket.setsockopt_bool(libc::SOL_PACKET, libc::PACKET_IGNORE_OUTGOING, true)
        {
            warn!(
                "Failed to enable PACKET_IGNORE_OUTGOING socket option, will rely on a less efficient packet filter: {err}"
            )
        }

        Ok(socket)
    }

    fn if_mac(&self) -> MacAddr {
        self.mac
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        loop {
            let mut guard = std::task::ready!(self.socket.poll_read_ready(cx))?;
            match guard.try_io(|fd| {
                let result = unsafe {
                    libc::recv(
                        fd.as_raw_fd(),
                        buf.as_mut_ptr() as *mut _,
                        buf.len(),
                        libc::MSG_DONTWAIT,
                    )
                };
                if result >= 0 {
                    Ok(result as usize)
                } else {
                    Err(io::Error::last_os_error())
                }
            }) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_send(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let mut sll_addr = [0u8; 8];
        sll_addr[0..6].copy_from_slice(self.mac.as_slice());
        let srcaddr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: libc::ETH_P_IPV6 as u16,
            sll_ifindex: self.if_index,
            sll_hatype: libc::ARPHRD_ETHER,
            sll_pkttype: 0,
            sll_halen: 6,
            sll_addr,
        };
        loop {
            let mut guard = std::task::ready!(self.socket.poll_write_ready(cx))?;
            match guard.try_io(|fd| {
                let result = unsafe {
                    libc::sendto(
                        fd.as_raw_fd(),
                        buf.as_ptr() as *const _,
                        buf.len(),
                        libc::MSG_DONTWAIT,
                        std::ptr::from_ref(&srcaddr).cast(),
                        std::mem::size_of_val(&srcaddr) as libc::socklen_t,
                    )
                };
                if result >= 0 {
                    Ok(result as usize)
                } else {
                    Err(io::Error::last_os_error())
                }
            }) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn setsockopt<T>(
        &self,
        level: libc::c_int,
        name: libc::c_int,
        value: &T,
    ) -> Result<(), io::Error>
    where
        T: Sized,
    {
        let fd = self.socket.as_raw_fd();
        match unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                std::ptr::from_ref(value).cast(),
                std::mem::size_of_val(value) as libc::socklen_t,
            )
        } {
            0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    fn setsockopt_bool(
        &self,
        level: libc::c_int,
        name: libc::c_int,
        value: bool,
    ) -> Result<(), io::Error> {
        let value = if value {
            1 as libc::c_int
        } else {
            0 as libc::c_int
        };
        self.setsockopt(level, name, &value)
    }

    fn ifr_name(name: &str) -> Result<[libc::c_char; libc::IFNAMSIZ], L2GatewayError> {
        match std::ffi::CString::new(name) {
            Ok(name) => {
                let name = name.as_bytes_with_nul();
                let mut ifr_name = [0; libc::IFNAMSIZ];
                if name.len() > ifr_name.len() {
                    return Err("Listen interace name is too long".into());
                }
                ifr_name
                    .iter_mut()
                    .zip(name)
                    .for_each(|(dst, src)| *dst = *src as libc::c_char);
                Ok(ifr_name)
            }
            Err(err) => {
                warn!("Failed to parse interface name {name}: {err}");
                Err("Failed to parse interface name".into())
            }
        }
    }

    fn iface_config(
        fd: std::os::unix::io::RawFd,
        name: &str,
    ) -> Result<(MacAddr, libc::c_int), L2GatewayError> {
        let ifr_name = Self::ifr_name(name)?;
        let mut ifreq = libc::ifreq {
            ifr_name,
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_hwaddr: libc::sockaddr {
                    sa_family: libc::AF_PACKET as u16,
                    sa_data: [0; 14],
                },
            },
        };
        let mac_addr = unsafe {
            match libc::ioctl(fd, libc::SIOCGIFHWADDR, std::ptr::from_mut(&mut ifreq)) {
                0 => {
                    let mut mac_addr = [0u8; 6];
                    mac_addr
                        .iter_mut()
                        .zip(&ifreq.ifr_ifru.ifru_hwaddr.sa_data[0..6])
                        .for_each(|(dst, src)| *dst = *src as u8);
                    MacAddr::from_data(&mac_addr)
                }
                _ => {
                    let err = io::Error::last_os_error();
                    warn!("Failed to get hardware address for {name}: {err}");
                    return Err(io::Error::last_os_error().into());
                }
            }
        };
        let mut ifreq = libc::ifreq {
            ifr_name,
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_ifindex: 0 },
        };
        let if_index = unsafe {
            match libc::ioctl(fd, libc::SIOCGIFINDEX, std::ptr::from_mut(&mut ifreq)) {
                0 => ifreq.ifr_ifru.ifru_ifindex,
                _ => {
                    let err = io::Error::last_os_error();
                    warn!("Failed to get interface index for {name}: {err}");
                    return Err(io::Error::last_os_error().into());
                }
            }
        };
        Ok((mac_addr, if_index))
    }

    fn set_mtu(
        fd: std::os::unix::io::RawFd,
        name: &str,
        mtu: usize,
    ) -> Result<bool, L2GatewayError> {
        let ifr_name = Self::ifr_name(name)?;
        let mut ifreq = libc::ifreq {
            ifr_name,
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_mtu: 0 },
        };
        let current_mtu = unsafe {
            match libc::ioctl(fd, libc::SIOCGIFMTU, std::ptr::from_mut(&mut ifreq)) {
                0 => ifreq.ifr_ifru.ifru_mtu,
                _ => {
                    let err = io::Error::last_os_error();
                    warn!("Failed to get MTU {name}: {err}");
                    return Err(io::Error::last_os_error().into());
                }
            }
        };
        if current_mtu >= mtu as i32 {
            return Ok(false);
        }
        let mut ifreq = libc::ifreq {
            ifr_name,
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_mtu: mtu as libc::c_int,
            },
        };
        unsafe {
            match libc::ioctl(fd, libc::SIOCSIFMTU, std::ptr::from_mut(&mut ifreq)) {
                0 => Ok(true),
                _ => {
                    let err = io::Error::last_os_error();
                    warn!("Failed to set MTU {name}: {err}");
                    Err(io::Error::last_os_error().into())
                }
            }
        }
    }

    fn set_nat64_filter(&self, prefix: &ip::Nat64Prefix) -> Result<(), io::Error> {
        // See https://docs.kernel.org/networking/filter.html for more information.
        let mut filter_data = BpfFilter::new_nat64_filter(&self.mac, prefix);
        let filter = libc::sock_fprog {
            len: filter_data.ops_len as libc::c_ushort,
            filter: filter_data.program_data.as_mut_ptr().cast(),
        };
        self.setsockopt(libc::SOL_SOCKET, libc::SO_ATTACH_FILTER, &filter)
    }
}

#[repr(C)]
struct BpfFilterOp {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

impl BpfFilterOp {
    fn new(code: u16, jt: u8, jf: u8, k: u32) -> BpfFilterOp {
        BpfFilterOp { code, jt, jf, k }
    }

    fn as_slice(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(self).cast(),
                std::mem::size_of::<BpfFilterOp>(),
            )
        }
    }
}

struct BpfFilter {
    ops_len: usize,
    program_data: Vec<u8>,
}

impl BpfFilter {
    fn new_program(prog: &[BpfFilterOp]) -> BpfFilter {
        let mut program_data = vec![0u8; std::mem::size_of_val(prog)];
        // TODO GATEWAY: write bytes directly, BPF is a standard documented in RFC 9669.
        program_data
            .chunks_exact_mut(std::mem::size_of::<BpfFilterOp>())
            .zip(prog.iter())
            .for_each(|(data, op)| data.copy_from_slice(op.as_slice()));
        BpfFilter {
            ops_len: prog.len(),
            program_data,
        }
    }

    fn new_nat64_filter(if_mac: &MacAddr, prefix: &ip::Nat64Prefix) -> BpfFilter {
        let prefix_part = |i: usize| -> u32 {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&prefix[i * 4..(i + 1) * 4]);
            u32::from_be_bytes(bytes)
        };
        let mut mac_part = [0u8; 4];
        mac_part.copy_from_slice(&if_mac.as_slice()[2..6]);
        let mac_end = u32::from_be_bytes(mac_part);
        let mut mac_part = [0u8; 4];
        mac_part[2..4].copy_from_slice(&if_mac.as_slice()[0..2]);
        let mac_start = u32::from_be_bytes(mac_part);
        // Output of 'sudo tcpdump -i wlo1 ether dst 12:34:56:78:9a:bc and ip6 dst net 0064:ff9b::/96 -ddd'
        BpfFilter::new_program(&[
            BpfFilterOp::new(32, 0, 0, 2),
            BpfFilterOp::new(21, 0, 11, mac_end),
            BpfFilterOp::new(40, 0, 0, 0),
            BpfFilterOp::new(21, 0, 9, mac_start),
            BpfFilterOp::new(40, 0, 0, 12),
            BpfFilterOp::new(21, 0, 7, 34525),
            BpfFilterOp::new(32, 0, 0, 38),
            BpfFilterOp::new(21, 0, 5, prefix_part(0)),
            BpfFilterOp::new(32, 0, 0, 42),
            BpfFilterOp::new(21, 0, 3, prefix_part(1)),
            BpfFilterOp::new(32, 0, 0, 46),
            BpfFilterOp::new(21, 0, 1, prefix_part(2)),
            BpfFilterOp::new(6, 0, 0, 262144),
            BpfFilterOp::new(6, 0, 0, 0),
        ])
    }
}

#[derive(Debug)]
pub enum L2GatewayError {
    Internal(&'static str),
    Ip(ip::IpError),
    Uplink(uplink::UplinkError),
    Io(io::Error),
}

impl fmt::Display for L2GatewayError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Internal(msg) => f.write_str(msg),
            Self::Ip(e) => write!(f, "IP error: {e}"),
            Self::Uplink(e) => write!(f, "Uplink/VPN error: {e}"),
            Self::Io(e) => write!(f, "IO error: {e}"),
        }
    }
}

impl error::Error for L2GatewayError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Internal(_msg) => None,
            Self::Ip(err) => Some(err),
            Self::Uplink(err) => Some(err),
            Self::Io(err) => Some(err),
        }
    }
}

impl From<&'static str> for L2GatewayError {
    fn from(msg: &'static str) -> L2GatewayError {
        Self::Internal(msg)
    }
}

impl From<ip::IpError> for L2GatewayError {
    fn from(err: ip::IpError) -> L2GatewayError {
        Self::Ip(err)
    }
}

impl From<uplink::UplinkError> for L2GatewayError {
    fn from(err: uplink::UplinkError) -> L2GatewayError {
        Self::Uplink(err)
    }
}

impl From<io::Error> for L2GatewayError {
    fn from(err: io::Error) -> L2GatewayError {
        Self::Io(err)
    }
}
