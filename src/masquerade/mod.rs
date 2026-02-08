use std::{
    collections::HashMap,
    error, fmt, future, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::Range,
    str::FromStr as _,
    task::Poll,
};

use log::{debug, warn};
use tokio::{
    fs,
    io::{AsyncBufReadExt as _, BufReader, ReadBuf},
    net::UdpSocket,
};

use crate::{ip, logger::fmt_slice_hex, uplink};

const MAX_IP_HEADER_LENGTH: usize = 40;

pub struct Config {
    pub masquerade_ip: IpAddr,
    pub dns_addrs: Vec<IpAddr>,
    pub nat64_prefix: Option<Ipv6Addr>,
    pub dns64_domains: Vec<String>,
}

pub struct MasqueradeClient {
    masquerade_ip: IpAddr,
    dns_addrs: Vec<IpAddr>,
    nat_table: NatTable,
    running: bool,
}

impl MasqueradeClient {
    pub fn new(config: Config) -> MasqueradeClient {
        let nat64_prefix = config.nat64_prefix.map(ip::Nat64Prefix::new);
        let dns_addrs = if let Some(nat64_prefix) = &nat64_prefix {
            config
                .dns_addrs
                .iter()
                .filter_map(|dns_addr| {
                    if nat64_prefix.matches(dns_addr) {
                        None
                    } else {
                        Some(*dns_addr)
                    }
                })
                .collect::<Vec<_>>()
        } else {
            config.dns_addrs
        };
        MasqueradeClient {
            masquerade_ip: config.masquerade_ip,
            dns_addrs,
            nat_table: NatTable::new(),
            running: true,
        }
    }

    async fn send_packet(&mut self, data: &[u8]) -> Result<(), MasqueradeError> {
        let packet = match ip::IpPacket::from_data(data) {
            Ok(packet) => packet,
            Err(err) => {
                warn!("Masquerade failed to decode packet: {err}");
                return Err("Masquerade failed to decode packet".into());
            }
        };
        match packet.transport_protocol() {
            ip::TransportProtocolType::TCP => {
                return Err("TCP support is not yet implemented".into());
            }
            ip::TransportProtocolType::UDP => {}
            protocol => {
                debug!("Masquerade doesn't support transport protocol {protocol}");
                return Err("Masquerade doesn't support transport protocol".into());
            }
        }
        if !packet.validate_ip_checksum() {
            warn!(
                "Received packet with invalid checksum: {}",
                fmt_slice_hex(data)
            );
            return Err("Packet has invalid checksum".into());
        }
        let src_port = if let Some(src_port) = packet.src_port() {
            src_port
        } else {
            warn!(
                "Packet with protocol {} has no source port",
                packet.transport_protocol()
            );
            return Err("Packet has no source port".into());
        };
        let dst_port = if let Some(dst_port) = packet.dst_port() {
            dst_port
        } else {
            warn!(
                "Packet with protocol {} has no destination port",
                packet.transport_protocol()
            );
            return Err("Packet has no destination port".into());
        };
        let src_addr = SocketAddr::new(packet.src_addr(), src_port);
        let dst_addr = SocketAddr::new(packet.dst_addr(), dst_port);
        let socket = match self.nat_table.obtain_udp_socket(src_addr, dst_addr).await {
            Ok(socket) => socket,
            Err(err) => {
                warn!("Failed to obtain socket in NAT table: {err}");
                return Err(err);
            }
        };

        socket
            .send_to(packet.transport_protocol_data().payload_data(), dst_addr)
            .await?;
        Ok(())
    }
}

impl uplink::UplinkService for MasqueradeClient {
    fn is_connected(&self) -> bool {
        self.running
    }

    fn ip_configuration(&self) -> Option<(IpAddr, &[IpAddr])> {
        if self.running {
            Some((self.masquerade_ip, &self.dns_addrs))
        } else {
            None
        }
    }

    async fn wait_event(&mut self, _buf: &mut [u8]) -> Result<(), uplink::UplinkError> {
        if self.running {
            self.nat_table.wait_event().await?;
        }
        Ok(())
    }

    async fn read_packet<'a>(
        &mut self,
        buffer: &'a mut [u8],
    ) -> Result<&'a [u8], uplink::UplinkError> {
        if self.running {
            let res = self.nat_table.read_packet(buffer).await;
            res
        } else {
            Ok(&[])
        }
    }

    async fn process_events(&mut self, send_slices: &[&[u8]]) -> Result<(), uplink::UplinkError> {
        for send_slice in send_slices {
            if send_slice.is_empty() {
                continue;
            }
            if let Err(err) = self.send_packet(send_slice).await {
                debug!("Failed to send packet: {err}");
            }
        }
        Ok(())
    }

    async fn terminate(&mut self) -> Result<(), uplink::UplinkError> {
        self.running = false;
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct NatFlowId {
    // TODO NAT: also track source ESP session?
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
enum UdpSocketId {
    V4(u16),
    V6(u16),
}

impl fmt::Display for UdpSocketId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::V4(port) => write!(f, "IPv4 UDP socket {port}"),
            Self::V6(port) => write!(f, "IPv6 UDP socket {port}"),
        }
    }
}

struct NatTable {
    udp_table: HashMap<NatFlowId, UdpSocketId>,
    udp_r_table: HashMap<UdpSocketId, Vec<NatFlowId>>,

    udp_sockets: UdpSocketPool,
    poll_seed: usize,
}

impl NatTable {
    fn new() -> NatTable {
        NatTable {
            udp_table: HashMap::new(),
            udp_r_table: HashMap::new(),
            udp_sockets: UdpSocketPool::new(),
            poll_seed: 0,
        }
    }

    async fn obtain_udp_socket(
        &mut self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
    ) -> Result<&UdpSocket, MasqueradeError> {
        let flow_id = NatFlowId { src_addr, dst_addr };
        let socket_id = if let Some(socket_id) = self.udp_table.get(&flow_id) {
            *socket_id
        } else {
            let usable_socket = self
                .udp_r_table
                .iter()
                .find(|(_socket_id, flows)| !flows.iter().any(|flow| flow.dst_addr == dst_addr))
                .map(|(socket_id, _flows)| *socket_id);

            let socket_id = if let Some(socket_id) = usable_socket {
                socket_id
            } else {
                let res = match dst_addr {
                    SocketAddr::V4(_) => self.udp_sockets.create_socket_v4().await,
                    SocketAddr::V6(_) => self.udp_sockets.create_socket_v6().await,
                };
                match res {
                    Ok(socket) => socket,
                    Err(err) => {
                        warn!("Failed to create socket: {err}");
                        return Err(err.into());
                    }
                }
            };
            self.insert_flow(flow_id, socket_id);
            socket_id
        };
        if let Some(udp_socket) = self.udp_sockets.get_socket(&socket_id) {
            Ok(udp_socket)
        } else {
            Err("UDP socket {socket_id} not found in NAT table".into())
        }
    }

    async fn wait_event(&mut self) -> Result<(), MasqueradeError> {
        self.poll_seed = self.poll_seed.wrapping_add(1);
        future::poll_fn(|cx| self.udp_sockets.poll_ready(cx, self.poll_seed)).await
    }

    async fn read_packet<'a>(
        &mut self,
        buffer: &'a mut [u8],
    ) -> Result<&'a [u8], uplink::UplinkError> {
        let read_bytes = future::poll_fn(|cx| {
            self.udp_sockets
                .poll_recv(cx, self.poll_seed, &self.udp_r_table, buffer)
        })
        .await?;
        let packet_data = &buffer[..read_bytes];
        Ok(packet_data)
    }

    fn insert_flow(&mut self, flow: NatFlowId, socket: UdpSocketId) {
        self.udp_table.insert(flow, socket);
        self.udp_r_table
            .entry(socket)
            .and_modify(|flows| {
                if !flows.contains(&flow) {
                    flows.push(flow)
                }
            })
            .or_insert_with(|| vec![flow]);
    }

    fn cleanup() {
        // TODO: clean up unused sockets from UDP table, based on TTL
        // Plus, clean up NAT table itself
    }
}

struct UdpSocketPool {
    sockets: HashMap<UdpSocketId, UdpSocket>,
}

impl UdpSocketPool {
    fn new() -> UdpSocketPool {
        UdpSocketPool {
            sockets: HashMap::new(),
        }
    }

    async fn create_socket_v4(&mut self) -> Result<UdpSocketId, io::Error> {
        let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await?;
        let socket_id = UdpSocketId::V4(socket.local_addr()?.port());
        self.sockets.insert(socket_id, socket);
        Ok(socket_id)
    }

    async fn create_socket_v6(&mut self) -> Result<UdpSocketId, io::Error> {
        let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)).await?;
        let socket_id = UdpSocketId::V6(socket.local_addr()?.port());
        self.sockets.insert(socket_id, socket);
        Ok(socket_id)
    }

    fn get_socket(&self, id: &UdpSocketId) -> Option<&UdpSocket> {
        self.sockets.get(id)
    }

    fn poll_ready(
        &self,
        cx: &mut std::task::Context<'_>,
        seed: usize,
    ) -> Poll<Result<(), MasqueradeError>> {
        if self.sockets.is_empty() {
            return Poll::Pending;
        }
        // Split socket list into two parts, then combine the second half with the first one.
        let seed = seed % self.sockets.len();
        let (left, right) = (
            self.sockets.iter().take(seed),
            self.sockets.iter().skip(seed),
        );
        let it = right.chain(left);
        for (socket_id, socket) in it {
            match socket.poll_recv_ready(cx) {
                Poll::Ready(Ok(())) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(err)) => {
                    warn!("Failed to check if socket {socket_id} is ready: {err}");
                    return Poll::Ready(Err(err.into()));
                }
                Poll::Pending => {}
            };
        }
        Poll::Pending
    }

    fn poll_recv<'a>(
        &self,
        cx: &mut std::task::Context<'_>,
        seed: usize,
        udp_r_table: &HashMap<UdpSocketId, Vec<NatFlowId>>,
        buf: &'a mut [u8],
    ) -> Poll<Result<usize, MasqueradeError>> {
        if self.sockets.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Split socket list into two parts, then combine the second half with the first one.
        let seed = seed % self.sockets.len();
        let (left, right) = (
            self.sockets.iter().take(seed),
            self.sockets.iter().skip(seed),
        );
        let it = right.chain(left);
        let mut read_buf = ReadBuf::new(&mut buf[MAX_IP_HEADER_LENGTH..]);
        for (socket_id, socket) in it {
            read_buf.clear();
            match socket.poll_recv_from(cx, &mut read_buf) {
                Poll::Ready(Ok(remote_addr)) => {
                    let data_range =
                        MAX_IP_HEADER_LENGTH..MAX_IP_HEADER_LENGTH + read_buf.filled().len();
                    let local_addr = if let Some(local_addr) = udp_r_table
                        .get(socket_id)
                        .map(|flows| {
                            flows
                                .iter()
                                .find(|flow| flow.dst_addr == remote_addr)
                                .map(|flow| flow.src_addr)
                        })
                        .flatten()
                    {
                        local_addr
                    } else {
                        warn!("Failed to find flow in NAT table for packet from {remote_addr}");
                        return Poll::Ready(Err("Failed to find flow in NAT table".into()));
                    };
                    return Poll::Ready(Self::write_ip_packet(
                        remote_addr,
                        local_addr,
                        buf,
                        data_range,
                    ));
                }
                Poll::Ready(Err(err)) => {
                    warn!("Failed to receive from socket {socket_id}: {err}");
                    return Poll::Ready(Err(err.into()));
                }
                Poll::Pending => {}
            };
        }
        Poll::Ready(Ok(0))
    }

    fn write_ip_packet<'a>(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        dest: &'a mut [u8],
        data_range: Range<usize>,
    ) -> Result<usize, MasqueradeError> {
        let start_offset =
            ip::IpPacket::write_ip_udp_header(src_addr, dst_addr, dest, data_range.clone())?;
        let packet_range = start_offset..data_range.end;
        let bytes_read = packet_range.len();
        dest.copy_within(packet_range, 0);
        Ok(bytes_read)
    }
}

pub async fn read_systen_dns_servers() -> Result<Vec<IpAddr>, MasqueradeError> {
    let file = fs::File::open("/etc/resolv.conf").await?;
    let mut lines = BufReader::new(file).lines();
    // Go parses this directly: https://go.dev/src/net/dnsclient_unix.go
    let mut dns_servers = vec![];
    while let Some(line) = lines.next_line().await? {
        if let Some("nameserver") = line.split_whitespace().next()
            && let Some(dns_server) = line.strip_prefix("nameserver")
        {
            match IpAddr::from_str(dns_server.trim()) {
                Ok(dns_server) => dns_servers.push(dns_server),
                Err(err) => warn!("Failed to parse nameserver entry: {err}"),
            }
        }
    }
    Ok(dns_servers)
}

#[derive(Debug)]
pub enum MasqueradeError {
    Internal(&'static str),
    Io(io::Error),
    Ip(ip::IpError),
}

impl fmt::Display for MasqueradeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Internal(msg) => f.write_str(msg),
            Self::Io(e) => write!(f, "IO error: {e}"),
            Self::Ip(e) => write!(f, "IP error: {e}"),
        }
    }
}

impl error::Error for MasqueradeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Internal(_msg) => None,
            Self::Io(err) => Some(err),
            Self::Ip(err) => Some(err),
        }
    }
}

impl From<&'static str> for MasqueradeError {
    fn from(msg: &'static str) -> MasqueradeError {
        Self::Internal(msg)
    }
}

impl From<io::Error> for MasqueradeError {
    fn from(err: io::Error) -> MasqueradeError {
        Self::Io(err)
    }
}

impl From<ip::IpError> for MasqueradeError {
    fn from(err: ip::IpError) -> MasqueradeError {
        Self::Ip(err)
    }
}
