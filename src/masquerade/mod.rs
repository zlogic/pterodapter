use std::{
    collections::HashMap,
    error, fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr as _,
};

use log::{debug, warn};
use tokio::{
    fs,
    io::{AsyncBufReadExt as _, BufReader},
    net::UdpSocket,
};

use crate::{ip, logger::fmt_slice_hex, uplink};

pub struct Config {
    pub masquerade_ip: IpAddr,
    pub dns_addrs: Vec<IpAddr>,
    pub nat64_prefix: Option<Ipv6Addr>,
    pub dns64_domains: Vec<String>,
}

pub struct MasqueradeClient {
    masquerade_ip: IpAddr,
    dns_addrs: Vec<IpAddr>,
    nat64_prefix: Option<ip::Nat64Prefix>,
    dns64_domains: ip::TunnelDomainsDns,
    dns_translator: Option<ip::Dns64Translator>,
    nat_table: NatTable,
    running: bool,
}

impl MasqueradeClient {
    pub fn new(config: Config) -> MasqueradeClient {
        let nat64_prefix = config.nat64_prefix.map(ip::Nat64Prefix::new);
        let dns_translator = nat64_prefix.clone().map(ip::Dns64Translator::new);
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
            nat64_prefix,
            dns64_domains: ip::TunnelDomainsDns::new(&config.dns64_domains),
            dns_translator,
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
        let dst_addr = packet.dst_addr();
        let socket = self
            .nat_table
            .obtain_udp_socket(src_port, dst_port, dst_addr)
            .await;
        socket
            .send_to(packet.into_data(), SocketAddr::new(dst_addr, dst_port))
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
        // TODO MASQUERADE: wait for TCP/UDP traffic from NAT, or for a timer event.
        std::future::pending().await
    }

    async fn read_packet<'a>(
        &mut self,
        buffer: &'a mut [u8],
    ) -> Result<&'a [u8], uplink::UplinkError> {
        // TODO MASQUERADE: wait for TCP/UDP traffic from NAT.
        std::future::pending().await
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

#[derive(Eq, Hash, PartialEq)]
struct NatFlowId {
    // TODO NAT: also track source ESP session?
    src_port: u16,
    dst_port: u16,
    dst_addr: IpAddr,
}

struct NatTable {
    udp_table: HashMap<NatFlowId, u16>,

    udp_sockets: UdpSocketPool,
}

impl NatTable {
    fn new() -> NatTable {
        NatTable {
            udp_table: HashMap::new(),
            udp_sockets: UdpSocketPool::new(),
        }
    }

    async fn obtain_udp_socket(
        &mut self,
        src_port: u16,
        dst_port: u16,
        dst_addr: IpAddr,
    ) -> &UdpSocket {
        let flow_id = NatFlowId {
            src_port,
            dst_port,
            dst_addr,
        };
        let port = if let Some(port) = self.udp_table.get(&flow_id) {
            *port
        } else {
            match dst_addr {
                IpAddr::V4(_) => self.udp_sockets.create_socket_v4().await,
                IpAddr::V6(_) => self.udp_sockets.create_socket_v6().await,
            }
            .expect("failed to create socket")
        };
        // TODO NAT: remove unwrap
        match dst_addr {
            IpAddr::V4(_) => self.udp_sockets.get_socket_v4(&port).unwrap(),
            IpAddr::V6(_) => self.udp_sockets.get_socket_v6(&port).unwrap(),
        }
    }
}

struct UdpSocketPool {
    sockets_v4: HashMap<u16, UdpSocket>,
    sockets_v6: HashMap<u16, UdpSocket>,
}

impl UdpSocketPool {
    fn new() -> UdpSocketPool {
        UdpSocketPool {
            sockets_v4: HashMap::new(),
            sockets_v6: HashMap::new(),
        }
    }

    async fn create_socket_v4(&mut self) -> Result<u16, io::Error> {
        let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await?;
        let port = socket.local_addr()?.port();
        self.sockets_v4.insert(port, socket);
        Ok(port)
    }

    async fn create_socket_v6(&mut self) -> Result<u16, io::Error> {
        let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)).await?;
        let port = socket.local_addr()?.port();
        self.sockets_v6.insert(port, socket);
        Ok(port)
    }

    fn get_socket_v4(&self, port: &u16) -> Option<&UdpSocket> {
        self.sockets_v4.get(port)
    }

    fn get_socket_v6(&self, port: &u16) -> Option<&UdpSocket> {
        self.sockets_v6.get(port)
    }
}

pub async fn read_systen_dns_servers() -> Result<Vec<IpAddr>, MasqueradeError> {
    let file = fs::File::open("/etc/resolv.conf").await?;
    let mut lines = BufReader::new(file).lines();
    // Go parses this directly: https://go.dev/src/net/dnsclient_unix.go
    let mut dns_servers = vec![];
    while let Some(line) = lines.next_line().await? {
        if let Some("nameserver") = line.split_whitespace().next() {
            if let Some(dns_server) = line.strip_prefix("nameserver") {
                match IpAddr::from_str(dns_server.trim()) {
                    Ok(dns_server) => dns_servers.push(dns_server),
                    Err(err) => warn!("Failed to parse nameserver entry: {err}"),
                }
            }
        }
    }
    Ok(dns_servers)
}

#[derive(Debug)]
pub enum MasqueradeError {
    Internal(&'static str),
    Io(io::Error),
}

impl fmt::Display for MasqueradeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Internal(msg) => f.write_str(msg),
            Self::Io(e) => write!(f, "IO error: {e}"),
        }
    }
}

impl error::Error for MasqueradeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Internal(_msg) => None,
            Self::Io(err) => Some(err),
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
