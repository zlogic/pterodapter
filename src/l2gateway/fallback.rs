use std::{
    collections::HashMap,
    error, fmt, future, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::Range,
    task::Poll,
    time::{Duration, Instant},
};

use log::{trace, warn};
use tokio::{io::ReadBuf, net::UdpSocket, time::timeout_at};

use crate::ip::{self, IpPacket};

const MAX_IP_HEADER_LENGTH: usize = 40;
const DNS_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct DnsFlow {
    query_id: u16,
    dest: SocketAddr,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct DnsQuery {
    src_mac: super::MacAddr,
    src_addr: SocketAddr,
    expires: Instant,
}

struct SharedSocket {
    queries: HashMap<DnsFlow, DnsQuery>,
    socket: UdpSocket,
}

pub struct FallbackDnsClient {
    udp_connections: Vec<SharedSocket>,
    poll_seed: usize,
}

impl FallbackDnsClient {
    pub fn new() -> FallbackDnsClient {
        FallbackDnsClient {
            udp_connections: vec![],
            poll_seed: 0,
        }
    }

    fn next_timeout(&self) -> Option<Instant> {
        self.udp_connections
            .iter()
            .flat_map(|connection| connection.queries.values().map(|query| query.expires).min())
            .min()
    }

    fn cleanup_expired(&mut self) {
        let now = Instant::now();
        self.udp_connections.iter_mut().for_each(|connection| {
            connection
                .queries
                .retain(|_flow, query| query.expires < now)
        });
    }

    async fn get_socket(
        &mut self,
        src_addr: SocketAddr,
        src_mac: super::MacAddr,
        dest: SocketAddr,
        query_id: u16,
    ) -> Result<&UdpSocket, io::Error> {
        let dns_flow = DnsFlow { dest, query_id };
        let dns_query = DnsQuery {
            src_addr,
            src_mac,
            expires: Instant::now() + DNS_TIMEOUT,
        };
        let socket_index = self
            .udp_connections
            .iter_mut()
            .enumerate()
            .filter_map(|(i, socket)| {
                // Check if the socket can be shared by query (no conflicting flows)
                if let Some(existing_query) = socket.queries.get_mut(&dns_flow) {
                    // Same source and query, likely retransmission.
                    if existing_query.src_addr == dns_query.src_addr {
                        existing_query.expires = dns_query.expires;
                        Some(i)
                    } else {
                        // No matching flows, safe to reuse.
                        socket.queries.insert(dns_flow, dns_query);
                        Some(i)
                    }
                } else {
                    None
                }
            })
            .next();
        let socket_index = if let Some(i) = socket_index {
            i
        } else {
            let socket =
                UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await?;
            let mut queries = HashMap::new();
            queries.insert(dns_flow, dns_query);
            self.udp_connections.push(SharedSocket { socket, queries });
            self.udp_connections.len() - 1
        };
        Ok(&self.udp_connections[socket_index].socket)
    }

    async fn send_request(
        &mut self,
        src_mac: super::MacAddr,
        packet: IpPacket<'_>,
    ) -> Result<(), FallbackError> {
        let header = packet.to_header();
        if header.transport_protocol() != ip::TransportProtocolType::UDP {
            trace!("Received non-UDP packet, dropping: {header}");
            return Err("Request is not a UDP packet".into());
        }
        let src_port = match (header.src_port(), header.dst_port()) {
            (Some(&src_port), Some(&53)) => src_port,
            _ => {
                trace!("Received non-DNS request, dropping: {header}");
                return Err("Request is not a DNS packet".into());
            }
        };
        let src_addr = SocketAddr::new(*header.src_addr(), src_port);
        let dest = SocketAddr::new(*header.dst_addr(), 53);
        let dns_data = packet.transport_protocol_data().payload_data();

        let query_id = match Self::dns_query(dns_data) {
            Ok(query_id) => query_id,
            Err(err) => {
                warn!("Failed to get DNS query ID from request: {err}");
                return Err(err);
            }
        };
        let socket = self.get_socket(src_addr, src_mac, dest, query_id).await?;
        socket.send_to(dns_data, dest).await?;
        Ok(())
    }

    fn dns_query(dns_data: &[u8]) -> Result<u16, FallbackError> {
        if dns_data.len() < 2 {
            Err("Not enough bytes in DNS payload".into())
        } else {
            // Just read the DNS query ID directly from the packet bytes.
            let mut query_id = [0u8; 2];
            query_id.copy_from_slice(&dns_data[0..2]);
            Ok(u16::from_be_bytes(query_id))
        }
    }

    fn prepend_ip_header(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        dest: &mut [u8],
        data_range: Range<usize>,
    ) -> Result<usize, FallbackError> {
        let start_offset =
            ip::IpPacket::write_ip_udp_header(src_addr, dst_addr, dest, data_range.clone())?;
        let packet_range = start_offset..data_range.end;
        let bytes_read = packet_range.len();
        dest.copy_within(packet_range, 0);
        Ok(bytes_read)
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
        seed: usize,
        buf: &mut [u8],
    ) -> Poll<Result<usize, FallbackError>> {
        if self.udp_connections.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Split socket list into two parts, then combine the second half with the first one.
        let (left, right) = self
            .udp_connections
            .split_at(seed % self.udp_connections.len());
        let it = right.iter().chain(left.iter());
        let mut read_buf = ReadBuf::new(&mut buf[MAX_IP_HEADER_LENGTH..]);
        for connection in it {
            read_buf.clear();
            match connection.socket.poll_recv_from(cx, &mut read_buf) {
                Poll::Ready(Ok(remote_addr)) => {
                    let data_range =
                        MAX_IP_HEADER_LENGTH..MAX_IP_HEADER_LENGTH + read_buf.filled().len();
                    if remote_addr.port() != 53 {
                        warn!("Received response from non-DNS port {remote_addr}");
                        return Poll::Ready(Err("Received response from non-DNS port".into()));
                    }
                    let query_id = match Self::dns_query(&buf[data_range.clone()]) {
                        Ok(query_id) => query_id,
                        Err(err) => {
                            warn!("Failed to extract DNS query from response: {err}");
                            return Poll::Ready(Err(
                                "Failed to extract DNS query from response".into()
                            ));
                        }
                    };
                    let dns_flow = DnsFlow {
                        dest: remote_addr,
                        query_id,
                    };

                    let src_addr = if let Some(query) = connection.queries.get(&dns_flow) {
                        query.src_addr
                    } else {
                        warn!(
                            "Failed to find DNS query source for ID {query_id} from {remote_addr}"
                        );
                        return Poll::Ready(Err("Failed to find flow in NAT table".into()));
                    };
                    let bytes_read =
                        Self::prepend_ip_header(remote_addr, src_addr, buf, data_range)?;
                    return Poll::Ready(Ok(bytes_read));
                }
                Poll::Ready(Err(err)) => {
                    warn!("Failed to receive from socket: {err}");
                    return Poll::Ready(Err(err.into()));
                }
                Poll::Pending => {}
            };
        }
        Poll::Ready(Ok(0))
    }

    pub async fn read_packet<'a>(
        &mut self,
        buffer: &'a mut [u8],
    ) -> Result<&'a [u8], FallbackError> {
        match future::poll_fn(|cx| self.poll_recv(cx, self.poll_seed, buffer)).await {
            Ok(read_bytes) => Ok(&buffer[..read_bytes]),
            Err(err) => Err(err.into()),
        }
    }

    fn poll_ready(
        &self,
        cx: &mut std::task::Context<'_>,
        seed: usize,
    ) -> Poll<Result<(), FallbackError>> {
        if self.udp_connections.is_empty() {
            return Poll::Pending;
        }
        // Split socket list into two parts, then combine the second half with the first one.
        let (left, right) = self
            .udp_connections
            .split_at(seed % self.udp_connections.len());
        let it = right.iter().chain(left.iter());
        for connection in it {
            match connection.socket.poll_recv_ready(cx) {
                Poll::Ready(Ok(())) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(err)) => {
                    warn!("Failed to check if socket is ready: {err}");
                    return Poll::Ready(Err(err.into()));
                }
                Poll::Pending => {}
            };
        }
        Poll::Pending
    }

    pub async fn wait_event(&mut self) -> Result<(), FallbackError> {
        self.poll_seed = self.poll_seed.wrapping_add(1);
        let ready = future::poll_fn(|cx| self.poll_ready(cx, self.poll_seed));
        if let Some(timeout) = self.next_timeout() {
            match timeout_at(timeout.into(), ready).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(err)) => Err(err),
                Err(_) => {
                    // Timeout.
                    self.cleanup_expired();
                    Ok(())
                }
            }
        } else {
            ready.await
        }
    }

    pub async fn process_events(
        &mut self,
        src_mac: super::MacAddr,
        send_slices: &[&[u8]],
    ) -> Result<(), FallbackError> {
        self.cleanup_expired();
        for send_data in send_slices {
            if send_data.is_empty() {
                continue;
            }
            let packet = match IpPacket::from_data(send_data) {
                Ok(packet) => packet,
                Err(err) => {
                    warn!("Failed to parse packet before sending: {err}");
                    return Err(err.into());
                }
            };
            match self.send_request(src_mac, packet).await {
                Ok(()) => {}
                Err(err) => {
                    warn!("Failed to send packet: {err}");
                    return Err(err);
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum FallbackError {
    Internal(&'static str),
    Io(io::Error),
    Ip(ip::IpError),
}

impl fmt::Display for FallbackError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Internal(msg) => f.write_str(msg),
            Self::Io(e) => write!(f, "IO error: {e}"),
            Self::Ip(e) => write!(f, "IP error: {e}"),
        }
    }
}

impl error::Error for FallbackError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Internal(_msg) => None,
            Self::Io(err) => Some(err),
            Self::Ip(err) => Some(err),
        }
    }
}

impl From<&'static str> for FallbackError {
    fn from(msg: &'static str) -> FallbackError {
        Self::Internal(msg)
    }
}

impl From<io::Error> for FallbackError {
    fn from(err: io::Error) -> FallbackError {
        Self::Io(err)
    }
}

impl From<ip::IpError> for FallbackError {
    fn from(err: ip::IpError) -> FallbackError {
        Self::Ip(err)
    }
}
