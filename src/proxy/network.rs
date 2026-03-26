use std::{
    collections::{HashMap, HashSet},
    error, fmt, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    task::Poll,
};

use log::{debug, trace, warn};
use rand::RngExt as _;
use smoltcp::{iface, phy, socket, storage, wire};
use tokio::{
    sync::{mpsc, oneshot},
    time::Duration,
};

use crate::uplink::{self, UplinkService as _};

const MAX_MTU_SIZE: usize = 1500;
const READ_BUFFER_SIZE: usize = 65536 * 2 * 2;
const WRITE_BUFFER_SIZE: usize = 65536 * 2;
const DEVICE_BUFFERS_COUNT: usize = 32 * 2;
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(1);

pub struct Network<'a> {
    device: UplinkDevice<'a>,
    iface: iface::Interface,
    sockets: iface::SocketSet<'a>,
    ip_addr: Option<IpAddr>,
    bridges: HashMap<iface::SocketHandle, ProxyClientConnection>,
    opening_connections: HashMap<iface::SocketHandle, SocketConnectionRequest>,
    shutdown: bool,
}

impl Network<'_> {
    pub fn new<'a>(uplink: uplink::UplinkServiceType) -> Result<Network<'a>, NetworkError> {
        let mut device = UplinkDevice::new(uplink);
        let mut config = iface::Config::new(smoltcp::wire::HardwareAddress::Ip);
        config.random_seed = rand::random();
        let iface = iface::Interface::new(config, &mut device, smoltcp::time::Instant::now());

        let sockets = iface::SocketSet::new(vec![]);

        Ok(Network {
            device,
            iface,
            sockets,
            ip_addr: None,
            bridges: HashMap::new(),
            opening_connections: HashMap::new(),
            shutdown: false,
        })
    }

    pub async fn run_process(&mut self, mut command_receiver: mpsc::Receiver<Command>) {
        use std::future::{self, Future};
        use std::pin::pin;
        use std::task::Poll;

        let mut next_wake = tokio::time::Instant::now();
        let mut uplink_buffer = [0u8; MAX_MTU_SIZE];
        while !self.shutdown {
            let (uplink_event, command, bridges_ready) = {
                let mut uplink_event = pin!(self.device.wait_event(&mut uplink_buffer));
                let mut device_ready = pin!(tokio::time::sleep_until(next_wake));
                let mut receive_command = pin!(command_receiver.recv());
                future::poll_fn(|cx| {
                    let uplink_event_received = match uplink_event.as_mut().poll(cx) {
                        Poll::Ready(res) => Some(res),
                        Poll::Pending => None,
                    };
                    let device_ready = device_ready.as_mut().poll(cx).is_ready();
                    let command = receive_command.as_mut().poll(cx);
                    let command = match command {
                        Poll::Ready(Some(command)) => Some(command),
                        Poll::Ready(None) => Some(Command::Shutdown),
                        Poll::Pending => None,
                    };
                    let mut bridges_ready = false;
                    for (handle, proxy_client) in self.bridges.iter_mut() {
                        use smoltcp::socket::tcp;

                        let socket = self.sockets.get_mut::<tcp::Socket>(*handle);
                        if !socket.is_open() {
                            bridges_ready = true;
                            // Socket is closing, need to process the close event.
                            continue;
                        }
                        match proxy_client.poll_read(cx, socket) {
                            Poll::Ready(Ok(_)) => {
                                bridges_ready = true;
                            }
                            Poll::Ready(Err(err)) => {
                                debug!("Failed to perform IO on client socket: {err}")
                            }
                            Poll::Pending => {}
                        }
                        if !socket.is_open() {
                            // Socket is closing, need to process the close event.
                            bridges_ready = true;
                            continue;
                        }
                        match proxy_client.poll_write(cx, socket) {
                            Poll::Ready(Ok(_)) => {
                                bridges_ready = true;
                            }
                            Poll::Ready(Err(err)) => {
                                debug!("Failed to perform IO on client socket: {err}")
                            }
                            Poll::Pending => {}
                        }
                    }
                    if bridges_ready
                        || uplink_event_received.is_some()
                        || device_ready
                        || command.is_some()
                    {
                        Poll::Ready((uplink_event_received, command, bridges_ready))
                    } else {
                        Poll::Pending
                    }
                })
                .await
            };
            self.maintain_bridges().await;
            if let Some(command) = command {
                self.process_command(command);
            }
            if uplink_event.is_some() {
                let ip_addr = self.device.ip_addr();
                if let Err(err) = self.update_ip_configuration(ip_addr) {
                    warn!("Failed to update device IP address: {err}");
                }
            }
            let vpn_data_received = if let Some(Err(err)) = uplink_event {
                warn!("Uplink/VPN reported an error status: {err}");
                false
            } else {
                match self.device.read_next_packet(&mut uplink_buffer).await {
                    Ok(data_received) => data_received,
                    Err(err) => {
                        warn!("Failed to read packet from Uplink/VPN: {err}");
                        false
                    }
                }
            };
            let vpn_data_sent = match self.device.process_lifecyle_events().await {
                Ok(data_sent) => data_sent,
                Err(err) => {
                    warn!("Failed to process uplink/VPN lifecycle events: {err}");
                    false
                }
            };
            if tokio::time::Instant::now() > next_wake
                || bridges_ready
                || vpn_data_received
                || vpn_data_sent
            {
                let start_poll = tokio::time::Instant::now();
                let timestamp = smoltcp::time::Instant::now();
                self.iface
                    .poll(timestamp, &mut self.device, &mut self.sockets);
                let poll_delay = match self.iface.poll_delay(timestamp, &self.sockets) {
                    Some(poll_delay) => Duration::from_micros(poll_delay.total_micros()),
                    None => MAX_POLL_INTERVAL,
                };
                next_wake = start_poll + poll_delay;
            }
        }
        if let Err(err) = self.device.terminate().await {
            warn!("Failed to terminate uplink/VPN connection: {err}");
        }
        debug!("Shutdown completed");
    }

    async fn maintain_bridges(&mut self) {
        use socket::tcp;

        let rt = tokio::runtime::Handle::current();
        self.bridges.values_mut().for_each(|bridge| {
            if let Some(mut tunnel) = bridge.take_shutdown_tunnel() {
                // Spawn shutdown as background task to prevent blocking the event loop.
                rt.spawn(async move {
                    use tokio::io::AsyncWriteExt as _;
                    if let Err(err) = tunnel.shutdown().await {
                        debug!("Failed to shut down proxy client socket: {err}");
                    }
                });
            };
        });
        self.bridges.retain(|_, tunnel| tunnel.is_open());
        let closed_sockets = self
            .sockets
            .iter()
            .filter_map(|(handle, socket)| {
                let socket::Socket::Tcp(socket) = socket;
                if !self.bridges.contains_key(&handle) && socket.state() == tcp::State::Closed {
                    Some(handle)
                } else {
                    None
                }
            })
            .collect::<HashSet<_>>();
        closed_sockets.into_iter().for_each(|handle| {
            self.bridges.remove(&handle);
            self.opening_connections.remove(&handle);
            self.sockets.remove(handle);
        });

        for (handle, response) in self.opening_connections.iter_mut() {
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);
            let result = match socket.state() {
                tcp::State::Closed | tcp::State::TimeWait | tcp::State::Closing => {
                    Some(Err("Socket is closed".into()))
                }
                tcp::State::SynSent | tcp::State::SynReceived => {
                    // Not ready.
                    None
                }
                tcp::State::Established | tcp::State::CloseWait => {
                    let send_response = match socket.local_endpoint() {
                        Some(endpoint) => {
                            (*handle, SocketAddr::from((endpoint.addr, endpoint.port)))
                        }
                        None => (*handle, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
                    };
                    if let Some(initial_data) = response.initial_data.take() {
                        match socket.send_slice(&initial_data) {
                            Ok(length) => {
                                if length != initial_data.len() {
                                    warn!("Failed to send all initial data to socket");
                                };
                            }
                            Err(err) => {
                                warn!("Failed to send initial data to socket: {err}");
                            }
                        };
                    }
                    Some(Ok(send_response))
                }
                tcp::State::Listen
                | tcp::State::FinWait1
                | tcp::State::FinWait2
                | tcp::State::LastAck => {
                    // About to close.
                    Some(Err("Socket is closing".into()))
                }
            };
            let result = if let Some(result) = result {
                result
            } else {
                continue;
            };
            if response.send(result).is_err() {
                debug!("Proxy listener not listening for response");
            }
        }
        self.opening_connections
            .retain(|_, response| !response.is_processed());
    }

    fn update_ip_configuration(&mut self, ip_addr: Option<IpAddr>) -> Result<(), NetworkError> {
        if self.ip_addr == ip_addr {
            return Ok(());
        }
        self.ip_addr = ip_addr;
        if let Some(ip_addr) = self.ip_addr {
            // TODO: how to choose the CIDR?
            let ip_cidr = wire::IpCidr::new(ip_addr.into(), 8);

            self.iface.update_ip_addrs(|ip_addrs| {
                if let Err(err) = ip_addrs.push(ip_cidr) {
                    log::error!("Failed to add IP address to virtual interface: {err}");
                }
            });
            if !self.iface.has_ip_addr(ip_cidr.address()) {
                return Err("Interface has no IP addresses".into());
            }
        } else {
            self.iface.update_ip_addrs(|ip_addrs| ip_addrs.clear());
        }
        Ok(())
    }

    fn process_command(&mut self, command: Command) {
        use socket::tcp;
        match command {
            Command::Connect(addr, mut connect_request) => {
                // smoltcp crashes if interface has no IPv6 address.
                if addr.is_ipv6() {
                    if let Err(err) =
                        connect_request.send(Err("IPv6 connections are not supported".into()))
                    {
                        debug!("Failed to send response to proxy client: {err}");
                    }
                    return;
                }
                let ip_addr = if let Some(ip_addr) = self.ip_addr {
                    ip_addr
                } else {
                    if let Err(err) =
                        connect_request.send(Err("Uplink/VPN is not connected".into()))
                    {
                        debug!("Failed to send response to proxy client: {err}");
                    }
                    return;
                };
                let rx_buffer = tcp::SocketBuffer::new(vec![0; READ_BUFFER_SIZE]);
                let tx_buffer = tcp::SocketBuffer::new(vec![0; WRITE_BUFFER_SIZE]);
                let mut socket = tcp::Socket::new(rx_buffer, tx_buffer);

                let mut local_port = rand::rng().random_range(49152..=65535);
                while !self.port_acceptable(&addr, local_port) {
                    local_port = rand::rng().random_range(49152..=65535);
                }
                let remote_addr = wire::IpAddress::from(addr.ip());
                if let Err(err) = socket.connect(
                    self.iface.context(),
                    (remote_addr, addr.port()),
                    (ip_addr, local_port),
                ) {
                    if let Err(err) = connect_request.send(Err(err.into())) {
                        debug!("Failed to send response to proxy client: {err}");
                    }
                    return;
                }

                let socket_handle = self.sockets.add(socket);
                self.opening_connections
                    .insert(socket_handle, connect_request);
            }
            Command::Bridge(socket_handle, socket) => {
                self.bridges
                    .insert(socket_handle, ProxyClientConnection::new(socket));
            }
            Command::Shutdown => self.shutdown = true,
        }
    }

    fn port_acceptable(
        &mut self,
        check_remote_endpoint: &SocketAddr,
        check_local_port: u16,
    ) -> bool {
        self.sockets.iter().all(|(_, socket)| {
            let socket::Socket::Tcp(socket) = socket;
            if let Some(remote_endpoint) = socket.remote_endpoint() {
                if remote_endpoint.addr != check_remote_endpoint.ip().into()
                    || remote_endpoint.port != check_remote_endpoint.port()
                {
                    return true;
                }
            } else {
                return true;
            }
            if let Some(local_endpoint) = socket.local_endpoint() {
                local_endpoint.port != check_local_port
            } else {
                true
            }
        })
    }
}

type SocketConnectionResult = Result<(iface::SocketHandle, SocketAddr), NetworkError>;

pub struct SocketConnectionRequest {
    response: Option<oneshot::Sender<SocketConnectionResult>>,
    initial_data: Option<Vec<u8>>,
}

impl SocketConnectionRequest {
    pub fn new(
        response: oneshot::Sender<SocketConnectionResult>,
        initial_data: Option<Vec<u8>>,
    ) -> SocketConnectionRequest {
        SocketConnectionRequest {
            response: Some(response),
            initial_data,
        }
    }

    fn send(&mut self, result: SocketConnectionResult) -> Result<(), NetworkError> {
        if let Some(response) = self.response.take() {
            response
                .send(result)
                .map_err(|_| "Proxy listener not listening for response")?;
            Ok(())
        } else {
            Err("Connection result already sent".into())
        }
    }

    fn is_processed(&self) -> bool {
        self.response.is_none()
    }
}

struct ProxyClientConnection {
    tunnel: Option<tokio::io::BufStream<tokio::net::TcpStream>>,
    stream_closed: bool,
}

impl ProxyClientConnection {
    fn new(tunnel: tokio::io::BufStream<tokio::net::TcpStream>) -> ProxyClientConnection {
        ProxyClientConnection {
            tunnel: Some(tunnel),
            stream_closed: false,
        }
    }

    fn is_open(&self) -> bool {
        self.tunnel.is_some()
    }

    fn poll_read(
        &mut self,
        cx: &mut std::task::Context<'_>,
        socket: &mut smoltcp::socket::tcp::Socket<'_>,
    ) -> Poll<Result<usize, NetworkError>> {
        use std::pin::pin;
        use tokio::io::AsyncRead as _;
        use tokio::io::ReadBuf;

        let tunnel = if !socket.can_send() {
            return Poll::Pending;
        } else if self.stream_closed {
            return Poll::Ready(Err("Proxy reader is closed".into()));
        } else if let Some(tunnel) = self.tunnel.as_mut() {
            pin!(tunnel)
        } else {
            return Poll::Ready(Err("Proxy client connection is closed".into()));
        };
        let result = socket.send(|dest| {
            let mut dest = ReadBuf::new(dest);
            match tunnel.poll_read(cx, &mut dest) {
                Poll::Ready(Ok(())) => {
                    let bytes = dest.filled().len();
                    (bytes, Poll::Ready(Ok(bytes)))
                }
                Poll::Ready(Err(err)) => (0, Poll::Ready(Err(err))),
                Poll::Pending => (0, Poll::Pending),
            }
        });
        match result {
            Ok(Poll::Ready(Ok(bytes))) => {
                if bytes == 0 {
                    // Zero bytes means the stream is closed.
                    self.close_socket(socket);
                }
                Poll::Ready(Ok(bytes))
            }
            Ok(Poll::Ready(Err(err))) => {
                debug!("Failed to read data from proxy client socket: {err}");
                self.close_socket(socket);
                Poll::Ready(Err("Failed to read data from proxy client socket".into()))
            }
            Ok(Poll::Pending) => Poll::Pending,
            Err(err) => {
                warn!("Failed to read data from virtual socket: {err}");
                self.close_socket(socket);
                Poll::Ready(Err("Failed to read data from virtual socket".into()))
            }
        }
    }

    fn poll_write(
        &mut self,
        cx: &mut std::task::Context<'_>,
        socket: &mut smoltcp::socket::tcp::Socket<'_>,
    ) -> Poll<Result<usize, NetworkError>> {
        use std::pin::pin;
        use tokio::io::AsyncWrite as _;

        let tunnel = if !socket.can_recv() {
            return Poll::Pending;
        } else if self.stream_closed {
            return Poll::Ready(Err("Proxy reader is closed".into()));
        } else if let Some(tunnel) = self.tunnel.as_mut() {
            pin!(tunnel)
        } else {
            return Poll::Ready(Err("Proxy client connection is closed".into()));
        };
        let result = socket.recv(|dest| match tunnel.poll_write(cx, dest) {
            Poll::Ready(Ok(bytes)) => (bytes, Poll::Ready(Ok(bytes))),
            Poll::Ready(Err(err)) => (0, Poll::Ready(Err(err))),
            Poll::Pending => (0, Poll::Pending),
        });
        match result {
            Ok(Poll::Ready(Ok(bytes))) => Poll::Ready(Ok(bytes)),
            Ok(Poll::Ready(Err(err))) => {
                debug!("Failed to write data to proxy client socket: {err}");
                self.close_socket(socket);
                Poll::Ready(Err("Failed to write data to proxy client socket".into()))
            }
            Ok(Poll::Pending) => Poll::Pending,
            Err(err) => {
                warn!("Failed to send data to virtual socket: {err}");
                self.close_socket(socket);
                Poll::Ready(Err("Failed to send data to virtual socket".into()))
            }
        }
    }

    fn take_shutdown_tunnel(&mut self) -> Option<tokio::io::BufStream<tokio::net::TcpStream>> {
        if self.stream_closed {
            self.tunnel.take()
        } else {
            None
        }
    }

    fn close_socket(&mut self, socket: &mut smoltcp::socket::tcp::Socket<'_>) {
        self.stream_closed = true;
        socket.close();
    }
}

pub enum Command {
    Connect(std::net::SocketAddr, SocketConnectionRequest),
    Bridge(
        iface::SocketHandle,
        tokio::io::BufStream<tokio::net::TcpStream>,
    ),
    Shutdown,
}

struct UplinkDevice<'a> {
    uplink: uplink::UplinkServiceType,
    read_buffers: storage::RingBuffer<'a, Vec<u8>>,
    write_buffers: storage::RingBuffer<'a, Vec<u8>>,
}

impl UplinkDevice<'_> {
    fn new<'a>(uplink: uplink::UplinkServiceType) -> UplinkDevice<'a> {
        let read_buffers = (0..DEVICE_BUFFERS_COUNT)
            .map(|_| Vec::with_capacity(MAX_MTU_SIZE))
            .collect::<Vec<_>>();
        let write_buffers = (0..DEVICE_BUFFERS_COUNT)
            .map(|_| Vec::with_capacity(MAX_MTU_SIZE))
            .collect::<Vec<_>>();
        UplinkDevice {
            uplink,
            read_buffers: storage::RingBuffer::new(read_buffers),
            write_buffers: storage::RingBuffer::new(write_buffers),
        }
    }
}

impl UplinkDevice<'_> {
    async fn wait_event(&mut self, buf: &mut [u8]) -> Result<(), NetworkError> {
        Ok(self.uplink.wait_event(buf).await?)
    }

    async fn terminate(&mut self) -> Result<(), NetworkError> {
        Ok(self.uplink.terminate().await?)
    }

    async fn read_next_packet(&mut self, buf: &mut [u8]) -> Result<bool, NetworkError> {
        let data = self.uplink.read_packet(buf).await?;
        if data.is_empty() {
            Ok(false)
        } else if let Ok(dest) = self.read_buffers.enqueue_one() {
            dest.clear();
            dest.extend_from_slice(data);
            Ok(true)
        } else {
            // Read buffers are full.
            trace!("Read buffers are full, dropping received packet");
            Ok(false)
        }
    }

    async fn process_lifecyle_events(&mut self) -> Result<bool, NetworkError> {
        if self.uplink.is_connected() {
            let send_packet = if let Ok(src) = self.write_buffers.dequeue_one() {
                self.uplink.process_events(&[src.as_slice()]).await?;
                src.clear();
                true
            } else {
                self.uplink.process_events(&[]).await?;
                false
            };
            Ok(send_packet)
        } else {
            Ok(false)
        }
    }

    fn ip_addr(&self) -> Option<IpAddr> {
        if let Some((ip_addr, _)) = self.uplink.ip_configuration() {
            Some(ip_addr)
        } else {
            None
        }
    }
}

impl phy::Device for UplinkDevice<'_> {
    type RxToken<'a>
        = RxToken<'a>
    where
        Self: 'a;

    type TxToken<'a>
        = TxToken<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.read_buffers.is_empty() || self.write_buffers.is_full() {
            return None;
        }
        let src = if let Ok(src) = self.read_buffers.dequeue_one() {
            src
        } else {
            // No read buffers are available.
            return None;
        };
        let dest = if let Ok(dest) = self.write_buffers.enqueue_one() {
            dest
        } else {
            // Write buffers are full.
            return None;
        };
        Some((RxToken { src }, TxToken { dest }))
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        if let Ok(dest) = self.write_buffers.enqueue_one() {
            Some(TxToken { dest })
        } else {
            // Write buffers are full.
            None
        }
    }

    fn capabilities(&self) -> phy::DeviceCapabilities {
        let mut caps = phy::DeviceCapabilities::default();
        caps.max_transmission_unit = self.uplink.mtu() as usize;
        caps.max_burst_size = Some(DEVICE_BUFFERS_COUNT);
        caps.medium = phy::Medium::Ip;
        caps.checksum.ipv4 = phy::Checksum::Both;
        caps.checksum.tcp = phy::Checksum::Both;
        caps.checksum.udp = phy::Checksum::Both;
        caps.checksum.icmpv4 = phy::Checksum::Both;
        caps.checksum.icmpv6 = phy::Checksum::Both;
        caps
    }
}

struct RxToken<'a> {
    src: &'a mut Vec<u8>,
}

impl phy::RxToken for RxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.src)
    }
}

struct TxToken<'a> {
    dest: &'a mut Vec<u8>,
}

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        self.dest.resize(len, 0);
        f(self.dest)
    }
}

#[derive(Debug)]
pub enum NetworkError {
    Internal(&'static str),
    Connect(socket::tcp::ConnectError),
    Io(io::Error),
    Uplink(uplink::UplinkError),
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Internal(msg) => f.write_str(msg),
            Self::Connect(err) => write!(f, "Connect error: {err}"),
            Self::Io(err) => write!(f, "IO error: {err}"),
            Self::Uplink(err) => write!(f, "Uplink/VPN error: {err}"),
        }
    }
}

impl error::Error for NetworkError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Internal(_msg) => None,
            Self::Connect(err) => Some(err),
            Self::Io(err) => Some(err),
            Self::Uplink(err) => Some(err),
        }
    }
}

impl From<&'static str> for NetworkError {
    fn from(msg: &'static str) -> NetworkError {
        Self::Internal(msg)
    }
}

impl From<socket::tcp::ConnectError> for NetworkError {
    fn from(err: socket::tcp::ConnectError) -> NetworkError {
        Self::Connect(err)
    }
}

impl From<io::Error> for NetworkError {
    fn from(err: io::Error) -> NetworkError {
        Self::Io(err)
    }
}

impl From<crate::uplink::UplinkError> for NetworkError {
    fn from(err: crate::uplink::UplinkError) -> NetworkError {
        Self::Uplink(err)
    }
}
