use std::{
    collections::{HashMap, HashSet},
    error, fmt, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use log::{debug, trace, warn};
use rand::Rng;
use smoltcp::{iface, phy, socket, storage, wire};
use tokio::{
    runtime,
    sync::{mpsc, oneshot},
    time::Duration,
};

use crate::fortivpn::{self, service::FortiTunnelEvent};

const MAX_MTU_SIZE: usize = 1500;
const READ_BUFFER_SIZE: usize = 65536 * 2 * 2;
const WRITE_BUFFER_SIZE: usize = 65536 * 2;
const DEVICE_BUFFERS_COUNT: usize = 32 * 2;
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(1);

type FortiService = fortivpn::service::FortiService<MAX_MTU_SIZE, MAX_MTU_SIZE>;

pub struct Network<'a> {
    device: VpnDevice<'a>,
    iface: iface::Interface,
    sockets: iface::SocketSet<'a>,
    ip_addr: Option<IpAddr>,
    bridges: HashMap<iface::SocketHandle, ProxyClientConnection>,
    opening_connections: HashMap<iface::SocketHandle, SocketConnectionRequest>,
    shutdown: bool,
}

impl Network<'_> {
    pub fn new<'a>(config: fortivpn::Config) -> Result<Network<'a>, NetworkError> {
        let vpn = fortivpn::service::FortiService::new(
            config,
            DEVICE_BUFFERS_COUNT,
            DEVICE_BUFFERS_COUNT,
        );
        let mut device = VpnDevice::new(vpn);
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

    pub async fn run(mut self, mut command_receiver: mpsc::Receiver<Command>) {
        use std::future::{self, Future};
        use std::pin::pin;
        use std::task::Poll;

        let rt = runtime::Handle::current();
        let mut next_wake = tokio::time::Instant::now();
        let mut vpn_events = Vec::with_capacity(DEVICE_BUFFERS_COUNT);
        while !self.shutdown {
            if !self.device.vpn.is_connected() {
                self.device.vpn.start_connection(&rt);
            }
            let (vpn_event_received, command) = {
                vpn_events.clear();
                let vpn_connected = self.device.vpn.is_connected();
                let mut vpn_event_received = pin!(self.device.next_vpn_events(&mut vpn_events));
                let mut device_ready = pin!(tokio::time::sleep_until(next_wake));
                let mut receive_command = pin!(command_receiver.recv());
                future::poll_fn(|cx| {
                    let vpn_event_received = if vpn_connected {
                        match vpn_event_received.as_mut().poll(cx) {
                            Poll::Ready(res) => Some(res),
                            Poll::Pending => None,
                        }
                    } else {
                        None
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
                        if let Some(tunnel) = proxy_client.tunnel.as_ref() {
                            let socket = self.sockets.get::<tcp::Socket>(*handle);
                            proxy_client.can_write =
                                socket.can_recv() && tunnel.poll_write_ready(cx).is_ready();
                            proxy_client.can_read =
                                socket.can_send() && tunnel.poll_read_ready(cx).is_ready();
                            if proxy_client.can_read || proxy_client.can_write || !socket.is_open()
                            {
                                bridges_ready = true;
                            }
                        } else {
                            // Socket is closing, need to process the close event.
                            bridges_ready = true;
                        }
                    }
                    if bridges_ready
                        || vpn_event_received.is_some()
                        || device_ready
                        || command.is_some()
                    {
                        Poll::Ready((vpn_event_received, command))
                    } else {
                        Poll::Pending
                    }
                })
                .await
            };
            let data_copied = self.copy_all_data().await;
            if let Some(command) = command {
                self.process_command(command);
            }
            let vpn_data_sent = match self.device.send_all_data().await {
                Ok(data_sent) => data_sent,
                Err(err) => {
                    warn!("Failed to transfer data to sockets: {}", err);
                    false
                }
            };
            let vpn_data_received = match vpn_event_received {
                Some(Ok(())) => vpn_events
                    .iter()
                    .map(|vpn_event| match self.process_vpn_event(vpn_event) {
                        Ok(data_received) => data_received,
                        Err(err) => {
                            warn!("Failed to process VPN event, terminating: {}", err);
                            self.shutdown = true;
                            false
                        }
                    })
                    .any(|b| b),
                Some(Err(err)) => {
                    self.shutdown = true;
                    warn!("Failed to receive events from VPN, terminating: {}", err);
                    false
                }
                None => false,
            };
            if tokio::time::Instant::now() > next_wake
                || data_copied
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
            warn!("Failed to terminate VPN connection: {}", err);
        }
        debug!("Shutdown completed");
    }

    async fn copy_all_data(&mut self) -> bool {
        // This is not fancy, but with a single-user (a few connections) should work OK.
        // smoltcp's poll works exactly the same way and seems to show reasonable performance.
        // The alternative is using poll/waking and additional buffers (or perhaps a list of futures), which
        // doesn't work well with smoltcp - as smoltcp keeps ownership of most of its data, and any writes
        // need to be guarded.
        use socket::tcp;
        let mut data_copied = false;
        for (handle, proxy_client) in self.bridges.iter_mut() {
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);
            match proxy_client.transfer_data(socket).await {
                Ok(true) => data_copied = true,
                Ok(false) => {}
                Err(err) => debug!("Failed to perform IO on client socket: {}", err),
            }
        }

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
                                warn!("Failed to send initial data to socket: {}", err);
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
        data_copied
    }

    fn update_ip_configuration(
        &mut self,
        ip_configuration: Option<IpAddr>,
    ) -> Result<(), NetworkError> {
        self.ip_addr = ip_configuration;
        if let Some(ip_addr) = self.ip_addr {
            // TODO: how to choose the CIDR?
            let ip_cidr = wire::IpCidr::new(ip_addr.into(), 8);

            self.iface.update_ip_addrs(|ip_addrs| {
                if let Err(err) = ip_addrs.push(ip_cidr) {
                    log::error!("Failed to add IP address to virtual interface: {}", err);
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
                        debug!("Failed to send response to proxy client: {}", err);
                    }
                    return;
                }
                let ip_addr = if let Some(ip_addr) = self.ip_addr {
                    ip_addr
                } else {
                    if let Err(err) = connect_request.send(Err("VPN is not connected".into())) {
                        debug!("Failed to send response to proxy client: {}", err);
                    }
                    return;
                };
                let rx_buffer = tcp::SocketBuffer::new(vec![0; READ_BUFFER_SIZE]);
                let tx_buffer = tcp::SocketBuffer::new(vec![0; WRITE_BUFFER_SIZE]);
                let mut socket = tcp::Socket::new(rx_buffer, tx_buffer);

                let mut local_port = rand::thread_rng().gen_range(49152..=65535);
                while !self.port_acceptable(&addr, local_port) {
                    local_port = rand::thread_rng().gen_range(49152..=65535);
                }
                let remote_addr = wire::IpAddress::from(addr.ip());
                if let Err(err) = socket.connect(
                    self.iface.context(),
                    (remote_addr, addr.port()),
                    (ip_addr, local_port),
                ) {
                    if let Err(err) = connect_request.send(Err(err.into())) {
                        debug!("Failed to send response to proxy client: {}", err);
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

    fn process_vpn_event(&mut self, vpn_event: &FortiTunnelEvent) -> Result<bool, NetworkError> {
        match vpn_event {
            FortiTunnelEvent::Connected(ip_addr, _) => {
                self.update_ip_configuration(Some(*ip_addr))?;
                Ok(false)
            }
            FortiTunnelEvent::Error(err) => {
                warn!("VPN reported an error status: {}", err);
                Ok(false)
            }
            FortiTunnelEvent::ReceivedPacket(buffer, read_bytes) => {
                let processed = match self.device.process_received_packet(&buffer[..*read_bytes]) {
                    Ok(processed) => processed,
                    Err(err) => {
                        warn!("Failed to forward packet from VPN to device: {}", err);
                        false
                    }
                };
                Ok(processed)
            }
            FortiTunnelEvent::Disconnected => {
                self.update_ip_configuration(None)?;
                Ok(false)
            }
            FortiTunnelEvent::EchoFailed(err) => {
                warn!("Echo request timed out: {}", err);
                Ok(false)
            }
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
    tunnel: Option<tokio::net::TcpStream>,
    can_read: bool,
    can_write: bool,
}

impl ProxyClientConnection {
    fn new(tunnel: tokio::net::TcpStream) -> ProxyClientConnection {
        ProxyClientConnection {
            tunnel: Some(tunnel),
            can_read: false,
            can_write: false,
        }
    }

    fn is_open(&self) -> bool {
        self.tunnel.is_some()
    }

    async fn transfer_data(
        &mut self,
        socket: &mut smoltcp::socket::tcp::Socket<'_>,
    ) -> Result<bool, NetworkError> {
        let tunnel = if let Some(tunnel) = self.tunnel.as_mut() {
            tunnel
        } else {
            return Err("Proxy client connection is closed".into());
        };
        let mut sent_data = false;
        while self.can_read && socket.can_send() {
            let result = socket.send(|dest| match tunnel.try_read(dest) {
                Ok(bytes) => {
                    if bytes > 0 && !dest.is_empty() {
                        (bytes, Ok(bytes))
                    } else {
                        // Zero bytes means the stream is closed.
                        (0, Err(NetworkError::Internal("Proxy reader is closed")))
                    }
                }
                Err(err) => match err.kind() {
                    io::ErrorKind::WouldBlock => (0, Ok(0)),
                    _ => (0, Err(err.into())),
                },
            });
            match result {
                Ok(Ok(bytes)) => {
                    if bytes > 0 {
                        sent_data = true;
                    } else {
                        self.can_read = false;
                    }
                }
                Ok(Err(err)) => {
                    debug!("Failed to read data from proxy client socket: {}", err);
                    self.close(socket).await;
                    return Err("Failed to read data from proxy client socket".into());
                }
                Err(err) => {
                    // Not critical if socket is still opening.
                    warn!("Failed to send data to virtual socket: {}", err);
                }
            }
        }

        let mut received_data = false;
        while self.can_write && socket.can_recv() {
            let result = socket.recv(|src| match tunnel.try_write(src) {
                Ok(bytes) => (bytes, Ok(bytes)),
                Err(err) => match err.kind() {
                    io::ErrorKind::WouldBlock => (0, Ok(0)),
                    _ => (0, Err(err)),
                },
            });
            match result {
                Ok(Ok(bytes)) => {
                    if bytes > 0 {
                        received_data = true;
                    } else {
                        self.can_write = false
                    }
                }
                Ok(Err(err)) => {
                    debug!("Failed to write data to proxy client socket: {}", err);
                    self.close(socket).await;
                    return Err("Failed to write data to proxy client socket".into());
                }
                Err(err) => {
                    warn!("Failed to read data from virtual socket: {}", err);
                }
            }
        }

        self.can_read = false;
        self.can_write = false;

        if !socket.is_open() {
            self.close(socket).await;
        }
        Ok(sent_data || received_data)
    }

    async fn close(&mut self, socket: &mut smoltcp::socket::tcp::Socket<'_>) {
        use tokio::io::AsyncWriteExt;
        socket.close();
        if let Some(mut tunnel) = self.tunnel.take() {
            if let Err(err) = tunnel.shutdown().await {
                debug!("Failed to shut down proxy client socket: {}", err);
            }
        }
    }
}

pub enum Command {
    Connect(std::net::SocketAddr, SocketConnectionRequest),
    Bridge(iface::SocketHandle, tokio::net::TcpStream),
    Shutdown,
}

struct VpnDevice<'a> {
    vpn: FortiService,
    read_buffers: storage::RingBuffer<'a, Vec<u8>>,
    write_buffers: storage::RingBuffer<'a, Vec<u8>>,
}

impl VpnDevice<'_> {
    fn new<'a>(vpn: FortiService) -> VpnDevice<'a> {
        let read_buffers = (0..DEVICE_BUFFERS_COUNT)
            .map(|_| Vec::with_capacity(MAX_MTU_SIZE))
            .collect::<Vec<_>>();
        let write_buffers = (0..DEVICE_BUFFERS_COUNT)
            .map(|_| Vec::with_capacity(MAX_MTU_SIZE))
            .collect::<Vec<_>>();
        VpnDevice {
            vpn,
            read_buffers: storage::RingBuffer::new(read_buffers),
            write_buffers: storage::RingBuffer::new(write_buffers),
        }
    }
}

impl VpnDevice<'_> {
    async fn next_vpn_events(
        &mut self,
        dest: &mut Vec<fortivpn::service::FortiTunnelEvent>,
    ) -> Result<(), NetworkError> {
        Ok(self.vpn.next_events(dest).await?)
    }

    async fn terminate(&mut self) -> Result<(), NetworkError> {
        self.vpn.start_disconnection().await?;
        while self.vpn.is_connected() && self.vpn.next_event().await.is_ok() {}
        Ok(())
    }

    fn process_received_packet(&mut self, data: &[u8]) -> Result<bool, NetworkError> {
        if let Ok(dest) = self.read_buffers.enqueue_one() {
            dest.clear();
            dest.extend_from_slice(data);
            Ok(true)
        } else {
            // Read buffers are full.
            trace!("Read buffers are full, dropping received packet");
            Ok(false)
        }
    }

    async fn send_all_data(&mut self) -> Result<bool, NetworkError> {
        let mut data_sent = false;
        if self.vpn.is_connected() {
            while let Ok(src) = self.write_buffers.dequeue_one() {
                self.vpn.send_packet(src).await?;
                src.clear();
                data_sent = true;
            }
        }
        Ok(data_sent)
    }
}

impl phy::Device for VpnDevice<'_> {
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
        caps.max_transmission_unit = self.vpn.mtu() as usize;
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
    Forti(fortivpn::service::VpnServiceError),
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Internal(msg) => f.write_str(msg),
            Self::Connect(ref e) => {
                write!(f, "Connect error: {}", e)
            }
            Self::Io(ref e) => {
                write!(f, "IO error: {}", e)
            }
            Self::Forti(ref e) => {
                write!(f, "VPN error: {}", e)
            }
        }
    }
}

impl error::Error for NetworkError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Self::Internal(_msg) => None,
            Self::Connect(ref err) => Some(err),
            Self::Io(ref err) => Some(err),
            Self::Forti(ref err) => Some(err),
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

impl From<crate::fortivpn::service::VpnServiceError> for NetworkError {
    fn from(err: crate::fortivpn::service::VpnServiceError) -> NetworkError {
        Self::Forti(err)
    }
}
