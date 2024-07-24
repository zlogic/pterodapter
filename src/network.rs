use std::{
    collections::HashMap,
    error, fmt, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use log::{debug, warn};
use rand::Rng;
use smoltcp::{iface, phy, socket, storage, wire};
use tokio::{
    sync::{mpsc, oneshot},
    time::Duration,
};

use crate::fortivpn::FortiVPNTunnel;

const MAX_MTU_SIZE: usize = 1500;
const SOCKET_BUFFER_SIZE: usize = 65536;
const DEVICE_BUFFERS_COUNT: usize = 32;
const IDLE_POLL_DELAY: Duration = Duration::from_secs(1);
const ECHO_SEND_INTERVAL: Duration = Duration::from_secs(10);
const ECHO_TIMEOUT: Duration = Duration::from_secs(60);

pub struct Network<'a> {
    device: VpnDevice<'a>,
    iface: iface::Interface,
    sockets: iface::SocketSet<'a>,
    bridges: HashMap<iface::SocketHandle, SocketTunnel>,
    opening_connections:
        HashMap<iface::SocketHandle, Option<oneshot::Sender<SocketConnectionResult>>>,
    canceled: bool,
    cmd_sender: mpsc::Sender<Command>,
    cmd_receiver: mpsc::Receiver<Command>,
}

impl Network<'_> {
    pub fn new<'a>(vpn: FortiVPNTunnel) -> Result<Network<'a>, NetworkError> {
        // TODO: how to choose the CIDR?
        let ip_cidr = wire::IpCidr::new(vpn.ip_addr().into(), 8);

        let mut device = VpnDevice::new(vpn);
        let mut config = iface::Config::new(smoltcp::wire::HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut iface = iface::Interface::new(config, &mut device, smoltcp::time::Instant::now());

        iface.update_ip_addrs(|ip_addrs| {
            if let Err(err) = ip_addrs.push(ip_cidr) {
                log::error!("Failed to add IP address to virtual interface: {}", err);
            }
        });
        if !iface.has_ip_addr(ip_cidr.address()) {
            return Err("Interface has no IP addresses".into());
        }

        let sockets = iface::SocketSet::new(vec![]);
        let (cmd_sender, cmd_receiver) = mpsc::channel(10);

        Ok(Network {
            device,
            iface,
            sockets,
            bridges: HashMap::new(),
            opening_connections: HashMap::new(),
            canceled: false,
            cmd_sender,
            cmd_receiver,
        })
    }

    pub async fn run(&mut self) -> Result<(), NetworkError> {
        while !self.canceled {
            self.device.send_data().await?;
            self.device.receive_data().await?;
            self.device.process_keepalive().await?;
            let timestamp = smoltcp::time::Instant::now();
            let start_time = tokio::time::Instant::now();
            self.iface
                .poll(timestamp, &mut self.device, &mut self.sockets);
            self.copy_all_data();
            match self.iface.poll_delay(timestamp, &self.sockets) {
                Some(poll_delay) => {
                    let empty_connections =
                        self.sockets.iter().count() == 0 && self.bridges.is_empty();
                    let poll_delay = if empty_connections {
                        IDLE_POLL_DELAY
                    } else {
                        Duration::from_micros(poll_delay.total_micros())
                    };
                    self.process_commands(Some(start_time + poll_delay)).await;
                }
                None => {
                    self.process_commands(None).await;
                }
            }
        }
        Ok(())
    }

    fn copy_all_data(&mut self) {
        // This is not fancy, but with a single-user (a few connections) should work OK.
        // smoltcp's poll works exactly the same way and seems to show reasonable performance.
        // The alternative is using poll/waking and additional buffers (or perhaps a list of futures), which
        // doesn't work well with smoltcp - as smoltcp keeps ownership of most of its data, and any writes
        // need to be guarded.
        use socket::tcp;
        self.bridges.iter().for_each(|(handle, tunnel)| {
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);
            if socket.can_send() {
                let result = socket.send(|dest| match tunnel.reader.try_read(dest) {
                    Ok(bytes) => {
                        if bytes > 0 && dest.len() > 0 {
                            (bytes, Ok::<(), NetworkError>(()))
                        } else {
                            // Zero bytes means the stream is closed.
                            // TODO: add a custom handler for this error.
                            (0, Err("Proxy reader is closed".into()))
                        }
                    }
                    Err(err) => match err.kind() {
                        io::ErrorKind::WouldBlock => (0, Ok(())),
                        _ => (0, Err(err.into())),
                    },
                });
                if let Ok(result) = result {
                    if let Err(err) = result {
                        warn!("Failed to read data from SOCKS socket: {}", err);
                        socket.close();
                        return;
                    }
                } else if let Err(err) = result {
                    // Not critical if socket is still opening.
                    warn!("Failed to send data to virtual socket: {}", err);
                }
            }

            if socket.can_recv() {
                let result = socket.recv(|src| match tunnel.writer.try_write(src) {
                    Ok(bytes) => (bytes, Ok(())),
                    Err(err) => match err.kind() {
                        io::ErrorKind::WouldBlock => (0, Ok(())),
                        _ => (0, Err(err)),
                    },
                });
                if let Ok(result) = result {
                    if let Err(err) = result {
                        warn!("Failed to write data to SOCKS socket: {}", err);
                        socket.close();
                        return;
                    }
                } else if let Err(err) = result {
                    warn!("Failed to read data from virtual socket: {}", err);
                }
            }
        });

        self.bridges.retain(|handle, _| {
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);
            if socket.is_open() {
                return true;
            }
            self.sockets.remove(*handle);
            false
        });
        let closed_sockets = self
            .sockets
            .iter()
            .filter_map(|(handle, _)| {
                let socket = self.sockets.get::<tcp::Socket>(handle);
                if !self.bridges.contains_key(&handle) && socket.state() == tcp::State::Closed {
                    Some(handle)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        closed_sockets.into_iter().for_each(|handle| {
            self.sockets.remove(handle);
        });

        for (handle, response) in self.opening_connections.iter_mut() {
            let socket = self.sockets.get::<tcp::Socket>(*handle);
            let result = match socket.state() {
                tcp::State::Closed | tcp::State::TimeWait | tcp::State::Closing => {
                    Some(Err("Socket is closed".into()))
                }
                tcp::State::SynSent | tcp::State::SynReceived => {
                    // Not ready.
                    None
                }
                _ => {
                    let response = match socket.local_endpoint() {
                        Some(endpoint) => {
                            (*handle, SocketAddr::from((endpoint.addr, endpoint.port)))
                        }
                        None => (*handle, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
                    };
                    Some(Ok(response))
                }
            };
            let result = if let Some(result) = result {
                result
            } else {
                continue;
            };
            let response = if let Some(response) = response.take() {
                response
            } else {
                continue;
            };
            if let Err(_) = response.send(result) {
                debug!("Proxy listener not listening for response");
            }
        }
        self.opening_connections
            .retain(|_, response| response.is_some());
    }

    pub fn create_command_sender(&self) -> mpsc::Sender<Command> {
        self.cmd_sender.clone()
    }

    fn process_command(&mut self, command: Command) {
        use socket::tcp;
        match command {
            Command::Connect(addr, response) => {
                // smoltcp crashes if interface has no IPv6 address.
                if addr.is_ipv6() {
                    if let Err(_) = response.send(Err("IPv6 connections are not supported".into()))
                    {
                        debug!("Proxy listener not listening for response");
                    }
                    return;
                }
                let rx_buffer = tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER_SIZE]);
                let tx_buffer = tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER_SIZE]);
                let mut socket = tcp::Socket::new(rx_buffer, tx_buffer);
                // TODO: check for collisions.
                let local_port = rand::thread_rng().gen_range(49152..=65535);
                let remote_addr = wire::IpAddress::from(addr.ip());
                if let Err(err) =
                    socket.connect(self.iface.context(), (remote_addr, addr.port()), local_port)
                {
                    if let Err(_) = response.send(Err(err.into())) {
                        debug!("Proxy listener not listening for response");
                    }
                    return;
                }

                let socket_handle = self.sockets.add(socket);
                self.opening_connections
                    .insert(socket_handle, Some(response));
            }
            Command::Bridge(socket_handle, reader, writer) => {
                let socket_tunnel = SocketTunnel { reader, writer };
                self.bridges.insert(socket_handle, socket_tunnel);
            }
            Command::Shutdown => {
                debug!("Shutdown command received");
                self.canceled = true;
            }
        }
    }

    async fn process_commands(&mut self, timeout_at: Option<tokio::time::Instant>) {
        let command = if let Some(timeout_at) = timeout_at {
            tokio::time::timeout_at(timeout_at, self.cmd_receiver.recv())
        } else {
            tokio::time::timeout(Duration::from_millis(0), self.cmd_receiver.recv())
        };
        let command = match command.await {
            Ok(command) => command,
            Err(_) => return,
        };

        if let Some(command) = command {
            self.process_command(command);
            return;
        }
    }

    pub async fn terminate(&mut self) -> Result<(), NetworkError> {
        Ok(self.device.vpn.terminate().await?)
    }
}

struct SocketTunnel {
    reader: tokio::net::tcp::OwnedReadHalf,
    writer: tokio::net::tcp::OwnedWriteHalf,
}

impl SocketTunnel {}

type SocketConnectionResult = Result<(iface::SocketHandle, SocketAddr), NetworkError>;

pub enum Command {
    Connect(
        std::net::SocketAddr,
        oneshot::Sender<SocketConnectionResult>,
    ),
    Bridge(
        iface::SocketHandle,
        tokio::net::tcp::OwnedReadHalf,
        tokio::net::tcp::OwnedWriteHalf,
    ),
    Shutdown,
}

struct VpnDevice<'a> {
    vpn: FortiVPNTunnel,
    last_echo_sent: tokio::time::Instant,
    read_buffers: storage::RingBuffer<'a, Vec<u8>>,
    write_buffers: storage::RingBuffer<'a, Vec<u8>>,
}

impl<'a> VpnDevice<'_> {
    fn new(vpn: FortiVPNTunnel) -> VpnDevice<'a> {
        VpnDevice {
            vpn,
            last_echo_sent: tokio::time::Instant::now(),
            read_buffers: storage::RingBuffer::new(vec![
                Vec::with_capacity(MAX_MTU_SIZE);
                DEVICE_BUFFERS_COUNT
            ]),
            write_buffers: storage::RingBuffer::new(vec![
                Vec::with_capacity(MAX_MTU_SIZE);
                DEVICE_BUFFERS_COUNT
            ]),
        }
    }
}

impl VpnDevice<'_> {
    async fn receive_data(&mut self) -> Result<(), NetworkError> {
        while !self.read_buffers.is_full() {
            let bytes_available = self
                .vpn
                .try_next_ip_packet(Some(Duration::from_millis(0)))
                .await?;
            if bytes_available == 0 {
                break;
            }
            let dest = if let Ok(dest) = self.read_buffers.enqueue_one() {
                dest
            } else {
                // Read buffers are full.
                return Ok(());
            };
            dest.resize(bytes_available, 0);
            let length = self
                .vpn
                .try_read_packet(dest, Some(Duration::from_millis(0)))
                .await?;
            dest.truncate(length);
            if length == 0 {
                break;
            }
        }
        Ok(())
    }

    async fn send_data(&mut self) -> Result<(), NetworkError> {
        while !self.write_buffers.is_empty() {
            let src = if let Ok(src) = self.write_buffers.dequeue_one() {
                src
            } else {
                // No write buffers are available.
                return Ok(());
            };

            if src.is_empty() {
                continue;
            }
            self.vpn.send_packet(src).await?;
            src.clear();
        }
        Ok(())
    }

    async fn process_keepalive(&mut self) -> Result<(), NetworkError> {
        let current_time = tokio::time::Instant::now();
        if self.last_echo_sent + ECHO_SEND_INTERVAL < current_time {
            self.vpn.send_echo_request().await?;
            self.last_echo_sent = tokio::time::Instant::now();
        }
        if self.vpn.last_echo_reply() + ECHO_TIMEOUT < current_time {
            Err("No echo replies received".into())
        } else {
            Ok(())
        }
    }
}

impl phy::Device for VpnDevice<'_> {
    type RxToken<'a> = RxToken<'a>
    where
         Self: 'a;

    type TxToken<'a> = TxToken<'a>
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
        let dest = if let Ok(dest) = self.write_buffers.enqueue_one() {
            dest
        } else {
            // Write buffers are full.
            return None;
        };
        Some(TxToken { dest })
    }

    fn capabilities(&self) -> phy::DeviceCapabilities {
        let mut caps = phy::DeviceCapabilities::default();
        caps.max_transmission_unit = self.vpn.mtu();
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

impl<'a> phy::RxToken for RxToken<'a> {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.src)
    }
}

struct TxToken<'a> {
    dest: &'a mut Vec<u8>,
}

impl<'a> phy::TxToken for TxToken<'a> {
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
    Forti(crate::fortivpn::FortiError),
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

impl From<crate::fortivpn::FortiError> for NetworkError {
    fn from(err: crate::fortivpn::FortiError) -> NetworkError {
        Self::Forti(err)
    }
}
