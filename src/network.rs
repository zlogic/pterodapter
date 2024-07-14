use std::{
    collections::HashMap,
    error, fmt, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use log::{debug, warn};
use smoltcp::{iface, phy, socket, wire};
use tokio::{
    runtime,
    sync::{mpsc, oneshot},
};

use crate::fortivpn::FortiVPNTunnel;

const MTU_SIZE: usize = 1500;
const SOCKET_BUFFER_SIZE: usize = 4096;

pub struct Network<'a> {
    device: PPPDevice,
    iface: iface::Interface,
    sockets: iface::SocketSet<'a>,
    bridges: HashMap<iface::SocketHandle, SocketTunnel>,
    opening_connections:
        HashMap<iface::SocketHandle, Option<oneshot::Sender<SocketConnectionResult>>>,
    cmd_sender: mpsc::Sender<Command>,
    cmd_receiver: mpsc::Receiver<Command>,
}

impl Network<'_> {
    pub fn new<'a>(vpn: FortiVPNTunnel) -> Result<Network<'a>, NetworkError> {
        // TODO: how to choose the CIDR?
        let ip_cidr = wire::IpCidr::new(vpn.ip_addr().into(), 24);

        let mut device = PPPDevice::new(vpn);
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
            cmd_sender,
            cmd_receiver,
        })
    }

    pub async fn run(&mut self) -> Result<(), NetworkError> {
        loop {
            let timestamp = smoltcp::time::Instant::now();
            self.copy_all_data();
            self.iface
                .poll(timestamp, &mut self.device, &mut self.sockets);
            self.device.receive_data().await?;
            self.device.send_data().await?;
            match self.iface.poll_delay(timestamp, &self.sockets) {
                Some(poll_delay) => {
                    let timeout_at = tokio::time::Instant::now()
                        + Duration::from_micros(poll_delay.total_micros());
                    self.process_commands(timeout_at.into()).await;
                }
                None => {
                    self.process_commands(None).await;
                }
            }
        }
    }

    fn copy_all_data(&mut self) {
        // This is not fancy or super efficient, but with a single-user (a few connections) should work OK.
        // The alternative is using poll/waking and additional buffers (or perhaps a list of futures), which
        // doesn't work well with smoltcp - as smoltcp keeps ownership of most of its data, and any writes
        // need to be guarded.
        use socket::tcp;
        for (handle, tunnel) in self.bridges.iter() {
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);
            if socket.can_send() {
                let result = socket.send(|dest| match tunnel.reader.try_read(dest) {
                    Ok(bytes) => (bytes, Ok(())),
                    Err(err) => match err.kind() {
                        io::ErrorKind::WouldBlock => (0, Ok(())),
                        _ => (0, Err(err)),
                    },
                });
                if let Ok(result) = result {
                    if let Err(err) = result {
                        warn!("Failed to read data from SOCKS socket: {}", err);
                    }
                } else if let Err(err) = result {
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
                    }
                } else if let Err(err) = result {
                    warn!("Failed to read data from virtual socket: {}", err);
                }
            }
        }

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
                println!("Socket state is {}", socket.state());
                continue;
            };
            let response = if let Some(response) = response.take() {
                response
            } else {
                continue;
            };
            let _ = response.send(result);
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
                let rx_buffer = tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER_SIZE]);
                let tx_buffer = tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER_SIZE]);
                let mut socket = tcp::Socket::new(rx_buffer, tx_buffer);
                // TODO: choose a random port between 49152 and 65535.
                let local_port = 8080;
                let remote_addr = wire::IpAddress::from(addr.ip());
                if let Err(err) =
                    socket.connect(self.iface.context(), (remote_addr, addr.port()), local_port)
                {
                    let _ = response.send(Err(err.into()));
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
        }
    }

    async fn process_commands(&mut self, timeout_at: Option<tokio::time::Instant>) {
        let command = if let Some(timeout_at) = timeout_at {
            match tokio::time::timeout_at(timeout_at, self.cmd_receiver.recv()).await {
                Ok(command) => command,
                Err(_) => return,
            }
        } else {
            self.cmd_receiver.recv().await
        };

        if let Some(command) = command {
            self.process_command(command);
            return;
        }
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
}

struct PPPDevice {
    vpn: FortiVPNTunnel,
    read_packet: [u8; MTU_SIZE],
    write_packet: [u8; MTU_SIZE],
    read_packet_size: usize,
    write_packet_size: usize,
}

impl PPPDevice {
    fn new(vpn: FortiVPNTunnel) -> PPPDevice {
        PPPDevice {
            vpn,
            read_packet: [0u8; MTU_SIZE],
            write_packet: [0u8; MTU_SIZE],
            read_packet_size: 0,
            write_packet_size: 0,
        }
    }
}

impl PPPDevice {
    async fn receive_data(&mut self) -> Result<(), NetworkError> {
        if self.read_packet_size > 0 {
            // Data is not consumed yet.
            return Ok(());
        }
        self.read_packet_size = self.vpn.read_packet(&mut self.read_packet).await?;
        Ok(())
    }

    async fn send_data(&mut self) -> Result<(), NetworkError> {
        if self.write_packet_size == 0 {
            // No data to send.
            return Ok(());
        }

        let buf = &self.write_packet[..self.write_packet_size];
        self.write_packet_size = 0;

        self.vpn.send_packet(buf).await?;
        Ok(())
    }
}

impl phy::Device for PPPDevice {
    type RxToken<'a> = PPPDeviceRxToken<'a>
    where
         Self: 'a;

    type TxToken<'a> = PPPDeviceTxToken<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.read_packet_size == 0 || self.write_packet_size != 0 {
            return None;
        }
        Some((
            PPPDeviceRxToken {
                read_packet: &mut self.read_packet[..self.read_packet_size],
            },
            PPPDeviceTxToken {
                write_packet: &mut self.write_packet,
                write_packet_size: &mut self.write_packet_size,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        if self.write_packet_size != 0 {
            return None;
        }
        Some(PPPDeviceTxToken {
            write_packet: &mut self.write_packet,
            write_packet_size: &mut self.write_packet_size,
        })
    }

    fn capabilities(&self) -> phy::DeviceCapabilities {
        let mut caps = phy::DeviceCapabilities::default();
        caps.max_transmission_unit = MTU_SIZE;
        caps.max_burst_size = Some(1);
        caps.medium = phy::Medium::Ip;
        caps
    }
}

struct PPPDeviceRxToken<'a> {
    read_packet: &'a mut [u8],
}

impl<'a> phy::RxToken for PPPDeviceRxToken<'a> {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let result = f(&mut self.read_packet);
        println!("Received packet {:?}", self.read_packet);
        result
    }
}

struct PPPDeviceTxToken<'a> {
    write_packet: &'a mut [u8],
    write_packet_size: &'a mut usize,
}

impl<'a> phy::TxToken for PPPDeviceTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // f will copy data into a provided buffer (avoid allocations).
        *self.write_packet_size = len;
        f(&mut self.write_packet[..len])
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
