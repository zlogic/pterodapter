use std::{
    error, fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use log::{debug, info, warn};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    runtime,
    sync::{mpsc, oneshot},
};

use crate::{http, network};

pub struct Config {
    pub listen_addr: SocketAddr,
}

pub struct Server {
    listen_addr: SocketAddr,
    command_bridge: mpsc::Sender<network::Command>,
}

impl Server {
    pub fn new(
        config: Config,
        command_bridge: mpsc::Sender<network::Command>,
    ) -> Result<Server, ProxyError> {
        Ok(Server {
            listen_addr: config.listen_addr,
            command_bridge,
        })
    }

    pub async fn run(&self) -> Result<(), ProxyError> {
        let listener = match TcpListener::bind(&self.listen_addr).await {
            Ok(listener) => listener,
            Err(err) => {
                warn!("Failed to bind listener on {}: {}", self.listen_addr, err);
                return Err("Failed to bind listener".into());
            }
        };
        info!("Started server on {}", self.listen_addr);
        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    debug!("Received connection from {}", addr);
                    let handler = ProxyConnection::new(socket, self.command_bridge.clone());
                    let rt = runtime::Handle::current();
                    rt.spawn(async move {
                        if let Err(err) = handler.handle_connection().await {
                            warn!("Proxy connection failed: {}", err);
                        }
                    });
                }
                Err(err) => warn!("Failed to accept incoming connection: {}", err),
            }
        }
    }
}

struct ProxyConnection {
    socket: Option<TcpStream>,
    command_bridge: mpsc::Sender<network::Command>,
}

impl ProxyConnection {
    fn new<'a>(
        socket: TcpStream,
        command_bridge: mpsc::Sender<network::Command>,
    ) -> ProxyConnection {
        ProxyConnection {
            socket: Some(socket),
            command_bridge,
        }
    }

    async fn handle_connection(mut self) -> Result<(), ProxyError> {
        let mut socket = match self.socket.take() {
            Some(reader) => reader,
            None => return Err("Socket already consumed".into()),
        };
        // Detect protocol type.
        let first_byte = socket.read_u8().await?;
        let destination_connection = match first_byte {
            b'a'..=b'z' | b'A'..=b'Z' => {
                self.handle_http_request(&mut socket, vec![first_byte])
                    .await?
            }
            SOCKS5_VERSION => {
                self.socks_handshake(&mut socket).await?;
                self.socks_read_request(&mut socket).await?
            }
            0x16 => {
                return Err("Received incoming TLS connection".into());
            }
            _ => {
                warn!("Received unexpected first byte {:2x}", first_byte);
                return Err("Unsupported protocol".into());
            }
        };

        match destination_connection {
            DestinationConnection::TunnelHandle(handle, _) => {
                match self
                    .command_bridge
                    .send(network::Command::Bridge(handle, socket))
                    .await
                {
                    Ok(_) => Ok(()),
                    Err(_) => Err("Command channel closed".into()),
                }
            }
            DestinationConnection::DirectConnection(mut stream) => {
                let rt = runtime::Handle::current();
                rt.spawn(async move {
                    if let Err(err) = tokio::io::copy_bidirectional(&mut socket, &mut stream).await
                    {
                        debug!("Direct connection tunnel failed: {}", err);
                    }
                });
                Ok(())
            }
            DestinationConnection::None => Ok(()),
        }
    }

    async fn handle_http_request(
        &mut self,
        socket: &mut TcpStream,
        mut request: Vec<u8>,
    ) -> Result<DestinationConnection, ProxyError> {
        http::read_unbuffered_chunk(socket, &mut request).await?;
        let request =
            String::from_utf8(request).map_err(|_| "First handshake byte is not utf-8")?;
        if request.starts_with("GET /proxy.pac HTTP/1.1\r\n") {
            Self::send_pac_file(socket).await?;
            Ok(DestinationConnection::None)
        } else if request.starts_with("CONNECT ") {
            let host = if let Some(host) = http::read_host(&request) {
                host
            } else {
                return Err("CONNECT request has no Host header".into());
            };
            let destination_connection = self.connect_to_domain(host, None).await?;
            // TODO: write an error if connection fails.
            socket
                .write_all("HTTP/1.1 200 Connection Established\r\n\r\n".as_bytes())
                .await?;
            socket.flush().await?;
            Ok(destination_connection)
        } else {
            // Assume it's an HTTP Proxy protocol.
            // TODO: remove host from HTTP request path.
            // TODO: remove the Proxy-Connection header?
            let host = if let Some(host) = http::read_host(&request) {
                host
            } else {
                return Err("HTTP proxy request has no Host header".into());
            };
            self.connect_to_domain(host, Some(request.as_bytes().into()))
                .await
        }
    }

    async fn send_pac_file(socket: &mut TcpStream) -> Result<(), ProxyError> {
        // TODO: allow configuring this
        let mut file = File::open("proxy.pac").await?;
        let mut contents = vec![];
        file.read_to_end(&mut contents).await?;
        http::write_pac_response(socket, &contents).await?;
        socket.shutdown().await?;
        Ok(())
    }

    async fn connect_to_domain(
        &mut self,
        host: &str,
        initial_data: Option<Vec<u8>>,
    ) -> Result<DestinationConnection, ProxyError> {
        let (host, domain) = if let Some((domain, _)) = host.split_once(":") {
            (host.to_owned(), domain)
        } else {
            // Fallback to port 80 (the default).
            (host.to_owned() + ":80", host)
        };
        // TODO: allow configuring this
        let direct_connection = domain.ends_with(".home");
        let ip = tokio::net::lookup_host(host).await?.next();
        match ip {
            Some(addr) => {
                self.connect_to_addr(addr, direct_connection, initial_data)
                    .await
            }
            None => Err("Failed to lookup host".into()),
        }
    }

    async fn connect_to_addr(
        &mut self,
        addr: SocketAddr,
        direct_connection: bool,
        initial_data: Option<Vec<u8>>,
    ) -> Result<DestinationConnection, ProxyError> {
        if !direct_connection && addr.is_ipv4() {
            let (sender, receiver) = oneshot::channel();
            let connect_command = network::Command::Connect(addr, initial_data, sender);
            if self.command_bridge.send(connect_command).await.is_err() {
                return Err("Command channel closed".into());
            }
            match receiver.await {
                Ok(Ok(socket)) => Ok(DestinationConnection::TunnelHandle(socket.0, socket.1)),
                Ok(Err(err)) => {
                    debug!("Failed to connect to host: {}", err);
                    Err("Failed to connect to host".into())
                }
                Err(_) => Err("Channel closed".into()),
            }
        } else {
            match TcpStream::connect(addr).await {
                Ok(mut socket) => {
                    if let Some(data) = initial_data {
                        socket.write_all(&data).await?;
                        socket.flush().await?;
                    }
                    Ok(DestinationConnection::DirectConnection(socket))
                }
                Err(err) => {
                    debug!("Failed to open direct connection: {}", err);
                    Err("Failed to open direct connection".into())
                }
            }
        }
    }

    async fn socks_handshake(&mut self, socket: &mut TcpStream) -> Result<(), ProxyError> {
        let nmethods = socket.read_u8().await?;
        let mut selected_method = AuthenticationMethod::NO_ACCEPTABLE_METHODS;
        for _ in 0..nmethods {
            let method = AuthenticationMethod::from_u8(socket.read_u8().await?);
            if method == AuthenticationMethod::NO_AUTHENTICATION_REQUIRED {
                selected_method = method;
            }
        }
        socket.write_u8(SOCKS5_VERSION).await?;
        socket.write_u8(selected_method.0).await?;
        socket.flush().await?;
        Ok(())
    }

    async fn socks_read_request(
        &mut self,
        socket: &mut TcpStream,
    ) -> Result<DestinationConnection, ProxyError> {
        let version = socket.read_u8().await?;
        if version != SOCKS5_VERSION {
            return Err("Unsupported SOCKS version".into());
        }
        let cmd = SocksCommand::from_u8(socket.read_u8().await?);
        let _ = socket.read_u8().await?; // Reserved byte.
        let addr_type = SocksAddressType::from_u8(socket.read_u8().await?);
        let addr = match addr_type {
            SocksAddressType::IPV4 => {
                let mut octets = [0u8; 4];
                socket.read_exact(&mut octets).await?;
                Some(DestinationAddress::IpAddr(IpAddr::V4(Ipv4Addr::from(
                    octets,
                ))))
            }
            SocksAddressType::DOMAINNAME => {
                let len = socket.read_u8().await?;
                let mut dest = vec![0; len as usize];
                socket.read_exact(dest.as_mut_slice()).await?;
                let domain = match String::from_utf8(dest) {
                    Ok(domain) => Ok(domain),
                    Err(err) => {
                        debug!("Failed to decode domain name: {}", err);
                        Err("Failed to decode domain")
                    }
                }?;
                Some(DestinationAddress::Domain(domain))
            }
            SocksAddressType::IPV6 => {
                let mut octets = [0u8; 16];
                socket.read_exact(&mut octets).await?;
                Some(DestinationAddress::IpAddr(IpAddr::V6(Ipv6Addr::from(
                    octets,
                ))))
            }
            _ => None,
        };
        let port = socket.read_u16().await?;

        socket.write_u8(SOCKS5_VERSION).await?;
        if cmd != SocksCommand::CONNECT {
            ProxyConnection::socks_write_error_response(
                socket,
                CommandResponse::COMMAND_NOT_SUPPORTED,
            )
            .await?;
            debug!("Command {} is not supported", cmd);
            return Err("Command is not supported".into());
        }
        Ok(self.socks_connect_to_host(socket, addr, port).await?)
    }

    async fn socks_connect_to_host(
        &mut self,
        socket: &mut TcpStream,
        addr: Option<DestinationAddress>,
        port: u16,
    ) -> Result<DestinationConnection, ProxyError> {
        let destination_connection = match addr {
            Some(DestinationAddress::IpAddr(ip)) => {
                self.connect_to_addr((ip, port).into(), false, None).await
            }
            Some(DestinationAddress::Domain(ref domain)) => {
                self.connect_to_domain(format!("{}:{}", domain, port).as_str(), None)
                    .await
            }
            None => {
                ProxyConnection::socks_write_error_response(
                    socket,
                    CommandResponse::ADDRESS_TYPE_NOT_SUPPORTED,
                )
                .await?;
                return Err("Address type unknown".into());
            }
        };
        let destination_connection = match destination_connection {
            Ok(connection) => connection,
            Err(err) => {
                debug!("Failed to connect to destination: {}", err);
                ProxyConnection::socks_write_error_response(
                    socket,
                    CommandResponse::NETWORK_UNREACHABLE,
                )
                .await?;
                return Err("Failed to connect to destination".into());
            }
        };
        let local_addr = match destination_connection {
            DestinationConnection::None => Err("Destination connection has no address"),
            DestinationConnection::TunnelHandle(_, local_addr) => Ok(local_addr),
            DestinationConnection::DirectConnection(ref stream) => {
                stream.local_addr().map_err(|err| {
                    debug!("Failed to get local address for connection: {}", err);
                    "Failed to get local address for connection"
                })
            }
        };
        let local_addr = match local_addr {
            Ok(addr) => addr,
            Err(err) => {
                ProxyConnection::socks_write_error_response(
                    socket,
                    CommandResponse::ADDRESS_TYPE_NOT_SUPPORTED,
                )
                .await?;
                return Err(err.into());
            }
        };
        let bnd_addr = local_addr.ip();
        let bnd_port = local_addr.port();

        socket.write_u8(CommandResponse::SUCCEDED.0).await?;
        socket.write_u8(0).await?; // Reserved byte.
        match bnd_addr {
            IpAddr::V4(ref ip) => {
                socket.write_u8(SocksAddressType::IPV4.0).await?;
                socket.write_all(&ip.octets()).await?;
            }
            IpAddr::V6(ref ip) => {
                socket.write_u8(SocksAddressType::IPV6.0).await?;
                socket.write_all(&ip.octets()).await?;
            }
        }
        socket.write_u16(bnd_port).await?;
        socket.flush().await?;
        Ok(destination_connection)
    }

    async fn socks_write_error_response(
        socket: &mut TcpStream,
        response: CommandResponse,
    ) -> Result<(), ProxyError> {
        socket.write_u8(response.0).await?;
        socket.write_u8(0).await?; // Reserved byte.
        socket.write_u8(SocksAddressType::DOMAINNAME.0).await?;
        socket.write_u8(0).await?; // Empty domain name.
        socket.write_u16(0).await?;
        socket.flush().await?;
        Ok(())
    }
}

enum DestinationConnection {
    None,
    TunnelHandle(smoltcp::iface::SocketHandle, SocketAddr),
    DirectConnection(TcpStream),
}

const SOCKS5_VERSION: u8 = 0x05;

#[derive(Clone, Copy, PartialEq, Eq)]
struct AuthenticationMethod(u8);
impl AuthenticationMethod {
    const NO_AUTHENTICATION_REQUIRED: AuthenticationMethod = AuthenticationMethod(0x00);
    const GSSAPI: AuthenticationMethod = AuthenticationMethod(0x01);
    const USERNAME_PASSWORD: AuthenticationMethod = AuthenticationMethod(0x02);
    const NO_ACCEPTABLE_METHODS: AuthenticationMethod = AuthenticationMethod(0xff);

    fn from_u8(method: u8) -> AuthenticationMethod {
        AuthenticationMethod(method)
    }
}
impl fmt::Display for AuthenticationMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &Self::NO_AUTHENTICATION_REQUIRED => write!(f, "NO AUTHENTICATION REQUIRED"),
            &Self::GSSAPI => write!(f, "GSSAPI"),
            &Self::USERNAME_PASSWORD => write!(f, "USERNAME/PASSWORD"),
            &Self::NO_ACCEPTABLE_METHODS => write!(f, "NO ACCEPTABLE METHODS"),
            _ => write!(f, "Unknown authentication method {}", self.0),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct SocksCommand(u8);
impl SocksCommand {
    const CONNECT: SocksCommand = SocksCommand(0x01);
    const BIND: SocksCommand = SocksCommand(0x02);
    const UDP_ASSOCIATE: SocksCommand = SocksCommand(0x03);

    fn from_u8(method: u8) -> SocksCommand {
        SocksCommand(method)
    }
}
impl fmt::Display for SocksCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &Self::CONNECT => write!(f, "CONNECT"),
            &Self::BIND => write!(f, "BIND"),
            &Self::UDP_ASSOCIATE => write!(f, "UDP ASSOCIATE"),
            _ => write!(f, "Unknown command {}", self.0),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct CommandResponse(u8);
impl CommandResponse {
    const SUCCEDED: CommandResponse = CommandResponse(0x00);
    const GENERAL_FAILURE: CommandResponse = CommandResponse(0x01);
    const CONNECTION_NOT_ALLOWED: CommandResponse = CommandResponse(0x02);
    const NETWORK_UNREACHABLE: CommandResponse = CommandResponse(0x03);
    const HOST_UNREACHABLE: CommandResponse = CommandResponse(0x04);
    const CONNECTION_REFUSED: CommandResponse = CommandResponse(0x05);
    const TTL_EXPIRED: CommandResponse = CommandResponse(0x06);
    const COMMAND_NOT_SUPPORTED: CommandResponse = CommandResponse(0x07);
    const ADDRESS_TYPE_NOT_SUPPORTED: CommandResponse = CommandResponse(0x08);
}

impl fmt::Display for CommandResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &Self::SUCCEDED => write!(f, "succeeded"),
            &Self::GENERAL_FAILURE => write!(f, "general SOCKS server failure"),
            &Self::CONNECTION_NOT_ALLOWED => write!(f, "connection not allowed by ruleset"),
            &Self::NETWORK_UNREACHABLE => write!(f, "Network unreachable"),
            &Self::HOST_UNREACHABLE => write!(f, "Host unreachable"),
            &Self::CONNECTION_REFUSED => write!(f, "Connection refused"),
            &Self::TTL_EXPIRED => write!(f, "TTL expired"),
            &Self::COMMAND_NOT_SUPPORTED => write!(f, "Command not supported"),
            &Self::ADDRESS_TYPE_NOT_SUPPORTED => write!(f, "Address type not supported"),
            _ => write!(f, "Unknown command response {}", self.0),
        }
    }
}

enum DestinationAddress {
    IpAddr(IpAddr),
    Domain(String),
}
impl fmt::Display for DestinationAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IpAddr(ref addr) => addr.fmt(f),
            Self::Domain(ref domain) => domain.fmt(f),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct SocksAddressType(u8);
impl SocksAddressType {
    const IPV4: SocksAddressType = SocksAddressType(0x01);
    const DOMAINNAME: SocksAddressType = SocksAddressType(0x03);
    const IPV6: SocksAddressType = SocksAddressType(0x04);

    fn from_u8(method: u8) -> SocksAddressType {
        SocksAddressType(method)
    }
}
impl fmt::Display for SocksAddressType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &Self::IPV4 => write!(f, "IP V4 address"),
            &Self::DOMAINNAME => write!(f, "DOMAINNAME"),
            &Self::IPV6 => write!(f, "IP V6 address"),
            _ => write!(f, "Unknown address type {}", self.0),
        }
    }
}

#[derive(Debug)]
pub enum ProxyError {
    Internal(&'static str),
    Join(tokio::task::JoinError),
    Io(io::Error),
    Http(crate::http::HttpError),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Internal(msg) => f.write_str(msg),
            Self::Join(ref e) => write!(f, "Tokio join error: {}", e),
            Self::Io(ref e) => {
                write!(f, "IO error: {}", e)
            }
            Self::Http(ref e) => {
                write!(f, "HTTP error: {}", e)
            }
        }
    }
}

impl error::Error for ProxyError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Self::Internal(_msg) => None,
            Self::Join(ref err) => Some(err),
            Self::Io(ref err) => Some(err),
            Self::Http(ref err) => Some(err),
        }
    }
}

impl From<&'static str> for ProxyError {
    fn from(msg: &'static str) -> ProxyError {
        Self::Internal(msg)
    }
}

impl From<tokio::task::JoinError> for ProxyError {
    fn from(err: tokio::task::JoinError) -> ProxyError {
        Self::Join(err)
    }
}

impl From<io::Error> for ProxyError {
    fn from(err: io::Error) -> ProxyError {
        Self::Io(err)
    }
}

impl From<crate::http::HttpError> for ProxyError {
    fn from(err: crate::http::HttpError) -> ProxyError {
        Self::Http(err)
    }
}
