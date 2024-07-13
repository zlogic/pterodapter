use std::{
    error, fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use log::{debug, info, warn};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter},
    net::{tcp, TcpListener, TcpStream},
    runtime, signal,
    sync::mpsc,
    task::JoinHandle,
};

pub struct Config {
    pub listen_addr: SocketAddr,
}
pub fn run(config: Config) -> Result<(), SocksError> {
    let server = Server::new(config)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;
    let (accept_sender, accept_receiver) = mpsc::channel(10);
    let handles = vec![rt.spawn(async move { server.listen_socket(accept_sender).await })];

    rt.block_on(Server::wait_termination(handles))?;
    rt.shutdown_timeout(Duration::from_secs(60));

    info!("Stopped server");
    Ok(())
}

pub struct Server {
    listen_addr: SocketAddr,
}

impl Server {
    pub fn new(config: Config) -> Result<Server, SocksError> {
        Ok(Server {
            listen_addr: config.listen_addr,
        })
    }

    async fn listen_socket(
        &self,
        offload_connections: mpsc::Sender<TcpStream>,
    ) -> Result<(), SocksError> {
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
                    let mut handler = SocksConnection::new(socket);
                    let rt = runtime::Handle::current();
                    rt.spawn(async move {
                        if let Err(err) = handler.handle_connection().await {
                            warn!("SOCKS connection failed: {}", err);
                        }
                    });
                }
                Err(err) => warn!("Failed to accept incoming connection: {}", err),
            }
        }
    }

    async fn wait_termination(
        handles: Vec<JoinHandle<Result<(), SocksError>>>,
    ) -> Result<(), SocksError> {
        signal::ctrl_c().await?;
        handles.iter().for_each(|handle| handle.abort());
        Ok(())
    }
}

struct SocksConnection {
    reader: BufReader<tcp::OwnedReadHalf>,
    writer: BufWriter<tcp::OwnedWriteHalf>,
}

impl SocksConnection {
    fn new<'a>(socket: TcpStream) -> SocksConnection {
        let (reader, writer) = socket.into_split();
        let reader = BufReader::new(reader);
        let writer = BufWriter::new(writer);
        SocksConnection { reader, writer }
    }

    async fn handle_connection(&mut self) -> Result<(), SocksError> {
        self.perform_handshake().await?;
        self.read_request().await?;

        let mut request = String::new();
        while self.reader.read_line(&mut request).await? > 0 {
            println!("Received request {}", request);
            request.clear();
        }

        Ok(())
    }

    async fn perform_handshake(&mut self) -> Result<(), SocksError> {
        let version = self.reader.read_u8().await?;
        if version != SOCKS5_VERSION {
            return Err("Unsupported SOCKS version".into());
        }
        let nmethods = self.reader.read_u8().await?;
        let mut selected_method = AuthenticationMethod::NO_ACCEPTABLE_METHODS;
        for _ in 0..nmethods {
            let method = AuthenticationMethod::from_u8(self.reader.read_u8().await?);
            if method == AuthenticationMethod::NO_AUTHENTICATION_REQUIRED {
                selected_method = method;
            }
        }
        self.writer.write_u8(SOCKS5_VERSION).await?;
        self.writer.write_u8(selected_method.0).await?;
        self.writer.flush().await?;
        Ok(())
    }

    async fn read_request(&mut self) -> Result<(), SocksError> {
        println!("Prepating to read request");
        let version = self.reader.read_u8().await?;
        println!("Read to read request");
        if version != SOCKS5_VERSION {
            return Err("Unsupported SOCKS version".into());
        }
        let cmd = SocksCommand::from_u8(self.reader.read_u8().await?);
        let _ = self.reader.read_u8().await?; // Reserved byte.
        let addr_type = SocksAddressType::from_u8(self.reader.read_u8().await?);
        let addr = match addr_type {
            SocksAddressType::IPV4 => {
                let mut octets = [0u8; 4];
                self.reader.read_exact(&mut octets).await?;
                Some(DestinationAddress::IpAddr(IpAddr::V4(Ipv4Addr::from(
                    octets,
                ))))
            }
            SocksAddressType::DOMAINNAME => {
                let len = self.reader.read_u8().await?;
                let mut dest = vec![0; len as usize];
                self.reader.read_exact(dest.as_mut_slice()).await?;
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
                self.reader.read_exact(&mut octets).await?;
                Some(DestinationAddress::IpAddr(IpAddr::V6(Ipv6Addr::from(
                    octets,
                ))))
            }
            _ => None,
        };
        let port = self.reader.read_u16().await?;

        self.writer.write_u8(SOCKS5_VERSION).await?;
        if cmd != SocksCommand::CONNECT {
            self.write_error_response(CommandResponse::COMMAND_NOT_SUPPORTED)
                .await?;
            debug!("Command {} is not supported", cmd);
            return Err("Command is not supported".into());
        }
        let addr = if let Some(addr) = addr {
            addr
        } else {
            self.write_error_response(CommandResponse::ADDRESS_TYPE_NOT_SUPPORTED)
                .await?;
            debug!("Address type {} is not supported", addr_type);
            return Err("Address type is not supported".into());
        };

        self.connect_to_host(addr, port).await?;
        Ok(())
    }

    async fn connect_to_host(
        &mut self,
        addr: DestinationAddress,
        port: u16,
    ) -> Result<(), SocksError> {
        // TODO: open SmolTCP/FortiVPN connection here.
        let bnd_addr = Ipv4Addr::LOCALHOST;
        let bnd_port = port;

        self.writer.write_u8(CommandResponse::SUCCEDED.0).await?;
        self.writer.write_u8(0).await?; // Reserved byte.
        self.writer.write_u8(SocksAddressType::IPV4.0).await?;
        self.writer.write_all(&bnd_addr.octets()).await?;
        self.writer.write_u16(bnd_port).await?;
        self.writer.flush().await?;
        Ok(())
    }

    async fn write_error_response(&mut self, response: CommandResponse) -> Result<(), SocksError> {
        self.writer.write_u8(response.0).await?;
        self.writer.write_u8(0).await?; // Reserved byte.
        self.writer.write_u8(SocksAddressType::DOMAINNAME.0).await?;
        self.writer.write_u8(0).await?; // Empty domain name.
        self.writer.write_u16(0).await?;
        self.writer.flush().await?;
        Ok(())
    }
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

    fn from_u8(method: u8) -> SocksCommand {
        SocksCommand(method)
    }
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
    const DOMAINNAME: SocksAddressType = SocksAddressType(0x02);
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
pub enum SocksError {
    Internal(&'static str),
    Join(tokio::task::JoinError),
    Io(io::Error),
}

impl fmt::Display for SocksError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Internal(msg) => f.write_str(msg),
            Self::Join(ref e) => write!(f, "Tokio join error: {}", e),
            Self::Io(ref e) => {
                write!(f, "IO error: {}", e)
            }
        }
    }
}

impl error::Error for SocksError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Self::Internal(_msg) => None,
            Self::Join(ref err) => Some(err),
            Self::Io(ref err) => Some(err),
        }
    }
}

impl From<&'static str> for SocksError {
    fn from(msg: &'static str) -> SocksError {
        Self::Internal(msg)
    }
}

impl From<tokio::task::JoinError> for SocksError {
    fn from(err: tokio::task::JoinError) -> SocksError {
        Self::Join(err)
    }
}

impl From<io::Error> for SocksError {
    fn from(err: io::Error) -> SocksError {
        Self::Io(err)
    }
}
