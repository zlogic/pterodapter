use log::{debug, info, warn};
use rand::Rng;
use std::{
    collections::HashMap,
    error, fmt,
    hash::{Hash, Hasher},
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{net::UdpSocket, signal, task::JoinHandle};

mod message;

const MAX_DATAGRAM_SIZE: usize = 1500;

pub struct Server {
    listen_ips: Vec<IpAddr>,
}

impl Server {
    pub fn new(listen_ips: Vec<IpAddr>) -> Server {
        Server { listen_ips }
    }

    async fn listen_socket(listen_ip: IpAddr) -> Result<(), IKEv2Error> {
        let socket = match UdpSocket::bind((listen_ip, 500)).await {
            Ok(socket) => socket,
            Err(err) => {
                log::error!("Failed to open listener on {}: {}", listen_ip, err);
                return Err(err.into());
            }
        };
        info!("Started server on {}", listen_ip);
        let mut buf = [0u8; MAX_DATAGRAM_SIZE];
        // TODO: share sessions between all threads: either using an async mutex, or by forwarding all messages to the same mpsc channel.
        let mut sessions = Sessions::new();
        loop {
            let (bytes_res, remote_addr) = socket.recv_from(&mut buf).await?;
            let datagram_bytes = &mut buf[..bytes_res];
            sessions
                .process_message(datagram_bytes, remote_addr)
                .await?;
        }
    }

    async fn wait_termination(
        handles: Vec<JoinHandle<Result<(), IKEv2Error>>>,
    ) -> Result<(), IKEv2Error> {
        signal::ctrl_c().await?;
        handles.iter().for_each(|handle| handle.abort());
        Ok(())
    }

    pub fn run(&self) -> Result<(), IKEv2Error> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()?;
        let handles = self
            .listen_ips
            .iter()
            .map(|listen_ip| rt.spawn(Server::listen_socket(listen_ip.to_owned())))
            .collect::<Vec<_>>();
        rt.block_on(Server::wait_termination(handles))?;
        rt.shutdown_timeout(Duration::from_secs(60));

        info!("Stopped server");
        Ok(())
    }
}

struct SessionID {
    remote_spi: u64,
    local_spi: u64,
}

impl PartialEq for SessionID {
    fn eq(&self, other: &Self) -> bool {
        self.remote_spi == other.remote_spi && self.local_spi == other.local_spi
    }
}

impl Eq for SessionID {}

impl Hash for SessionID {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.remote_spi.hash(state);
        self.local_spi.hash(state);
    }
}

impl SessionID {
    fn from_message(message: &message::Message) -> Result<SessionID, message::FormatError> {
        // As IKE_SA_INIT is unencrypted and unauthenticated, prevent sessions from being hijacked
        // by generating a unique session ID for every packet.
        let local_spi = if message.read_exchange_type()? == message::ExchangeType::IKE_SA_INIT {
            rand::thread_rng().gen::<u64>()
        } else {
            message.read_responder_spi()
        };
        let remote_spi = message.read_initiator_spi();
        Ok(SessionID {
            remote_spi,
            local_spi,
        })
    }
}

struct Sessions {
    sessions: HashMap<SessionID, IKEv2Session>,
}

impl Sessions {
    fn new() -> Sessions {
        Sessions {
            sessions: HashMap::new(),
        }
    }

    fn get(
        &mut self,
        message: &message::Message,
        remote_addr: SocketAddr,
    ) -> Result<&mut IKEv2Session, message::FormatError> {
        let id = SessionID::from_message(message)?;
        Ok(self
            .sessions
            .entry(id)
            .or_insert_with(|| IKEv2Session::new(remote_addr)))
    }

    async fn process_message(
        &mut self,
        datagram_bytes: &[u8],
        remote_addr: SocketAddr,
    ) -> Result<(), IKEv2Error> {
        let ikev2_message = message::Message::from_datagram(datagram_bytes)?;
        if !ikev2_message.is_valid() {
            warn!("Invalid IKEv2 message from {}", remote_addr);
            return Err("Invalid message received".into());
        }
        let session = self.get(&ikev2_message, remote_addr)?;
        session.process_message(&ikev2_message);
        Ok(())
    }
}

struct IKEv2Session {
    remote_addr: SocketAddr,
}

impl IKEv2Session {
    fn new(remote_addr: SocketAddr) -> IKEv2Session {
        IKEv2Session { remote_addr }
    }

    fn process_message(&mut self, message: &message::Message) {
        debug!("Received packet from {} {:?}", self.remote_addr, message);
        // TODO: process message if exchange type is supported
        // TODO: return error if payload type is critical but not recognized

        // Response retransmisisons are initiated by client.
    }
}

#[derive(Debug)]
pub enum IKEv2Error {
    Internal(&'static str),
    Format(message::FormatError),
    Join(tokio::task::JoinError),
    Io(io::Error),
}

impl fmt::Display for IKEv2Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            IKEv2Error::Internal(msg) => f.write_str(msg),
            IKEv2Error::Format(ref e) => write!(f, "Format error: {}", e),
            IKEv2Error::Join(ref e) => write!(f, "Tokio join error: {}", e),
            IKEv2Error::Io(ref e) => {
                write!(f, "IO error: {}", e)
            }
        }
    }
}

impl error::Error for IKEv2Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            IKEv2Error::Internal(_msg) => None,
            IKEv2Error::Format(ref err) => Some(err),
            IKEv2Error::Join(ref err) => Some(err),
            IKEv2Error::Io(ref err) => Some(err),
        }
    }
}

impl From<&'static str> for IKEv2Error {
    fn from(msg: &'static str) -> IKEv2Error {
        IKEv2Error::Internal(msg)
    }
}

impl From<message::FormatError> for IKEv2Error {
    fn from(err: message::FormatError) -> IKEv2Error {
        IKEv2Error::Format(err)
    }
}

impl From<tokio::task::JoinError> for IKEv2Error {
    fn from(err: tokio::task::JoinError) -> IKEv2Error {
        IKEv2Error::Join(err)
    }
}

impl From<io::Error> for IKEv2Error {
    fn from(err: io::Error) -> IKEv2Error {
        IKEv2Error::Io(err)
    }
}
