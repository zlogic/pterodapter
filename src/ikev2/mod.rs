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
        let listen_addr = socket.local_addr()?;
        info!("Started server on {}", listen_addr);
        let mut buf = [0u8; MAX_DATAGRAM_SIZE];
        // TODO: share sessions between all threads: either using an async mutex, or by forwarding all messages to the same mpsc channel.
        let mut sessions = Sessions::new();
        loop {
            let (bytes_res, remote_addr) = socket.recv_from(&mut buf).await?;
            let datagram_bytes = &mut buf[..bytes_res];
            sessions
                .process_message(datagram_bytes, &socket, remote_addr)
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

#[derive(Clone)]
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
    fn from_message(message: &message::InputMessage) -> Result<SessionID, message::FormatError> {
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
        id: SessionID,
        remote_addr: SocketAddr,
    ) -> Result<&mut IKEv2Session, message::FormatError> {
        Ok(self
            .sessions
            .entry(id)
            .or_insert_with(|| IKEv2Session::new(remote_addr)))
    }

    async fn process_message(
        &mut self,
        datagram_bytes: &[u8],
        local_socket: &UdpSocket,
        remote_addr: SocketAddr,
    ) -> Result<(), IKEv2Error> {
        let ikev2_request = message::InputMessage::from_datagram(datagram_bytes)?;
        if !ikev2_request.is_valid() {
            warn!("Invalid IKEv2 message from {}", remote_addr);
            return Err("Invalid message received".into());
        }

        debug!("Received packet from {} {:?}", remote_addr, ikev2_request);

        let session_id = SessionID::from_message(&ikev2_request)?;
        let session = self.get(session_id.clone(), remote_addr)?;
        let mut response_bytes = [0u8; MAX_DATAGRAM_SIZE];
        let mut ikev2_response = message::MessageWriter::new(response_bytes.as_mut_slice())?;

        let response_len =
            session.process_message(session_id, &ikev2_request, &mut ikev2_response)?;
        let response_bytes = &response_bytes[..response_len];

        {
            // TODO: remove this debug code
            let responser_msg = message::InputMessage::from_datagram(response_bytes)?;
            debug!("Sending response {:?} to {}", responser_msg, remote_addr);
        }
        // Response retransmisisons are initiated by client.
        if !response_bytes.is_empty() {
            local_socket.send_to(response_bytes, remote_addr).await?;
        }

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

    fn process_message(
        &mut self,
        session_id: SessionID,
        request: &message::InputMessage,
        response: &mut message::MessageWriter,
    ) -> Result<usize, IKEv2Error> {
        // TODO: process message if exchange type is supported
        // TODO: return error if payload type is critical but not recognized

        if request.read_exchange_type()? == message::ExchangeType::IKE_SA_INIT {
            response.write_header(
                session_id.remote_spi,
                0,
                message::ExchangeType::IKE_SA_INIT,
                false,
                request.read_message_id(),
            )?;

            Ok(response.complete_message())
        } else {
            Ok(0)
        }
    }
}

#[derive(Debug)]
pub enum IKEv2Error {
    Internal(&'static str),
    Format(message::FormatError),
    NotEnoughSpace(message::NotEnoughSpaceError),
    Join(tokio::task::JoinError),
    Io(io::Error),
}

impl fmt::Display for IKEv2Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            IKEv2Error::Internal(msg) => f.write_str(msg),
            IKEv2Error::Format(ref e) => write!(f, "Format error: {}", e),
            IKEv2Error::NotEnoughSpace(_) => write!(f, "Not enough space error"),
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
            IKEv2Error::NotEnoughSpace(ref err) => Some(err),
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

impl From<message::NotEnoughSpaceError> for IKEv2Error {
    fn from(err: message::NotEnoughSpaceError) -> IKEv2Error {
        IKEv2Error::NotEnoughSpace(err)
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
