use log::{debug, info, warn};
use rand::Rng;
use sha1::{Digest, Sha1};
use std::{
    collections::HashMap,
    error, fmt,
    hash::{Hash, Hasher},
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
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
            let addr = (listen_addr, remote_addr);
            sessions
                .process_message(datagram_bytes, &socket, addr)
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
        addr: (SocketAddr, SocketAddr),
    ) -> Result<(), IKEv2Error> {
        let ikev2_request = message::InputMessage::from_datagram(datagram_bytes)?;
        let (_, remote_addr) = addr;
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
            session.process_message(session_id, addr, &ikev2_request, &mut ikev2_response)?;
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
        addr: (SocketAddr, SocketAddr),
        request: &message::InputMessage,
        response: &mut message::MessageWriter,
    ) -> Result<usize, IKEv2Error> {
        // TODO: process message if exchange type is supported
        // TODO: return error if payload type is critical but not recognized

        if request.read_exchange_type()? == message::ExchangeType::IKE_SA_INIT {
            self.process_sa_init_message(session_id, addr, request, response)
        } else {
            Ok(0)
        }
    }

    fn process_sa_init_message(
        &mut self,
        session_id: SessionID,
        addr: (SocketAddr, SocketAddr),
        request: &message::InputMessage,
        response: &mut message::MessageWriter,
    ) -> Result<usize, IKEv2Error> {
        let (_, remote_addr) = addr;

        response.write_header(
            session_id.remote_spi,
            0,
            message::ExchangeType::IKE_SA_INIT,
            false,
            request.read_message_id(),
        )?;

        for payload in request.iter_payloads() {
            let payload = if let Ok(payload) = payload {
                payload
            } else {
                // TODO: return INVALID_SYNTAX notification.
                continue;
            };
            if payload.payload_type() == message::PayloadType::SECURITY_ASSOCIATION {
                let sa = payload.to_security_association()?;
                choose_sa_parameters(&sa, response)?;
            }
        }

        // Simulate that the host is behind a NAT - same as StrongSwan's encap=yes does it.
        let local_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 500);
        let nat_ip = nat_detection_ip(
            request.read_initiator_spi(),
            request.read_responder_spi(),
            local_addr.ip(),
            local_addr.port(),
        );
        response.write_notify_payload(
            None,
            &[],
            message::NotifyMessageType::NAT_DETECTION_SOURCE_IP,
            &nat_ip,
        )?;
        let nat_ip = nat_detection_ip(
            request.read_initiator_spi(),
            request.read_responder_spi(),
            remote_addr.ip(),
            remote_addr.port(),
        );
        response.write_notify_payload(
            None,
            &[],
            message::NotifyMessageType::NAT_DETECTION_DESTINATION_IP,
            &nat_ip,
        )?;

        Ok(response.complete_message())
    }
}

fn nat_detection_ip(initiator_spi: u64, responder_spi: u64, addr: IpAddr, port: u16) -> [u8; 20] {
    let mut src_data = [0u8; 8 + 8 + 16 + 2];
    src_data[0..8].copy_from_slice(&initiator_spi.to_be_bytes());
    src_data[8..16].copy_from_slice(&responder_spi.to_be_bytes());
    let addr_len = match addr {
        IpAddr::V4(addr) => {
            src_data[16..16 + 4].copy_from_slice(&addr.octets());
            4
        }
        IpAddr::V6(addr) => {
            src_data[16..16 + 16].copy_from_slice(&addr.octets());
            16
        }
    };
    src_data[16 + addr_len..16 + addr_len + 2].copy_from_slice(&port.to_be_bytes());
    let src_data = &src_data[..16 + addr_len + 2];

    let mut hasher = Sha1::new();
    hasher.update(src_data);
    hasher.finalize().into()
}

fn choose_sa_parameters<'a>(
    sa: &'a message::PayloadSecurityAssociation,
    response: &mut message::MessageWriter,
) -> Result<(), IKEv2Error> {
    for prop in sa.iter_proposals() {
        let prop = if let Ok(prop) = prop {
            prop
        } else {
            continue;
        };
        let mut enc: Option<message::TransformType> = None;
        let mut prf: Option<message::TransformType> = None;
        let mut auth: Option<message::TransformType> = None;
        let mut dh: Option<message::TransformType> = None;
        let mut esn: Option<message::TransformType> = None;

        let mut key_length: Option<u16> = None;

        let ok = prop.iter_transforms().all(|tt| {
            let tt = if let Ok(tt) = tt {
                tt
            } else {
                return true;
            };
            let tt_type = tt.transform_type();
            match tt_type {
                message::TransformType::Encryption(_) => {
                    if enc.is_some() {
                        return false;
                    }
                    enc = Some(tt_type);
                }
                message::TransformType::PseudorandomFunction(_) => {
                    if prf.is_some() {
                        return false;
                    }
                    prf = Some(tt_type);
                }
                message::TransformType::IntegrityAlgorithm(_) => {
                    if auth.is_some() {
                        return false;
                    }
                    auth = Some(tt_type);
                }
                message::TransformType::DiffieHellman(_) => {
                    if dh.is_some() {
                        return false;
                    }
                    dh = Some(tt_type);
                }
                message::TransformType::ExtendedSequenceNumbers(_) => {
                    if esn.is_some() {
                        return false;
                    }
                    esn = Some(tt_type);
                }
            }
            // TODO: attach key length to attribute.
            tt.iter_attributes().all(|attr| {
                let attr = if let Ok(attr) = attr {
                    attr
                } else {
                    return false;
                };
                if attr.attribute_type() != message::TransformAttributeType::KEY_LENGTH {
                    return false;
                }
                if key_length.is_some() {
                    return false;
                }
                let value = attr.value();
                if value.len() != 2 {
                    return false;
                }
                let mut key_length_value = [0u8; 2];
                key_length_value.copy_from_slice(value);
                key_length = Some(u16::from_be_bytes(key_length_value));
                true
            });
            true
        });
        if !ok {
            // TODO: if multiple values are proposed, choose only one of them.
            continue;
        }

        // TODO: support more combinations.
        if enc == Some(message::TransformType::ENCR_AES_CBC)
            && prf == Some(message::TransformType::PRF_HMAC_SHA2_256)
            && auth == Some(message::TransformType::AUTH_HMAC_SHA2_256_128)
            && dh == Some(message::TransformType::DH_1024_MODP)
            && key_length == Some(128)
        {
            // Valid Windows configuration.
            // TODO: init encryption handlers.
            response.write_accept_proposal(&prop)?;
            return Ok(());
        }
        if enc == Some(message::TransformType::ENCR_AES_GCM_16)
            && prf == Some(message::TransformType::PRF_HMAC_SHA2_256)
            && auth.is_none()
            && dh == Some(message::TransformType::DH_256_ECP)
            && key_length == Some(256)
        {
            // Valid macOS configuration.
            // TODO: init encryption handlers.
            response.write_accept_proposal(&prop)?;
            return Ok(());
        }
    }
    // TODO: return an error response if no proposal is acceptable.
    Ok(())
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
