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

mod crypto;
mod message;

// TODO: for Windows, add IKEV2_FRAGMENTATION_SUPPORTED support. Otherwise, UDP fragmentation will be used to transmit larger packets.
const MAX_DATAGRAM_SIZE: usize = 4096;
const MAX_ENCRYPTED_DATA_SIZE: usize = 4096;

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
        // TODO: check source of Tokio's join! macro to listen on multiple addresses.
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

#[derive(Clone, Copy)]
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

        debug!("Received packet from {}\n{:?}", remote_addr, ikev2_request);

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
            debug!("Sending response to {}\n{:?}", remote_addr, responser_msg);
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
    params: Option<crypto::TransformParameters>,
    crypto_stack: Option<crypto::CryptoStack>,
}

impl IKEv2Session {
    fn new(remote_addr: SocketAddr) -> IKEv2Session {
        IKEv2Session {
            remote_addr,
            params: None,
            crypto_stack: None,
        }
    }

    fn process_message(
        &mut self,
        session_id: SessionID,
        addr: (SocketAddr, SocketAddr),
        request: &message::InputMessage,
        response: &mut message::MessageWriter,
    ) -> Result<usize, IKEv2Error> {
        // TODO: return error if payload type is critical but not recognized
        // TODO: keep track of message numbers and replies - only send response if message ID is up to date.
        // TODO: for all exchange types except IKE_SA_INIT check that the session already exists.

        let exchange_type = request.read_exchange_type()?;
        match exchange_type {
            message::ExchangeType::IKE_SA_INIT => {
                self.process_sa_init_message(session_id, addr, request, response)
            }
            message::ExchangeType::IKE_AUTH => {
                self.process_auth_message(session_id, addr, request, response)
            }
            message::ExchangeType::INFORMATIONAL => {
                self.process_informational_message(session_id, request, response)
            }
            _ => {
                debug!("Unimplemented handler for message {}", exchange_type);
                Err("Unimplemented message".into())
            }
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
            session_id.local_spi,
            message::ExchangeType::IKE_SA_INIT,
            false,
            request.read_message_id(),
        )?;

        let mut dh_transform = None;
        let mut shared_secret = None;
        for payload in request.iter_payloads() {
            let payload = if let Ok(payload) = payload {
                payload
            } else {
                // TODO: return INVALID_SYNTAX notification.
                continue;
            };
            // IKEv2 payloads need to be sent in a very specific order.
            // By the time the Nonce is reached, SA and KE should already be processed.
            match payload.payload_type() {
                message::PayloadType::SECURITY_ASSOCIATION => {
                    let sa = payload.to_security_association()?;
                    let (prop, proposal_num) =
                        if let Some(transform) = crypto::choose_sa_parameters(&sa) {
                            transform
                        } else {
                            debug!("No compatible SA parameters found");
                            // TODO: return INVALID_SYNTAX notification.
                            continue;
                        };
                    response.write_accept_proposal(proposal_num, &prop)?;
                    match prop.create_dh() {
                        Ok(dh) => dh_transform = Some(dh),
                        Err(err) => {
                            debug!("Failed to init DH {}", err)
                        }
                    }
                    self.params = Some(prop);
                }
                message::PayloadType::KEY_EXCHANGE => {
                    let kex = payload.to_key_exchange()?;
                    if let Some(dh) = dh_transform.as_ref() {
                        let public_key = dh.read_public_key();
                        shared_secret = match dh.compute_shared_secret(kex.read_value()) {
                            Ok(shared_secret) => Some(shared_secret),
                            Err(err) => {
                                // TODO: return INVALID_KE_PAYLOAD notification.
                                debug!("Failed to compute shared secret {}", err);
                                continue;
                            }
                        };
                        response
                            .write_key_exchange_payload(dh.group_number(), public_key.as_slice())?;
                    }
                }
                message::PayloadType::NONCE => {
                    let nonce = payload.to_nonce()?;
                    let nonce_remote = nonce.read_value();
                    // All keys are less than 256 bits.
                    let mut nonce_local = [0u8; 32];
                    rand::thread_rng().fill(nonce_local.as_mut_slice());
                    let mut prf_key = vec![0; nonce_remote.len() + nonce_local.len() + 8 + 8];
                    let mut prf_key_cursor = 0;
                    prf_key[prf_key_cursor..prf_key_cursor + nonce_remote.len()]
                        .copy_from_slice(nonce_remote);
                    prf_key_cursor += nonce_remote.len();
                    prf_key[prf_key_cursor..prf_key_cursor + nonce_local.len()]
                        .copy_from_slice(&nonce_local);
                    prf_key_cursor += nonce_local.len();
                    prf_key[prf_key_cursor..prf_key_cursor + 8]
                        .copy_from_slice(&session_id.remote_spi.to_be_bytes());
                    prf_key_cursor += 8;
                    prf_key[prf_key_cursor..prf_key_cursor + 8]
                        .copy_from_slice(&session_id.local_spi.to_be_bytes());

                    let params = if let Some(params) = self.params.as_ref() {
                        params
                    } else {
                        debug!("Unspecified transform parametes");
                        // TODO: return INVALID_SYNTAX notification.
                        continue;
                    };
                    let mut prf_transform = match params
                        .create_prf(&prf_key[0..nonce_remote.len() + nonce_local.len()])
                    {
                        Ok(prf) => prf,
                        Err(err) => {
                            debug!("Failed to init PRF transform for SKEYSEED {}", err);
                            // TODO: return INVALID_SYNTAX notification.
                            continue;
                        }
                    };
                    let shared_secret = if let Some(ref shared_secret) = shared_secret {
                        shared_secret
                    } else {
                        debug!("Unspecified shared secret");
                        // TODO: return INVALID_SYNTAX notification.
                        continue;
                    };
                    let skeyseed = prf_transform.prf(shared_secret.as_slice());
                    let mut prf_transform = match params.create_prf(skeyseed.as_slice()) {
                        Ok(prf) => prf,
                        Err(err) => {
                            debug!("Failed to init PRF transform for keying material {}", err);
                            // TODO: return INVALID_SYNTAX notification.
                            continue;
                        }
                    };
                    match prf_transform.create_crypto_stack(&params, &prf_key) {
                        Ok(crypto_stack) => self.crypto_stack = Some(crypto_stack),
                        Err(err) => {
                            debug!("Failed to set up cryptography stack {}", err);
                            // TODO: return INVALID_SYNTAX notification.
                            continue;
                        }
                    };
                    let dest = response
                        .next_payload_slice(message::PayloadType::NONCE, nonce_local.len())?;
                    dest.copy_from_slice(&nonce_local);
                }
                _ => {}
            }
        }

        /*
        response.write_notify_payload(
            None,
            &[],
            message::NotifyMessageType::IKEV2_FRAGMENTATION_SUPPORTED,
            &[],
        )?;

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
        */

        Ok(response.complete_message())
    }

    fn process_auth_message(
        &mut self,
        session_id: SessionID,
        addr: (SocketAddr, SocketAddr),
        request: &message::InputMessage,
        response: &mut message::MessageWriter,
    ) -> Result<usize, IKEv2Error> {
        let (_, remote_addr) = addr;

        response.write_header(
            session_id.remote_spi,
            session_id.local_spi,
            message::ExchangeType::IKE_AUTH,
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
            // IKEv2 payloads need to be sent in a very specific order.
            // By the time the Nonce is reached, SA and KE should already be processed.
            match payload.payload_type() {
                message::PayloadType::ENCRYPTED_AND_AUTHENTICATED => {
                    let encrypted_payload = payload.encrypted_data()?;
                    let encrypted_data = encrypted_payload.encrypted_data();
                    let mut decrypted_data = [0u8; MAX_ENCRYPTED_DATA_SIZE];
                    decrypted_data[..encrypted_data.len()].copy_from_slice(encrypted_data);
                    let crypto_stack = if let Some(crypto_stack) = self.crypto_stack.as_mut() {
                        crypto_stack
                    } else {
                        debug!("Crypto stack not initialized");
                        // TODO: return error notification.
                        continue;
                    };
                    let signature_length = {
                        // The RFC states that the signature should be extracted from the ENCRYPTED_AND_AUTHENTICATED
                        // packet, but it's supposed to be the last payload, and there should not be any unaccounted bytes.
                        // While this will fail if a packet is slightly malformed, it's probably for the best.
                        let validate_slice = request.raw_data();
                        let valid_signature = crypto_stack.validate_signature(validate_slice);
                        if !valid_signature {
                            debug!("Packet has invalid signature");
                            // TODO: return error notification or even ignore packet.
                            continue;
                        }
                        if let Some(params) = self.params.as_ref() {
                            params.auth_signature_length() / 8
                        } else {
                            debug!("Crypto parameters not initialized");
                            // TODO: return error notification.
                            continue;
                        }
                    };
                    let encrypted_data_len = encrypted_data.len();
                    let encrypted_data_len = if encrypted_data_len >= signature_length {
                        encrypted_data_len - signature_length
                    } else {
                        debug!("Signature is larger than encrypted data");
                        // TODO: return error notification.
                        continue;
                    };
                    let associated_data = {
                        let raw_data = request.raw_data();
                        &raw_data[..raw_data.len() - encrypted_data.len()]
                    };
                    let decrypted_slice = match crypto_stack.decrypt_data(
                        &mut decrypted_data,
                        encrypted_data_len,
                        associated_data,
                    ) {
                        Ok(decrypted_slice) => decrypted_slice,
                        Err(err) => {
                            debug!("Failed to decrypt data {}", err);
                            // TODO: return error notification.
                            continue;
                        }
                    };
                    for pl in encrypted_payload.iter_decrypted_message(decrypted_slice) {
                        match pl {
                            Ok(pl) => debug!("Decrypted payload\n {:?}", pl),
                            Err(err) => {
                                debug!("Failed to read decrypted payload data {}", err);
                                // TODO: return error notification.
                                continue;
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(response.complete_message())
    }

    fn process_informational_message(
        &mut self,
        session_id: SessionID,
        request: &message::InputMessage,
        response: &mut message::MessageWriter,
    ) -> Result<usize, IKEv2Error> {
        response.write_header(
            session_id.remote_spi,
            session_id.local_spi,
            message::ExchangeType::INFORMATIONAL,
            false,
            request.read_message_id(),
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
