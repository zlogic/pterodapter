use log::{debug, info, warn};
use rand::Rng;
use sha1::{Digest, Sha1};
use std::{
    collections::{self, HashMap},
    error, fmt,
    hash::{Hash, Hasher},
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{net::UdpSocket, signal, sync::mpsc, task::JoinHandle};

mod crypto;
mod message;

use crypto::DHTransform;

const IKEV2_PORT: u16 = 500;
const IKEV2_NAT_PORT: u16 = 4500;
const IKEV2_LISTEN_PORTS: [u16; 2] = [IKEV2_PORT, IKEV2_NAT_PORT];

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

    async fn listen_socket(
        socket: Arc<UdpSocket>,
        listen_addr: SocketAddr,
        dest: mpsc::Sender<SessionMessage>,
    ) -> Result<(), IKEv2Error> {
        loop {
            // Theoretically the allocator should be smart enough to recycle memory.
            // In the unlikely case this becomes a problem, switching to stack-allocated
            // arrays would reduce memory usage, but increase number of copy operations.
            // As mpsc uses a queue internally, memory will be allocated for the queue elements
            // in any case.
            let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
            let (bytes_res, remote_addr) = socket.recv_from(&mut buf).await?;
            buf.truncate(bytes_res);
            let msg = SessionMessage::UdpDatagram(UdpDatagram {
                remote_addr,
                local_addr: listen_addr,
                request: buf,
            });
            dest.send(msg)
                .await
                .map_err(|_| IKEv2Error::Internal("Channel closed"))?;
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
        let sockets = rt.block_on(Sockets::new(&self.listen_ips))?;
        let sessions = Sessions::new(sockets.clone());
        let mut handles = sockets
            .iter_sockets()
            .map(|(listen_addr, socket)| {
                rt.spawn(Server::listen_socket(
                    socket.clone(),
                    *listen_addr,
                    sessions.create_sender(),
                ))
            })
            .collect::<Vec<_>>();
        handles.push(rt.spawn(async move {
            let mut sessions = sessions;
            sessions.process_messages().await
        }));
        rt.block_on(Server::wait_termination(handles))?;
        rt.shutdown_timeout(Duration::from_secs(60));

        info!("Stopped server");
        Ok(())
    }
}

#[derive(Clone)]
struct Sockets {
    sockets: HashMap<SocketAddr, Arc<UdpSocket>>,
}

impl Sockets {
    async fn new(listen_ips: &[IpAddr]) -> Result<Sockets, IKEv2Error> {
        let mut sockets = HashMap::new();
        for listen_ip in listen_ips {
            for listen_port in IKEV2_LISTEN_PORTS {
                let socket = match UdpSocket::bind((*listen_ip, listen_port)).await {
                    Ok(socket) => socket,
                    Err(err) => {
                        log::error!("Failed to open listener on {}: {}", listen_ip, err);
                        return Err(err.into());
                    }
                };
                let listen_addr = socket.local_addr()?;
                info!("Started server on {}", listen_addr);
                sockets.insert(listen_addr, Arc::new(socket));
            }
        }
        Ok(Sockets { sockets })
    }

    fn iter_sockets(&self) -> collections::hash_map::Iter<SocketAddr, Arc<UdpSocket>> {
        self.sockets.iter()
    }

    async fn send_datagram(
        &self,
        send_from: &SocketAddr,
        send_to: &SocketAddr,
        data: &[u8],
    ) -> Result<(), IKEv2Error> {
        match self.sockets.get(&send_from) {
            Some(ref socket) => {
                socket.send_to(data, send_to).await?;
                Ok(())
            }
            None => {
                warn!(
                    "No open sockets for source address {} (destination {})",
                    send_from, send_to
                );
                Err("No open sockets for source address".into())
            }
        }
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
            // TODO: for retransmitted IKE_SA_INIT requests, keep a short-lived lookup cache with local SPI values.
            // Use checksum of original message (e.g. std::hash::DefaultHasher) as lookup key (or remote SPI + remote address).
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

struct UdpDatagram {
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    request: Vec<u8>,
}

impl UdpDatagram {
    fn is_non_esp(&self) -> bool {
        self.request.len() >= 4
            && self.request[0] == 0x00
            && self.request[1] == 0x00
            && self.request[2] == 0x00
            && self.request[3] == 0x00
    }

    fn is_ikev2(&self) -> bool {
        self.local_addr.port() == IKEV2_PORT || self.is_non_esp()
    }

    fn ikev2_data(&self) -> &[u8] {
        if self.local_addr.port() == IKEV2_PORT {
            // Regular IKEv2 message sent to port 500.
            self.request.as_slice()
        } else if self.is_non_esp() {
            // Shared IKEv2/ESP-in-UDP port, marked as an IKEv2 message.
            &self.request[4..]
        } else {
            // Shared IKEv2/ESP-in-UDP port, an ESP-in-UDP message.
            &[]
        }
    }
}

enum SessionMessage {
    UdpDatagram(UdpDatagram),
    // TODO: add more messages like a cleanup timer or message from bridge.
}

struct Sessions {
    sockets: Sockets,
    sessions: HashMap<SessionID, IKEv2Session>,
    tx: mpsc::Sender<SessionMessage>,
    rx: mpsc::Receiver<SessionMessage>,
}

impl Sessions {
    fn new(sockets: Sockets) -> Sessions {
        let (tx, rx) = mpsc::channel(100);
        Sessions {
            sockets,
            sessions: HashMap::new(),
            tx,
            rx,
        }
    }

    fn create_sender(&self) -> mpsc::Sender<SessionMessage> {
        self.tx.clone()
    }

    fn get_or_create(&mut self, id: SessionID, remote_addr: SocketAddr) -> &mut IKEv2Session {
        self.sessions
            .entry(id)
            .or_insert_with(|| IKEv2Session::new(remote_addr))
    }

    fn get(&mut self, id: SessionID) -> Option<&mut IKEv2Session> {
        self.sessions.get_mut(&id)
    }

    async fn process_messages(&mut self) -> Result<(), IKEv2Error> {
        while let Some(message) = self.rx.recv().await {
            match message {
                SessionMessage::UdpDatagram(mut datagram) => {
                    if let Err(err) = self.process_message(&mut datagram).await {
                        warn!(
                            "Failed to process message from {}: {}",
                            datagram.remote_addr, err
                        );
                    }
                }
            }
        }
        Ok(())
    }

    async fn process_message(&mut self, datagram: &mut UdpDatagram) -> Result<(), IKEv2Error> {
        if !datagram.is_ikev2() {
            debug!(
                "Received ESP packet from {}\n{:?}",
                datagram.remote_addr, datagram.request
            );
            return Ok(());
        }
        let request_bytes = datagram.ikev2_data();
        let ikev2_request = message::InputMessage::from_datagram(request_bytes)?;
        if !ikev2_request.is_valid() {
            return Err("Invalid message received".into());
        }

        debug!(
            "Received packet from {}\n{:?}",
            datagram.remote_addr, ikev2_request
        );

        let session_id = SessionID::from_message(&ikev2_request)?;
        let session = if ikev2_request.read_exchange_type()? == message::ExchangeType::IKE_SA_INIT {
            self.get_or_create(session_id.clone(), datagram.remote_addr)
        } else if let Some(session) = self.get(session_id.clone()) {
            session
        } else {
            return Err("Session not found".into());
        };
        let mut response_bytes = [0u8; MAX_DATAGRAM_SIZE];
        let start_offset = if datagram.is_non_esp() { 4 } else { 0 };
        let mut ikev2_response = message::MessageWriter::new(&mut response_bytes[start_offset..])?;

        let response_len = session.process_message(
            session_id,
            datagram.remote_addr,
            &ikev2_request,
            &mut ikev2_response,
        )?;

        let response_bytes = &response_bytes[..response_len + start_offset];

        {
            // TODO: remove this debug code
            let responser_msg =
                message::InputMessage::from_datagram(&response_bytes[start_offset..])?;
            debug!(
                "Sending response to {}\n{:?}",
                datagram.remote_addr, responser_msg
            );
        }
        // Response retransmisisons are initiated by client.
        if !response_bytes.is_empty() {
            self.sockets
                .send_datagram(&datagram.local_addr, &datagram.remote_addr, response_bytes)
                .await?;
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
        remote_addr: SocketAddr,
        request: &message::InputMessage,
        response: &mut message::MessageWriter,
    ) -> Result<usize, IKEv2Error> {
        // TODO: return error if payload type is critical but not recognized
        // TODO: keep track of message numbers and replies - only send response if message ID is up to date.
        // TODO: for all exchange types except IKE_SA_INIT check that the session already exists.

        let exchange_type = request.read_exchange_type()?;

        response.write_header(
            session_id.remote_spi,
            session_id.local_spi,
            exchange_type.clone(),
            false,
            request.read_message_id(),
        )?;

        match exchange_type {
            message::ExchangeType::IKE_SA_INIT => {
                self.process_sa_init_message(session_id, remote_addr, request, response)
            }
            message::ExchangeType::IKE_AUTH => {
                self.process_auth_message(session_id, request, response)
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

    fn process_encrypted_payload<'a>(
        &mut self,
        request: &message::InputMessage,
        encrypted_payload: &message::EncryptedMessage,
        decrypted_data: &'a mut [u8],
    ) -> Result<&'a [u8], IKEv2Error> {
        let encrypted_data = encrypted_payload.encrypted_data();
        decrypted_data[..encrypted_data.len()].copy_from_slice(encrypted_data);
        let crypto_stack = if let Some(crypto_stack) = self.crypto_stack.as_mut() {
            crypto_stack
        } else {
            return Err("Crypto stack not initialized".into());
        };
        let signature_length = if let Some(params) = self.params.as_ref() {
            params.auth_signature_length().map(|len| len / 8)
        } else {
            return Err("Crypto parameters not initialized".into());
        };
        let validate_slice = request.signature_data(&encrypted_payload, signature_length.is_some());
        let valid_signature = crypto_stack.validate_signature(validate_slice);
        if !valid_signature {
            return Err("Packet has invalid signature".into());
        }
        let associated_data = if signature_length.is_none() {
            validate_slice
        } else {
            &[]
        };
        let encrypted_data_len = if let Some(signature_length) = signature_length {
            encrypted_data.len().saturating_sub(signature_length)
        } else {
            encrypted_data.len()
        };
        match crypto_stack.decrypt_data(decrypted_data, encrypted_data_len, associated_data) {
            Ok(decrypted_slice) => Ok(decrypted_slice),
            Err(err) => {
                debug!("Failed to decrypt data {}", err);
                Err("Failed to decrypt data {}".into())
            }
        }
    }

    fn complete_encrypted_payload(
        &mut self,
        response: &mut message::MessageWriter,
    ) -> Result<usize, IKEv2Error> {
        let crypto_stack = if let Some(crypto_stack) = self.crypto_stack.as_mut() {
            crypto_stack
        } else {
            return Err("Crypto stack not initialized".into());
        };
        let add_signature = if let Some(params) = self.params.as_ref() {
            params.auth_signature_length().is_some()
        } else {
            return Err("Crypto parameters not initialized".into());
        };

        let encrypted_data_len = if let Some(len) = response.encrypted_data_length() {
            len
        } else {
            return Err("Encrypted payload is not started".into());
        };
        let full_encrypted_length = crypto_stack.encrypted_payload_length(encrypted_data_len);
        response.set_encrypted_payload_length(full_encrypted_length);
        let full_message_len = response.complete_message();

        let raw_data = response.raw_data_mut();
        {
            let (associated_data, encrypt_data) =
                raw_data.split_at_mut(full_message_len - full_encrypted_length);
            let associated_data = if !add_signature {
                associated_data.as_ref()
            } else {
                &[]
            };

            crypto_stack
                .encrypt_data(encrypt_data, encrypted_data_len, associated_data)
                .map_err(|err| {
                    // TODO: return error notification.
                    debug!("Failed to encrypt data {}", err);
                    "Failed to encrypt data"
                })?;
        }

        crypto_stack
            .sign(&mut raw_data[..full_message_len])
            .map_err(|err| {
                debug!("Failed to sign data {}", err);
                "Failed to sign data"
            })?;

        Ok(full_message_len)
    }

    fn process_sa_init_message(
        &mut self,
        session_id: SessionID,
        remote_addr: SocketAddr,
        request: &message::InputMessage,
        response: &mut message::MessageWriter,
    ) -> Result<usize, IKEv2Error> {
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

        // Simulate that the host is behind a NAT - same as StrongSwan's encap=yes does it.
        let local_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), IKEV2_PORT);
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

    fn process_auth_message(
        &mut self,
        session_id: SessionID,
        request: &message::InputMessage,
        response: &mut message::MessageWriter,
    ) -> Result<usize, IKEv2Error> {
        let mut decrypted_request = [0u8; MAX_ENCRYPTED_DATA_SIZE];
        let mut decrypted_iter = None;

        for payload in request.iter_payloads() {
            let payload = if let Ok(payload) = payload {
                payload
            } else {
                // TODO: return INVALID_SYNTAX notification.
                continue;
            };
            match payload.payload_type() {
                message::PayloadType::ENCRYPTED_AND_AUTHENTICATED => {
                    let encrypted_payload = payload.encrypted_data()?;
                    // TODO: return AUTHENTICATION_FAILED notification on error.
                    let decrypted_slice = self.process_encrypted_payload(
                        request,
                        &encrypted_payload,
                        &mut decrypted_request,
                    )?;
                    decrypted_iter =
                        Some(encrypted_payload.iter_decrypted_message(decrypted_slice));
                }
                _ => {}
            }
        }

        let decrypted_iter = if let Some(decrypted_iter) = decrypted_iter {
            decrypted_iter
        } else {
            // TODO: return AUTHENTICATION_FAILED notification.
            // AUTH payload is supposed to have an encrypted payload.
            return Ok(response.complete_message());
        };
        for pl in decrypted_iter {
            let pl = match pl {
                Ok(pl) => pl,
                Err(err) => {
                    debug!("Failed to read decrypted payload data {}", err);
                    // TODO: return error notification.
                    continue;
                }
            };
            debug!("Decrypted payload\n {:?}", pl);
        }

        response.start_encrypted_payload()?;

        // Just for test
        response.write_notify_payload(
            None,
            &[],
            message::NotifyMessageType::AUTHENTICATION_FAILED,
            &[],
        )?;

        self.complete_encrypted_payload(response)
    }

    fn process_informational_message(
        &mut self,
        session_id: SessionID,
        request: &message::InputMessage,
        response: &mut message::MessageWriter,
    ) -> Result<usize, IKEv2Error> {
        let mut decrypted_data = [0u8; MAX_ENCRYPTED_DATA_SIZE];
        let mut decrypted_iter = None;

        for payload in request.iter_payloads() {
            let payload = if let Ok(payload) = payload {
                payload
            } else {
                // TODO: return INVALID_SYNTAX notification.
                continue;
            };
            match payload.payload_type() {
                message::PayloadType::ENCRYPTED_AND_AUTHENTICATED => {
                    let encrypted_payload = payload.encrypted_data()?;
                    let decrypted_slice = self.process_encrypted_payload(
                        request,
                        &encrypted_payload,
                        &mut decrypted_data,
                    )?;
                    decrypted_iter =
                        Some(encrypted_payload.iter_decrypted_message(decrypted_slice));
                }
                _ => {}
            }
        }

        let decrypted_iter = if let Some(decrypted_iter) = decrypted_iter {
            decrypted_iter
        } else {
            // TODO: return INVALID_SYNTAX notification.
            // AUTH payload is supposed to have an encrypted payload.
            return Ok(response.complete_message());
        };
        for pl in decrypted_iter {
            match pl {
                Ok(pl) => debug!("Decrypted payload\n {:?}", pl),
                Err(err) => {
                    debug!("Failed to read decrypted payload data {}", err);
                    // TODO: return error notification.
                    continue;
                }
            }
        }

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
