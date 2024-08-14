use log::{debug, info, warn};
use rand::Rng;
use std::{
    collections::{self, HashMap},
    error, fmt,
    hash::{Hash, Hasher},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, signal, sync::mpsc, task::JoinHandle};

mod crypto;
mod message;
mod pki;

use crypto::DHTransform;

const IKEV2_PORT: u16 = 500;
const IKEV2_NAT_PORT: u16 = 4500;
const IKEV2_LISTEN_PORTS: [u16; 2] = [IKEV2_PORT, IKEV2_NAT_PORT];

// TODO: for Windows, add IKEV2_FRAGMENTATION_SUPPORTED support. Otherwise, UDP fragmentation will be used to transmit larger packets.
const MAX_DATAGRAM_SIZE: usize = 4096;
const MAX_ENCRYPTED_DATA_SIZE: usize = 4096;
// All keys are less than 256 bits, but mathching the client nonce size is a good idea.
const MAX_NONCE: usize = 384 / 8;

const IKE_INIT_SA_EXPIRATION: Duration = Duration::from_secs(15);
const IKE_SESSION_EXPIRATION: Duration = Duration::from_secs(60 * 15);
const IKE_RESPONSE_EXPIRATION: Duration = Duration::from_secs(60);

pub struct Config {
    pub listen_ips: Vec<IpAddr>,
    pub hostname: Option<String>,
    pub root_ca: Option<String>,
    pub server_cert: Option<(String, String)>,
}

pub struct Server {
    listen_ips: Vec<IpAddr>,
    pki_processing: Arc<pki::PkiProcessing>,
}

impl Server {
    pub fn new(config: Config) -> Result<Server, IKEv2Error> {
        let pki_processing = pki::PkiProcessing::new(
            config.hostname.as_deref(),
            config.root_ca.as_deref(),
            config
                .server_cert
                .as_ref()
                .map(|(public_cert, private_key)| (public_cert.as_str(), private_key.as_str())),
        )?;
        Ok(Server {
            listen_ips: config.listen_ips,
            pki_processing: Arc::new(pki_processing),
        })
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

    async fn send_timer_ticks(
        duration: Duration,
        dest: mpsc::Sender<SessionMessage>,
    ) -> Result<(), IKEv2Error> {
        let mut interval = tokio::time::interval(duration);
        loop {
            interval.tick().await;
            dest.send(SessionMessage::CleanupTimer)
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
            .enable_time()
            .build()?;
        let sockets = rt.block_on(Sockets::new(&self.listen_ips))?;
        let sessions = Sessions::new(self.pki_processing.clone(), sockets.clone());
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
        handles.push(rt.spawn(Server::send_timer_ticks(
            Duration::from_secs(15),
            sessions.create_sender(),
        )));
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
        match self.sockets.get(send_from) {
            Some(socket) => {
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
        let remote_spi = message.read_initiator_spi();
        let local_spi = message.read_responder_spi();
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
    CleanupTimer,
}

struct Sessions {
    pki_processing: Arc<pki::PkiProcessing>,
    sockets: Sockets,
    sessions: HashMap<SessionID, IKEv2Session>,
    half_sessions: HashMap<(SocketAddr, u64), (u64, Instant)>,
    tx: mpsc::Sender<SessionMessage>,
    rx: mpsc::Receiver<SessionMessage>,
}

impl Sessions {
    fn new(pki_processing: Arc<pki::PkiProcessing>, sockets: Sockets) -> Sessions {
        let (tx, rx) = mpsc::channel(100);
        Sessions {
            pki_processing,
            sockets,
            sessions: HashMap::new(),
            half_sessions: HashMap::new(),
            tx,
            rx,
        }
    }

    fn create_sender(&self) -> mpsc::Sender<SessionMessage> {
        self.tx.clone()
    }

    fn get_init_session(&mut self, remote_spi: u64, remote_addr: SocketAddr) -> SessionID {
        let now = Instant::now();
        let half_key = (remote_addr, remote_spi);
        let new_session_id = (rand::thread_rng().gen::<u64>(), now);
        let existing_half_session = self
            .half_sessions
            .entry(half_key)
            .and_modify(|existing| {
                if existing.1 + IKE_SESSION_EXPIRATION < now {
                    // Already expired, should switch to new generated session ID.
                    *existing = new_session_id
                }
            })
            .or_insert_with(|| new_session_id);
        let session_id = SessionID {
            remote_spi,
            local_spi: existing_half_session.0,
        };
        // TODO: get address from FortiVPN, or through a custom config variable.
        let internal_addr = IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10));
        self.sessions.entry(session_id).or_insert_with(|| {
            IKEv2Session::new(remote_addr, internal_addr, self.pki_processing.clone())
        });
        session_id
    }

    fn get(&mut self, id: SessionID) -> Option<&mut IKEv2Session> {
        self.sessions.get_mut(&id)
    }

    fn cleanup(&mut self) {
        let now = Instant::now();
        self.half_sessions
            .retain(|(remote_addr, remote_spi), (_, expires_at)| {
                if *expires_at + IKE_INIT_SA_EXPIRATION < now {
                    debug!(
                        "Deleting expired init session {} (SPI {:x})",
                        remote_addr, remote_spi
                    );
                    false
                } else {
                    true
                }
            });
        self.sessions.retain(|session_id, session| {
            if session.last_update + IKE_SESSION_EXPIRATION < now {
                debug!(
                    "Deleting expired session with SPI {:x}-{:x} {:?}",
                    session_id.remote_spi, session_id.local_spi, session.user_id
                );
                false
            } else {
                true
            }
        });
        self.sessions.values_mut().for_each(|session| {
            if session.last_update + IKE_RESPONSE_EXPIRATION < now {
                session.last_response = None;
            }
        });
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
                SessionMessage::CleanupTimer => {
                    self.cleanup();
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

        let session_id = if ikev2_request.read_exchange_type()?
            == message::ExchangeType::IKE_SA_INIT
            && ikev2_request.read_message_id() == 0
        {
            self.get_init_session(ikev2_request.read_initiator_spi(), datagram.remote_addr)
        } else {
            SessionID::from_message(&ikev2_request)?
        };
        let session = if let Some(session) = self.get(session_id) {
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
        // Response retransmissions are initiated by client.
        if !response_bytes.is_empty() {
            self.sockets
                .send_datagram(&datagram.local_addr, &datagram.remote_addr, response_bytes)
                .await?;
        }

        Ok(())
    }
}

#[derive(Clone)]
struct InitSAContext {
    message_initiator: Vec<u8>,
    message_responder: Vec<u8>,
    nonce_initiator: Vec<u8>,
    nonce_responder: Vec<u8>,
}

enum SessionState {
    Empty,
    InitSA(InitSAContext),
    Established,
}

struct IKEv2Session {
    remote_addr: SocketAddr,
    state: SessionState,
    internal_addr: IpAddr,
    pki_processing: Arc<pki::PkiProcessing>,
    params: Option<crypto::TransformParameters>,
    crypto_stack: Option<crypto::CryptoStack>,
    user_id: Option<String>,
    last_update: Instant,
    last_message_id: u32,
    last_response: Option<([u8; MAX_DATAGRAM_SIZE], usize)>,
}

impl IKEv2Session {
    fn new(
        remote_addr: SocketAddr,
        internal_addr: IpAddr,
        pki_processing: Arc<pki::PkiProcessing>,
    ) -> IKEv2Session {
        IKEv2Session {
            remote_addr,
            state: SessionState::Empty,
            internal_addr,
            pki_processing,
            params: None,
            crypto_stack: None,
            user_id: None,
            last_update: Instant::now(),
            last_message_id: 0,
            last_response: None,
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

        self.last_update = Instant::now();
        let message_id = request.read_message_id();
        if message_id < self.last_message_id {
            // This is an outdated retransmission, nothing to do.
            return Ok(0);
        }
        if message_id == self.last_message_id {
            // Retransmit last response if available.
            if let Some(last_response) = self.last_response {
                let len = last_response.1;
                response.raw_data_mut()[..len].copy_from_slice(&last_response.0[..len]);
                return Ok(len);
            }
        }

        let exchange_type = request.read_exchange_type()?;

        response.write_header(
            session_id.remote_spi,
            session_id.local_spi,
            exchange_type,
            false,
            request.read_message_id(),
        )?;

        let response_length = match exchange_type {
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
        }?;

        if let Some(mut last_response) = self.last_response {
            last_response.0[..response_length]
                .copy_from_slice(&response.raw_data()[..response_length]);
            last_response.1 = response_length;
        } else {
            let mut last_response = ([0u8; MAX_DATAGRAM_SIZE], response_length);
            last_response.0[..response_length]
                .copy_from_slice(&response.raw_data()[..response_length]);
            self.last_response = Some(last_response);
        };
        self.last_message_id = message_id;

        Ok(response_length)
    }

    fn process_encrypted_payload<'a>(
        &self,
        request: &message::InputMessage,
        encrypted_payload: &message::EncryptedMessage,
        decrypted_data: &'a mut [u8],
    ) -> Result<&'a [u8], IKEv2Error> {
        let encrypted_data = encrypted_payload.encrypted_data();
        decrypted_data[..encrypted_data.len()].copy_from_slice(encrypted_data);
        let crypto_stack = if let Some(crypto_stack) = self.crypto_stack.as_ref() {
            crypto_stack
        } else {
            return Err("Crypto stack not initialized".into());
        };
        let signature_length = if let Some(params) = self.params.as_ref() {
            params.auth_signature_length().map(|len| len / 8)
        } else {
            return Err("Crypto parameters not initialized".into());
        };
        let validate_slice = request.signature_data(encrypted_payload, signature_length.is_some());
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
        &self,
        response: &mut message::MessageWriter,
    ) -> Result<usize, IKEv2Error> {
        let crypto_stack = if let Some(crypto_stack) = &self.crypto_stack {
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
                associated_data
            } else {
                &mut [0u8; 0]
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
        let mut nonce_responder = None;
        let mut nonce_initiator = None;
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
                            // TODO: return NO_PROPOSAL_CHOSEN notification.
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
                    nonce_initiator = {
                        let mut nonce_initiator = vec![0; nonce_remote.len()];
                        nonce_initiator.copy_from_slice(nonce_remote);
                        Some(nonce_initiator)
                    };
                    let mut nonce_local = [0u8; MAX_NONCE];
                    let nonce_local = &mut nonce_local[..nonce_remote.len()];
                    rand::thread_rng().fill(nonce_local);
                    nonce_responder = {
                        let mut nonce_responder = vec![0; nonce_local.len()];
                        nonce_responder.copy_from_slice(nonce_local);
                        Some(nonce_responder)
                    };
                    let mut prf_key = vec![0; nonce_remote.len() + nonce_local.len() + 8 + 8];
                    let mut prf_key_cursor = 0;
                    prf_key[prf_key_cursor..prf_key_cursor + nonce_remote.len()]
                        .copy_from_slice(nonce_remote);
                    prf_key_cursor += nonce_remote.len();
                    prf_key[prf_key_cursor..prf_key_cursor + nonce_local.len()]
                        .copy_from_slice(nonce_local);
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
                    let prf_transform = match params
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
                    let prf_transform = match params.create_prf(skeyseed.as_slice()) {
                        Ok(prf) => prf,
                        Err(err) => {
                            debug!("Failed to init PRF transform for keying material {}", err);
                            // TODO: return INVALID_SYNTAX notification.
                            continue;
                        }
                    };
                    match prf_transform.create_crypto_stack(params, &prf_key) {
                        Ok(crypto_stack) => self.crypto_stack = Some(crypto_stack),
                        Err(err) => {
                            debug!("Failed to set up cryptography stack {}", err);
                            // TODO: return INVALID_SYNTAX notification.
                            continue;
                        }
                    };
                    let dest = response
                        .next_payload_slice(message::PayloadType::NONCE, nonce_local.len())?;
                    dest.copy_from_slice(nonce_local);
                }
                _ => {}
            }
        }

        if let Some(root_ca) = self.pki_processing.root_ca_request() {
            response.write_certificate_request_payload(
                message::CertificateEncoding::X509_SIGNATURE,
                root_ca,
            )?;
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

        let nonce_initiator = if let Some(nonce) = nonce_initiator {
            nonce
        } else {
            // TODO: return INVALID_SYNTAX notification.
            return Err("Initiator didn't provide nonce".into());
        };
        let nonce_responder = if let Some(nonce) = nonce_responder {
            nonce
        } else {
            // TODO: return INVALID_SYNTAX notification.
            return Err("No nonce provided in response".into());
        };

        let response_length = response.complete_message();
        let response_data = &response.raw_data()[..response_length];
        let mut message_responder = vec![0; response_data.len()];
        message_responder.copy_from_slice(response_data);

        let initiator_data = request.raw_data();
        let mut message_initiator = vec![0; initiator_data.len()];
        message_initiator.copy_from_slice(initiator_data);
        self.state = SessionState::InitSA(InitSAContext {
            message_initiator,
            message_responder,
            nonce_initiator,
            nonce_responder,
        });

        Ok(response_length)
    }

    fn process_auth_message(
        &mut self,
        session_id: SessionID,
        request: &message::InputMessage,
        response: &mut message::MessageWriter,
    ) -> Result<usize, IKEv2Error> {
        let ctx = match self.state {
            SessionState::InitSA(ref ctx) => ctx.clone(),
            _ => {
                return self
                    .process_auth_failed_response(response, "Session is not in init state".into());
            }
        };
        let crypto_stack = if let Some(crypto_stack) = self.crypto_stack.as_ref() {
            crypto_stack
        } else {
            return Err("Crypto stack not initialized".into());
        };
        let prf_key_len = if let Some(params) = self.params.as_ref() {
            params.prf_key_length() / 8
        } else {
            return Err("Crypto parameters not initialized".into());
        };
        let mut decrypted_request = [0u8; MAX_ENCRYPTED_DATA_SIZE];
        let mut decrypted_iter = None;

        for payload in request.iter_payloads() {
            let payload = if let Ok(payload) = payload {
                payload
            } else {
                // TODO: return INVALID_SYNTAX notification.
                continue;
            };
            if payload.payload_type() == message::PayloadType::ENCRYPTED_AND_AUTHENTICATED {
                let encrypted_payload = payload.encrypted_data()?;
                // TODO: return AUTHENTICATION_FAILED notification on error.
                let decrypted_slice = self.process_encrypted_payload(
                    request,
                    &encrypted_payload,
                    &mut decrypted_request,
                )?;
                decrypted_iter = Some(encrypted_payload.iter_decrypted_message(decrypted_slice));
            }
        }

        let decrypted_iter = if let Some(decrypted_iter) = decrypted_iter {
            decrypted_iter
        } else {
            // TODO: return AUTHENTICATION_FAILED notification.
            // AUTH payload is supposed to have an encrypted payload.
            return Ok(response.complete_message());
        };

        let mut client_cert = None;
        let mut client_auth = None;
        let mut server_cert = self.pki_processing.default_server_cert();
        let mut id_initiator = None;
        let mut transform_params = None;
        let mut ts_remote = vec![];
        let mut ts_local = vec![];
        let mut ipv4_address_requested = false;

        for payload in decrypted_iter {
            let payload = match payload {
                Ok(payload) => payload,
                Err(err) => {
                    debug!("Failed to read decrypted payload data {}", err);
                    // TODO: return error notification.
                    continue;
                }
            };
            debug!("Decrypted payload\n {:?}", payload);
            match payload.payload_type() {
                message::PayloadType::CERTIFICATE => {
                    let certificate = payload.to_certificate()?;
                    if certificate.encoding() != message::CertificateEncoding::X509_SIGNATURE {
                        debug!(
                            "Certificate encoding {} is unsupported",
                            certificate.encoding()
                        );
                        return self.process_auth_failed_response(
                            response,
                            "Certificate encoding is unsupported".into(),
                        );
                    }
                    match self
                        .pki_processing
                        .verify_client_cert(certificate.read_value())
                    {
                        Ok(cert) => client_cert = Some(cert),
                        Err(err) => {
                            debug!("Certificate is not valid: {}", err);
                        }
                    };
                }
                message::PayloadType::CERTIFICATE_REQUEST => {
                    let certreq = payload.to_certificate_request()?;
                    if certreq.read_encoding() != message::CertificateEncoding::X509_SIGNATURE {
                        debug!(
                            "Certificate request encoding {} is unsupported",
                            certreq.read_encoding()
                        );
                        return self.process_auth_failed_response(
                            response,
                            "Certificate request encoding is unsupported".into(),
                        );
                    }
                    match self.pki_processing.server_cert(certreq.read_value()) {
                        Some(cert) => server_cert = Some(cert),
                        None => {
                            debug!("No certificates found for client's certificate request",);
                        }
                    };
                }
                message::PayloadType::ID_INITIATOR => {
                    let id = payload.to_identification()?;
                    id_initiator = Some(id.raw_value().to_vec());
                }
                message::PayloadType::AUTHENTICATION => {
                    let auth = payload.to_authentication()?;
                    if auth.read_method() != message::AuthMethod::RSA_DIGITAL_SIGNATURE {
                        debug!(
                            "Authentication method {} is unsupported",
                            auth.read_method()
                        );
                        return self.process_auth_failed_response(
                            response,
                            "Authentication method is unsupported".into(),
                        );
                    }
                    client_auth = Some(auth.read_value().to_vec());
                }
                message::PayloadType::SECURITY_ASSOCIATION => {
                    let sa = payload.to_security_association()?;
                    transform_params = crypto::choose_sa_parameters(&sa);
                    if transform_params.is_none() {
                        debug!("No compatible SA parameters found");
                        continue;
                    };
                }
                message::PayloadType::TRAFFIC_SELECTOR_INITIATOR => {
                    let ts = payload
                        .to_traffic_selector()?
                        .iter_traffic_selectors()
                        .collect::<Result<Vec<_>, message::FormatError>>()
                        .map_err(|err| {
                            debug!("Failed to decode initiator traffic selectors: {}", err);
                            err
                        });
                    if let Ok(ts) = ts {
                        ts_remote = ts
                    }
                }
                message::PayloadType::TRAFFIC_SELECTOR_RESPONDER => {
                    let ts = payload
                        .to_traffic_selector()?
                        .iter_traffic_selectors()
                        .collect::<Result<Vec<_>, message::FormatError>>()
                        .map_err(|err| {
                            debug!("Failed to decode responder traffic selectors: {}", err);
                            err
                        });
                    if let Ok(ts) = ts {
                        ts_local = ts
                    }
                }
                message::PayloadType::CONFIGURATION => {
                    ipv4_address_requested =
                        payload.to_configuration()?.iter_attributes().any(|attr| {
                            let attr = match attr {
                                Ok(attr) => attr,
                                Err(err) => {
                                    debug!("Failed to decode configuration attribute: {}", err);
                                    return false;
                                }
                            };
                            attr.attribute_type()
                                == message::ConfigurationAttributeType::INTERNAL_IP4_ADDRESS
                        })
                }
                _ => {}
            }
        }

        let client_cert = if let Some(cert) = client_cert {
            cert
        } else {
            return self.process_auth_failed_response(response, "Client provided no cert".into());
        };
        let client_auth = if let Some(auth) = client_auth {
            auth
        } else {
            return self.process_auth_failed_response(response, "Client provided no auth".into());
        };
        let id_initiator = if let Some(id) = id_initiator {
            id
        } else {
            return self.process_auth_failed_response(response, "Client provided no ID".into());
        };
        let (mut transform_params, proposal_num) = if let Some(params) = transform_params {
            params
        } else {
            // TODO: return NO_PROPOSAL_CHOSEN notification.
            return Err("Unacceptable Security Association proposals".into());
        };
        if ts_local.is_empty() || ts_remote.is_empty() {
            // TODO: return TS_UNACCEPTABLE notification.
            return Err("No traffic selectors offered by client".into());
        }

        let initiator_signed_len =
            ctx.message_initiator.len() + ctx.nonce_responder.len() + prf_key_len;
        let mut initiator_signed = [0u8; MAX_DATAGRAM_SIZE];
        initiator_signed[..ctx.message_initiator.len()].copy_from_slice(&ctx.message_initiator);
        initiator_signed
            [ctx.message_initiator.len()..ctx.message_initiator.len() + ctx.nonce_responder.len()]
            .copy_from_slice(&ctx.nonce_responder);
        crypto_stack.authenticate_id_initiator(
            &id_initiator,
            &mut initiator_signed
                [ctx.message_initiator.len() + ctx.nonce_responder.len()..initiator_signed_len],
        );
        if let Err(err) =
            client_cert.verify_signature(&initiator_signed[..initiator_signed_len], &client_auth)
        {
            debug!("Client authentication failed: {}", err);
            return Err("Client authentication failed".into());
        }

        // At this point the client identity has been successfully verified, proceed with sending a successful response.
        self.user_id = Some(client_cert.subject().into());
        self.state = SessionState::Established;
        response.start_encrypted_payload()?;

        if let Some(id_responder) = self.pki_processing.server_id() {
            let write_slice = response
                .next_payload_slice(message::PayloadType::ID_RESPONDER, id_responder.len())?;
            write_slice.copy_from_slice(id_responder);
        }

        if let Some(cert) = server_cert {
            response
                .write_certificate_payload(message::CertificateEncoding::X509_SIGNATURE, cert)?;
        }

        if let Some(id_responder) = self.pki_processing.server_id() {
            let responder_signed_len =
                ctx.message_responder.len() + ctx.nonce_initiator.len() + prf_key_len;
            let mut responder_signed = [0u8; MAX_DATAGRAM_SIZE];
            responder_signed[..ctx.message_responder.len()].copy_from_slice(&ctx.message_responder);
            responder_signed[ctx.message_responder.len()
                ..ctx.message_responder.len() + ctx.nonce_initiator.len()]
                .copy_from_slice(&ctx.nonce_initiator);
            crypto_stack.authenticate_id_responder(
                id_responder,
                &mut responder_signed
                    [ctx.message_responder.len() + ctx.nonce_initiator.len()..responder_signed_len],
            );

            let write_slice = response.write_authentication_payload_slice(
                message::AuthMethod::RSA_DIGITAL_SIGNATURE,
                self.pki_processing.signature_length(),
            )?;
            self.pki_processing
                .sign_auth(&responder_signed[..responder_signed_len], write_slice)?;
        };

        if ipv4_address_requested {
            response.write_configuration_payload(self.internal_addr)?;
        }

        let local_spi = message::Spi::U32(rand::thread_rng().gen::<u32>());
        transform_params.set_local_spi(local_spi);
        response.write_accept_proposal(proposal_num, &transform_params)?;

        // TODO: narrow down Traffic Selectors.
        // TODO: will macOS or Windows accept more traffic selectors?
        response.write_traffic_selector_payload(true, &ts_remote)?;
        response.write_traffic_selector_payload(false, &ts_local)?;

        self.complete_encrypted_payload(response)
    }

    fn process_auth_failed_response(
        &self,
        response: &mut message::MessageWriter,
        _err: IKEv2Error,
    ) -> Result<usize, IKEv2Error> {
        response.start_encrypted_payload()?;

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
            if payload.payload_type() == message::PayloadType::ENCRYPTED_AND_AUTHENTICATED {
                let encrypted_payload = payload.encrypted_data()?;
                let decrypted_slice = self.process_encrypted_payload(
                    request,
                    &encrypted_payload,
                    &mut decrypted_data,
                )?;
                decrypted_iter = Some(encrypted_payload.iter_decrypted_message(decrypted_slice));
            }
        }

        let decrypted_iter = if let Some(decrypted_iter) = decrypted_iter {
            decrypted_iter
        } else {
            // TODO: return INVALID_SYNTAX notification.
            // INFORMATIONAL payload is supposed to have an encrypted payload.
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

    crypto::hash_sha1(src_data)
}

struct SecurityAssociation {
    ts_local: message::TrafficSelector,
    ts_remote: message::TrafficSelector,
    // TODO: store encryption parameters
}

impl SecurityAssociation {
    fn contains(&self, remote_addr: &SocketAddr, local_addr: &SocketAddr) -> bool {
        self.ts_remote.addr_range().contains(&remote_addr.ip())
            && self.ts_remote.port_range().contains(&remote_addr.port())
            && self.ts_local.addr_range().contains(&local_addr.ip())
            && self.ts_local.port_range().contains(&local_addr.port())
    }
}

#[derive(Debug)]
pub enum IKEv2Error {
    Internal(&'static str),
    Format(message::FormatError),
    NotEnoughSpace(message::NotEnoughSpaceError),
    CertError(pki::CertError),
    Join(tokio::task::JoinError),
    Io(io::Error),
}

impl fmt::Display for IKEv2Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Internal(msg) => f.write_str(msg),
            Self::Format(ref e) => write!(f, "Format error: {}", e),
            Self::NotEnoughSpace(_) => write!(f, "Not enough space error"),
            Self::CertError(ref e) => write!(f, "PKI cert error: {}", e),
            Self::Join(ref e) => write!(f, "Tokio join error: {}", e),
            Self::Io(ref e) => {
                write!(f, "IO error: {}", e)
            }
        }
    }
}

impl error::Error for IKEv2Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Self::Internal(_msg) => None,
            Self::Format(ref err) => Some(err),
            Self::NotEnoughSpace(ref err) => Some(err),
            Self::CertError(ref err) => Some(err),
            Self::Join(ref err) => Some(err),
            Self::Io(ref err) => Some(err),
        }
    }
}

impl From<&'static str> for IKEv2Error {
    fn from(msg: &'static str) -> IKEv2Error {
        Self::Internal(msg)
    }
}

impl From<message::FormatError> for IKEv2Error {
    fn from(err: message::FormatError) -> IKEv2Error {
        Self::Format(err)
    }
}

impl From<message::NotEnoughSpaceError> for IKEv2Error {
    fn from(err: message::NotEnoughSpaceError) -> IKEv2Error {
        Self::NotEnoughSpace(err)
    }
}

impl From<pki::CertError> for IKEv2Error {
    fn from(err: pki::CertError) -> IKEv2Error {
        Self::CertError(err)
    }
}

impl From<tokio::task::JoinError> for IKEv2Error {
    fn from(err: tokio::task::JoinError) -> IKEv2Error {
        Self::Join(err)
    }
}

impl From<io::Error> for IKEv2Error {
    fn from(err: io::Error) -> IKEv2Error {
        Self::Io(err)
    }
}
