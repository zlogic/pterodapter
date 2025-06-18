use log::{debug, info, trace, warn};
use rand::Rng;
use std::{
    cmp::Ordering,
    collections::HashSet,
    error, fmt,
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{self, Instant},
};

use super::{MAX_DATAGRAM_SIZE, Sockets, ip::Network};
use super::{SendError, crypto, esp, message, pki};

use crypto::DHTransform;

// All keys are less than 256 bits, but mathching the client nonce size is a good idea.
const MAX_NONCE: usize = 384 / 8;
// ECSDA DER-encoded signatures can vary in length and reach up to 72 bytes, plus optional algorithm parameters.
const MAX_SIGNATURE_LENGTH: usize = 1 + 12 + 72;

const MAX_ENCRYPTED_FRAGMENT_SIZE: usize = 1500;
const MAX_ENCRYPTED_DATA_SIZE: usize = 4096;

// RFC 7383 recommends a limit of 576 bytes for the entire IPv4 datagram.
// This includes IP/UDP headers, the IKEv2 header and encryption IV, rounding of encryption blocks, tag and validation signature.
const MAX_TRANSMIT_FRAGMENT_SIZE: usize = 576;

const IKE_SESSION_EXPIRATION: time::Duration = time::Duration::from_secs(60 * 60);
const IKE_RESPONSE_EXPIRATION: time::Duration = time::Duration::from_secs(60);
// TODO: set a time limit instead of retransmission limit.
const IKE_RETRANSMISSIONS_LIMIT: usize = 5;

const IKE_DELETE_DELAY: time::Duration = time::Duration::from_secs(30);
const ESP_DELETE_DELAY: time::Duration = time::Duration::from_secs(30);

#[derive(Clone, Copy)]
pub struct SessionID {
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
    pub fn new(remote_spi: u64, local_spi: u64) -> SessionID {
        SessionID {
            remote_spi,
            local_spi,
        }
    }

    pub fn from_message(
        message: &message::InputMessage,
    ) -> Result<SessionID, message::FormatError> {
        let (remote_spi, local_spi) = if message.read_flags()?.has(message::Flags::INITIATOR) {
            (message.read_initiator_spi(), message.read_responder_spi())
        } else {
            (message.read_responder_spi(), message.read_initiator_spi())
        };
        Ok(SessionID {
            remote_spi,
            local_spi,
        })
    }

    pub fn local_spi(&self) -> u64 {
        self.local_spi
    }
}

impl fmt::Display for SessionID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}-{:x}", self.remote_spi, self.local_spi)
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
    Deleting,
}

pub enum IKEv2PendingAction {
    DeleteHalfOpenSession(SocketAddr, u64),
    CreateChildSA(esp::SecurityAssociationID, Box<esp::SecurityAssociation>),
    DeleteChildSA(esp::SecurityAssociationID, time::Duration),
    CreateIKEv2Session(SessionID, Box<IKEv2Session>),
    DeleteIKESession(time::Duration),
    DeleteOtherIKESessions(Vec<u8>),
}

pub enum NextRetransmission {
    Delay(time::Duration),
    Timeout,
}

pub struct IKEv2Session {
    session_id: SessionID,
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    state: SessionState,
    network: Network,
    ts_local: Vec<message::TrafficSelector>,
    child_sas: HashSet<ChildSessionID>,
    pki_processing: Arc<pki::PkiProcessing>,
    use_fragmentation: bool,
    params: Option<crypto::TransformParameters>,
    crypto_stack: Option<crypto::CryptoStack>,
    client_id: Option<(String, Vec<u8>)>,
    last_update: Instant,
    remote_message_id: u32,
    local_message_id: u32,
    fragment_reassembly: Option<FragmentReassembly>,
    last_request_hash: Option<[u8; 32]>,
    last_response: Vec<Vec<u8>>,
    last_sent_request: Vec<Vec<u8>>,
    sent_request: Option<RequestContext>,
    request_retransmit: usize,
    pending_actions: Vec<IKEv2PendingAction>,
}

impl IKEv2Session {
    pub fn new(
        session_id: SessionID,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        pki_processing: Arc<pki::PkiProcessing>,
        network: &Network,
        ts_local: Vec<message::TrafficSelector>,
    ) -> IKEv2Session {
        IKEv2Session {
            session_id,
            remote_addr,
            local_addr,
            state: SessionState::Empty,
            network: network.clone(),
            ts_local,
            child_sas: HashSet::new(),
            pki_processing,
            use_fragmentation: false,
            params: None,
            crypto_stack: None,
            client_id: None,
            last_update: Instant::now(),
            remote_message_id: 0,
            local_message_id: 0,
            fragment_reassembly: None,
            last_request_hash: None,
            last_response: vec![],
            last_sent_request: vec![],
            sent_request: None,
            request_retransmit: 0,
            pending_actions: vec![],
        }
    }

    pub fn is_expired(&self, now: time::Instant) -> bool {
        self.last_update + IKE_SESSION_EXPIRATION < now
            || self.request_retransmit > IKE_RETRANSMISSIONS_LIMIT
    }

    pub fn user_id(&self) -> Option<&str> {
        if let Some((user_id, _)) = self.client_id.as_ref() {
            Some(user_id.as_str())
        } else {
            None
        }
    }

    pub fn certificate_serial(&self) -> Option<&[u8]> {
        if let Some((_, certificate_serial)) = self.client_id.as_ref() {
            Some(certificate_serial.as_slice())
        } else {
            None
        }
    }

    pub fn handle_response_expiration(&mut self, now: time::Instant) {
        if self.last_update + IKE_RESPONSE_EXPIRATION < now {
            self.last_response = vec![];
            self.fragment_reassembly = None;
        }
    }

    pub fn next_retransmission(&self) -> NextRetransmission {
        if self.request_retransmit > IKE_RETRANSMISSIONS_LIMIT {
            return NextRetransmission::Timeout;
        }
        let next_retransmission = 3000 * self.request_retransmit as u64;
        let jitter = next_retransmission * 15 / 100;
        let next_delay = rand::rng().random_range(
            next_retransmission.saturating_sub(jitter)..=next_retransmission.saturating_add(jitter),
        );
        NextRetransmission::Delay(time::Duration::from_millis(next_delay))
    }

    pub fn update_network(&mut self, network: &Network) {
        self.network = network.clone();
    }

    pub fn process_request(
        &mut self,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        request: &message::InputMessage,
        new_ids: &mut ReservedSpi,
    ) -> Result<bool, SessionError> {
        self.last_update = Instant::now();
        let message_id = request.read_message_id();
        match message_id.cmp(&self.remote_message_id) {
            Ordering::Less => {
                // This is an outdated retransmission, nothing to do.
                return Ok(false);
            }
            Ordering::Equal => {
                // Retransmit last response if available.
                if let Some(last_request_hash) = self.last_request_hash.as_ref() {
                    if !Self::should_retransmit(request) {
                        return Ok(false);
                    }
                    let request_hash = crypto::hash_sha256(request.raw_data());
                    if &request_hash == last_request_hash {
                        // Update remote address if client changed IP or switched to another NAT port.
                        self.remote_addr = remote_addr;
                        self.local_addr = local_addr;
                        return Ok(true);
                    } else {
                        // Retransmitted request is modified - could be an attacker
                        // attempting to request a copy of the response.
                        return Err(
                            "Retransmitted request hash mismatch, not sending response".into()
                        );
                    }
                } else if self.remote_message_id > 0 {
                    // Last response expired, and this is not a "start from 0" session.
                    return Ok(false);
                }
            }
            Ordering::Greater => {
                // New message ID, can proceed.
            }
        }

        let exchange_type = request.read_exchange_type()?;

        let mut response_bytes = [0u8; MAX_ENCRYPTED_DATA_SIZE];
        let mut response = message::MessageWriter::new(&mut response_bytes[4..])?;
        response.write_header(
            self.session_id.remote_spi,
            self.session_id.local_spi,
            exchange_type,
            false,
            request.read_message_id(),
        )?;

        let decrypted_data = if exchange_type == message::ExchangeType::IKE_SA_INIT {
            self.last_request_hash = Some(crypto::hash_sha256(request.raw_data()));
            None
        } else {
            let decrypted_data = self.decrypt_request(request)?;
            if Self::should_retransmit(request) {
                self.last_request_hash = Some(crypto::hash_sha256(request.raw_data()));
            }
            if decrypted_data.is_none() {
                // Not all fragments have been received.
                return Ok(false);
            }
            self.fragment_reassembly = None;
            decrypted_data
        };
        let request = if let Some(decrypted_data) = decrypted_data.as_ref() {
            &message::InputMessage::from_datagram(decrypted_data, request.is_nat())?
        } else {
            request
        };
        if decrypted_data.is_some() {
            debug!("Decrypted packet from {remote_addr}\n{request:?}");
        }

        match exchange_type {
            message::ExchangeType::IKE_SA_INIT => {
                self.process_sa_init_request(request, &mut response)
            }
            message::ExchangeType::IKE_AUTH => {
                self.process_auth_request(remote_addr, local_addr, request, &mut response, new_ids)
            }
            message::ExchangeType::INFORMATIONAL => {
                self.process_informational_request(request, &mut response)
            }
            message::ExchangeType::CREATE_CHILD_SA => {
                self.process_create_child_sa_request(request, &mut response, new_ids)
            }
            _ => {
                warn!("Unimplemented handler for message {exchange_type}");
                Err("Unimplemented message".into())
            }
        }?;

        self.last_response = if exchange_type == message::ExchangeType::IKE_SA_INIT {
            let response_length = response.complete_message();
            vec![response_bytes[..4 + response_length].to_vec()]
        } else {
            self.encrypt_message(&mut response)?
        };
        self.remote_message_id = message_id;

        // Update remote address if client changed IP or switched to another NAT port.
        self.remote_addr = remote_addr;
        self.local_addr = local_addr;

        Ok(true)
    }

    fn decrypt_request(
        &mut self,
        request: &message::InputMessage,
    ) -> Result<Option<Vec<u8>>, SessionError> {
        let encrypted_payload = match request.iter_payloads().next() {
            Some(Ok(message::Payload::Encrypted(payload))) => payload,
            Some(Ok(message::Payload::EncryptedFragment(payload))) => payload,
            Some(Err(err)) => return Err(err.into()),
            Some(Ok(_)) | None => return Err("Request has no encrypted payloads".into()),
        };

        let mut decrypted_data = [0u8; MAX_ENCRYPTED_FRAGMENT_SIZE];
        let encrypted_data = encrypted_payload.encrypted_data();
        let decrypted_data = &mut decrypted_data[..encrypted_data.len()];
        decrypted_data.copy_from_slice(encrypted_data);
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
        let decrypted_slice =
            match crypto_stack.decrypt_data(decrypted_data, encrypted_data_len, associated_data) {
                Ok(decrypted_slice) => decrypted_slice,
                Err(err) => {
                    info!("Failed to decrypt data: {err}");
                    return Err("Failed to decrypt data".into());
                }
            };
        if encrypted_payload.total_fragments() == 1 {
            let mut header = request.header();
            let full_length = decrypted_slice.len() + header.len();
            message::MessageWriter::update_header(
                &mut header,
                encrypted_payload.next_payload(),
                full_length as u32,
            );
            let mut decrypted_message = Vec::with_capacity(MAX_ENCRYPTED_FRAGMENT_SIZE);
            if request.is_nat() {
                decrypted_message.resize(4, 0);
            }
            decrypted_message.extend_from_slice(&header);
            decrypted_message.extend_from_slice(decrypted_slice);
            Ok(Some(decrypted_message))
        } else {
            debug!(
                "Decrypted fragment {}, total: {}",
                encrypted_payload.fragment_number(),
                encrypted_payload.total_fragments()
            );
            let message_id = request.read_message_id();
            let fragment_reassembly = match self.fragment_reassembly.as_mut() {
                Some(fragment_reassembly) => {
                    if fragment_reassembly.message_id != message_id {
                        let mut fragment_reassembly = FragmentReassembly::new(message_id);
                        fragment_reassembly.add(&encrypted_payload, decrypted_slice)?;
                        self.fragment_reassembly = Some(fragment_reassembly);
                        return Ok(None);
                    }
                    fragment_reassembly
                }
                None => {
                    let mut fragment_reassembly = FragmentReassembly::new(message_id);
                    fragment_reassembly.add(&encrypted_payload, decrypted_slice)?;
                    self.fragment_reassembly = Some(fragment_reassembly);
                    return Ok(None);
                }
            };
            fragment_reassembly.add(&encrypted_payload, decrypted_slice)?;
            if !fragment_reassembly.is_complete() {
                return Ok(None);
            }
            let decrypted_message = fragment_reassembly.to_vec(request);
            self.fragment_reassembly = None;
            Ok(Some(decrypted_message))
        }
    }

    fn should_retransmit(request: &message::InputMessage) -> bool {
        if let Ok(exchange_type) = request.read_exchange_type() {
            if exchange_type == message::ExchangeType::IKE_SA_INIT {
                return request.read_message_id() == 0;
            }
        } else {
            return false;
        };
        // RFC 7383 2.6.1 states that only message 1 should trigger a retransmission.
        // Otherwise, the first payload should be an encrypted message
        // (avoid any retransmissions if request is not encrypted).
        match request.iter_payloads().next() {
            Some(Ok(message::Payload::EncryptedFragment(payload))) => {
                payload.fragment_number() == 1
            }
            Some(Ok(message::Payload::Encrypted(_))) => true,
            Some(Err(_)) => false,
            Some(Ok(_)) | None => false,
        }
    }

    fn encrypt_message(
        &mut self,
        msg: &mut message::MessageWriter,
    ) -> Result<Vec<Vec<u8>>, SessionError> {
        if log::log_enabled!(log::Level::Debug) {
            let msg_length = msg.complete_message();
            match message::InputMessage::from_datagram(&msg.raw_data()[..msg_length], false) {
                Ok(msg) => {
                    trace!("Encrypting message\n{msg:?}");
                }
                Err(err) => {
                    warn!("Failed to decode message for encryption: {err}");
                }
            }
        }
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

        let first_payload_type = msg.first_payload_type();
        let chunks = if self.use_fragmentation {
            let chunks = msg.payloads_data().chunks(MAX_TRANSMIT_FRAGMENT_SIZE);
            if chunks.len() > 0 {
                chunks.collect::<Vec<_>>()
            } else {
                // If the chunk list is empty, most likely this is an empty reponse
                // e.g. INFORMATIONAL keepalive.
                vec![msg.payloads_data()]
            }
        } else {
            vec![msg.payloads_data()]
        };
        let total_fragments = chunks.len() as u16;
        chunks
            .into_iter()
            .enumerate()
            .map(|(i, fragment)| {
                let encrypted_data_len = fragment.len();
                let mut msg_bytes = vec![0u8; MAX_DATAGRAM_SIZE];
                let mut msg = msg.clone_header(&mut msg_bytes[4..])?;
                let full_encrypted_length =
                    crypto_stack.encrypted_payload_length(encrypted_data_len);
                let unencrypted_len = msg.write_encrypted_payload(
                    fragment,
                    full_encrypted_length,
                    first_payload_type,
                    i as u16,
                    total_fragments,
                )?;
                let full_message_len = msg.complete_message();
                msg_bytes.truncate(4 + full_message_len);

                {
                    let msg_bytes = &mut msg_bytes[4..];
                    let (associated_data, encrypt_data) = msg_bytes.split_at_mut(unencrypted_len);
                    let associated_data = if !add_signature {
                        associated_data
                    } else {
                        &mut [0u8; 0]
                    };

                    crypto_stack
                        .encrypt_data(encrypt_data, encrypted_data_len, associated_data)
                        .map_err(|err| {
                            warn!("Failed to encrypt data {err}");
                            "Failed to encrypt data"
                        })?;
                }

                crypto_stack.sign(&mut msg_bytes[4..]).map_err(|err| {
                    warn!("Failed to sign data {err}");
                    "Failed to sign data"
                })?;
                Ok(msg_bytes)
            })
            .collect::<_>()
    }

    fn process_sa_init_request(
        &mut self,
        request: &message::InputMessage,
        response: &mut message::MessageWriter,
    ) -> Result<(), SessionError> {
        response.write_header(
            self.session_id.remote_spi,
            self.session_id.local_spi,
            message::ExchangeType::IKE_SA_INIT,
            false,
            request.read_message_id(),
        )?;

        let mut dh_transform = None;
        let mut shared_secret = None;
        let mut nonce_responder = None;
        let mut nonce_initiator = None;
        for payload in request.iter_payloads() {
            let payload = match payload {
                Ok(payload) => payload,
                Err(err) => {
                    warn!("Received invalid payload: {err}");
                    return self.write_failed_response(
                        response,
                        message::NotifyMessageType::INVALID_SYNTAX,
                    );
                }
            };
            // IKEv2 payloads need to be sent in a very specific order.
            // By the time the Nonce is reached, SA and KE should already be processed.
            match payload {
                message::Payload::SecurityAssociation(sa) => {
                    let (prop, proposal_num) =
                        if let Some(transform) = crypto::choose_sa_parameters(&sa) {
                            transform
                        } else {
                            warn!("No compatible SA parameters found");
                            return self.write_failed_response(
                                response,
                                message::NotifyMessageType::NO_PROPOSAL_CHOSEN,
                            );
                        };
                    response.write_security_association(&[(&prop, proposal_num)])?;
                    match prop.create_dh() {
                        Ok(dh) => dh_transform = Some(dh),
                        Err(err) => {
                            warn!("Failed to init DH: {err}")
                        }
                    }
                    self.params = Some(prop);
                }
                message::Payload::KeyExchange(kex) => {
                    if let Some(ref mut dh) = dh_transform.as_mut() {
                        let public_key = dh.read_public_key();
                        shared_secret = match dh.compute_shared_secret(kex.read_value()) {
                            Ok(shared_secret) => Some(shared_secret),
                            Err(err) => {
                                warn!("Failed to compute shared secret: {err}");
                                return self.write_failed_response(
                                    response,
                                    message::NotifyMessageType::INVALID_KE_PAYLOAD,
                                );
                            }
                        };
                        response
                            .write_key_exchange_payload(dh.group_number(), public_key.as_slice())?;
                    }
                }
                message::Payload::Nonce(nonce) => {
                    let nonce_remote = nonce.read_value();
                    nonce_initiator = {
                        let mut nonce_initiator = vec![0; nonce_remote.len()];
                        nonce_initiator.copy_from_slice(nonce_remote);
                        Some(nonce_initiator)
                    };
                    let mut nonce_local = [0u8; MAX_NONCE];
                    let nonce_local = &mut nonce_local[..nonce_remote.len()];
                    rand::rng().fill(nonce_local);
                    nonce_responder = {
                        let mut nonce_responder = vec![0; nonce_local.len()];
                        nonce_responder.copy_from_slice(nonce_local);
                        Some(nonce_responder)
                    };
                    let prf_key = [
                        nonce_remote,
                        nonce_local,
                        &self.session_id.remote_spi.to_be_bytes(),
                        &self.session_id.local_spi.to_be_bytes(),
                    ]
                    .concat();
                    let params = if let Some(params) = self.params.as_ref() {
                        params
                    } else {
                        warn!("Unspecified transform parameters");
                        return self.write_failed_response(
                            response,
                            message::NotifyMessageType::INVALID_SYNTAX,
                        );
                    };
                    let prf_transform = match params
                        .create_prf(&prf_key[0..nonce_remote.len() + nonce_local.len()])
                    {
                        Ok(prf) => prf,
                        Err(err) => {
                            warn!("Failed to init PRF transform for SKEYSEED: {err}");
                            return self.write_failed_response(
                                response,
                                message::NotifyMessageType::NO_PROPOSAL_CHOSEN,
                            );
                        }
                    };
                    let shared_secret = if let Some(ref shared_secret) = shared_secret {
                        shared_secret
                    } else {
                        warn!("Unspecified shared secret");
                        return self.write_failed_response(
                            response,
                            message::NotifyMessageType::NO_PROPOSAL_CHOSEN,
                        );
                    };
                    let skeyseed = prf_transform.prf(shared_secret.as_slice());
                    let prf_transform = match params.create_prf_plus(skeyseed.as_slice()) {
                        Ok(prf) => prf,
                        Err(err) => {
                            warn!("Failed to init PRF transform for keying material: {err}");
                            return self.write_failed_response(
                                response,
                                message::NotifyMessageType::NO_PROPOSAL_CHOSEN,
                            );
                        }
                    };
                    match prf_transform.create_crypto_stack(params, &prf_key) {
                        Ok(crypto_stack) => self.crypto_stack = Some(crypto_stack),
                        Err(err) => {
                            warn!("Failed to set up cryptography stack: {err}");
                            return self.write_failed_response(
                                response,
                                message::NotifyMessageType::NO_PROPOSAL_CHOSEN,
                            );
                        }
                    };
                    let dest = response
                        .next_payload_slice(message::PayloadType::NONCE, nonce_local.len())?;
                    dest.copy_from_slice(nonce_local);
                }
                message::Payload::Notify(notify) => match notify.message_type() {
                    message::NotifyMessageType::SIGNATURE_HASH_ALGORITHMS => {
                        let supports_sha256 = notify
                            .to_signature_hash_algorithms()?
                            .any(|alg| alg == message::SignatureHashAlgorithm::SHA2_256);
                        if !supports_sha256 {
                            warn!("No supported signature hash algorithms");
                            return self.write_failed_response(
                                response,
                                message::NotifyMessageType::NO_PROPOSAL_CHOSEN,
                            );
                        }
                    }
                    message::NotifyMessageType::IKEV2_FRAGMENTATION_SUPPORTED => {
                        self.use_fragmentation = true;
                    }
                    _ => {}
                },
                _ => {
                    if payload.is_critical() {
                        warn!(
                            "Received critical, unsupported payload: {}",
                            payload.payload_type()
                        );
                        return self.write_failed_response(
                            response,
                            message::NotifyMessageType::UNSUPPORTED_CRITICAL_PAYLOAD,
                        );
                    }
                }
            }
        }

        if let Some(root_ca) = self.pki_processing.root_ca_request() {
            response.write_certificate_request_payload(
                message::CertificateEncoding::X509_SIGNATURE,
                root_ca,
            )?;
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
            self.remote_addr.ip(),
            self.remote_addr.port(),
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
            warn!("Initiator didn't provide nonce");
            return self
                .write_failed_response(response, message::NotifyMessageType::INVALID_SYNTAX);
        };
        let nonce_responder = if let Some(nonce) = nonce_responder {
            nonce
        } else {
            warn!("No nonce provided in response");
            return self
                .write_failed_response(response, message::NotifyMessageType::INVALID_SYNTAX);
        };

        response.write_notify_payload(
            None,
            &[],
            message::NotifyMessageType::NAT_DETECTION_DESTINATION_IP,
            &nat_ip,
        )?;

        if self.use_fragmentation {
            response.write_notify_payload(
                None,
                &[],
                message::NotifyMessageType::IKEV2_FRAGMENTATION_SUPPORTED,
                &[],
            )?;
        }

        // Only one algorithm is supported, otherwise this would need to be an array.
        let supported_signature_algorithms =
            message::SignatureHashAlgorithm::SHA2_256.to_be_bytes();
        response.write_notify_payload(
            None,
            &[],
            message::NotifyMessageType::SIGNATURE_HASH_ALGORITHMS,
            &supported_signature_algorithms,
        )?;

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

        Ok(())
    }

    fn process_auth_request(
        &mut self,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        request: &message::InputMessage,
        response: &mut message::MessageWriter,
        new_ids: &mut ReservedSpi,
    ) -> Result<(), SessionError> {
        self.pending_actions
            .push(IKEv2PendingAction::DeleteHalfOpenSession(
                self.remote_addr,
                self.session_id.remote_spi,
            ));
        let ctx = match self.state {
            SessionState::InitSA(ref ctx) => ctx.clone(),
            _ => {
                warn!("Received IKE_AUTH request for session not in init state");
                return self.write_failed_response(
                    response,
                    message::NotifyMessageType::AUTHENTICATION_FAILED,
                );
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

        let mut client_cert = None;
        let mut client_auth = None;
        let mut server_cert = self.pki_processing.default_server_cert();
        let mut id_initiator = None;
        let mut transform_params = None;
        let mut ts_remote = vec![];
        let mut ts_local = vec![];
        let mut ipv4_address_requested = false;
        let mut internal_domain_requested = false;
        let mut initial_contact = false;

        for payload in request.iter_payloads() {
            let payload = match payload {
                Ok(payload) => payload,
                Err(err) => {
                    warn!("Failed to read decrypted payload data: {err}");
                    return self.write_failed_response(
                        response,
                        message::NotifyMessageType::INVALID_SYNTAX,
                    );
                }
            };
            match payload {
                message::Payload::Certificate(certificate) => {
                    if certificate.encoding() != message::CertificateEncoding::X509_SIGNATURE {
                        warn!(
                            "Certificate encoding {} is unsupported",
                            certificate.encoding()
                        );
                        return self.write_failed_response(
                            response,
                            message::NotifyMessageType::AUTHENTICATION_FAILED,
                        );
                    }
                    match self
                        .pki_processing
                        .verify_client_cert(certificate.read_value())
                    {
                        Ok(cert) => client_cert = Some(cert),
                        Err(err) => {
                            warn!("Certificate is not valid: {err}");
                        }
                    };
                }
                message::Payload::Notify(notify) => {
                    if notify.message_type() == message::NotifyMessageType::INITIAL_CONTACT
                        && notify.spi() == message::Spi::None
                    {
                        initial_contact = true;
                    }
                }
                message::Payload::CertificateRequest(certreq) => {
                    if certreq.read_encoding() != message::CertificateEncoding::X509_SIGNATURE {
                        warn!(
                            "Certificate request encoding {} is unsupported",
                            certreq.read_encoding()
                        );
                        return self.write_failed_response(
                            response,
                            message::NotifyMessageType::AUTHENTICATION_FAILED,
                        );
                    }
                    match self.pki_processing.server_cert(certreq.read_value()) {
                        Some(cert) => server_cert = Some(cert),
                        None => {
                            warn!("No certificates found for client's certificate request",);
                        }
                    };
                }
                message::Payload::IdentificationInitiator(id) => {
                    id_initiator = Some(id.raw_value().to_vec());
                }
                message::Payload::Authentication(auth) => {
                    client_auth = match auth.read_method() {
                        message::AuthMethod::ECDSA_SHA256_P256 => {
                            Some((auth.read_value().to_vec(), pki::SignatureFormat::Default))
                        }
                        message::AuthMethod::DIGITAL_SIGNATURE => Some((
                            auth.read_value().to_vec(),
                            pki::SignatureFormat::AdditionalParameters,
                        )),
                        _ => {
                            warn!(
                                "Authentication method {} is unsupported",
                                auth.read_method()
                            );
                            return self.write_failed_response(
                                response,
                                message::NotifyMessageType::AUTHENTICATION_FAILED,
                            );
                        }
                    }
                }
                message::Payload::SecurityAssociation(sa) => {
                    transform_params = crypto::choose_sa_parameters(&sa);
                    if transform_params.is_none() {
                        warn!("No compatible SA parameters found");
                        continue;
                    };
                }
                message::Payload::TrafficSelectorInitiator(ts) => {
                    let ts = ts
                        .iter_traffic_selectors()
                        .collect::<Result<Vec<_>, message::FormatError>>()
                        .map_err(|err| {
                            warn!("Failed to decode initiator traffic selectors: {err}");
                            err
                        });
                    if let Ok(mut ts) = ts {
                        ts.retain(|ts| self.traffic_selector_compatible(ts));
                        ts_remote = ts
                    }
                }
                message::Payload::TrafficSelectorResponder(ts) => {
                    let ts = ts
                        .iter_traffic_selectors()
                        .collect::<Result<Vec<_>, message::FormatError>>()
                        .map_err(|err| {
                            warn!("Failed to decode responder traffic selectors: {err}");
                            err
                        });
                    if let Ok(mut ts) = ts {
                        ts.retain(|ts| self.traffic_selector_compatible(ts));
                        ts_local = ts
                    }
                }
                message::Payload::Configuration(configuration) => {
                    configuration.iter_attributes().try_for_each(|attr| {
                        let attr = attr.map_err(|err| {
                            warn!("Failed to decode configuration attribute: {err}");
                            err
                        })?;
                        match attr.attribute_type() {
                            message::ConfigurationAttributeType::INTERNAL_IP4_ADDRESS => {
                                ipv4_address_requested = true
                            }
                            message::ConfigurationAttributeType::INTERNAL_DNS_DOMAIN => {
                                internal_domain_requested = true
                            }
                            _ => {}
                        }
                        Ok::<_, SessionError>(())
                    })?;
                }
                _ => {
                    if payload.is_critical() {
                        warn!(
                            "Received critical, unsupported payload: {}",
                            payload.payload_type()
                        );
                        return self.write_failed_response(
                            response,
                            message::NotifyMessageType::UNSUPPORTED_CRITICAL_PAYLOAD,
                        );
                    }
                }
            }
        }

        let client_cert = if let Some(cert) = client_cert {
            cert
        } else {
            warn!("Initiator provided no valid cert");
            return self.write_failed_response(
                response,
                message::NotifyMessageType::AUTHENTICATION_FAILED,
            );
        };
        let (client_auth, signature_format) = if let Some(auth) = client_auth {
            auth
        } else {
            warn!("Initiator provided no valid auth");
            return self.write_failed_response(
                response,
                message::NotifyMessageType::AUTHENTICATION_FAILED,
            );
        };
        let id_initiator = if let Some(id) = id_initiator {
            id
        } else {
            warn!("Initiator provided no ID");
            return self.write_failed_response(
                response,
                message::NotifyMessageType::AUTHENTICATION_FAILED,
            );
        };
        let (mut transform_params, proposal_num) = if let Some(params) = transform_params {
            params
        } else {
            warn!("Unacceptable Security Association proposals");
            return self
                .write_failed_response(response, message::NotifyMessageType::NO_PROPOSAL_CHOSEN);
        };
        if ts_local.is_empty() || ts_remote.is_empty() {
            warn!("No traffic selectors offered by client");
            return self
                .write_failed_response(response, message::NotifyMessageType::TS_UNACCEPTABLE);
        }
        if !self.ts_local.iter().all(|local_ts| {
            ts_local
                .iter()
                .any(|client_ts| client_ts.contains(local_ts))
        }) {
            warn!("Failed to narrow traffic selector");
            return self
                .write_failed_response(response, message::NotifyMessageType::TS_UNACCEPTABLE);
        }

        let local_spi = if let Some(local_spi) = new_ids.take_esp() {
            local_spi
        } else {
            warn!("No pre-generated SA ID available");
            return self
                .write_failed_response(response, message::NotifyMessageType::TEMPORARY_FAILURE);
        };
        transform_params.set_local_spi(message::Spi::U32(local_spi));
        let remote_spi = match transform_params.remote_spi() {
            message::Spi::U32(remote_spi) => remote_spi,
            _ => return Err("Security Association has unsupported remote SPI type".into()),
        };
        self.child_sas.insert(ChildSessionID {
            remote_spi,
            local_spi,
        });

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
        if let Err(err) = client_cert.verify_signature(
            signature_format,
            &initiator_signed[..initiator_signed_len],
            &client_auth,
        ) {
            warn!("Client authentication failed: {err}");
            return self.write_failed_response(
                response,
                message::NotifyMessageType::AUTHENTICATION_FAILED,
            );
        }

        // At this point the client identity has been successfully verified, proceed with sending a successful response.
        self.client_id = Some((client_cert.subject().into(), client_cert.serial().into()));
        self.state = SessionState::Established;

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

            let mut signature = [0u8; MAX_SIGNATURE_LENGTH];
            let signature_length = self.pki_processing.sign_auth(
                signature_format,
                &responder_signed[..responder_signed_len],
                &mut signature,
            )?;
            let auth_method = match signature_format {
                pki::SignatureFormat::Default => message::AuthMethod::ECDSA_SHA256_P256,
                pki::SignatureFormat::AdditionalParameters => {
                    message::AuthMethod::DIGITAL_SIGNATURE
                }
            };
            response
                .write_authentication_payload_slice(auth_method, &signature[..signature_length])?;
        };

        if ipv4_address_requested {
            let ip_netmasks = self.network.ip_netmasks();
            let dns64_domains = if internal_domain_requested {
                self.network.dns64_domains()
            } else {
                &[]
            };
            if ip_netmasks.is_empty() {
                warn!("No IP address is available, notifying client");
                return self.write_failed_response(
                    response,
                    message::NotifyMessageType::INTERNAL_ADDRESS_FAILURE,
                );
            } else {
                response.write_configuration_payload(
                    ip_netmasks,
                    self.network.dns_addrs(),
                    dns64_domains,
                )?
            }
        }

        let child_crypto_stack = match crypto_stack.create_child_stack(
            &transform_params,
            [ctx.nonce_initiator, ctx.nonce_responder]
                .concat()
                .as_slice(),
        ) {
            Ok(crypto_stack) => crypto_stack,
            Err(err) => {
                warn!("Failed to set up child SA cryptography stack: {err}");
                return self
                    .write_failed_response(response, message::NotifyMessageType::INVALID_SYNTAX);
            }
        };

        if initial_contact {
            self.pending_actions
                .push(IKEv2PendingAction::DeleteOtherIKESessions(
                    client_cert.serial().to_vec(),
                ));
        }

        response.write_security_association(&[(&transform_params, proposal_num)])?;

        response.write_traffic_selector_payload(true, &ts_remote)?;
        response.write_traffic_selector_payload(false, &self.ts_local)?;

        let child_sa = esp::SecurityAssociation::new(
            self.network.clone(),
            (self.ts_local.clone(), local_addr, local_spi),
            (ts_remote, remote_addr, remote_spi),
            child_crypto_stack,
            &transform_params,
            new_ids.next_esp_index(),
        );
        self.pending_actions.push(IKEv2PendingAction::CreateChildSA(
            local_spi,
            Box::new(child_sa),
        ));
        Ok(())
    }

    fn write_failed_response(
        &mut self,
        response: &mut message::MessageWriter,
        reason: message::NotifyMessageType,
    ) -> Result<(), SessionError> {
        Ok(response.write_notify_payload(None, &[], reason, &[])?)
    }

    fn process_informational_request(
        &mut self,
        request: &message::InputMessage,
        response: &mut message::MessageWriter,
    ) -> Result<(), SessionError> {
        let mut delete_spi = vec![];
        let mut delete_ike = false;

        for payload in request.iter_payloads() {
            let payload = match payload {
                Ok(payload) => payload,
                Err(err) => {
                    warn!("Failed to read decrypted payload data: {err}");
                    return self.write_failed_response(
                        response,
                        message::NotifyMessageType::INVALID_SYNTAX,
                    );
                }
            };
            match payload {
                message::Payload::Delete(delete) => {
                    delete_spi = delete.iter_spi().collect::<Vec<_>>();
                    delete_ike = delete_spi.is_empty();
                }
                _ => {
                    if payload.is_critical() {
                        warn!(
                            "Received critical, unsupported payload: {}",
                            payload.payload_type()
                        );
                        return self.write_failed_response(
                            response,
                            message::NotifyMessageType::UNSUPPORTED_CRITICAL_PAYLOAD,
                        );
                    }
                }
            }
        }

        if delete_ike {
            self.pending_actions
                .push(IKEv2PendingAction::DeleteIKESession(IKE_DELETE_DELAY));
            self.child_sas.iter().for_each(|sa_id| {
                self.pending_actions.push(IKEv2PendingAction::DeleteChildSA(
                    sa_id.local_spi,
                    ESP_DELETE_DELAY,
                ));
            });
            Ok(response.write_delete_payload(message::IPSecProtocolID::IKE, &[])?)
        } else if !delete_spi.is_empty() {
            let local_spis = delete_spi
                .into_iter()
                .flat_map(|remote_spi| {
                    let remote_spi = match remote_spi {
                        message::Spi::U32(remote_spi) => remote_spi,
                        message::Spi::U64(_) | message::Spi::None => {
                            info!("Received request to delete unsupported SPI type {remote_spi}");
                            return None;
                        }
                    };
                    let sa_id = match self
                        .child_sas
                        .iter()
                        .find(|sa_id| sa_id.remote_spi == remote_spi)
                    {
                        Some(sa_id) => *sa_id,
                        None => {
                            info!(
                                "Received request to delete non-existing child SA {remote_spi:x}"
                            );
                            return None;
                        }
                    };
                    self.child_sas.remove(&sa_id);
                    self.pending_actions.push(IKEv2PendingAction::DeleteChildSA(
                        sa_id.local_spi,
                        ESP_DELETE_DELAY,
                    ));
                    Some(message::Spi::U32(sa_id.local_spi))
                })
                .collect::<Vec<_>>();
            Ok(response.write_delete_payload(message::IPSecProtocolID::ESP, &local_spis)?)
        } else {
            // No action needed - most likely a keepalive request.
            Ok(())
        }
    }

    fn process_create_child_sa_request(
        &mut self,
        request: &message::InputMessage,
        response: &mut message::MessageWriter,
        new_ids: &mut ReservedSpi,
    ) -> Result<(), SessionError> {
        let crypto_stack = if let Some(crypto_stack) = self.crypto_stack.as_ref() {
            crypto_stack
        } else {
            return Err("Crypto stack not initialized".into());
        };

        let mut rekey_child_sa = None;
        let mut dh_transform = None;
        let mut transform_params = None;
        let mut public_key = None;
        let mut shared_secret = None;
        let mut nonce_initiator = None;
        let mut nonce_responder = None;
        let mut ts_remote = vec![];
        let mut ts_local = vec![];
        for payload in request.iter_payloads() {
            let payload = match payload {
                Ok(payload) => payload,
                Err(err) => {
                    warn!("Failed to read decrypted payload data: {err}");
                    return self.write_failed_response(
                        response,
                        message::NotifyMessageType::INVALID_SYNTAX,
                    );
                }
            };
            match payload {
                message::Payload::Notify(notify) => {
                    if notify.message_type() == message::NotifyMessageType::REKEY_SA {
                        rekey_child_sa = Some(notify.spi());
                    }
                }
                message::Payload::SecurityAssociation(sa) => {
                    transform_params = crypto::choose_sa_parameters(&sa);
                    let prop = match transform_params {
                        Some(params) => params.0,
                        None => {
                            warn!("No compatible SA parameters found");
                            continue;
                        }
                    };
                    match prop.create_dh() {
                        Ok(dh) => dh_transform = Some(dh),
                        Err(err) => {
                            debug!("Failed to init DH: {err}");
                        }
                    }
                }
                message::Payload::Nonce(nonce) => {
                    let nonce_remote = nonce.read_value();
                    nonce_initiator = {
                        let mut nonce_initiator = vec![0; nonce_remote.len()];
                        nonce_initiator.copy_from_slice(nonce_remote);
                        Some(nonce_initiator)
                    };
                    let mut nonce_local = [0u8; MAX_NONCE];
                    let nonce_local = &mut nonce_local[..nonce_remote.len()];
                    rand::rng().fill(nonce_local);
                    nonce_responder = {
                        let mut nonce_responder = vec![0; nonce_local.len()];
                        nonce_responder.copy_from_slice(nonce_local);
                        Some(nonce_responder)
                    };
                }
                message::Payload::KeyExchange(kex) => {
                    if let Some(ref mut dh) = dh_transform.as_mut() {
                        public_key = Some(dh.read_public_key());
                        shared_secret = match dh.compute_shared_secret(kex.read_value()) {
                            Ok(shared_secret) => Some(shared_secret),
                            Err(err) => {
                                warn!("Failed to compute shared secret: {err}");
                                return self.write_failed_response(
                                    response,
                                    message::NotifyMessageType::INVALID_KE_PAYLOAD,
                                );
                            }
                        };
                    }
                }
                message::Payload::TrafficSelectorInitiator(ts) => {
                    let ts = ts
                        .iter_traffic_selectors()
                        .collect::<Result<Vec<_>, message::FormatError>>()
                        .map_err(|err| {
                            warn!("Failed to decode initiator traffic selectors: {err}");
                            err
                        });
                    if let Ok(mut ts) = ts {
                        ts.retain(|ts| self.traffic_selector_compatible(ts));
                        ts_remote = ts
                    }
                }
                message::Payload::TrafficSelectorResponder(ts) => {
                    let ts = ts
                        .iter_traffic_selectors()
                        .collect::<Result<Vec<_>, message::FormatError>>()
                        .map_err(|err| {
                            warn!("Failed to decode responder traffic selectors: {err}");
                            err
                        });
                    if let Ok(mut ts) = ts {
                        ts.retain(|ts| self.traffic_selector_compatible(ts));
                        ts_local = ts
                    }
                }
                _ => {
                    if payload.is_critical() {
                        warn!(
                            "Received critical, unsupported payload: {}",
                            payload.payload_type()
                        );
                        return self.write_failed_response(
                            response,
                            message::NotifyMessageType::UNSUPPORTED_CRITICAL_PAYLOAD,
                        );
                    }
                }
            }
        }

        let nonce_initiator = if let Some(nonce_initiator) = nonce_initiator {
            nonce_initiator
        } else {
            warn!("Initiator didn't provide nonce");
            return self
                .write_failed_response(response, message::NotifyMessageType::INVALID_SYNTAX);
        };
        let nonce_responder = if let Some(nonce_responder) = nonce_responder {
            nonce_responder
        } else {
            warn!("No nonce provided in response");
            return self
                .write_failed_response(response, message::NotifyMessageType::INVALID_SYNTAX);
        };
        let (mut transform_params, proposal_num) = if let Some(params) = transform_params {
            params
        } else {
            warn!("Unacceptable Security Association proposals");
            return self
                .write_failed_response(response, message::NotifyMessageType::NO_PROPOSAL_CHOSEN);
        };
        let key_exchange = match (dh_transform, public_key) {
            (Some(dh_transform), Some(public_key)) => {
                Some((dh_transform.group_number(), public_key))
            }
            (None, None) => None,
            _ => {
                warn!("DH transform or key exchange is not initialized");
                return self.write_failed_response(
                    response,
                    message::NotifyMessageType::INVALID_KE_PAYLOAD,
                );
            }
        };
        let create_child_sa = rekey_child_sa.is_none()
            && transform_params.protocol_id() == message::IPSecProtocolID::ESP;
        let new_crypto_stack = {
            let shared_secret = if let Some(ref shared_secret) = shared_secret {
                shared_secret.as_slice()
            } else {
                debug!("Rekeying without additional keying material");
                &[]
            };
            let prf_key = [shared_secret, &nonce_initiator, &nonce_responder].concat();
            let crypto_stack = if rekey_child_sa.is_some() || create_child_sa {
                let local_spi = if let Some(local_spi) = new_ids.take_esp() {
                    local_spi
                } else {
                    warn!("No pre-generated SA ID available");
                    return self.write_failed_response(
                        response,
                        message::NotifyMessageType::TEMPORARY_FAILURE,
                    );
                };
                transform_params.set_local_spi(message::Spi::U32(local_spi));
                crypto_stack.create_child_stack(&transform_params, &prf_key)
            } else {
                let local_spi = if let Some(local_spi) = new_ids.take_ike() {
                    message::Spi::U64(local_spi)
                } else {
                    warn!("No pre-generated IKE SA ID available");
                    return self.write_failed_response(
                        response,
                        message::NotifyMessageType::TEMPORARY_FAILURE,
                    );
                };
                transform_params.set_local_spi(local_spi);
                let skeyseed = crypto_stack.rekey_skeyseed(&prf_key);
                let remote_spi = transform_params.remote_spi();
                let mut spi_slice = [0u8; 8 + 8];
                remote_spi.write_to(&mut spi_slice[0..remote_spi.length()]);
                local_spi.write_to(
                    &mut spi_slice[remote_spi.length()..remote_spi.length() + local_spi.length()],
                );
                let prf_key = [
                    nonce_initiator.as_slice(),
                    nonce_responder.as_slice(),
                    &spi_slice[..remote_spi.length() + local_spi.length()],
                ]
                .concat();
                crypto_stack.create_rekey_stack(&transform_params, skeyseed.as_slice(), &prf_key)
            };
            match crypto_stack {
                Ok(crypto_stack) => crypto_stack,
                Err(err) => {
                    warn!("Failed to rekey crypto stack: {err}");
                    return self.write_failed_response(
                        response,
                        message::NotifyMessageType::INVALID_SYNTAX,
                    );
                }
            }
        };
        if rekey_child_sa.is_some() && (ts_local.is_empty() || ts_remote.is_empty()) {
            warn!("No traffic selectors offered by client");
            return self
                .write_failed_response(response, message::NotifyMessageType::TS_UNACCEPTABLE);
        }
        if let Some(old_spi) = rekey_child_sa {
            debug!("Rekeying child SA");
            let old_spi = match old_spi {
                message::Spi::U32(old_spi) => old_spi,
                _ => return Err("Security Association has unsupported REKEY_SA SPI type".into()),
            };
            if !self
                .child_sas
                .iter()
                .any(|sa_id| sa_id.remote_spi == old_spi)
            {
                warn!("Cannot find child SA to rekey");
                return self.write_failed_response(
                    response,
                    message::NotifyMessageType::CHILD_SA_NOT_FOUND,
                );
            };
            let (remote_spi, local_spi) =
                match (transform_params.remote_spi(), transform_params.local_spi()) {
                    (message::Spi::U32(remote_spi), message::Spi::U32(local_spi)) => {
                        (remote_spi, local_spi)
                    }
                    _ => return Err("Security Association has unsupported remote SPI type".into()),
                };
            self.child_sas.insert(ChildSessionID {
                remote_spi,
                local_spi,
            });
            let child_sa = esp::SecurityAssociation::new(
                self.network.clone(),
                (self.ts_local.clone(), self.local_addr, local_spi),
                (ts_remote.clone(), self.remote_addr, remote_spi),
                new_crypto_stack,
                &transform_params,
                new_ids.next_esp_index(),
            );
            self.pending_actions.push(IKEv2PendingAction::CreateChildSA(
                local_spi,
                Box::new(child_sa),
            ));
        } else if create_child_sa {
            debug!("Creating new child SA");
            let (remote_spi, local_spi) =
                match (transform_params.remote_spi(), transform_params.local_spi()) {
                    (message::Spi::U32(remote_spi), message::Spi::U32(local_spi)) => {
                        (remote_spi, local_spi)
                    }
                    _ => return Err("Security Association has unsupported remote SPI type".into()),
                };
            self.child_sas.insert(ChildSessionID {
                remote_spi,
                local_spi,
            });
            let child_sa = esp::SecurityAssociation::new(
                self.network.clone(),
                (self.ts_local.clone(), self.local_addr, local_spi),
                (ts_remote.clone(), self.remote_addr, remote_spi),
                new_crypto_stack,
                &transform_params,
                new_ids.next_esp_index(),
            );
            self.pending_actions.push(IKEv2PendingAction::CreateChildSA(
                local_spi,
                Box::new(child_sa),
            ));
        } else {
            debug!("Rekeying IKEv2 session");
            let (remote_spi, local_spi) =
                match (transform_params.remote_spi(), transform_params.local_spi()) {
                    (message::Spi::U64(remote_spi), message::Spi::U64(local_spi)) => {
                        (remote_spi, local_spi)
                    }
                    _ => return Err("Security Association has unsupported remote SPI type".into()),
                };
            let session_id = SessionID::new(remote_spi, local_spi);
            let child_sas = self.child_sas.drain().collect::<HashSet<_>>();
            let new_session = IKEv2Session {
                session_id,
                remote_addr: self.remote_addr,
                local_addr: self.local_addr,
                state: SessionState::Established,
                network: self.network.clone(),
                ts_local: self.ts_local.clone(),
                child_sas,
                pki_processing: self.pki_processing.clone(),
                use_fragmentation: self.use_fragmentation,
                params: Some(transform_params),
                crypto_stack: Some(new_crypto_stack),
                client_id: self.client_id.clone(),
                last_update: self.last_update,
                remote_message_id: 0,
                local_message_id: 0,
                fragment_reassembly: None,
                last_request_hash: None,
                last_response: vec![],
                last_sent_request: vec![],
                sent_request: None,
                request_retransmit: 0,
                pending_actions: vec![],
            };
            self.pending_actions
                .push(IKEv2PendingAction::CreateIKEv2Session(
                    session_id,
                    Box::new(new_session),
                ));
        }

        response.write_security_association(&[(&transform_params, proposal_num)])?;
        let dest =
            response.next_payload_slice(message::PayloadType::NONCE, nonce_responder.len())?;
        dest.copy_from_slice(nonce_responder.as_slice());
        if let Some((dh_group, public_key)) = key_exchange {
            response.write_key_exchange_payload(dh_group, public_key.as_slice())?;
        }

        if rekey_child_sa.is_some() || create_child_sa {
            response.write_traffic_selector_payload(true, &ts_remote)?;
            response.write_traffic_selector_payload(false, &self.ts_local)?;
        }
        Ok(())
    }

    pub fn take_pending_actions(&mut self) -> Vec<IKEv2PendingAction> {
        self.pending_actions.drain(..).collect::<Vec<_>>()
    }

    pub fn is_deleting_request(&mut self) -> bool {
        matches!(self.sent_request, Some(RequestContext::DeleteIKEv2))
    }

    pub fn is_established(&mut self) -> bool {
        match self.state {
            SessionState::Established | SessionState::Deleting => true,
            SessionState::Empty | SessionState::InitSA(_) => false,
        }
    }

    fn start_request(
        &mut self,
        exchange_type: message::ExchangeType,
        command_generator: impl FnOnce(&mut message::MessageWriter) -> Result<(), SessionError>,
    ) -> Result<u32, SessionError> {
        if self.sent_request.is_some() || !self.last_sent_request.is_empty() {
            return Err("Already processing another command".into());
        }
        let mut request_bytes = [0u8; MAX_DATAGRAM_SIZE];
        let mut ikev2_request = message::MessageWriter::new(&mut request_bytes)?;
        ikev2_request.write_header(
            self.session_id.remote_spi,
            self.session_id.local_spi,
            exchange_type,
            true,
            self.local_message_id,
        )?;
        self.last_sent_request = vec![];
        command_generator(&mut ikev2_request)?;

        self.last_sent_request = self.encrypt_message(&mut ikev2_request)?;

        self.request_retransmit = 0;
        Ok(self.local_message_id)
    }

    pub fn start_request_delete_ike(&mut self) -> Result<u32, SessionError> {
        match self.state {
            SessionState::Empty | SessionState::InitSA(_) | SessionState::Deleting => {
                return Err(
                    "Received Delete request for a non-established session, ignoring".into(),
                );
            }
            SessionState::Established => {}
        }
        let message_id = self.start_request(message::ExchangeType::INFORMATIONAL, |writer| {
            Ok(writer.write_delete_payload(message::IPSecProtocolID::IKE, &[])?)
        })?;
        self.state = SessionState::Deleting;
        self.sent_request = Some(RequestContext::DeleteIKEv2);
        Ok(message_id)
    }

    pub fn expand_local_ts(&mut self, updated_local_ts: &[message::TrafficSelector]) {
        for check_ts in updated_local_ts {
            if !self
                .ts_local
                .iter()
                .any(|existing_ts| existing_ts.contains(check_ts))
            {
                self.ts_local.push(check_ts.clone());
            }
        }
    }

    fn traffic_selector_compatible(&self, ts: &message::TrafficSelector) -> bool {
        match ts.ts_type() {
            message::TrafficSelectorType::TS_IPV4_ADDR_RANGE => self.network.supports_ipv4(),
            message::TrafficSelectorType::TS_IPV6_ADDR_RANGE => self.network.supports_ipv6(),
            _ => false,
        }
    }

    fn log_fragment_contents(
        message_type: &str,
        message_id: u32,
        session_id: SessionID,
        fragment: &[u8],
        fragment_number: usize,
        total_fragments: usize,
    ) {
        if log::log_enabled!(log::Level::Trace) {
            // Fragments are always prepended with the NAT header just in case.
            match message::InputMessage::from_datagram(fragment, true) {
                Ok(msg) => {
                    trace!(
                        "Transmitting {} ID {} for session {} (fragment {} of {}):\n{:?}",
                        message_type,
                        message_id,
                        session_id,
                        fragment_number + 1,
                        total_fragments,
                        msg
                    );
                }
                Err(err) => {
                    warn!(
                        "Transmitting {} ID {} for session {} (fragment {} of {}), cannot decode: {:?}",
                        message_type,
                        message_id,
                        session_id,
                        fragment_number + 1,
                        total_fragments,
                        err
                    );
                }
            }
        } else {
            debug!(
                "Transmitting {} ID {} for session {} (fragment {} of {})",
                message_type,
                message_id,
                session_id,
                fragment_number + 1,
                total_fragments,
            );
        }
    }

    pub async fn send_last_response(
        &self,
        sockets: &Sockets,
        message_id: u32,
        is_nat: bool,
    ) -> Result<(), SendError> {
        if message_id != self.remote_message_id {
            return Ok(());
        }
        let total_fragments = self.last_response.len();
        for (i, fragment) in self.last_response.iter().enumerate() {
            Self::log_fragment_contents(
                "response",
                self.remote_message_id,
                self.session_id,
                fragment,
                i,
                total_fragments,
            );
            let fragment = if is_nat { fragment } else { &fragment[4..] };
            sockets
                .send_datagram(&self.local_addr, &self.remote_addr, fragment)
                .await?;
        }
        Ok(())
    }

    pub async fn send_last_request(
        &mut self,
        sockets: &Sockets,
        message_id: u32,
    ) -> Result<(), SendError> {
        if message_id != self.local_message_id {
            return Ok(());
        }
        if !self.last_sent_request.is_empty() {
            self.request_retransmit += 1;
        }
        let total_fragments = self.last_sent_request.len();
        for (i, fragment) in self.last_sent_request.iter().enumerate() {
            Self::log_fragment_contents(
                "request",
                self.remote_message_id,
                self.session_id,
                fragment,
                i,
                total_fragments,
            );
            // Requests are always sent to the NAT port.
            sockets
                .send_datagram(&self.local_addr, &self.remote_addr, fragment)
                .await?;
        }
        Ok(())
    }

    pub fn process_response(
        &mut self,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        response: &message::InputMessage,
    ) -> Result<(), SessionError> {
        self.last_update = Instant::now();
        let message_id = response.read_message_id();
        match message_id.cmp(&self.local_message_id) {
            Ordering::Less => {
                // This is an outdated retransmission, nothing to do.
                return Ok(());
            }
            Ordering::Equal => {}
            Ordering::Greater => {
                // This is an unexpected response.
                return Err("Received unexpected response message ID".into());
            }
        }

        let exchange_type = response.read_exchange_type()?;
        match exchange_type {
            message::ExchangeType::INFORMATIONAL => self.process_informational_response(response),
            _ => {
                warn!("Unimplemented response handler for message {exchange_type}");
                Err("Unimplemented response message".into())
            }
        }?;

        // Remove last request to stop retransmissions.
        self.local_message_id += 1;
        self.last_sent_request = vec![];
        self.sent_request = None;
        self.request_retransmit = 0;

        // Update remote address if client changed IP or switched to another NAT port.
        self.remote_addr = remote_addr;
        self.local_addr = local_addr;

        Ok(())
    }

    fn process_informational_response(
        &mut self,
        request: &message::InputMessage,
    ) -> Result<(), SessionError> {
        for payload in request.iter_payloads() {
            let payload = match payload {
                Ok(payload) => payload,
                Err(err) => {
                    warn!("Failed to read decrypted payload data: {err}");
                    continue;
                }
            };
            // No payloads are parsed here, so only critical ones are checked.
            if payload.is_critical() {
                warn!(
                    "Received critical, unsupported payload: {}",
                    payload.payload_type()
                );
                return Err("Received critical, unsupported payload".into());
            }
        }
        let sent_request = self.sent_request.take();
        match sent_request {
            Some(RequestContext::DeleteIKEv2) => {
                self.pending_actions
                    .push(IKEv2PendingAction::DeleteIKESession(time::Duration::ZERO));
            }
            None => {
                return Err("Received response for a non-existing request".into());
            }
        }
        Ok(())
    }

    pub fn get_local_sa_spis(&self) -> Vec<esp::SecurityAssociationID> {
        self.child_sas
            .iter()
            .map(|sa_id| sa_id.local_spi)
            .collect::<Vec<_>>()
    }
}

pub enum RequestContext {
    DeleteIKEv2,
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

pub struct ReservedSpi {
    ike: Option<u64>,
    esp: Option<u32>,
    esp_index: usize,
}

impl ReservedSpi {
    pub fn new(esp_index: usize) -> ReservedSpi {
        ReservedSpi {
            ike: None,
            esp: None,
            esp_index,
        }
    }

    pub fn needs_ike(&self) -> bool {
        self.ike.is_none()
    }

    pub fn needs_esp(&self) -> bool {
        self.esp.is_none()
    }

    pub fn add_ike(&mut self, value: u64) {
        self.ike = Some(value)
    }

    pub fn add_esp(&mut self, value: u32) {
        self.esp = Some(value)
    }

    pub fn take_ike(&mut self) -> Option<u64> {
        self.ike.take()
    }

    fn take_esp(&mut self) -> Option<u32> {
        self.esp.take()
    }

    fn next_esp_index(&mut self) -> usize {
        let index = self.esp_index;
        self.esp_index += 1;
        index
    }
}

#[derive(Clone, Copy)]
struct ChildSessionID {
    remote_spi: u32,
    local_spi: u32,
}

impl PartialEq for ChildSessionID {
    fn eq(&self, other: &Self) -> bool {
        self.remote_spi == other.remote_spi && self.local_spi == other.local_spi
    }
}

impl Eq for ChildSessionID {}

impl Hash for ChildSessionID {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.remote_spi.hash(state);
        self.local_spi.hash(state);
    }
}

struct FragmentReassembly {
    message_id: u32,
    next_payload: message::PayloadType,
    fragments: Vec<Option<Vec<u8>>>,
}

impl FragmentReassembly {
    fn new(message_id: u32) -> FragmentReassembly {
        FragmentReassembly {
            message_id,
            next_payload: message::PayloadType::NONE,
            fragments: vec![],
        }
    }

    fn add(
        &mut self,
        fragment: &message::EncryptedMessage,
        decrypted_data: &[u8],
    ) -> Result<(), SessionError> {
        if fragment.fragment_number() == 1 {
            self.next_payload = fragment.next_payload();
        }
        let total_fragments = fragment.total_fragments() as usize;
        if self.fragments.is_empty() {
            self.fragments.resize(total_fragments, None);
        } else if self.fragments.len() != total_fragments {
            return Err("Total fragments count mismatch".into());
        }
        let fragment_number = fragment.fragment_number() as usize;
        let fragment_number = if fragment_number >= 1 {
            fragment_number - 1
        } else {
            return Err("Fragment number is less than 1".into());
        };
        if fragment_number < self.fragments.len() {
            let dest = &mut self.fragments[fragment_number];
            if dest.is_none() {
                *dest = Some(decrypted_data.to_vec());
            }
            Ok(())
        } else {
            Err("Fragment number exceeds total fragments".into())
        }
    }

    fn is_complete(&self) -> bool {
        !self.fragments.is_empty() && self.fragments.iter().all(|fragment| fragment.is_some())
    }

    fn data_length(&self) -> usize {
        self.fragments
            .iter()
            .map(|fragment| {
                if let Some(fragment) = fragment {
                    fragment.len()
                } else {
                    0
                }
            })
            .sum()
    }

    fn to_vec(&self, request: &message::InputMessage) -> Vec<u8> {
        let decrypted_length = self.data_length();
        let mut decrypted_message = Vec::with_capacity(MAX_ENCRYPTED_DATA_SIZE);
        if request.is_nat() {
            decrypted_message.resize(4, 0);
        }
        let mut header = request.header();
        let full_length = header.len() + decrypted_length;
        message::MessageWriter::update_header(&mut header, self.next_payload, full_length as u32);
        decrypted_message.extend_from_slice(&header);
        self.fragments.iter().for_each(|fragment| {
            if let Some(fragment) = fragment {
                decrypted_message.extend_from_slice(fragment)
            }
        });
        decrypted_message
    }
}

#[derive(Debug)]
pub enum SessionError {
    Internal(&'static str),
    Format(message::FormatError),
    NotEnoughSpace(message::NotEnoughSpaceError),
    CryptoInit(crypto::InitError),
    CertError(pki::CertError),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Internal(msg) => f.write_str(msg),
            Self::Format(e) => write!(f, "Format error: {e}"),
            Self::NotEnoughSpace(_) => write!(f, "Not enough space error"),
            Self::CryptoInit(e) => write!(f, "Crypto init error: {e}"),
            Self::CertError(e) => write!(f, "PKI cert error: {e}"),
        }
    }
}

impl error::Error for SessionError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Internal(_msg) => None,
            Self::Format(err) => Some(err),
            Self::NotEnoughSpace(err) => Some(err),
            Self::CryptoInit(err) => Some(err),
            Self::CertError(err) => Some(err),
        }
    }
}

impl From<&'static str> for SessionError {
    fn from(msg: &'static str) -> SessionError {
        Self::Internal(msg)
    }
}

impl From<message::FormatError> for SessionError {
    fn from(err: message::FormatError) -> SessionError {
        Self::Format(err)
    }
}

impl From<message::NotEnoughSpaceError> for SessionError {
    fn from(err: message::NotEnoughSpaceError) -> SessionError {
        Self::NotEnoughSpace(err)
    }
}

impl From<crypto::InitError> for SessionError {
    fn from(err: crypto::InitError) -> SessionError {
        Self::CryptoInit(err)
    }
}

impl From<pki::CertError> for SessionError {
    fn from(err: pki::CertError) -> SessionError {
        Self::CertError(err)
    }
}
