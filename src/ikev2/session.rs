use log::{debug, info, trace, warn};
use rand::Rng;
use std::{
    error, fmt,
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{self, Instant},
};

use super::{crypto, esp, message, pki, SendError, Sockets};
use super::{IKEV2_NAT_PORT, IKEV2_PORT, MAX_DATAGRAM_SIZE};

use crypto::DHTransform;

// All keys are less than 256 bits, but mathching the client nonce size is a good idea.
const MAX_NONCE: usize = 384 / 8;
// ECSDA DER-encoded signatures can vafy in length and reach up to 72 bytes, plus optional algorithm parameters.
const MAX_SIGNATURE_LENGTH: usize = 1 + 12 + 72;

const MAX_ENCRYPTED_DATA_SIZE: usize = 4096;

const IKE_SESSION_EXPIRATION: time::Duration = time::Duration::from_secs(60 * 15);
const IKE_RESPONSE_EXPIRATION: time::Duration = time::Duration::from_secs(60);
// TODO: set a time limit instead of retransmission limit.
const IKE_RETRANSMISSIONS_LIMIT: usize = 5;

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
    CreateChildSA(esp::SecurityAssociationID, esp::SecurityAssociation),
    UpdateSplitRoutes,
    DeleteIKESession,
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
    internal_addr: IpAddr,
    child_sas: Vec<ChildSA>,
    pki_processing: Arc<pki::PkiProcessing>,
    params: Option<crypto::TransformParameters>,
    crypto_stack: Option<crypto::CryptoStack>,
    user_id: Option<String>,
    last_update: Instant,
    remote_message_id: u32,
    local_message_id: u32,
    last_response: Option<([u8; MAX_DATAGRAM_SIZE], usize)>,
    last_request: Option<([u8; MAX_DATAGRAM_SIZE], usize)>,
    sent_request: Option<RequestContext>,
    request_retransmit: usize,
    pending_actions: Vec<IKEv2PendingAction>,
}

impl IKEv2Session {
    pub fn new(
        session_id: SessionID,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        internal_addr: IpAddr,
        pki_processing: Arc<pki::PkiProcessing>,
    ) -> IKEv2Session {
        IKEv2Session {
            session_id,
            remote_addr,
            local_addr,
            state: SessionState::Empty,
            internal_addr,
            child_sas: vec![],
            pki_processing,
            params: None,
            crypto_stack: None,
            user_id: None,
            last_update: Instant::now(),
            remote_message_id: 0,
            local_message_id: 0,
            last_response: None,
            last_request: None,
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
        self.user_id.as_deref()
    }

    pub fn handle_response_expiration(&mut self, now: time::Instant) {
        if self.last_update + IKE_RESPONSE_EXPIRATION < now {
            self.last_response = None;
        }
    }

    pub fn next_retransmission(&self) -> NextRetransmission {
        if self.request_retransmit > IKE_RETRANSMISSIONS_LIMIT {
            return NextRetransmission::Timeout;
        }
        let next_retransmission = 3000 * self.request_retransmit as u64;
        let jitter = next_retransmission * 15 / 100;
        let next_delay = rand::thread_rng().gen_range(
            next_retransmission.saturating_sub(jitter)..=next_retransmission.saturating_add(jitter),
        );
        NextRetransmission::Delay(time::Duration::from_millis(next_delay))
    }

    pub fn process_request(
        &mut self,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        request: &message::InputMessage,
        response: &mut message::MessageWriter,
    ) -> Result<usize, SessionError> {
        // TODO: return error if payload type is critical but not recognized
        self.last_update = Instant::now();
        let message_id = request.read_message_id();
        if message_id < self.remote_message_id {
            // This is an outdated retransmission, nothing to do.
            return Ok(0);
        }
        if message_id == self.remote_message_id {
            // Retransmit last response if available.
            if let Some(last_response) = self.last_response {
                let len = last_response.1;
                response.raw_data_mut()[..len].copy_from_slice(&last_response.0[..len]);
                return Ok(len);
            }
        }

        let exchange_type = request.read_exchange_type()?;

        response.write_header(
            self.session_id.remote_spi,
            self.session_id.local_spi,
            exchange_type,
            false,
            request.read_message_id(),
        )?;

        let response_length = match exchange_type {
            message::ExchangeType::IKE_SA_INIT => self.process_sa_init_request(request, response),
            message::ExchangeType::IKE_AUTH => {
                self.process_auth_request(remote_addr, local_addr, request, response)
            }
            message::ExchangeType::INFORMATIONAL => {
                self.process_informational_request(request, response)
            }
            message::ExchangeType::CREATE_CHILD_SA => {
                self.process_create_child_sa_request(request, response)
            }
            _ => {
                warn!("Unimplemented handler for message {}", exchange_type);
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
        self.remote_message_id = message_id;

        // Update remote address if client changed IP or switched to another NAT port.
        self.remote_addr = remote_addr;
        self.local_addr = local_addr;

        Ok(response_length)
    }

    fn process_encrypted_payload<'a>(
        &self,
        request: &message::InputMessage,
        encrypted_payload: &message::EncryptedMessage,
        decrypted_data: &'a mut [u8],
    ) -> Result<&'a [u8], SessionError> {
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
                info!("Failed to decrypt data: {}", err);
                Err("Failed to decrypt data".into())
            }
        }
    }

    fn complete_encrypted_payload(
        &self,
        response: &mut message::MessageWriter,
    ) -> Result<usize, SessionError> {
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
                    warn!("Failed to encrypt data {}", err);
                    "Failed to encrypt data"
                })?;
        }

        crypto_stack
            .sign(&mut raw_data[..full_message_len])
            .map_err(|err| {
                warn!("Failed to sign data {}", err);
                "Failed to sign data"
            })?;

        Ok(full_message_len)
    }

    fn process_sa_init_request(
        &mut self,
        request: &message::InputMessage,
        response: &mut message::MessageWriter,
    ) -> Result<usize, SessionError> {
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
                    // TODO: return INVALID_SYNTAX notification.
                    info!("Received invalid payload: {}", err);
                    continue;
                }
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
                            warn!("No compatible SA parameters found");
                            // TODO: return NO_PROPOSAL_CHOSEN notification.
                            continue;
                        };
                    let accept_proposal = [(proposal_num, &prop)];
                    response.write_security_association(&accept_proposal)?;
                    match prop.create_dh() {
                        Ok(dh) => dh_transform = Some(dh),
                        Err(err) => {
                            warn!("Failed to init DH: {}", err)
                        }
                    }
                    self.params = Some(prop);
                }
                message::PayloadType::KEY_EXCHANGE => {
                    let kex = payload.to_key_exchange()?;
                    if let Some(ref mut dh) = dh_transform.as_mut() {
                        let public_key = dh.read_public_key();
                        shared_secret = match dh.compute_shared_secret(kex.read_value()) {
                            Ok(shared_secret) => Some(shared_secret),
                            Err(err) => {
                                // TODO: return INVALID_KE_PAYLOAD notification.
                                warn!("Failed to compute shared secret: {}", err);
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
                        .copy_from_slice(&self.session_id.remote_spi.to_be_bytes());
                    prf_key_cursor += 8;
                    prf_key[prf_key_cursor..prf_key_cursor + 8]
                        .copy_from_slice(&self.session_id.local_spi.to_be_bytes());

                    let params = if let Some(params) = self.params.as_ref() {
                        params
                    } else {
                        warn!("Unspecified transform parametes");
                        // TODO: return INVALID_SYNTAX notification.
                        continue;
                    };
                    let prf_transform = match params
                        .create_prf(&prf_key[0..nonce_remote.len() + nonce_local.len()])
                    {
                        Ok(prf) => prf,
                        Err(err) => {
                            warn!("Failed to init PRF transform for SKEYSEED: {}", err);
                            // TODO: return NO_PROPOSAL_CHOSEN notification.
                            continue;
                        }
                    };
                    let shared_secret = if let Some(ref shared_secret) = shared_secret {
                        shared_secret
                    } else {
                        warn!("Unspecified shared secret");
                        // TODO: return NO_PROPOSAL_CHOSEN notification.
                        continue;
                    };
                    let skeyseed = prf_transform.prf(shared_secret.as_slice());
                    let prf_transform = match params.create_prf(skeyseed.as_slice()) {
                        Ok(prf) => prf,
                        Err(err) => {
                            warn!("Failed to init PRF transform for keying material: {}", err);
                            // TODO: return NO_PROPOSAL_CHOSEN notification.
                            continue;
                        }
                    };
                    match prf_transform.create_crypto_stack(params, &prf_key) {
                        Ok(crypto_stack) => self.crypto_stack = Some(crypto_stack),
                        Err(err) => {
                            warn!("Failed to set up cryptography stack: {}", err);
                            // TODO: return INVALID_SYNTAX notification.
                            continue;
                        }
                    };
                    let dest = response
                        .next_payload_slice(message::PayloadType::NONCE, nonce_local.len())?;
                    dest.copy_from_slice(nonce_local);
                }
                message::PayloadType::NOTIFY => {
                    let notify = payload.to_notify()?;
                    if notify.message_type()
                        == message::NotifyMessageType::SIGNATURE_HASH_ALGORITHMS
                    {
                        let supports_sha256 = notify
                            .to_signature_hash_algorithms()?
                            .any(|alg| alg == message::SignatureHashAlgorithm::SHA2_256);
                        if !supports_sha256 {
                            // TODO: return NO_PROPOSAL_CHOSEN notification.
                            return Err("No supported signature hash algorithms".into());
                        }
                    }
                }
                _ => {
                    if payload.is_critical() {
                        warn!(
                            "Received critical, unsupported payload: {}",
                            payload.payload_type()
                        );
                        // TODO: return UNSUPPORTED_CRITICAL_PAYLOAD.
                        return Err("Received critical, unsupported payload".into());
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
            // TODO: return INVALID_SYNTAX notification.
            return Err("Initiator didn't provide nonce".into());
        };
        let nonce_responder = if let Some(nonce) = nonce_responder {
            nonce
        } else {
            // TODO: return INVALID_SYNTAX notification.
            return Err("No nonce provided in response".into());
        };

        response.write_notify_payload(
            None,
            &[],
            message::NotifyMessageType::NAT_DETECTION_DESTINATION_IP,
            &nat_ip,
        )?;

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

        Ok(response_length)
    }

    fn process_auth_request(
        &mut self,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        request: &message::InputMessage,
        response: &mut message::MessageWriter,
    ) -> Result<usize, SessionError> {
        self.pending_actions
            .push(IKEv2PendingAction::DeleteHalfOpenSession(
                self.remote_addr,
                self.session_id.remote_spi,
            ));
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
            let payload = match payload {
                Ok(payload) => payload,
                Err(err) => {
                    // TODO: return INVALID_SYNTAX notification.
                    warn!("Received invalid payload: {}", err);
                    continue;
                }
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
                    warn!("Failed to read decrypted payload data: {}", err);
                    // TODO: return INVALID_SYNTAX notification.
                    continue;
                }
            };
            trace!("Decrypted payload\n {:?}", payload);
            match payload.payload_type() {
                message::PayloadType::CERTIFICATE => {
                    let certificate = payload.to_certificate()?;
                    if certificate.encoding() != message::CertificateEncoding::X509_SIGNATURE {
                        warn!(
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
                            warn!("Certificate is not valid: {}", err);
                        }
                    };
                }
                message::PayloadType::CERTIFICATE_REQUEST => {
                    let certreq = payload.to_certificate_request()?;
                    if certreq.read_encoding() != message::CertificateEncoding::X509_SIGNATURE {
                        warn!(
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
                            warn!("No certificates found for client's certificate request",);
                        }
                    };
                }
                message::PayloadType::ID_INITIATOR => {
                    let id = payload.to_identification()?;
                    id_initiator = Some(id.raw_value().to_vec());
                }
                message::PayloadType::AUTHENTICATION => {
                    let auth = payload.to_authentication()?;
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
                            return self.process_auth_failed_response(
                                response,
                                "Authentication method is unsupported".into(),
                            );
                        }
                    }
                }
                message::PayloadType::SECURITY_ASSOCIATION => {
                    let sa = payload.to_security_association()?;
                    transform_params = crypto::choose_sa_parameters(&sa);
                    if transform_params.is_none() {
                        warn!("No compatible SA parameters found");
                        continue;
                    };
                }
                message::PayloadType::TRAFFIC_SELECTOR_INITIATOR => {
                    let ts = payload
                        .to_traffic_selector()?
                        .iter_traffic_selectors()
                        .collect::<Result<Vec<_>, message::FormatError>>()
                        .map_err(|err| {
                            warn!("Failed to decode initiator traffic selectors: {}", err);
                            err
                        });
                    if let Ok(mut ts) = ts {
                        ts.retain(|ts| {
                            ts.ts_type() == message::TrafficSelectorType::TS_IPV4_ADDR_RANGE
                        });
                        ts_remote = ts
                    }
                }
                message::PayloadType::TRAFFIC_SELECTOR_RESPONDER => {
                    let ts = payload
                        .to_traffic_selector()?
                        .iter_traffic_selectors()
                        .collect::<Result<Vec<_>, message::FormatError>>()
                        .map_err(|err| {
                            warn!("Failed to decode responder traffic selectors: {}", err);
                            err
                        });
                    if let Ok(mut ts) = ts {
                        ts.retain(|ts| {
                            ts.ts_type() == message::TrafficSelectorType::TS_IPV4_ADDR_RANGE
                        });
                        ts_local = ts
                    }
                }
                message::PayloadType::CONFIGURATION => {
                    ipv4_address_requested =
                        payload.to_configuration()?.iter_attributes().any(|attr| {
                            let attr = match attr {
                                Ok(attr) => attr,
                                Err(err) => {
                                    warn!("Failed to decode configuration attribute: {}", err);
                                    return false;
                                }
                            };
                            attr.attribute_type()
                                == message::ConfigurationAttributeType::INTERNAL_IP4_ADDRESS
                        })
                }
                _ => {
                    if payload.is_critical() {
                        warn!(
                            "Received critical, unsupported payload: {}",
                            payload.payload_type()
                        );
                        // TODO: return UNSUPPORTED_CRITICAL_PAYLOAD.
                        return Err("Received critical, unsupported payload".into());
                    }
                }
            }
        }

        let client_cert = if let Some(cert) = client_cert {
            cert
        } else {
            return self.process_auth_failed_response(response, "Client provided no cert".into());
        };
        let (client_auth, signature_format) = if let Some(auth) = client_auth {
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
        // TODO: use the client's IP address.
        if let Err(err) = ts_local
            .iter_mut()
            .try_for_each(|ts| ts.set_to_address(self.internal_addr))
        {
            // TODO: return TS_UNACCEPTABLE notification.
            warn!("Failed to narrow traffic selector: {}", err);
            return Err("Failed to narrow traffic selector".into());
        }

        let local_spi = rand::thread_rng().gen::<u32>();
        transform_params.set_local_spi(message::Spi::U32(local_spi));
        let remote_spi = match transform_params.remote_spi() {
            message::Spi::U32(remote_spi) => remote_spi,
            _ => return Err("Security Association has unsupported remote SPI type".into()),
        };

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
            warn!("Client authentication failed: {}", err);
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
            response.write_configuration_payload(self.internal_addr)?;
        }

        let child_crypto_stack = match crypto_stack.create_child_stack(
            &transform_params,
            false,
            [ctx.nonce_initiator, ctx.nonce_responder]
                .concat()
                .as_slice(),
        ) {
            Ok(crypto_stack) => crypto_stack,
            Err(err) => {
                warn!("Failed to set up child SA cryptography stack: {}", err);
                // TODO: return INVALID_SYNTAX notification.
                return Err("Failed to set up child SA cryptography stack".into());
            }
        };

        let accept_proposal = [(proposal_num, &transform_params)];
        response.write_security_association(&accept_proposal)?;

        // TODO: will macOS or Windows accept more traffic selectors?
        response.write_traffic_selector_payload(true, &ts_remote)?;
        response.write_traffic_selector_payload(false, &ts_local)?;

        let child_sa = ChildSA {
            local_spi,
            remote_spi,
            ts_local: ts_local.clone(),
            ts_remote: ts_remote.clone(),
        };
        self.child_sas.push(child_sa);

        let child_sa = esp::SecurityAssociation::new(
            ts_local,
            ts_remote,
            local_addr,
            remote_addr,
            child_crypto_stack,
            &transform_params,
        );
        self.pending_actions
            .push(IKEv2PendingAction::CreateChildSA(local_spi, child_sa));
        self.pending_actions
            .push(IKEv2PendingAction::UpdateSplitRoutes);

        self.complete_encrypted_payload(response)
    }

    fn process_auth_failed_response(
        &self,
        response: &mut message::MessageWriter,
        _err: SessionError,
    ) -> Result<usize, SessionError> {
        response.start_encrypted_payload()?;

        response.write_notify_payload(
            None,
            &[],
            message::NotifyMessageType::AUTHENTICATION_FAILED,
            &[],
        )?;

        self.complete_encrypted_payload(response)
    }

    fn process_informational_request(
        &mut self,
        request: &message::InputMessage,
        response: &mut message::MessageWriter,
    ) -> Result<usize, SessionError> {
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

        let mut delete_spi = vec![];

        let decrypted_iter = if let Some(decrypted_iter) = decrypted_iter {
            decrypted_iter
        } else {
            // TODO: return INVALID_SYNTAX notification.
            // INFORMATIONAL payload is supposed to have an encrypted payload.
            return Ok(response.complete_message());
        };
        for payload in decrypted_iter {
            let payload = match payload {
                Ok(payload) => payload,
                Err(err) => {
                    warn!("Failed to read decrypted payload data: {}", err);
                    // TODO: return INVALID_SYNTAX notification.
                    continue;
                }
            };
            trace!("Decrypted payload\n {:?}", payload);
            match payload.payload_type() {
                message::PayloadType::DELETE => {
                    let delete = payload.to_delete()?;
                    delete_spi = delete.iter_spi().collect::<Vec<_>>();
                }
                _ => {
                    if payload.is_critical() {
                        warn!(
                            "Received critical, unsupported payload: {}",
                            payload.payload_type()
                        );
                        // TODO: return UNSUPPORTED_CRITICAL_PAYLOAD.
                        return Err("Received critical, unsupported payload".into());
                    }
                }
            }
        }

        // For now, no data is processed.
        response.start_encrypted_payload()?;

        if !delete_spi.is_empty() {
            // TODO: process deletion of child SAs.
            response.write_notify_payload(
                None,
                &[],
                message::NotifyMessageType::CHILD_SA_NOT_FOUND,
                &[],
            )?;
        } else {
            self.pending_actions
                .push(IKEv2PendingAction::DeleteIKESession);
        }

        self.complete_encrypted_payload(response)
    }

    fn process_create_child_sa_request(
        &mut self,
        request: &message::InputMessage,
        response: &mut message::MessageWriter,
    ) -> Result<usize, SessionError> {
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
            // CREATE_CHILD_SA payload is supposed to have an encrypted payload.
            return Ok(response.complete_message());
        };
        for payload in decrypted_iter {
            let payload = match payload {
                Ok(payload) => payload,
                Err(err) => {
                    warn!("Failed to read decrypted payload data: {}", err);
                    // TODO: return INVALID_SYNTAX notification.
                    continue;
                }
            };
            trace!("Decrypted payload\n {:?}", payload);
            match payload.payload_type() {
                _ => {
                    if payload.is_critical() {
                        warn!(
                            "Received critical, unsupported payload: {}",
                            payload.payload_type()
                        );
                        // TODO: return UNSUPPORTED_CRITICAL_PAYLOAD.
                        return Err("Received critical, unsupported payload".into());
                    }
                }
            }
        }

        // For now, no data is processed.
        response.start_encrypted_payload()?;

        self.complete_encrypted_payload(response)
    }

    pub fn take_pending_actions(&mut self) -> Vec<IKEv2PendingAction> {
        self.pending_actions.drain(..).collect::<Vec<_>>()
    }

    pub fn is_deleting_request(&mut self) -> bool {
        match self.sent_request {
            Some(RequestContext::DeleteIKEv2) => true,
            _ => false,
        }
    }

    fn start_request(
        &mut self,
        exchange_type: message::ExchangeType,
        command_generator: impl FnOnce(&mut message::MessageWriter) -> Result<(), SessionError>,
    ) -> Result<u32, SessionError> {
        if self.sent_request.is_some() || self.last_request.is_some() {
            return Err("Already processing another command".into());
        }
        let mut request_bytes = [0u8; MAX_DATAGRAM_SIZE];
        // Requests will always be sent to the ESP port.
        let start_offset = if self.remote_addr.port() == IKEV2_NAT_PORT {
            4
        } else {
            0
        };
        let mut ikev2_request = message::MessageWriter::new(&mut request_bytes[start_offset..])?;
        ikev2_request.write_header(
            self.session_id.remote_spi,
            self.session_id.local_spi,
            exchange_type,
            true,
            self.local_message_id,
        )?;
        ikev2_request.start_encrypted_payload()?;
        command_generator(&mut ikev2_request)?;
        let request_len = self.complete_encrypted_payload(&mut ikev2_request)?;

        self.last_request = Some((request_bytes, request_len + start_offset));
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

    pub fn update_split_routes(
        &mut self,
        tunnel_ips: &[IpAddr],
    ) -> Result<Option<u32>, SessionError> {
        match self.state {
            SessionState::Empty | SessionState::InitSA(_) | SessionState::Deleting => {
                return Err(
                    "Received Update Spit Routes action for a non-established session, ignoring"
                        .into(),
                );
            }
            SessionState::Established => {}
        }

        let next_ip = tunnel_ips
            .iter()
            .filter_map(|tunnel_ip| {
                let addr = SocketAddr::from((tunnel_ip.clone(), 0));
                if !self
                    .child_sas
                    .iter()
                    .any(|child_sa| child_sa.accepts(&addr))
                {
                    Some(tunnel_ip)
                } else {
                    None
                }
            })
            .next();
        let full_ts = message::TrafficSelector::from_ip_range(
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))..=IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
        )?;
        let accepts_all_traffic = self.child_sas.iter().any(|child_sa| {
            child_sa
                .ts_local
                .iter()
                .any(|ts_local| *ts_local == full_ts)
        });
        // Prepare create_child_sa request.
        let next_ts = if let Some(next_ip) = next_ip {
            message::TrafficSelector::from_ip_range(*next_ip..=*next_ip)?
        } else if tunnel_ips.is_empty() && !accepts_all_traffic {
            full_ts.clone()
        } else {
            // There's a traffic selector for every tunneled IP.
            return Ok(None);
        };
        let mut nonce_local = [0u8; MAX_NONCE];
        rand::thread_rng().fill(nonce_local.as_mut_slice());
        let local_spi = rand::thread_rng().gen::<u32>();
        let transform_parameters = crypto::offer_esp_sa_parameters(local_spi);
        let transform_params = transform_parameters
            .iter()
            .enumerate()
            .map(|(proposal_num, params)| (proposal_num as u8 + 1, params))
            .collect::<Vec<_>>();

        let message_id = self.start_request(message::ExchangeType::CREATE_CHILD_SA, |writer| {
            writer.write_security_association(&transform_params)?;

            let dest = writer.next_payload_slice(message::PayloadType::NONCE, nonce_local.len())?;
            dest.copy_from_slice(nonce_local.as_slice());

            writer.write_traffic_selector_payload(true, &[next_ts.clone()])?;
            Ok(writer.write_traffic_selector_payload(false, &[full_ts])?)
        })?;
        self.sent_request = Some(RequestContext::CreateChildSA(
            transform_parameters,
            nonce_local,
            local_spi,
        ));
        Ok(Some(message_id))
    }

    pub async fn send_last_request(
        &mut self,
        sockets: &Sockets,
        message_id: u32,
    ) -> Result<(), SendError> {
        if message_id != self.local_message_id {
            return Ok(());
        }
        if let Some((request_bytes, request_len)) = self.last_request {
            debug!(
                "Transmitting request {} for session {}",
                self.local_message_id, self.session_id
            );
            self.request_retransmit += 1;
            sockets
                .send_datagram(
                    &self.local_addr,
                    &self.remote_addr,
                    &request_bytes[..request_len],
                )
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
        // TODO: return error if payload type is critical but not recognized
        self.last_update = Instant::now();
        let message_id = response.read_message_id();
        if message_id < self.local_message_id {
            // This is an outdated retransmission, nothing to do.
            return Ok(());
        }

        let mut decrypted_data = [0u8; MAX_ENCRYPTED_DATA_SIZE];
        let mut decrypted_iter = None;
        for payload in response.iter_payloads() {
            let payload = if let Ok(payload) = payload {
                payload
            } else {
                // TODO: return INVALID_SYNTAX notification.
                continue;
            };
            if payload.payload_type() == message::PayloadType::ENCRYPTED_AND_AUTHENTICATED {
                let encrypted_payload = payload.encrypted_data()?;
                let decrypted_slice = self.process_encrypted_payload(
                    response,
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
            // Responses are always sent encrypted.
            return Err("Response has no encrypted payload".into());
        };

        let exchange_type = response.read_exchange_type()?;
        match exchange_type {
            message::ExchangeType::INFORMATIONAL => {
                self.process_informational_response(decrypted_iter)
            }
            message::ExchangeType::CREATE_CHILD_SA => {
                self.process_create_child_sa_response(decrypted_iter)
            }
            _ => {
                warn!(
                    "Unimplemented response handler for message {}",
                    exchange_type
                );
                Err("Unimplemented response message".into())
            }
        }?;

        // Remove last request to stop retransmissions.
        self.local_message_id += 1;
        self.last_request = None;
        self.sent_request = None;
        self.request_retransmit = 0;

        // Update remote address if client changed IP or switched to another NAT port.
        self.remote_addr = remote_addr;
        self.local_addr = local_addr;

        Ok(())
    }

    fn process_informational_response(
        &mut self,
        payloads: message::PayloadIter,
    ) -> Result<(), SessionError> {
        for payload in payloads {
            let payload = match payload {
                Ok(payload) => payload,
                Err(err) => {
                    warn!("Failed to read decrypted payload data: {}", err);
                    // TODO: return INVALID_SYNTAX notification.
                    continue;
                }
            };
            trace!("Decrypted payload\n {:?}", payload);
            match payload.payload_type() {
                _ => {
                    if payload.is_critical() {
                        warn!(
                            "Received critical, unsupported payload: {}",
                            payload.payload_type()
                        );
                        // TODO: return UNSUPPORTED_CRITICAL_PAYLOAD.
                        return Err("Received critical, unsupported payload".into());
                    }
                }
            }
        }
        let sent_request = self.sent_request.take();
        match sent_request {
            Some(RequestContext::DeleteIKEv2) => {
                self.pending_actions
                    .push(IKEv2PendingAction::DeleteIKESession);
            }
            Some(RequestContext::CreateChildSA(_, _, _)) => {
                return Err("INFORMATIONAL response received, was expecting CREATE_CHILD_SA".into())
            }
            None => {
                return Err("Received response for a non-existing request".into());
            }
        }
        Ok(())
    }

    fn process_create_child_sa_response(
        &mut self,
        payloads: message::PayloadIter,
    ) -> Result<(), SessionError> {
        let crypto_stack = if let Some(crypto_stack) = self.crypto_stack.as_ref() {
            crypto_stack
        } else {
            return Err("Crypto stack not initialized".into());
        };
        let (offered_params, nonce_initiator, local_spi) = match self.sent_request {
            Some(RequestContext::CreateChildSA(ref offered_params, ref nonce_local, local_spi)) => {
                (offered_params, nonce_local, local_spi)
            }
            Some(RequestContext::DeleteIKEv2) => {
                return Err("CREATE_CHILD_SA response received, was expecting INFORMATIONAL".into())
            }
            None => {
                return Err("Received response for a non-existing request".into());
            }
        };
        let mut transform_params = None;
        let mut nonce_responder = None;
        let mut ts_remote = vec![];
        let mut ts_local = vec![];
        for payload in payloads {
            let payload = match payload {
                Ok(payload) => payload,
                Err(err) => {
                    warn!("Failed to read decrypted payload data: {}", err);
                    continue;
                }
            };
            trace!("Decrypted payload\n {:?}", payload);
            match payload.payload_type() {
                message::PayloadType::SECURITY_ASSOCIATION => {
                    let sa = payload.to_security_association()?;
                    let prop = if let Some(transform) =
                        crypto::confirm_accepted_proposal(offered_params, &sa)
                    {
                        transform
                    } else {
                        warn!("No proposals accepted by remote side");
                        continue;
                    };
                    transform_params = Some(prop);
                }
                message::PayloadType::NONCE => {
                    let nonce = payload.to_nonce()?;
                    nonce_responder = Some(nonce.read_value().to_vec());
                }
                message::PayloadType::TRAFFIC_SELECTOR_INITIATOR => {
                    let ts = payload
                        .to_traffic_selector()?
                        .iter_traffic_selectors()
                        .collect::<Result<Vec<_>, message::FormatError>>()
                        .map_err(|err| {
                            warn!("Failed to decode initiator traffic selectors: {}", err);
                            err
                        });
                    if let Ok(mut ts) = ts {
                        ts.retain(|ts| {
                            ts.ts_type() == message::TrafficSelectorType::TS_IPV4_ADDR_RANGE
                        });
                        ts_local = ts
                    }
                }
                message::PayloadType::TRAFFIC_SELECTOR_RESPONDER => {
                    let ts = payload
                        .to_traffic_selector()?
                        .iter_traffic_selectors()
                        .collect::<Result<Vec<_>, message::FormatError>>()
                        .map_err(|err| {
                            warn!("Failed to decode responder traffic selectors: {}", err);
                            err
                        });
                    if let Ok(mut ts) = ts {
                        ts.retain(|ts| {
                            ts.ts_type() == message::TrafficSelectorType::TS_IPV4_ADDR_RANGE
                        });
                        ts_remote = ts
                    }
                }
                _ => {
                    if payload.is_critical() {
                        warn!(
                            "Received critical, unsupported payload: {}",
                            payload.payload_type()
                        );
                        // TODO: return UNSUPPORTED_CRITICAL_PAYLOAD.
                        return Err("Received critical, unsupported payload".into());
                    }
                }
            }
        }

        let transform_params = if let Some(params) = transform_params {
            params
        } else {
            return Err("Unacceptable Security Association proposals".into());
        };
        let remote_spi = match transform_params.remote_spi() {
            message::Spi::U32(remote_spi) => remote_spi,
            _ => return Err("Security Association has unsupported remote SPI type".into()),
        };
        let nonce_responder = if let Some(nonce) = nonce_responder {
            nonce
        } else {
            return Err("No nonce provided in response".into());
        };
        let child_crypto_stack = match crypto_stack.create_child_stack(
            &transform_params,
            true,
            [nonce_initiator, nonce_responder.as_slice()]
                .concat()
                .as_slice(),
        ) {
            Ok(crypto_stack) => crypto_stack,
            Err(err) => {
                warn!("Failed to set up child SA cryptography stack: {}", err);
                return Err("Failed to set up child SA cryptography stack".into());
            }
        };
        let child_sa = ChildSA {
            local_spi,
            remote_spi,
            ts_local: ts_local.clone(),
            ts_remote: ts_remote.clone(),
        };
        self.child_sas.push(child_sa);

        let child_sa = esp::SecurityAssociation::new(
            ts_local,
            ts_remote,
            self.local_addr,
            self.remote_addr,
            child_crypto_stack,
            &transform_params,
        );
        self.pending_actions
            .push(IKEv2PendingAction::CreateChildSA(local_spi, child_sa));
        self.pending_actions
            .push(IKEv2PendingAction::UpdateSplitRoutes);

        Ok(())
    }
}

pub enum RequestContext {
    DeleteIKEv2,
    CreateChildSA(Vec<crypto::TransformParameters>, [u8; MAX_NONCE], u32),
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

struct ChildSA {
    local_spi: u32,
    remote_spi: u32,
    ts_local: Vec<message::TrafficSelector>,
    ts_remote: Vec<message::TrafficSelector>,
}

impl ChildSA {
    fn accepts(&self, addr: &SocketAddr) -> bool {
        esp::ts_accepts(&self.ts_local, addr)
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
        match *self {
            Self::Internal(msg) => f.write_str(msg),
            Self::Format(ref e) => write!(f, "Format error: {}", e),
            Self::NotEnoughSpace(_) => write!(f, "Not enough space error"),
            Self::CryptoInit(ref e) => write!(f, "Crypto init error: {}", e),
            Self::CertError(ref e) => write!(f, "PKI cert error: {}", e),
        }
    }
}

impl error::Error for SessionError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Self::Internal(_msg) => None,
            Self::Format(ref err) => Some(err),
            Self::NotEnoughSpace(ref err) => Some(err),
            Self::CryptoInit(ref err) => Some(err),
            Self::CertError(ref err) => Some(err),
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
