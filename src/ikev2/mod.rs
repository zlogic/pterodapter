use log::{debug, info, trace, warn};
use rand::Rng;
use std::{
    collections::{self, HashMap},
    error, fmt, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, runtime, sync::mpsc, task::JoinHandle, time};

mod crypto;
mod esp;
mod message;
mod pki;
mod session;

const IKEV2_PORT: u16 = 500;
const IKEV2_NAT_PORT: u16 = 4500;
const IKEV2_LISTEN_PORTS: [u16; 2] = [IKEV2_PORT, IKEV2_NAT_PORT];

// TODO: for Windows, add IKEV2_FRAGMENTATION_SUPPORTED support. Otherwise, UDP fragmentation will be used to transmit larger packets.
const MAX_DATAGRAM_SIZE: usize = 4096;

const IKE_INIT_SA_EXPIRATION: Duration = Duration::from_secs(15);

pub struct Config {
    pub listen_ips: Vec<IpAddr>,
    pub hostname: Option<String>,
    pub root_ca: Option<String>,
    pub server_cert: Option<(String, String)>,
}

pub struct Server {
    listen_ips: Vec<IpAddr>,
    pki_processing: Arc<pki::PkiProcessing>,
    command_sender: Option<mpsc::Sender<SessionMessage>>,
    handles: Vec<JoinHandle<Result<(), IKEv2Error>>>,
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
            command_sender: None,
            handles: vec![],
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

    pub async fn terminate(&mut self) -> Result<(), IKEv2Error> {
        match self.command_sender {
            Some(ref command_sender) => {
                if command_sender.send(SessionMessage::Shutdown).await.is_err() {
                    return Err("Command channel closed".into());
                }
            }
            None => return Err("Shutdown already in progress".into()),
        }
        for handle in self.handles.drain(..self.handles.len()) {
            if let Err(err) = handle.await {
                warn!("Error returned when shutting down: {}", err);
            }
        }
        Ok(())
    }

    pub async fn start(&mut self) -> Result<(), IKEv2Error> {
        let sockets = Arc::new(Sockets::new(&self.listen_ips).await?);
        let mut sessions = Sessions::new(self.pki_processing.clone(), sockets.clone());
        let rt = runtime::Handle::current();
        // Non-critical futures sockets will be terminated by Tokio during the shutdown_timeout phase.
        sockets.iter_sockets().for_each(|(listen_addr, socket)| {
            rt.spawn(Server::listen_socket(
                socket.clone(),
                *listen_addr,
                sessions.create_sender(),
            ));
        });
        rt.spawn(Server::send_timer_ticks(
            Duration::from_secs(15),
            sessions.create_sender(),
        ));
        self.command_sender = Some(sessions.create_sender());
        self.handles = vec![rt.spawn(async move { sessions.process_messages().await })];
        Ok(())
    }
}

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
    ) -> Result<(), SendError> {
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

struct UdpDatagram {
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    request: Vec<u8>,
}

impl UdpDatagram {
    fn is_non_esp(&self) -> bool {
        self.request.len() >= 4 && self.request[0..4] == [0x00, 0x00, 0x00, 0x00]
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
    RetransmitRequest(session::SessionID, u32),
    CleanupTimer,
    Shutdown,
}

struct Sessions {
    pki_processing: Arc<pki::PkiProcessing>,
    sockets: Arc<Sockets>,
    sessions: HashMap<session::SessionID, session::IKEv2Session>,
    security_associations: HashMap<esp::SecurityAssociationID, esp::SecurityAssociation>,
    half_sessions: HashMap<(SocketAddr, u64), (u64, Instant)>,
    tx: mpsc::Sender<SessionMessage>,
    rx: mpsc::Receiver<SessionMessage>,
    shutdown: bool,
}

impl Sessions {
    fn new(pki_processing: Arc<pki::PkiProcessing>, sockets: Arc<Sockets>) -> Sessions {
        let (tx, rx) = mpsc::channel(100);
        Sessions {
            pki_processing,
            sockets,
            sessions: HashMap::new(),
            security_associations: HashMap::new(),
            half_sessions: HashMap::new(),
            tx,
            rx,
            shutdown: false,
        }
    }

    fn create_sender(&self) -> mpsc::Sender<SessionMessage> {
        self.tx.clone()
    }

    fn get_init_session(
        &mut self,
        remote_spi: u64,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> session::SessionID {
        let now = Instant::now();
        let half_key = (remote_addr, remote_spi);
        let new_session_id = (rand::thread_rng().gen::<u64>(), now);
        let existing_half_session = self
            .half_sessions
            .entry(half_key)
            .and_modify(|existing| {
                if existing.1 + IKE_INIT_SA_EXPIRATION < now {
                    // Already expired, should switch to new generated session ID.
                    *existing = new_session_id
                }
            })
            .or_insert_with(|| new_session_id);
        let session_id = session::SessionID::new(remote_spi, existing_half_session.0);
        // TODO: get address from FortiVPN, or through a custom config variable.
        let internal_addr = IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10));
        self.sessions.entry(session_id).or_insert_with(|| {
            session::IKEv2Session::new(
                session_id,
                remote_addr,
                local_addr,
                internal_addr,
                self.pki_processing.clone(),
            )
        });
        session_id
    }

    fn get(&mut self, id: session::SessionID) -> Option<&mut session::IKEv2Session> {
        self.sessions.get_mut(&id)
    }

    async fn cleanup(&mut self) {
        let now = Instant::now();
        self.half_sessions
            .retain(|(remote_addr, remote_spi), (_, expires_at)| {
                if *expires_at + IKE_INIT_SA_EXPIRATION < now {
                    info!(
                        "Deleting expired init session {} (SPI {:x})",
                        remote_addr, remote_spi
                    );
                    false
                } else {
                    true
                }
            });
        self.sessions.retain(|session_id, session| {
            if session.is_expired(now) {
                info!(
                    "Deleting expired session with SPI {} {:?}",
                    session_id,
                    session.user_id().unwrap_or("Unknown")
                );
                false
            } else {
                true
            }
        });
        self.sessions.values_mut().for_each(|session| {
            session.handle_response_expiration(now);
        });
        if self.shutdown {
            for (session_id, session) in self.sessions.iter_mut() {
                if session.is_deleting_request() {
                    continue;
                }
                let message_id = match session.start_request_delete_ike() {
                    Ok(message_id) => message_id,
                    Err(err) => {
                        warn!(
                            "Failed to prepare Delete request to session {}: {}",
                            session_id, err
                        );
                        continue;
                    }
                };
                if let Err(err) = session.send_last_request(&self.sockets, message_id).await {
                    warn!(
                        "Failed to send Delete request to session {}: {}",
                        session_id, err
                    );
                }
                let _ = self
                    .tx
                    .send(SessionMessage::RetransmitRequest(*session_id, message_id))
                    .await;
            }
        }
    }

    async fn process_messages(&mut self) -> Result<(), IKEv2Error> {
        while let Some(message) = self.rx.recv().await {
            match message {
                SessionMessage::UdpDatagram(mut datagram) => {
                    if let Err(err) = self.process_datagram(&mut datagram).await {
                        warn!(
                            "Failed to process message from {}: {}",
                            datagram.remote_addr, err
                        );
                    }
                }
                SessionMessage::CleanupTimer => {
                    self.cleanup().await;
                }
                SessionMessage::RetransmitRequest(session_id, message_id) => {
                    self.retransmit_request(session_id, message_id).await;
                }
                SessionMessage::Shutdown => {
                    self.shutdown = true;
                    self.cleanup().await;
                }
            }
            if self.shutdown && self.sessions.is_empty() {
                break;
            }
        }
        debug!("Shutdown completed");
        Ok(())
    }

    async fn process_datagram(&mut self, datagram: &mut UdpDatagram) -> Result<(), IKEv2Error> {
        if datagram.is_ikev2() {
            self.process_ikev2_message(datagram).await
        } else {
            self.process_esp_packet(datagram).await
        }
    }

    async fn process_ikev2_message(
        &mut self,
        datagram: &mut UdpDatagram,
    ) -> Result<(), IKEv2Error> {
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
            if self.shutdown {
                return Err(
                    "Ignoring IKE_SA_INIT request, because a shutdown is in progress".into(),
                );
            }
            self.get_init_session(
                ikev2_request.read_initiator_spi(),
                datagram.remote_addr,
                datagram.local_addr,
            )
        } else {
            session::SessionID::from_message(&ikev2_request)?
        };
        let session = if let Some(session) = self.get(session_id) {
            session
        } else {
            return Err("Session not found".into());
        };
        let mut response_bytes = [0u8; MAX_DATAGRAM_SIZE];
        let start_offset = if datagram.is_non_esp() { 4 } else { 0 };

        if ikev2_request.read_flags()?.has(message::Flags::RESPONSE) {
            session.process_response(datagram.remote_addr, datagram.local_addr, &ikev2_request)?;
        } else {
            let mut ikev2_response =
                message::MessageWriter::new(&mut response_bytes[start_offset..])?;

            let response_len = session.process_request(
                datagram.remote_addr,
                datagram.local_addr,
                &ikev2_request,
                &mut ikev2_response,
            )?;

            let response_bytes = &response_bytes[..response_len + start_offset];

            // Response retransmissions are initiated by client.
            if !response_bytes.is_empty() {
                self.sockets
                    .send_datagram(&datagram.local_addr, &datagram.remote_addr, response_bytes)
                    .await?;
            }
        }

        self.process_pending_actions(session_id);

        Ok(())
    }

    fn process_pending_actions(&mut self, session_id: session::SessionID) {
        let session = if let Some(session_id) = self.sessions.get_mut(&session_id) {
            session_id
        } else {
            warn!(
                "Failed to find IKEv2 session {} to process pending actions",
                session_id
            );
            return;
        };

        let mut delete_session = false;
        session
            .take_pending_actions()
            .into_iter()
            .for_each(|action| match action {
                session::IKEv2PendingAction::DeleteHalfOpenSession(remote_addr, remote_spi) => {
                    if self
                        .half_sessions
                        .remove(&(remote_addr, remote_spi))
                        .is_some()
                    {
                        debug!(
                            "Cleaned up completed init session {} (SPI {:x})",
                            remote_addr, remote_spi
                        );
                    }
                }
                session::IKEv2PendingAction::CreateChildSA(session_id, security_association) => {
                    self.security_associations
                        .insert(session_id, security_association);
                }
                session::IKEv2PendingAction::DeleteIKESession => {
                    // TODO: also delete Child SAs (have IKE send IKEv2PendingAction per child SA?).
                    delete_session = true;
                }
            });
        if delete_session && self.sessions.remove(&session_id).is_some() {
            info!("Deleted IKEv2 session {}", session_id);
        }
    }

    async fn retransmit_request(&mut self, session_id: session::SessionID, message_id: u32) {
        let session = if let Some(session) = self.sessions.get_mut(&session_id) {
            session
        } else {
            return;
        };
        if let Err(err) = session.send_last_request(&self.sockets, message_id).await {
            warn!(
                "Failed to retransmit last reqeust to session {}: {}",
                session_id, err
            );
        }
        match session.next_retransmission() {
            session::NextRetransmission::Timeout => {
                warn!("Session {} reached retrasmission limit", session_id);
            }
            session::NextRetransmission::Delay(delay) => {
                Self::schedule_retransmission(self.tx.clone(), session_id, message_id, delay).await
            }
        }
    }

    async fn schedule_retransmission(
        tx: mpsc::Sender<SessionMessage>,
        session_id: session::SessionID,
        message_id: u32,
        delay: time::Duration,
    ) {
        let rt = runtime::Handle::current();
        rt.spawn(async move {
            time::sleep(delay).await;
            tx.send(SessionMessage::RetransmitRequest(session_id, message_id))
                .await
        });
    }

    async fn process_esp_packet(&mut self, datagram: &mut UdpDatagram) -> Result<(), IKEv2Error> {
        let packet_bytes = datagram.request.as_mut_slice();
        if packet_bytes == [0xff] {
            debug!("Received ESP NAT keepalive from {}", datagram.remote_addr);
            return Ok(self
                .sockets
                .send_datagram(&datagram.local_addr, &datagram.remote_addr, &[0xff])
                .await?);
        }
        debug!(
            "Received ESP packet from {}\n{:?}",
            datagram.remote_addr, packet_bytes,
        );
        if packet_bytes.len() < 8 {
            return Err("Not enough data in ESP packet".into());
        }
        let mut local_spi = [0u8; 4];
        local_spi.copy_from_slice(&packet_bytes[0..4]);
        let local_spi = u32::from_be_bytes(local_spi);
        let sa_id = esp::SecurityAssociationID::from_datagram(local_spi, datagram.remote_addr);
        if let Some(sa) = self.security_associations.get(&sa_id) {
            let decrypted_data = sa.handle_esp(packet_bytes)?;
            trace!(
                "Decrypted ESP packet from {}\n{:?}",
                datagram.remote_addr,
                decrypted_data
            );
            Ok(())
        } else {
            warn!(
                "Security Association {:x} from {} not found",
                local_spi, datagram.remote_addr
            );
            Err("Security Association not found".into())
        }
    }
}

#[derive(Debug)]
pub enum SendError {
    Internal(&'static str),
    Io(io::Error),
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Internal(msg) => f.write_str(msg),
            Self::Io(ref e) => {
                write!(f, "IO error: {}", e)
            }
        }
    }
}

impl error::Error for SendError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Self::Internal(_msg) => None,
            Self::Io(ref err) => Some(err),
        }
    }
}

impl From<&'static str> for SendError {
    fn from(msg: &'static str) -> SendError {
        Self::Internal(msg)
    }
}

impl From<io::Error> for SendError {
    fn from(err: io::Error) -> SendError {
        Self::Io(err)
    }
}

#[derive(Debug)]
pub enum IKEv2Error {
    Internal(&'static str),
    Format(message::FormatError),
    NotEnoughSpace(message::NotEnoughSpaceError),
    CertError(pki::CertError),
    Session(session::SessionError),
    Esp(esp::EspError),
    SendError(SendError),
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
            Self::Session(ref e) => write!(f, "IKEv2 session error: {}", e),
            Self::Esp(ref e) => write!(f, "ESP error: {}", e),
            Self::SendError(ref e) => write!(f, "Send error: {}", e),
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
            Self::Session(ref err) => Some(err),
            Self::Esp(ref err) => Some(err),
            Self::SendError(ref err) => Some(err),
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

impl From<session::SessionError> for IKEv2Error {
    fn from(err: session::SessionError) -> IKEv2Error {
        Self::Session(err)
    }
}

impl From<esp::EspError> for IKEv2Error {
    fn from(err: esp::EspError) -> IKEv2Error {
        Self::Esp(err)
    }
}

impl From<SendError> for IKEv2Error {
    fn from(err: SendError) -> IKEv2Error {
        Self::SendError(err)
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
