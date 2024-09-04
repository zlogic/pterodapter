use log::{debug, info, trace, warn};
use rand::Rng;
use std::{
    collections::{self, HashMap},
    error, fmt, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    runtime,
    sync::{mpsc, oneshot},
    task::JoinSet,
    time,
};

use crate::fortivpn;

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
// Use 1500 as max MTU, real value is likely lower.
const MAX_ESP_PACKET_SIZE: usize = 1500;

const IKE_INIT_SA_EXPIRATION: Duration = Duration::from_secs(15);
const SPLIT_TUNNEL_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);

const VPN_ECHO_SEND_INTERVAL: Duration = Duration::from_secs(10);
const VPN_ECHO_TIMEOUT: Duration = Duration::from_secs(60);

pub struct Config {
    pub listen_ips: Vec<IpAddr>,
    pub hostname: Option<String>,
    pub root_ca: Option<String>,
    pub server_cert: Option<(String, String)>,
    pub tunnel_domains: Vec<String>,
}

pub struct Server {
    listen_ips: Vec<IpAddr>,
    pki_processing: Arc<pki::PkiProcessing>,
    tunnel_domains: Vec<String>,
    command_sender: Option<mpsc::Sender<SessionMessage>>,
    join_set: JoinSet<Result<(), IKEv2Error>>,
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
            tunnel_domains: config.tunnel_domains,
            command_sender: None,
            join_set: JoinSet::new(),
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
            dest.send(msg).await.map_err(|_| "Channel closed")?;
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
                .map_err(|_| "Channel closed")?;
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
        self.command_sender = None;
        while let Some(res) = self.join_set.join_next().await {
            if let Err(err) = res {
                warn!("Error returned when shutting down: {}", err);
            }
        }
        Ok(())
    }

    pub async fn start(&mut self, fortivpn_config: fortivpn::Config) -> Result<(), IKEv2Error> {
        if self.command_sender.is_some() {
            return Err("Server already started".into());
        }
        let sockets = Arc::new(Sockets::new(&self.listen_ips).await?);
        let mut split_routes = SplitRouteRegistry::new(self.tunnel_domains.clone());
        let (tunnel_ips, traffic_selectors) = split_routes.refresh_addresses().await?;
        let vpn_service = FortiService::new(fortivpn_config);
        let mut sessions = Sessions::new(
            self.pki_processing.clone(),
            sockets.clone(),
            vpn_service,
            tunnel_ips,
            traffic_selectors,
        );
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
        let command_sender = sessions.create_sender();
        rt.spawn(async move {
            let mut delay = tokio::time::interval(SPLIT_TUNNEL_REFRESH_INTERVAL);
            loop {
                delay.tick().await;
                let (tunnel_ips, traffic_selectors) = match split_routes.refresh_addresses().await {
                    Ok(split_routes) => split_routes,
                    Err(err) => {
                        warn!("Failed to refresh IP addresses for split routes: {}", err);
                        continue;
                    }
                };
                let _ = command_sender
                    .send(SessionMessage::UpdateSplitRoutes(
                        tunnel_ips,
                        traffic_selectors,
                    ))
                    .await;
            }
        });
        self.command_sender = Some(sessions.create_sender());
        self.join_set
            .spawn_on(async move { sessions.process_messages().await }, &rt);
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
    VpnPacket(Vec<u8>),
    VpnDisconnected,
    CleanupTimer,
    Shutdown,
    UpdateSplitRoutes(Vec<IpAddr>, Vec<message::TrafficSelector>),
}

struct Sessions {
    pki_processing: Arc<pki::PkiProcessing>,
    sockets: Arc<Sockets>,
    vpn_service: FortiService,
    tunnel_ips: Vec<IpAddr>,
    traffic_selectors: Vec<message::TrafficSelector>,
    sessions: HashMap<session::SessionID, session::IKEv2Session>,
    security_associations: HashMap<esp::SecurityAssociationID, esp::SecurityAssociation>,
    half_sessions: HashMap<(SocketAddr, u64), (u64, Instant)>,
    reserved_spi: Option<session::ReservedSpi>,
    tx: mpsc::Sender<SessionMessage>,
    rx: mpsc::Receiver<SessionMessage>,
    shutdown: bool,
}

impl Sessions {
    fn new(
        pki_processing: Arc<pki::PkiProcessing>,
        sockets: Arc<Sockets>,
        vpn_service: FortiService,
        tunnel_ips: Vec<IpAddr>,
        traffic_selectors: Vec<message::TrafficSelector>,
    ) -> Sessions {
        let (tx, rx) = mpsc::channel(100);
        Sessions {
            pki_processing,
            sockets,
            vpn_service,
            tunnel_ips,
            traffic_selectors,
            sessions: HashMap::new(),
            security_associations: HashMap::new(),
            half_sessions: HashMap::new(),
            reserved_spi: None,
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
        local_spi: u64,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> session::SessionID {
        let now = Instant::now();
        let half_key = (remote_addr, remote_spi);
        let new_session_id = (local_spi, now);
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
        self.sessions.entry(session_id).or_insert_with(|| {
            session::IKEv2Session::new(
                session_id,
                remote_addr,
                local_addr,
                self.pki_processing.clone(),
                &self.traffic_selectors,
            )
        });
        session_id
    }

    fn get(&mut self, id: session::SessionID) -> Option<&mut session::IKEv2Session> {
        self.sessions.get_mut(&id)
    }

    fn cleanup(&mut self, rt: &runtime::Handle) {
        let now = Instant::now();
        self.half_sessions
            .retain(|(remote_addr, remote_spi), (local_spi, expires_at)| {
                if *expires_at + IKE_INIT_SA_EXPIRATION < now {
                    info!(
                        "Deleting expired init session {} (SPI {:x})",
                        remote_addr, remote_spi
                    );
                    self.sessions
                        .remove(&session::SessionID::new(*remote_spi, *local_spi));
                    false
                } else {
                    true
                }
            });
        self.sessions.retain(|session_id, session| {
            if session.is_expired(now) {
                info!(
                    "Deleting expired session with SPI {} {}",
                    session_id,
                    session.user_id().unwrap_or("Unknown")
                );
                session
                    .get_local_sa_spis()
                    .into_iter()
                    .for_each(|local_spi| {
                        if self.security_associations.remove(&local_spi).is_some() {
                            info!(
                                "Deleted Security Association {:x} from expired session {}",
                                local_spi, session_id
                            );
                        }
                    });
                false
            } else {
                true
            }
        });
        self.sessions.values_mut().for_each(|session| {
            session.handle_response_expiration(now);
        });
        if self.shutdown {
            self.delete_all_sessions(rt);
        }
    }

    fn delete_all_sessions(&mut self, rt: &runtime::Handle) {
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
            let sender = self.tx.clone();
            let session_id = session_id.clone();
            rt.spawn(async move {
                let _ = sender
                    .send(SessionMessage::RetransmitRequest(session_id, message_id))
                    .await;
            });
        }
    }

    async fn update_all_split_routes(&mut self) {
        for (session_id, session) in self.sessions.iter_mut() {
            if let Err(err) = session.update_split_routes(&self.tunnel_ips) {
                warn!(
                    "Failed to update split routes for session {}: {}",
                    session_id, err
                );
            }
        }
    }

    fn reserve_session_ids(&mut self) -> session::ReservedSpi {
        let mut reserved_spi = if let Some(reserved_spi) = self.reserved_spi.take() {
            reserved_spi
        } else {
            session::ReservedSpi::new()
        };
        while reserved_spi.needs_ike() {
            let next_id = rand::thread_rng().gen::<u64>();
            if !self.sessions.keys().any(|key| key.local_spi() == next_id) {
                reserved_spi.add_ike(next_id);
            }
        }
        while reserved_spi.needs_esp() {
            let next_id = rand::thread_rng().gen::<u32>();
            if (0..255).contains(&next_id) {
                // RFC 9333, section 3 states these SPI values are reserved and should not be used.
                continue;
            }
            if !self.security_associations.keys().any(|key| *key == next_id) {
                reserved_spi.add_esp(next_id);
            }
        }
        reserved_spi
    }

    async fn process_messages(&mut self) -> Result<(), IKEv2Error> {
        self.vpn_service.start(self.create_sender()).await?;
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
                SessionMessage::VpnPacket(data) => {
                    if let Err(err) = self.process_vpn_packet(data).await {
                        warn!("Failed to process VPN packet: {}", err);
                    }
                }
                SessionMessage::VpnDisconnected => {
                    let rt = runtime::Handle::current();
                    self.delete_all_sessions(&rt);
                }
                SessionMessage::CleanupTimer => {
                    let rt = runtime::Handle::current();
                    self.cleanup(&rt);
                }
                SessionMessage::UpdateSplitRoutes(tunnel_ips, traffic_selectors) => {
                    self.tunnel_ips = tunnel_ips;
                    self.traffic_selectors = traffic_selectors;
                    self.update_all_split_routes().await;
                }
                SessionMessage::RetransmitRequest(session_id, message_id) => {
                    self.retransmit_request(session_id, message_id).await;
                }
                SessionMessage::Shutdown => {
                    self.shutdown = true;
                    let rt = runtime::Handle::current();
                    self.cleanup(&rt);
                }
            }
            if self.shutdown && self.sessions.is_empty() {
                break;
            }
        }
        self.vpn_service.terminate().await?;
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
            let mut reserved_spi = self.reserve_session_ids();
            let local_spi = if let Some(local_spi) = reserved_spi.take_ike() {
                local_spi
            } else {
                return Err("No pre-generated IKE SA ID available".into());
            };
            self.reserved_spi = Some(reserved_spi);
            self.get_init_session(
                ikev2_request.read_initiator_spi(),
                local_spi,
                datagram.remote_addr,
                datagram.local_addr,
            )
        } else {
            session::SessionID::from_message(&ikev2_request)?
        };
        let ip_configuration = if ikev2_request.read_exchange_type()?
            == message::ExchangeType::IKE_AUTH
            && !ikev2_request.read_flags()?.has(message::Flags::RESPONSE)
        {
            self.vpn_service.ip_configuration().await?
        } else {
            None
        };
        let mut reserved_spi = self.reserve_session_ids();
        let session = if let Some(session) = self.get(session_id) {
            session
        } else {
            return Err("Session not found".into());
        };
        if let Some((client_ip, dns_addrs)) = ip_configuration {
            session.update_ip(client_ip, dns_addrs);
        }

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
                &mut reserved_spi,
            )?;
            self.reserved_spi = Some(reserved_spi);

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
                    delete_session = true;
                }
                session::IKEv2PendingAction::DeleteChildSA(session_id) => {
                    if self.security_associations.remove(&session_id).is_some() {
                        info!("Deleted Security Association {:x}", session_id)
                    }
                }
                session::IKEv2PendingAction::CreateIKEv2Session(session_id, session) => {
                    self.sessions.insert(session_id, session);
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
            debug!(
                "Failed to retransmit request: missing session {}",
                session_id
            );
            return;
        };
        if let Err(err) = session.send_last_request(&self.sockets, message_id).await {
            warn!(
                "Failed to retransmit last request to session {}: {}",
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
        let packet_bytes = datagram.request.as_slice();
        if packet_bytes == [0xff] {
            debug!("Received ESP NAT keepalive from {}", datagram.remote_addr);
            return Ok(self
                .sockets
                .send_datagram(&datagram.local_addr, &datagram.remote_addr, &[0xff])
                .await?);
        }
        trace!(
            "Received ESP packet from {}\n{:?}",
            datagram.remote_addr,
            packet_bytes,
        );
        if packet_bytes.len() < 8 {
            return Err("Not enough data in ESP packet".into());
        }
        let mut local_spi = [0u8; 4];
        local_spi.copy_from_slice(&packet_bytes[0..4]);
        let local_spi = u32::from_be_bytes(local_spi);
        if let Some(sa) = self.security_associations.get_mut(&local_spi) {
            let packet_bytes = datagram.request.as_mut_slice();
            let decrypted_slice = sa.handle_esp(packet_bytes)?;
            trace!(
                "Decrypted ESP packet from {}\n{:?}",
                datagram.remote_addr,
                decrypted_slice
            );
            let hdr = esp::IpHeader::from_packet(decrypted_slice)?;
            trace!("IP header {}", hdr);
            if !sa.accepts_esp_to_vpn(&hdr) {
                return Err("ESP packet dropped by traffic selector".into());
            }
            if decrypted_slice.len() > MAX_ESP_PACKET_SIZE {
                warn!(
                    "Decrypted packet size {} exceeds MTU {}",
                    decrypted_slice.len(),
                    MAX_ESP_PACKET_SIZE
                );
                return Err("Decrypted ESP packet size exceeds MTU".into());
            }
            let mut decrypted_data = Vec::with_capacity(MAX_ESP_PACKET_SIZE);
            decrypted_data.extend_from_slice(decrypted_slice);
            self.vpn_service.send_packet(decrypted_data).await
        } else {
            warn!(
                "Security Association {:x} from {} not found",
                local_spi, datagram.remote_addr
            );
            Err("Security Association not found".into())
        }
    }

    async fn process_vpn_packet(&mut self, mut data: Vec<u8>) -> Result<(), IKEv2Error> {
        let hdr = match esp::IpHeader::from_packet(&data) {
            Ok(hdr) => hdr,
            Err(err) => {
                warn!(
                    "Failed to read header in IP packet from VPN: {}\n{:?}",
                    err, data
                );
                return Err("Failed to read header in IP packet from VPN".into());
            }
        };
        trace!("Received packet from VPN {}\n{:?}", hdr, data);
        // Prefer SA with lower sequence number - but only if it's active.
        // Might be a better idea to instead just use a counter?
        if let Some(sa) = self
            .security_associations
            .values_mut()
            .filter(|sa| sa.accepts_vpn_to_esp(&hdr))
            .reduce(|a, b| {
                let a_seq = a.max_sequence_number();
                if a_seq > 0 && a_seq < b.max_sequence_number() {
                    a
                } else {
                    b
                }
            })
        {
            let msg_len = data.len();
            if data.len() >= MAX_ESP_PACKET_SIZE {
                return Err("Vector doesn't have capacity for ESP headers".into());
            }
            data.resize(sa.encoded_length(data.len()), 0);
            let encrypted_data = sa.handle_vpn(data.as_mut_slice(), msg_len)?;
            trace!(
                "Encrypted VPN packet to {}\n{:?}",
                sa.remote_addr(),
                encrypted_data
            );
            self.sockets
                .send_datagram(&sa.local_addr(), &sa.remote_addr(), encrypted_data)
                .await?;
            Ok(())
        } else {
            Err("No matching Security Associations found".into())
        }
    }
}

struct FortiService {
    config: Option<fortivpn::Config>,
    command_sender: Option<mpsc::Sender<FortiServiceCommand>>,
    join_set: JoinSet<Result<(), IKEv2Error>>,
}

impl FortiService {
    fn new(config: fortivpn::Config) -> FortiService {
        FortiService {
            config: Some(config),
            command_sender: None,
            join_set: JoinSet::new(),
        }
    }

    async fn connect(
        config: fortivpn::Config,
    ) -> Result<fortivpn::FortiVPNTunnel, fortivpn::FortiError> {
        let sslvpn_cookie = fortivpn::get_oauth_cookie(&config).await?;
        fortivpn::FortiVPNTunnel::new(&config, sslvpn_cookie).await
    }

    async fn process_echo(
        forti_client: &mut fortivpn::FortiVPNTunnel,
        last_echo_sent: time::Instant,
    ) -> Result<(), IKEv2Error> {
        forti_client.send_echo_request().await?;
        if forti_client.last_echo_reply() + VPN_ECHO_TIMEOUT < last_echo_sent {
            Err("No echo replies received".into())
        } else {
            Ok(())
        }
    }

    async fn peek_vpn(forti_client: &mut fortivpn::FortiVPNTunnel) -> Option<FortiServiceCommand> {
        if let Err(err) = forti_client.peek_recv().await {
            debug!("Failed to check if VPN has data available: {}", err);
        }
        Some(FortiServiceCommand::ReceivePacket)
    }

    async fn read_vpn_packet(
        forti_client: &mut fortivpn::FortiVPNTunnel,
    ) -> Result<Vec<u8>, fortivpn::FortiError> {
        let mut buffer = [0u8; MAX_ESP_PACKET_SIZE];
        match forti_client.try_read_packet(&mut buffer, None).await {
            Ok(msg_len) => {
                if msg_len > 0 {
                    let mut packet_buffer = Vec::with_capacity(MAX_ESP_PACKET_SIZE);
                    packet_buffer.extend_from_slice(&buffer[..msg_len]);
                    Ok(packet_buffer)
                } else {
                    Ok(vec![])
                }
            }
            Err(err) => Err(err),
        }
    }

    async fn run(
        config: fortivpn::Config,
        tx: mpsc::Sender<FortiServiceCommand>,
        mut rx: mpsc::Receiver<FortiServiceCommand>,
        sessions_tx: mpsc::Sender<SessionMessage>,
    ) -> Result<(), IKEv2Error> {
        loop {
            // Spawn a new connection task.
            let connect_handle = {
                let rt = runtime::Handle::current();
                let tx = tx.clone();
                let config = config.clone();
                rt.spawn(async move {
                    let result = Self::connect(config).await;
                    let _ = tx.send(FortiServiceCommand::HandleConnection(result)).await;
                })
            };
            let mut res = None;
            // Wait for async events or the connection to open.
            while let Some(command) = rx.recv().await {
                match command {
                    FortiServiceCommand::HandleConnection(forti_client) => {
                        res = Some(forti_client);
                        break;
                    }
                    FortiServiceCommand::Shutdown => return Ok(()),
                    FortiServiceCommand::SendPacket(_) => {
                        debug!("Received packet for closed FortiClient channel");
                    }
                    FortiServiceCommand::ReceivePacket => {
                        debug!("Received packet from closed FortiClient channel");
                    }
                    FortiServiceCommand::SendEcho => {}
                    FortiServiceCommand::RequestIpConfiguration(tx) => {
                        debug!("Received IP request for closed FortiClient channel");
                        let _ = tx.send(None);
                    }
                }
            }
            connect_handle.abort();
            let mut forti_client = match res.unwrap() {
                Ok(forti_client) => forti_client,
                Err(err) => {
                    debug!("Error occurred when connecting to FortiClient: {}", err);
                    continue;
                }
            };
            let keepalive_timer = {
                let rt = runtime::Handle::current();
                let tx = tx.clone();
                rt.spawn(async move {
                    let mut interval = tokio::time::interval(VPN_ECHO_SEND_INTERVAL);
                    loop {
                        interval.tick().await;
                        let _ = tx.send(FortiServiceCommand::SendEcho).await;
                    }
                })
            };
            // Handle connection until it drops.
            let mut last_echo_sent = time::Instant::now();
            let mut selector = crate::futures::RoundRobinSelector::new();
            while let Some(command) = selector
                .select(rx.recv(), Self::peek_vpn(&mut forti_client))
                .await
            {
                match command {
                    FortiServiceCommand::SendPacket(data) => {
                        if let Err(err) = forti_client.send_packet(&data).await {
                            warn!("Failed to send packet to VPN: {}", err);
                            break;
                        };
                        if let Err(err) = forti_client.flush().await {
                            warn!("Failed to flush VPN stream: {}", err);
                            break;
                        }
                    }
                    FortiServiceCommand::ReceivePacket => {
                        let data = match Self::read_vpn_packet(&mut forti_client).await {
                            Ok(data) => data,
                            Err(err) => {
                                warn!("Failed to receive packet from VPN: {}", err);
                                break;
                            }
                        };
                        if !data.is_empty() {
                            let rt = runtime::Handle::current();
                            let tx = sessions_tx.clone();
                            rt.spawn(async move { tx.send(SessionMessage::VpnPacket(data)).await });
                        }
                    }
                    FortiServiceCommand::SendEcho => {
                        let next_echo_sent = time::Instant::now();
                        if let Err(err) =
                            Self::process_echo(&mut forti_client, last_echo_sent).await
                        {
                            warn!("Echo request timed out: {}", err);
                            break;
                        }
                        last_echo_sent = next_echo_sent;
                    }
                    FortiServiceCommand::RequestIpConfiguration(tx) => {
                        let _ =
                            tx.send(Some((forti_client.ip_addr(), forti_client.dns().to_vec())));
                    }
                    FortiServiceCommand::Shutdown => {
                        forti_client.terminate().await?;
                        return Ok(());
                    }
                    FortiServiceCommand::HandleConnection(forti_client) => {
                        warn!("Received unexpected new connection, closing");
                        let mut forti_client = match forti_client {
                            Ok(forti_client) => forti_client,
                            Err(err) => {
                                debug!("Error occurred when connecting to FortiClient: {}", err);
                                continue;
                            }
                        };
                        if let Err(err) = forti_client.terminate().await {
                            warn!("Failed to terminate VPN client connection: {}", err);
                        }
                    }
                }
            }
            keepalive_timer.abort();
            if let Err(err) = forti_client.terminate().await {
                warn!("Failed to terminate VPN client connection: {}", err);
            }
            let _ = sessions_tx.send(SessionMessage::VpnDisconnected).await;
        }
    }

    async fn start(&mut self, sessions_tx: mpsc::Sender<SessionMessage>) -> Result<(), IKEv2Error> {
        if self.command_sender.is_some() {
            return Err("VPN client service is already started".into());
        }
        let config = if let Some(config) = self.config.take() {
            config
        } else {
            return Err("VPN client config is already consumed".into());
        };
        let (tx, rx) = mpsc::channel(100);
        self.command_sender = Some(tx.clone());
        let rt = runtime::Handle::current();
        self.join_set
            .spawn_on(Self::run(config, tx, rx, sessions_tx), &rt);

        Ok(())
    }

    async fn send_packet(&self, data: Vec<u8>) -> Result<(), IKEv2Error> {
        if let Some(tx) = self.command_sender.as_ref() {
            let rt = runtime::Handle::current();
            let tx = tx.clone();
            rt.spawn(async move { tx.send(FortiServiceCommand::SendPacket(data)).await });
            Ok(())
        } else {
            Err("VPN client service is not running".into())
        }
    }

    async fn ip_configuration(&self) -> Result<Option<(IpAddr, Vec<IpAddr>)>, IKEv2Error> {
        if let Some(command_sender) = self.command_sender.as_ref() {
            let (tx, rx) = oneshot::channel();
            command_sender
                .send(FortiServiceCommand::RequestIpConfiguration(tx))
                .await
                .map_err(|_| "VPN client command channel closed")?;
            Ok(rx.await.map_err(|_| "IP address receiver closed")?)
        } else {
            Err("VPN client service is not running".into())
        }
    }

    async fn terminate(&mut self) -> Result<(), IKEv2Error> {
        match self.command_sender {
            Some(ref command_sender) => {
                if command_sender
                    .send(FortiServiceCommand::Shutdown)
                    .await
                    .is_err()
                {
                    return Err("Command channel closed".into());
                }
            }
            None => return Err("Shutdown already in progress".into()),
        }
        self.command_sender = None;
        while let Some(res) = self.join_set.join_next().await {
            if let Err(err) = res {
                warn!("Error returned when stopping VPN client: {}", err);
            }
        }
        Ok(())
    }
}

enum FortiServiceCommand {
    HandleConnection(Result<fortivpn::FortiVPNTunnel, fortivpn::FortiError>),
    RequestIpConfiguration(oneshot::Sender<Option<(IpAddr, Vec<IpAddr>)>>),
    SendPacket(Vec<u8>),
    ReceivePacket,
    SendEcho,
    Shutdown,
}

struct SplitRouteRegistry {
    tunnel_domains: Vec<String>,
}

impl SplitRouteRegistry {
    fn new(tunnel_domains: Vec<String>) -> SplitRouteRegistry {
        SplitRouteRegistry { tunnel_domains }
    }

    async fn refresh_addresses(
        &mut self,
    ) -> Result<(Vec<IpAddr>, Vec<message::TrafficSelector>), IKEv2Error> {
        // Use a predefined port just in case.
        let addresses = self
            .tunnel_domains
            .iter()
            .map(|domain| tokio::net::lookup_host((domain.clone(), 80)))
            .collect::<Vec<_>>();

        let mut ip_addresses = vec![];
        for addrs in addresses.into_iter() {
            addrs
                .await?
                .into_iter()
                .for_each(|addr| ip_addresses.push(addr.ip()));
        }
        if ip_addresses.is_empty() {
            let full_ts = message::TrafficSelector::from_ip_range(
                IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
                    ..=IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
            )?;
            Ok((ip_addresses, vec![full_ts]))
        } else {
            let traffic_selectors = ip_addresses
                .iter()
                .map(|ip_address| {
                    message::TrafficSelector::from_ip_range(*ip_address..=*ip_address)
                })
                .collect::<Result<Vec<message::TrafficSelector>, message::FormatError>>()?;
            Ok((ip_addresses, traffic_selectors))
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
    Forti(fortivpn::FortiError),
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
            Self::Forti(ref e) => {
                write!(f, "VPN error: {}", e)
            }
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
            Self::Forti(ref err) => Some(err),
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

impl From<fortivpn::FortiError> for IKEv2Error {
    fn from(err: fortivpn::FortiError) -> IKEv2Error {
        Self::Forti(err)
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
