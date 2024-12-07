use log::{debug, info, trace, warn};
use rand::Rng;
use std::{
    collections::{HashMap, HashSet},
    error, fmt,
    future::{self, Future},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::pin,
    sync::Arc,
    task::Poll,
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    runtime,
    sync::{mpsc, oneshot},
    task::JoinSet,
    time,
};

use crate::fortivpn::{self, service::FortiTunnelEvent};

mod crypto;
mod esp;
mod message;
mod pki;
mod session;

const MAX_DATAGRAM_SIZE: usize = 1500;
// Use 1500 as max MTU, real value is likely lower.
const MAX_ESP_PACKET_SIZE: usize = 1500;

const CLEANUP_INTERVAL: Duration = Duration::from_secs(15);
const IKE_INIT_SA_EXPIRATION: Duration = Duration::from_secs(15);

const SPLIT_TUNNEL_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);

pub struct Config {
    pub port: u16,
    pub nat_port: u16,
    pub listen_ips: Vec<IpAddr>,
    pub hostname: Option<String>,
    pub root_ca: Option<String>,
    pub server_cert: Option<(String, String)>,
    pub tunnel_domains: Vec<String>,
}

pub struct Server {
    listen_ips: Vec<IpAddr>,
    port: u16,
    nat_port: u16,
    pki_processing: Arc<pki::PkiProcessing>,
    tunnel_domains: Vec<String>,
    cancel_sender: Option<oneshot::Sender<()>>,
    join_set: JoinSet<Result<(), IKEv2Error>>,
}

type FortiService = fortivpn::service::FortiService<MAX_ESP_PACKET_SIZE, MAX_DATAGRAM_SIZE>;

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
            port: config.port,
            nat_port: config.nat_port,
            pki_processing: Arc::new(pki_processing),
            tunnel_domains: config.tunnel_domains,
            cancel_sender: None,
            join_set: JoinSet::new(),
        })
    }

    async fn send_cleanup_ticks(
        duration: Duration,
        dest: mpsc::Sender<SessionMessage>,
    ) -> Result<(), IKEv2Error> {
        let mut interval = tokio::time::interval(duration);
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            dest.send(SessionMessage::CleanupTimer)
                .await
                .map_err(|_| "Channel closed")?;
        }
    }

    pub async fn terminate(&mut self) -> Result<(), IKEv2Error> {
        match self.cancel_sender.take() {
            Some(cancel_sender) => {
                if cancel_sender.send(()).is_err() {
                    return Err("Cancel channel closed".into());
                }
            }
            None => return Err("Shutdown already in progress".into()),
        }
        while let Some(res) = self.join_set.join_next().await {
            if let Err(err) = res {
                warn!("Error returned when shutting down: {}", err);
            }
        }
        Ok(())
    }

    pub async fn start(&mut self, fortivpn_config: fortivpn::Config) -> Result<(), IKEv2Error> {
        let sockets = Sockets::new(&self.listen_ips, self.port, self.nat_port).await?;
        let mut split_routes = SplitRouteRegistry::new(self.tunnel_domains.clone());
        let (tunnel_ips, traffic_selectors) = split_routes.refresh_addresses().await?;
        let vpn_service = fortivpn::service::FortiService::new(fortivpn_config, 64, 16);

        let rt = runtime::Handle::current();
        let (command_sender, command_receiver) = mpsc::channel(32);
        // Non-critical futures will be terminated by Tokio during the shutdown_timeout phase.
        rt.spawn(Server::send_cleanup_ticks(
            CLEANUP_INTERVAL,
            command_sender.clone(),
        ));
        let routes_sender = command_sender.clone();
        rt.spawn(async move {
            let mut delay = tokio::time::interval(SPLIT_TUNNEL_REFRESH_INTERVAL);
            delay.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
            loop {
                delay.tick().await;
                let (tunnel_ips, traffic_selectors) = match split_routes.refresh_addresses().await {
                    Ok(split_routes) => split_routes,
                    Err(err) => {
                        warn!("Failed to refresh IP addresses for split routes: {}", err);
                        continue;
                    }
                };
                let _ = routes_sender
                    .send(SessionMessage::UpdateSplitRoutes(
                        tunnel_ips,
                        traffic_selectors,
                    ))
                    .await;
            }
        });

        let sessions = Sessions::new(
            self.pki_processing.clone(),
            command_sender.clone(),
            sockets.create_sender(),
            tunnel_ips,
            traffic_selectors,
        );
        let (cancel_sender, cancel_receiver) = oneshot::channel();
        self.cancel_sender = Some(cancel_sender);
        rt.spawn(async move {
            if cancel_receiver.await.is_ok()
                && command_sender.send(SessionMessage::Shutdown).await.is_err()
            {
                warn!("Command channel closed");
            }
        });

        self.join_set.spawn_on(
            Self::run(command_receiver, sockets, sessions, vpn_service),
            &rt,
        );
        Ok(())
    }

    async fn run(
        mut command_receiver: mpsc::Receiver<SessionMessage>,
        mut sockets: Sockets,
        mut sessions: Sessions,
        mut vpn_service: FortiService,
    ) -> Result<(), IKEv2Error> {
        let rt = runtime::Handle::current();
        let mut shutdown = false;
        loop {
            if shutdown && sessions.is_empty() && !vpn_service.is_connected() {
                debug!("Shutdown completed");
                return Ok(());
            }
            if !shutdown && !vpn_service.is_connected() {
                vpn_service.start_connection(&rt);
            }
            // Wait until something is ready.
            let (command_message, datagram, vpn_event) = {
                let ignore_vpn = shutdown && !vpn_service.is_connected();
                let mut receive_command = pin!(command_receiver.recv());
                let mut receive_udp = pin!(sockets.receive_datagram());
                let mut vpn_event = pin!(vpn_service.next_event());
                future::poll_fn(move |cx| {
                    let mut ready = false;
                    let received_command = receive_command.as_mut().poll(cx);
                    ready = ready || received_command.is_ready();
                    let received_command = match received_command {
                        Poll::Ready(cmd) => cmd,
                        Poll::Pending => None,
                    };
                    let received_udp = receive_udp.as_mut().poll(cx);
                    ready = ready || received_udp.is_ready();
                    let received_udp = match received_udp {
                        Poll::Ready(cmd) => cmd,
                        Poll::Pending => None,
                    };
                    let vpn_event = if !ignore_vpn {
                        let vpn_event = vpn_event.as_mut().poll(cx);
                        ready = ready || vpn_event.is_ready();
                        match vpn_event {
                            Poll::Ready(cmd) => Some(cmd),
                            Poll::Pending => None,
                        }
                    } else {
                        // Avoid waking if VPN is already shut down.
                        None
                    };
                    if ready {
                        Poll::Ready((received_command, received_udp, vpn_event))
                    } else {
                        Poll::Pending
                    }
                })
                .await
            };
            // Process all ready events.
            if let Some(message) = command_message {
                match message {
                    SessionMessage::Shutdown => {
                        shutdown = true;
                        sessions.cleanup(&rt);
                        if let Err(err) = vpn_service.start_disconnection().await {
                            warn!("Failed to terminate VPN client connection: {}", err);
                        }
                    }
                    _ => {
                        // These messages are handled by Session.
                    }
                }
                sessions.process_message(message).await;
            }
            if let Some(mut datagram) = datagram {
                let result = if datagram.is_ikev2() {
                    sessions
                        .process_ikev2_message(&datagram, vpn_service.ip_configuration())
                        .await
                } else {
                    sessions
                        .process_esp_packet(&mut datagram, &mut vpn_service)
                        .await
                };
                if let Err(err) = result {
                    warn!(
                        "Failed to process message from {}: {}",
                        datagram.remote_addr, err
                    );
                }
            }
            match vpn_event {
                Some(Ok(FortiTunnelEvent::Error(err))) => {
                    warn!("VPN reported an error status: {}", err);
                }
                Some(Ok(FortiTunnelEvent::ReceivedPacket(mut data, read_bytes))) => {
                    if let Err(err) = sessions.process_vpn_packet(&mut data, read_bytes).await {
                        warn!("Failed to process VPN packet: {}", err);
                    }
                }
                Some(Ok(FortiTunnelEvent::EchoFailed(err))) => {
                    warn!("Echo request timed out: {}", err);
                }
                Some(Ok(FortiTunnelEvent::Disconnected)) => {
                    sessions.delete_all_sessions(&rt);
                }
                Some(Err(err)) => {
                    warn!("VPN reported an error status: {}", err);
                }
                Some(Ok(FortiTunnelEvent::Connected(_, _))) | None => {}
            }
        }
    }
}

struct Sockets {
    listen_rx: mpsc::Receiver<UdpDatagram>,
    send_tx: mpsc::Sender<SendUdpDatagram>,
}

impl Sockets {
    async fn new(listen_ips: &[IpAddr], port: u16, nat_port: u16) -> Result<Sockets, IKEv2Error> {
        let mut sockets = HashMap::new();
        for listen_ip in listen_ips {
            for listen_port in [port, nat_port] {
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
        let rt = runtime::Handle::current();
        let (listen_tx, listen_rx) = mpsc::channel(16);
        sockets.iter().for_each(|(listen_addr, socket)| {
            rt.spawn(Self::run_receiver(
                listen_tx.clone(),
                *listen_addr,
                socket.clone(),
                listen_addr.port() == nat_port,
            ));
        });
        let (send_tx, send_rx) = mpsc::channel(16);
        rt.spawn(Self::run_sender(send_rx, sockets));
        Ok(Sockets { listen_rx, send_tx })
    }

    async fn run_receiver(
        tx: mpsc::Sender<UdpDatagram>,
        listen_addr: SocketAddr,
        socket: Arc<UdpSocket>,
        is_nat_port: bool,
    ) {
        loop {
            // Theoretically the allocator should be smart enough to recycle memory.
            // In the unlikely case this becomes a problem, switching to stack-allocated
            // arrays would reduce memory usage, but increase number of copy operations.
            // As mpsc uses a queue internally, memory will be allocated for the queue elements
            // in any case.
            let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
            let (bytes_res, remote_addr) = match socket.recv_from(&mut buf).await {
                Ok(res) => res,
                Err(err) => {
                    warn!("Failed to receive from socket {}: {}", listen_addr, err);
                    return;
                }
            };
            buf.truncate(bytes_res);
            let msg = UdpDatagram {
                remote_addr,
                local_addr: listen_addr,
                is_nat_port,
                bytes: buf,
            };
            if tx.send(msg).await.is_err() {
                warn!("Channel closed for {}", listen_addr);
                return;
            }
        }
    }

    async fn run_sender(
        mut rx: mpsc::Receiver<SendUdpDatagram>,
        sockets: HashMap<SocketAddr, Arc<UdpSocket>>,
    ) {
        while let Some(datagram) = rx.recv().await {
            let socket = if let Some(socket) = sockets.get(&datagram.local_addr) {
                socket
            } else {
                warn!(
                    "No open sockets for source address {} (destination {})",
                    datagram.local_addr, datagram.remote_addr
                );
                continue;
            };
            if let Err(err) = socket.send_to(&datagram.bytes, datagram.remote_addr).await {
                warn!(
                    "Failed to send UDP message from {} to {}: {}",
                    datagram.local_addr, datagram.remote_addr, err
                );
            }
        }
    }

    async fn receive_datagram(&mut self) -> Option<UdpDatagram> {
        self.listen_rx.recv().await
    }

    fn create_sender(&self) -> UdpSender {
        UdpSender {
            tx: self.send_tx.clone(),
        }
    }
}

struct UdpDatagram {
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    is_nat_port: bool,
    bytes: Vec<u8>,
}

impl UdpDatagram {
    fn is_non_esp(&self) -> bool {
        self.bytes.len() >= 4 && self.bytes[0..4] == [0x00, 0x00, 0x00, 0x00]
    }

    fn is_ikev2(&self) -> bool {
        !self.is_nat_port || self.is_non_esp()
    }
}

#[derive(Clone)]
struct UdpSender {
    tx: mpsc::Sender<SendUdpDatagram>,
}

impl UdpSender {
    async fn send_datagram(
        &self,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        data: &[u8],
    ) -> Result<(), SendError> {
        let mut buffer = Vec::with_capacity(MAX_DATAGRAM_SIZE);
        buffer.extend_from_slice(data);
        self.tx
            .send(SendUdpDatagram {
                local_addr: *local_addr,
                remote_addr: *remote_addr,
                bytes: buffer,
            })
            .await
            .map_err(|_| "UDP sender channel closed".into())
    }
}

struct SendUdpDatagram {
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    bytes: Vec<u8>,
}

enum SessionMessage {
    DeleteSession(session::SessionID),
    DeleteSecurityAssociation(u32),
    RetransmitRequest(session::SessionID, u32),
    CleanupTimer,
    UpdateSplitRoutes(Vec<IpAddr>, Vec<message::TrafficSelector>),
    Shutdown,
}

struct Sessions {
    pki_processing: Arc<pki::PkiProcessing>,
    udp_sender: UdpSender,
    tunnel_ips: Vec<IpAddr>,
    traffic_selectors: Vec<message::TrafficSelector>,
    sessions: HashMap<session::SessionID, session::IKEv2Session>,
    security_associations: HashMap<esp::SecurityAssociationID, esp::SecurityAssociation>,
    next_sa_index: usize,
    half_sessions: HashMap<(SocketAddr, u64), (u64, Instant)>,
    reserved_spi: Option<session::ReservedSpi>,
    command_sender: mpsc::Sender<SessionMessage>,
    shutdown: bool,
}

impl Sessions {
    fn new(
        pki_processing: Arc<pki::PkiProcessing>,
        command_sender: mpsc::Sender<SessionMessage>,
        udp_sender: UdpSender,
        tunnel_ips: Vec<IpAddr>,
        traffic_selectors: Vec<message::TrafficSelector>,
    ) -> Sessions {
        Sessions {
            pki_processing,
            udp_sender,
            tunnel_ips,
            traffic_selectors,
            sessions: HashMap::new(),
            next_sa_index: 0,
            security_associations: HashMap::new(),
            half_sessions: HashMap::new(),
            reserved_spi: None,
            command_sender,
            shutdown: false,
        }
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
                self.udp_sender.clone(),
                &self.traffic_selectors,
            )
        });
        session_id
    }

    fn is_empty(&self) -> bool {
        self.sessions.is_empty()
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
            let sender = self.command_sender.clone();
            let session_id = *session_id;
            rt.spawn(async move {
                let _ = sender
                    .send(SessionMessage::RetransmitRequest(session_id, message_id))
                    .await;
            });
        }
        self.sessions.retain(|session_id, session| {
            if !session.is_established() {
                info!(
                    "Deleting non-established session with SPI {} {}",
                    session_id,
                    session.user_id().unwrap_or("Unknown")
                );
                session
                    .get_local_sa_spis()
                    .into_iter()
                    .for_each(|local_spi| {
                        if self.security_associations.remove(&local_spi).is_some() {
                            info!(
                                "Deleted Security Association {:x} from non-established session {}",
                                local_spi, session_id
                            );
                        }
                    });
                false
            } else {
                true
            }
        });
    }

    fn delete_session(&mut self, session_id: session::SessionID) {
        if let Some(session) = self.sessions.remove(&session_id) {
            debug!("Deleted IKEv2 session {}", session_id);
            session
                .get_local_sa_spis()
                .into_iter()
                .for_each(|local_spi| {
                    if self.security_associations.remove(&local_spi).is_some() {
                        debug!(
                            "Deleted Security Association {:x} from session {}",
                            local_spi, session_id
                        );
                    }
                });
        }
    }

    fn delete_security_association(&mut self, session_id: u32) {
        if self.security_associations.remove(&session_id).is_some() {
            debug!("Deleted Security Association {:x}", session_id)
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
            session::ReservedSpi::new(self.next_sa_index)
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

    async fn process_message(&mut self, message: SessionMessage) {
        match message {
            SessionMessage::DeleteSession(session_id) => self.delete_session(session_id),
            SessionMessage::DeleteSecurityAssociation(session_id) => {
                self.delete_security_association(session_id)
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
            }
        }
    }

    async fn process_ikev2_message(
        &mut self,
        datagram: &UdpDatagram,
        ip_configuration: Option<(IpAddr, &[IpAddr])>,
    ) -> Result<(), IKEv2Error> {
        let is_nat = datagram.is_non_esp();
        let ikev2_request = message::InputMessage::from_datagram(&datagram.bytes, is_nat)?;
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
        let mut reserved_spi = self.reserve_session_ids();
        let session = if let Some(session) = self.sessions.get_mut(&session_id) {
            session
        } else {
            return Err("Session not found".into());
        };
        if ikev2_request.read_exchange_type()? == message::ExchangeType::IKE_AUTH
            && !ikev2_request.read_flags()?.has(message::Flags::RESPONSE)
        {
            if let Some((client_ip, dns_addrs)) = ip_configuration {
                session.update_ip(client_ip, dns_addrs.to_vec());
            }
        };

        if ikev2_request.read_flags()?.has(message::Flags::RESPONSE) {
            session.process_response(datagram.remote_addr, datagram.local_addr, &ikev2_request)?;
        } else {
            let transmit_response = session.process_request(
                datagram.remote_addr,
                datagram.local_addr,
                &ikev2_request,
                &mut reserved_spi,
            )?;
            self.reserved_spi = Some(reserved_spi);
            // Response retransmissions are initiated by client.
            if transmit_response {
                if let Err(err) = session
                    .send_last_response(ikev2_request.read_message_id(), is_nat)
                    .await
                {
                    warn!(
                        "Failed to transmit response to session {}: {}",
                        session_id, err
                    );
                }
            }
        }

        let rt = runtime::Handle::current();
        self.process_pending_actions(session_id, rt);

        Ok(())
    }

    fn process_pending_actions(&mut self, session_id: session::SessionID, rt: runtime::Handle) {
        let session = if let Some(session_id) = self.sessions.get_mut(&session_id) {
            session_id
        } else {
            warn!(
                "Failed to find IKEv2 session {} to process pending actions",
                session_id
            );
            return;
        };

        let mut delete_session_ids = HashSet::new();
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
                    self.next_sa_index = self.next_sa_index.max(security_association.index() + 1);
                    self.security_associations
                        .insert(session_id, *security_association);
                }
                session::IKEv2PendingAction::DeleteIKESession(delay) => {
                    let tx = self.command_sender.clone();
                    let cmd = SessionMessage::DeleteSession(session_id);
                    rt.spawn(async move {
                        debug!("Scheduling to delete IKEv2 session {}", session_id);
                        if !delay.is_zero() {
                            time::sleep(delay).await;
                        }
                        let _ = tx.send(cmd).await;
                    });
                }
                session::IKEv2PendingAction::DeleteOtherIKESessions(cert_serial) => {
                    delete_session_ids = self
                        .sessions
                        .iter()
                        .filter_map(|(other_session_id, session)| {
                            if other_session_id != &session_id
                                && session.certificate_serial() == Some(&cert_serial)
                            {
                                Some(other_session_id.to_owned())
                            } else {
                                None
                            }
                        })
                        .collect::<HashSet<_>>();
                }
                session::IKEv2PendingAction::DeleteChildSA(session_id, delay) => {
                    let tx = self.command_sender.clone();
                    let cmd = SessionMessage::DeleteSecurityAssociation(session_id);
                    rt.spawn(async move {
                        debug!(
                            "Scheduling to delete Security Association session {:x}",
                            session_id
                        );
                        if !delay.is_zero() {
                            time::sleep(delay).await;
                        }
                        let _ = tx.send(cmd).await;
                    });
                }
                session::IKEv2PendingAction::CreateIKEv2Session(session_id, session) => {
                    self.sessions.insert(session_id, *session);
                }
            });

        self.sessions.retain(|session_id, session| {
            // RFC 7296 Section 2.4 states that sessions may be terminated without a timeout.
            if delete_session_ids.contains(session_id) {
                session
                    .get_local_sa_spis()
                    .into_iter()
                    .for_each(|local_spi| {
                        if self.security_associations.remove(&local_spi).is_some() {
                            info!(
                                "Deleted Security Association {:x} from session {} deleted on INITIAL_CONTACT",
                                local_spi, session_id
                            );
                        }
                    });
                info!(
                    "Deleting session with SPI {} {} on INITIAL_CONTACT",
                    session_id,
                    session.user_id().unwrap_or("Unknown")
                );
                false
            } else {
                true
            }
        });
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
        if let Err(err) = session.send_last_request(message_id).await {
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
                Self::schedule_retransmission(
                    self.command_sender.clone(),
                    session_id,
                    message_id,
                    delay,
                )
                .await
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

    async fn process_esp_packet(
        &mut self,
        datagram: &mut UdpDatagram,
        vpn_service: &mut FortiService,
    ) -> Result<(), IKEv2Error> {
        if datagram.bytes.as_slice() == &[0xff] {
            debug!("Received ESP NAT keepalive from {}", datagram.remote_addr);
            return Ok(self
                .udp_sender
                .send_datagram(&datagram.local_addr, &datagram.remote_addr, &[0xff])
                .await?);
        }
        trace!(
            "Received ESP packet from {}\n{:?}",
            datagram.remote_addr,
            datagram.bytes,
        );
        if datagram.bytes.len() < 8 {
            return Err("Not enough data in ESP packet".into());
        }
        let mut local_spi = [0u8; 4];
        local_spi.copy_from_slice(&datagram.bytes[0..4]);
        let local_spi = u32::from_be_bytes(local_spi);
        if let Some(sa) = self.security_associations.get_mut(&local_spi) {
            let decrypted_slice = sa.handle_esp(&mut datagram.bytes)?;
            trace!(
                "Decrypted ESP packet from {}\n{:?}",
                datagram.remote_addr,
                decrypted_slice
            );
            let hdr = esp::IpHeader::from_packet(decrypted_slice)?;
            trace!("IP header {}", hdr);
            if !sa.accepts_esp_to_vpn(&hdr) {
                debug!("ESP packet {} dropped by traffic selector", hdr);
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
            Ok(vpn_service.send_packet(decrypted_slice).await?)
        } else {
            warn!(
                "Security Association {:x} from {} not found",
                local_spi, datagram.remote_addr
            );
            Err("Security Association not found".into())
        }
    }

    async fn process_vpn_packet(
        &mut self,
        data: &mut [u8],
        data_len: usize,
    ) -> Result<(), IKEv2Error> {
        if data_len == 0 {
            return Ok(());
        }
        let hdr = match esp::IpHeader::from_packet(&data[..data_len]) {
            Ok(hdr) => hdr,
            Err(err) => {
                warn!(
                    "Failed to read header in IP packet from VPN: {}\n{:?}",
                    err,
                    &data[..data_len]
                );
                return Err("Failed to read header in IP packet from VPN".into());
            }
        };
        trace!("Received packet from VPN {}\n{:?}", hdr, data);
        // Prefer an active, most recent SA.
        if let Some(sa) = self
            .security_associations
            .values_mut()
            .filter(|sa| sa.accepts_vpn_to_esp(&hdr))
            .reduce(|a, b| {
                if a.is_active() && a.index() > b.index() {
                    a
                } else {
                    b
                }
            })
        {
            let encoded_length = sa.encoded_length(data_len);
            if encoded_length > data.len() {
                // This sometimes happens when FortiVPN returns a zero-padded packet.
                warn!(
                    "Slice doesn't have capacity for ESP headers, message length is {}, slice has {}",
                    encoded_length,
                    data.len()
                );
                return Err("Vector doesn't have capacity for ESP headers".into());
            }
            let encrypted_data = sa.handle_vpn(&mut data[..encoded_length], data_len)?;
            trace!(
                "Encrypted VPN packet to {}\n{:?}",
                sa.remote_addr(),
                encrypted_data
            );
            self.udp_sender
                .send_datagram(&sa.local_addr(), &sa.remote_addr(), encrypted_data)
                .await?;
            Ok(())
        } else {
            debug!(
                "No matching Security Associations found for VPN packet {}",
                hdr
            );
            Err("No matching Security Associations found for VPN packet".into())
        }
    }
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
            addrs.await?.for_each(|addr| ip_addresses.push(addr.ip()));
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
    Forti(fortivpn::service::VpnServiceError),
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

impl From<fortivpn::service::VpnServiceError> for IKEv2Error {
    fn from(err: fortivpn::service::VpnServiceError) -> IKEv2Error {
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
