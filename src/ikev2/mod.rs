use ip::{Nat64Prefix, Network};
use log::{debug, info, trace, warn};
use rand::Rng;
use std::{
    collections::{HashMap, HashSet},
    error, fmt,
    future::{self, Future},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::pin,
    sync::Arc,
    task::Poll,
    time::{Duration, Instant},
};
use tokio::{
    io::ReadBuf,
    net::UdpSocket,
    runtime,
    sync::{mpsc, oneshot},
    time,
};

use crate::{
    fortivpn::{self, service::FortiService},
    logger::fmt_slice_hex,
};

mod crypto;
mod esp;
mod ip;
mod message;
mod pki;
mod session;

const MAX_DATAGRAM_SIZE: usize = 1500 + fortivpn::PPP_HEADER_SIZE;
// Use 1500 as max MTU, real value is likely lower.
const MAX_ESP_PACKET_SIZE: usize = 1500 + fortivpn::PPP_HEADER_SIZE;

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
    pub nat64_prefix: Option<Ipv6Addr>,
}

pub struct Server {
    listen_ips: Vec<IpAddr>,
    port: u16,
    nat_port: u16,
    pki_processing: Arc<pki::PkiProcessing>,
    tunnel_domains: Vec<String>,
    nat64_prefix: Option<Nat64Prefix>,
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
            port: config.port,
            nat_port: config.nat_port,
            pki_processing: Arc::new(pki_processing),
            tunnel_domains: config.tunnel_domains,
            nat64_prefix: config.nat64_prefix.map(Nat64Prefix::new),
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

    pub async fn run(
        self,
        fortivpn_config: fortivpn::Config,
        shutdown_receiver: oneshot::Receiver<()>,
    ) -> Result<(), IKEv2Error> {
        let sockets = Sockets::new(&self.listen_ips, self.port, self.nat_port).await?;
        let vpn_service = FortiService::new(fortivpn_config);

        let rt = runtime::Handle::current();
        let (command_sender, command_receiver) = mpsc::channel(32);
        // Non-critical futures will be terminated by Tokio during the shutdown_timeout phase.
        rt.spawn(Server::send_cleanup_ticks(
            CLEANUP_INTERVAL,
            command_sender.clone(),
        ));
        let mut network = ip::Network::new(self.nat64_prefix, self.tunnel_domains.clone())?;
        if !network.is_nat64() {
            network.refresh_addresses().await?;
            let routes_sender = command_sender.clone();
            let mut refresh_network = network.clone();
            rt.spawn(async move {
                let mut delay = tokio::time::interval(SPLIT_TUNNEL_REFRESH_INTERVAL);
                delay.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
                loop {
                    delay.tick().await;
                    if let Err(err) = refresh_network.refresh_addresses().await {
                        warn!("Failed to refresh IP addresses for split routes: {}", err);
                        continue;
                    };
                    let _ = routes_sender
                        .send(SessionMessage::UpdateSplitRoutes(refresh_network.clone()))
                        .await;
                }
            });
        };

        let sessions = Sessions::new(
            self.pki_processing.clone(),
            sockets,
            command_sender.clone(),
            network,
        );
        rt.spawn(async move {
            if shutdown_receiver.await.is_ok()
                && command_sender.send(SessionMessage::Shutdown).await.is_err()
            {
                warn!("Command channel closed");
            }
        });

        Self::run_process(command_receiver, sessions, vpn_service).await
    }

    async fn run_process(
        mut command_receiver: mpsc::Receiver<SessionMessage>,
        mut sessions: Sessions,
        mut vpn_service: FortiService,
    ) -> Result<(), IKEv2Error> {
        let rt = runtime::Handle::current();
        let mut shutdown = false;
        let mut udp_read_buffer = vec![0u8; MAX_DATAGRAM_SIZE];
        let mut udp_write_buffer = vec![0u8; MAX_DATAGRAM_SIZE];
        let mut vpn_read_buffer = vec![0u8; MAX_DATAGRAM_SIZE];
        let mut vpn_write_buffer = vec![0u8; MAX_DATAGRAM_SIZE];
        let mut poll_seed = 0usize;
        loop {
            let vpn_is_connected = vpn_service.is_connected();
            if shutdown && sessions.is_empty() && !vpn_is_connected {
                debug!("Shutdown completed");
                return Ok(());
            }
            // Wait until something is ready.
            let mut udp_exchange = UdpExchange::new(&mut udp_read_buffer, &mut udp_write_buffer);
            poll_seed = poll_seed.wrapping_add(1);
            let (command_message, udp_source, vpn_event) = {
                let mut vpn_event = None;
                let mut udp_source = None;
                let mut command_message = None;
                let ignore_vpn = shutdown && !vpn_is_connected;
                let mut receive_command = pin!(command_receiver.recv());
                let mut receive_vpn_event = pin!(vpn_service.wait_event(&mut vpn_read_buffer));
                let sockets = &sessions.sockets;
                future::poll_fn(|cx| {
                    if vpn_event.is_none() {
                        vpn_event = if !ignore_vpn {
                            let vpn_event = receive_vpn_event.as_mut().poll(cx);
                            match vpn_event {
                                Poll::Ready(cmd) => Some(cmd),
                                Poll::Pending => None,
                            }
                        } else {
                            // Avoid waking if VPN is already shut down.
                            None
                        };
                    }
                    if udp_source.is_none() {
                        udp_source = match sockets.poll_recv(cx, poll_seed, &mut udp_exchange) {
                            Poll::Ready(result) => Some(result),
                            Poll::Pending => None,
                        };
                    }
                    if command_message.is_none() {
                        command_message = match receive_command.as_mut().poll(cx) {
                            Poll::Ready(cmd) => cmd,
                            Poll::Pending => None,
                        }
                    }
                    if vpn_event.is_some() || udp_source.is_some() || command_message.is_some() {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
                (command_message, udp_source, vpn_event)
            };
            // Process all ready events.
            if let Some(message) = command_message {
                match message {
                    SessionMessage::Shutdown => {
                        shutdown = true;
                        sessions.cleanup(&rt);
                        if let Err(err) = vpn_service.terminate().await {
                            warn!("Failed to terminate VPN client connection: {}", err);
                        }
                    }
                    _ => {
                        // These messages are handled by Session.
                    }
                }
                sessions.process_message(message).await;
            }
            let mut vpn_exchange = VpnExchange::new(&mut vpn_read_buffer, &mut vpn_write_buffer);
            match vpn_event {
                Some(Ok(())) => {
                    match vpn_exchange
                        .exchange_mut()
                        .entire_request_mut_async(async |vpn_buffer| {
                            match vpn_service.read_packet(vpn_buffer).await {
                                Ok(read_range) => (read_range.clone(), Ok(read_range)),
                                Err(err) => (0..0, Err(err)),
                            }
                        })
                        .await
                    {
                        Ok(_) => {
                            if let Err(err) = sessions.process_vpn_packet(&mut vpn_exchange) {
                                warn!("Failed to forward VPN packet to IKEv2: {}", err);
                                vpn_exchange.clear();
                            }
                        }
                        Err(err) => {
                            warn!("Failed to read packet from VPN: {}", err);
                            vpn_exchange.clear();
                        }
                    }
                }
                Some(Err(err)) => {
                    warn!("VPN reported an error status: {}", err);
                    vpn_exchange.clear();
                }
                None => {
                    vpn_exchange.clear();
                }
            };
            let (vpn_reply, vpn_send_to_udp) = vpn_exchange.into_packets();
            match udp_source {
                Some(Ok(udp_source)) => {
                    let result = if udp_source.is_ikev2() {
                        sessions.update_ip(vpn_service.ip_configuration());
                        sessions
                            .process_ikev2_message(udp_exchange.exchange(), &udp_source)
                            .await
                    } else {
                        sessions.process_esp_packet(udp_exchange.exchange_mut(), &udp_source)
                    };
                    if let Err(err) = result {
                        warn!(
                            "Failed to process message from {}: {}",
                            udp_source.remote_addr, err
                        );
                    } else {
                        udp_exchange.source = Some(udp_source);
                    }
                }
                Some(Err(err)) => {
                    warn!("Failed to read data from UDP socket: {}", err);
                    udp_exchange.clear();
                }
                None => {
                    udp_exchange.clear();
                }
            };
            let (udp_reply, udp_send_to_vpn) = udp_exchange.into_packets();
            let (vpn_event, sent_udp_response, forwarded_udp_packet) = {
                let send_slices_to_vpn = [vpn_reply, udp_send_to_vpn];
                let mut process_vpn_events = pin!(vpn_service.process_events(&send_slices_to_vpn));
                let mut sent_udp_response = None;
                let mut forwarded_udp_packet = None;
                let mut vpn_event = None;
                let sockets = &mut sessions.sockets;
                future::poll_fn(|cx| {
                    if vpn_event.is_none() {
                        vpn_event = match process_vpn_events.as_mut().poll(cx) {
                            Poll::Ready(result) => Some(result),
                            Poll::Pending => None,
                        };
                    }
                    if sent_udp_response.is_none() {
                        sent_udp_response = if let Some((source, udp_reply_data)) = &udp_reply {
                            match sockets.poll_send(
                                cx,
                                source.local_addr,
                                source.remote_addr,
                                udp_reply_data,
                            ) {
                                Poll::Ready(result) => Some(result),
                                Poll::Pending => None,
                            }
                        } else {
                            Some(Ok(()))
                        }
                    }
                    if forwarded_udp_packet.is_none() {
                        forwarded_udp_packet =
                            if let Some((destination, vpn_packet)) = &vpn_send_to_udp {
                                match sockets.poll_send(
                                    cx,
                                    destination.local_addr,
                                    destination.remote_addr,
                                    vpn_packet,
                                ) {
                                    Poll::Ready(result) => Some(result),
                                    Poll::Pending => None,
                                }
                            } else {
                                Some(Ok(()))
                            }
                    }
                    if vpn_event.is_some()
                        && sent_udp_response.is_some()
                        && forwarded_udp_packet.is_some()
                    {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
                (vpn_event, sent_udp_response, forwarded_udp_packet)
            };
            if let Some(Err(err)) = sent_udp_response {
                warn!("Failed to send UDP ESP response: {}", err);
            }
            if let Some(Err(err)) = forwarded_udp_packet {
                warn!("Failed to forward message to UDP ESP: {}", err);
            }
            if let Some(Err(err)) = vpn_event {
                warn!("Failed to process VPN lifecycle events: {}", err);
            }
            if vpn_is_connected && !vpn_service.is_connected() {
                sessions.delete_all_sessions(&rt);
            }
        }
    }
}

struct Sockets {
    sockets: HashMap<SocketAddr, Arc<UdpSocket>>,
    socket_list: Vec<(SocketAddr, Arc<UdpSocket>)>,
    nat_port: u16,
}

impl Sockets {
    async fn new(listen_ips: &[IpAddr], port: u16, nat_port: u16) -> Result<Sockets, IKEv2Error> {
        let mut sockets = HashMap::new();
        let mut socket_list = vec![];
        for listen_ip in listen_ips {
            for listen_port in [port, nat_port] {
                let socket = match UdpSocket::bind((*listen_ip, listen_port)).await {
                    Ok(socket) => socket,
                    Err(err) => {
                        log::error!("Failed to open listener on {}: {}", listen_ip, err);
                        return Err(err.into());
                    }
                };
                let socket = Arc::new(socket);
                let listen_addr = socket.local_addr()?;
                info!("Started server on {}", listen_addr);
                sockets.insert(listen_addr, socket.clone());
                socket_list.push((listen_addr, socket));
            }
        }
        Ok(Sockets {
            sockets,
            socket_list,
            nat_port,
        })
    }

    fn poll_send(
        &self,
        cx: &mut std::task::Context<'_>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        data: &[u8],
    ) -> Poll<Result<(), IKEv2Error>> {
        if !data.is_empty() {
            if let Some(socket) = self.sockets.get(&local_addr) {
                match socket.poll_send_to(cx, data, remote_addr) {
                    Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
                    Poll::Ready(Err(err)) => Poll::Ready(Err(err.into())),
                    Poll::Pending => Poll::Pending,
                }
            } else {
                warn!(
                    "No open sockets for source address {} (destination {})",
                    local_addr, remote_addr
                );
                Poll::Ready(Err("No open sockets for source address".into()))
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
        seed: usize,
        udp_exchange: &mut UdpExchange,
    ) -> Poll<Result<UdpDatagramSource, IKEv2Error>> {
        // Split socket list into two parts, then combine the second half with the first one.
        let seed = seed % self.socket_list.len();
        let (left, right) = self.socket_list.split_at(seed % self.socket_list.len());
        let it = right.iter().chain(left.iter());
        for (listen_addr, socket) in it {
            let is_nat_port = listen_addr.port() == self.nat_port;
            let result = udp_exchange
                .exchange_mut()
                .entire_request_mut(|udp_read_buffer| {
                    let mut buf = ReadBuf::new(udp_read_buffer);
                    let result = socket.poll_recv_from(cx, &mut buf);
                    (0..buf.filled().len(), result)
                });
            match result {
                Poll::Ready(Ok(remote_addr)) => {
                    let request = udp_exchange.exchange().request();
                    let is_non_esp =
                        request.len() >= 4 && request[0..4] == [0x00, 0x00, 0x00, 0x00];
                    return Poll::Ready(Ok(UdpDatagramSource {
                        remote_addr,
                        local_addr: *listen_addr,
                        is_nat_port,
                        is_non_esp,
                    }));
                }
                Poll::Ready(Err(err)) => {
                    warn!("Failed to receive from socket {}: {}", listen_addr, err);
                    return Poll::Ready(Err(err.into()));
                }
                Poll::Pending => {}
            };
        }
        Poll::Pending
    }

    async fn send_datagram(
        &self,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        data: &[u8],
    ) -> Result<(), SendError> {
        if let Some(socket) = self.sockets.get(local_addr) {
            socket.send_to(data, remote_addr).await.map_err(|err| {
                warn!(
                    "Failed to send UDP message from {} to {}: {}",
                    local_addr, remote_addr, err
                );
                err
            })?;
            Ok(())
        } else {
            warn!(
                "No open sockets for source address {} (destination {})",
                local_addr, remote_addr
            );
            Err("No open sockets for source address".into())
        }
    }
}

struct UdpDatagramSource {
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    is_nat_port: bool,
    is_non_esp: bool,
}

impl UdpDatagramSource {
    fn is_ikev2(&self) -> bool {
        !self.is_nat_port || self.is_non_esp
    }
}

struct UdpExchange<'a> {
    exchange: ip::Exchange<'a>,
    source: Option<UdpDatagramSource>,
}

impl<'a> UdpExchange<'a> {
    pub fn new(request: &'a mut [u8], response: &'a mut [u8]) -> UdpExchange<'a> {
        UdpExchange {
            exchange: ip::Exchange::new(request, response),
            source: None,
        }
    }

    fn clear(&mut self) {
        self.exchange.reset();
        self.source = None;
    }

    #[inline]
    fn exchange(&self) -> &ip::Exchange {
        &self.exchange
    }

    #[inline]
    fn exchange_mut(&mut self) -> &mut ip::Exchange<'a> {
        &mut self.exchange
    }

    fn into_packets(self) -> (Option<(UdpDatagramSource, &'a [u8])>, &'a [u8]) {
        let (request_slice, response_slice) = self.exchange.into_slices();
        let udp_reply = if response_slice.is_empty() {
            None
        } else if let Some(source) = self.source {
            Some((source, response_slice))
        } else {
            None
        };
        (udp_reply, request_slice)
    }
}

struct UdpDatagramDestination {
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
}

struct VpnExchange<'a> {
    exchange: ip::Exchange<'a>,
    destination: Option<UdpDatagramDestination>,
}

impl<'a> VpnExchange<'a> {
    pub fn new(request: &'a mut [u8], response: &'a mut [u8]) -> VpnExchange<'a> {
        VpnExchange {
            exchange: ip::Exchange::new(request, response),
            destination: None,
        }
    }

    fn clear(&mut self) {
        self.exchange.reset();
        self.destination = None;
    }

    #[inline]
    fn exchange(&self) -> &ip::Exchange {
        &self.exchange
    }

    #[inline]
    fn exchange_mut(&mut self) -> &mut ip::Exchange<'a> {
        &mut self.exchange
    }

    fn into_packets(self) -> (&'a [u8], Option<(UdpDatagramDestination, &'a [u8])>) {
        let (request_slice, response_slice) = self.exchange.into_slices();
        let udp_forward = if request_slice.is_empty() {
            None
        } else if let Some(destination) = self.destination {
            Some((destination, request_slice))
        } else {
            None
        };
        (response_slice, udp_forward)
    }
}
enum SessionMessage {
    DeleteSession(session::SessionID),
    DeleteSecurityAssociation(u32),
    RetransmitRequest(session::SessionID, u32),
    CleanupTimer,
    UpdateSplitRoutes(Network),
    Shutdown,
}

struct Sessions {
    pki_processing: Arc<pki::PkiProcessing>,
    sockets: Sockets,
    network: Network,
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
        sockets: Sockets,
        command_sender: mpsc::Sender<SessionMessage>,
        network: Network,
    ) -> Sessions {
        Sessions {
            pki_processing,
            sockets,
            network,
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
                &self.network,
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

    fn update_all_split_routes(&mut self) {
        for (_, session) in self.sessions.iter_mut() {
            session.update_split_routes(self.network.ts_local())
        }
    }

    fn update_ip(&mut self, configuration: Option<(IpAddr, &[IpAddr])>) {
        let (internal_addr, dns_addrs): (Option<IpAddr>, &[IpAddr]) =
            if let Some((internal_addr, dns_addrs)) = configuration {
                (Some(internal_addr), dns_addrs)
            } else {
                (None, &[])
            };
        // TODO 0.5.0: Remove this debug code.
        let internal_addr = Some(IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)));
        let dns_addrs = &[
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        ];
        self.network
            .update_ip_configuration(internal_addr, dns_addrs);
    }

    fn reserve_session_ids(&mut self) -> session::ReservedSpi {
        let mut reserved_spi = if let Some(reserved_spi) = self.reserved_spi.take() {
            reserved_spi
        } else {
            session::ReservedSpi::new(self.next_sa_index)
        };
        while reserved_spi.needs_ike() {
            let next_id = rand::rng().random::<u64>();
            if !self.sessions.keys().any(|key| key.local_spi() == next_id) {
                reserved_spi.add_ike(next_id);
            }
        }
        while reserved_spi.needs_esp() {
            let next_id = rand::rng().random::<u32>();
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
            SessionMessage::UpdateSplitRoutes(network) => {
                self.network = network;
                self.update_all_split_routes();
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
        exchange: &ip::Exchange<'_>,
        udp_source: &UdpDatagramSource,
    ) -> Result<(), IKEv2Error> {
        let is_nat = udp_source.is_non_esp;
        let ikev2_request = message::InputMessage::from_datagram(exchange.request(), is_nat)?;
        if !ikev2_request.is_valid() {
            return Err("Invalid message received".into());
        }

        debug!(
            "Received packet from {}\n{:?}",
            udp_source.remote_addr, ikev2_request
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
                udp_source.remote_addr,
                udp_source.local_addr,
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
            session.update_network(&self.network);
        };

        if ikev2_request.read_flags()?.has(message::Flags::RESPONSE) {
            session.process_response(
                udp_source.remote_addr,
                udp_source.local_addr,
                &ikev2_request,
            )?;
        } else {
            let transmit_response = session.process_request(
                udp_source.remote_addr,
                udp_source.local_addr,
                &ikev2_request,
                &mut reserved_spi,
            )?;
            self.reserved_spi = Some(reserved_spi);
            // Response retransmissions are initiated by client.
            if transmit_response {
                if let Err(err) = session
                    .send_last_response(&self.sockets, ikev2_request.read_message_id(), is_nat)
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

    fn process_esp_packet(
        &mut self,
        exchange: &mut ip::Exchange,
        udp_source: &UdpDatagramSource,
    ) -> Result<(), IKEv2Error> {
        let remote_addr = udp_source.remote_addr;
        if exchange.request() == [0xff] {
            debug!("Received ESP NAT keepalive from {}", udp_source.remote_addr);
            exchange.reset();
            return exchange.entire_response_mut(|response| {
                response[0] = 0xff;
                (0..1, Ok(()))
            });
        }
        trace!(
            "Received ESP packet from {}\n{}",
            remote_addr,
            fmt_slice_hex(exchange.request())
        );
        if exchange.request().len() < 8 {
            return Err("Not enough data in ESP packet".into());
        }
        let mut local_spi = [0u8; 4];
        local_spi.copy_from_slice(&exchange.request()[0..4]);
        let local_spi = u32::from_be_bytes(local_spi);
        if let Some(sa) = self.security_associations.get_mut(&local_spi) {
            sa.handle_esp(exchange)?;
            trace!(
                "Decrypted ESP packet from {}\n{}",
                remote_addr,
                fmt_slice_hex(exchange.request())
            );
            let ip_packet = match ip::IpPacket::from_data(exchange.request()) {
                Ok(packet) => packet,
                Err(err) => {
                    warn!(
                        "Failed to parse IP packet from ESP: {}\n{}",
                        err,
                        fmt_slice_hex(exchange.request()),
                    );
                    return Err("Failed to parse IP packet from ESP".into());
                }
            };
            trace!("Decoded IP packet from ESP {}", ip_packet);
            let ip_header = match ip_packet.to_header() {
                Ok(hdr) => hdr,
                Err(err) => {
                    warn!(
                        "Failed to read header in IP packet from ESP: {}\n{}",
                        err, ip_packet
                    );
                    return Err("Failed to read header in IP packet from ESP".into());
                }
            };
            if !sa.accepts_esp_to_vpn(&ip_header) {
                debug!("ESP packet {} dropped by traffic selector", ip_header);
                // Microsoft Teams can spam the network with a lot of stray packets.
                // Don't log an error if the packet is dropped to keep the logs clean on the info
                // level.
                exchange.reset();
                return Ok(());
            }
            if exchange.request().len() > MAX_ESP_PACKET_SIZE {
                warn!(
                    "Decrypted packet size {} exceeds MTU {}",
                    exchange.request().len(),
                    MAX_ESP_PACKET_SIZE
                );
                return Err("Decrypted ESP packet size exceeds MTU".into());
            }
            // TODO 0.5.0: Find a better place for this function call.
            if let Err(err) = sa.nat_to_vpn(&ip_packet) {
                warn!("Failed to NAT packet from ESP: {}", err);
                return Err("Failed to NAT packet from ESP".into());
            }
            Ok(())
        } else {
            warn!(
                "Security Association {:x} from {} not found",
                local_spi, udp_source.remote_addr
            );
            Err("Security Association not found".into())
        }
    }

    fn process_vpn_packet(&mut self, exchange: &mut VpnExchange<'_>) -> Result<(), IKEv2Error> {
        if exchange.exchange().request().is_empty() {
            return Ok(());
        }
        let ip_packet = match ip::IpPacket::from_data(exchange.exchange().request()) {
            Ok(packet) => packet,
            Err(err) => {
                warn!(
                    "Failed to decode IP packet from VPN: {}\n{}",
                    err,
                    fmt_slice_hex(exchange.exchange().request()),
                );
                return Err("Failed to decode IP packet from VPN".into());
            }
        };
        trace!("Decoded IP packet from VPN {}", ip_packet);
        let ip_header = match ip_packet.to_header() {
            Ok(hdr) => hdr,
            Err(err) => {
                warn!(
                    "Failed to read header in IP packet from VPN: {}\n{}",
                    err, ip_packet
                );
                return Err("Failed to read header in IP packet from VPN".into());
            }
        };
        // Prefer an active, most recent SA.
        if let Some(sa) = self
            .security_associations
            .values_mut()
            .filter(|sa| sa.accepts_vpn_to_esp(&ip_header))
            .reduce(|a, b| {
                if a.is_active() && a.index() > b.index() {
                    a
                } else {
                    b
                }
            })
        {
            let encoded_length = sa.encoded_length(exchange.exchange().request().len());
            if encoded_length > exchange.exchange().request_capacity() {
                // This sometimes happens when FortiVPN returns a zero-padded packet.
                warn!(
                    "Slice doesn't have capacity for ESP headers, message length is {}, buffer has {}",
                    encoded_length,
                    exchange.exchange().request_capacity()
                );
                return Err("Vector doesn't have capacity for ESP headers".into());
            }
            sa.handle_vpn(exchange.exchange_mut())?;
            trace!(
                "Encrypted VPN packet to {}\n{}",
                sa.remote_addr(),
                fmt_slice_hex(exchange.exchange().request())
            );

            exchange.destination = Some(UdpDatagramDestination {
                remote_addr: sa.remote_addr(),
                local_addr: sa.local_addr(),
            });
            Ok(())
        } else {
            debug!(
                "No matching Security Associations found for VPN packet {}",
                ip_header
            );
            Err("No matching Security Associations found for VPN packet".into())
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
            Self::Io(ref e) => write!(f, "IO error: {}", e),
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
    Ip(ip::IpError),
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
            Self::Ip(ref e) => write!(f, "IP error: {}", e),
            Self::Forti(ref e) => write!(f, "VPN error: {}", e),
            Self::SendError(ref e) => write!(f, "Send error: {}", e),
            Self::Join(ref e) => write!(f, "Tokio join error: {}", e),
            Self::Io(ref e) => write!(f, "IO error: {}", e),
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
            Self::Ip(ref err) => Some(err),
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

impl From<ip::IpError> for IKEv2Error {
    fn from(err: ip::IpError) -> IKEv2Error {
        Self::Ip(err)
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
