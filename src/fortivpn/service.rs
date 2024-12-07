use std::{error, fmt, net::IpAddr};

use log::{debug, warn};
use tokio::{runtime, sync::mpsc, task::JoinHandle};

use super::{Config, FortiVPNTunnel};

pub enum FortiTunnelEvent {
    Connected(IpAddr, Vec<IpAddr>),
    ReceivedPacket(Vec<u8>, usize),
    Error(VpnServiceError),
    Disconnected,
    EchoFailed(VpnServiceError),
}

enum FortiTunnelCommand {
    SendPacket(Vec<u8>),
    Disconnect,
}

pub struct FortiService<const S: usize, const R: usize> {
    config: Config,
    recv_queue: usize,
    send_queue: usize,
    ip_configuration: Option<(IpAddr, Vec<IpAddr>)>,
    tunnel_tx: Option<mpsc::Sender<FortiTunnelCommand>>,
    tunnel_rx: Option<mpsc::Receiver<FortiTunnelEvent>>,
    tunnel_task: Option<JoinHandle<Result<(), VpnServiceError>>>,
}

impl<const S: usize, const R: usize> FortiService<S, R> {
    pub fn new(config: Config, recv_queue: usize, send_queue: usize) -> FortiService<S, R> {
        FortiService {
            config,
            recv_queue,
            send_queue,
            ip_configuration: None,
            tunnel_tx: None,
            tunnel_rx: None,
            tunnel_task: None,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.tunnel_tx.is_some() || self.tunnel_rx.is_some() || self.tunnel_task.is_some()
    }

    async fn get_oauth_cookie(
        config: &Config,
        rx: &mut mpsc::Receiver<FortiTunnelCommand>,
    ) -> Result<String, VpnServiceError> {
        use std::future::{self, Future};
        use std::pin::pin;
        use std::task::Poll;
        loop {
            let (sslvpn_cookie, received_cancel) = {
                let mut sslvpn_cookie = pin!(super::get_oauth_cookie(config));
                let mut receive_command = pin!(rx.recv());
                future::poll_fn(move |cx| {
                    let received_cookie = match sslvpn_cookie.as_mut().poll(cx) {
                        Poll::Ready(res) => Some(res),
                        Poll::Pending => None,
                    };
                    let received_cancel = match receive_command.as_mut().poll(cx) {
                        Poll::Ready(Some(FortiTunnelCommand::Disconnect)) => Some(true),
                        Poll::Ready(Some(_)) => Some(false),
                        Poll::Ready(None) => Some(true),
                        Poll::Pending => None,
                    };
                    if received_cookie.is_some() || received_cancel.is_some() {
                        Poll::Ready((received_cookie, received_cancel))
                    } else {
                        Poll::Pending
                    }
                })
                .await
            };
            if matches![received_cancel, Some(true)] {
                rx.close();
                return Err("VPN connection canceled while waiting for cookie".into());
            } else if let Some(sslvpn_cookie) = sslvpn_cookie {
                debug!("VPN cookie received");
                return Ok(sslvpn_cookie?);
            }
        }
    }

    async fn connect(
        config: &Config,
        sslvpn_cookie: String,
        rx: &mut mpsc::Receiver<FortiTunnelCommand>,
    ) -> Result<FortiVPNTunnel, VpnServiceError> {
        use std::future::{self, Future};
        use std::pin::pin;
        use std::task::Poll;
        loop {
            let (tunnel, received_cancel) = {
                let mut tunnel_connected = pin!(FortiVPNTunnel::new(config, sslvpn_cookie.clone()));
                let mut receive_command = pin!(rx.recv());
                future::poll_fn(move |cx| {
                    let tunnel_connected = match tunnel_connected.as_mut().poll(cx) {
                        Poll::Ready(res) => Some(res),
                        Poll::Pending => None,
                    };
                    let received_cancel = match receive_command.as_mut().poll(cx) {
                        Poll::Ready(Some(FortiTunnelCommand::Disconnect)) => Some(true),
                        Poll::Ready(Some(_)) => Some(false),
                        Poll::Ready(None) => Some(true),
                        Poll::Pending => None,
                    };
                    if tunnel_connected.is_some() || received_cancel.is_some() {
                        Poll::Ready((tunnel_connected, received_cancel))
                    } else {
                        Poll::Pending
                    }
                })
                .await
            };
            if matches![received_cancel, Some(true)] {
                rx.close();
                return Err("VPN connection canceled while opening tunnel".into());
            } else if let Some(tunnel) = tunnel {
                debug!("VPN connection opened");
                return Ok(tunnel?);
            }
        }
    }

    async fn run_tunnel(
        config: Config,
        tx: &mpsc::Sender<FortiTunnelEvent>,
        rx: &mut mpsc::Receiver<FortiTunnelCommand>,
    ) -> Result<(), VpnServiceError> {
        use std::future::{self, Future};
        use std::pin::pin;
        use std::task::Poll;

        let sslvpn_cookie = Self::get_oauth_cookie(&config.clone(), rx).await?;
        let mut tunnel = Self::connect(&config.clone(), sslvpn_cookie, rx).await?;
        if tx
            .send(FortiTunnelEvent::Connected(
                tunnel.ip_addr(),
                tunnel.dns().to_vec(),
            ))
            .await
            .is_err()
        {
            debug!("VPN sink channel closed");
            rx.close();
        }
        let mut echo_timer = tokio::time::interval(super::ECHO_SEND_INTERVAL);
        echo_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut need_flush = false;
        let mut is_connected = true;
        while is_connected {
            let (can_recv, command, send_echo, flush) = {
                let mut received_packet = pin!(tunnel.peek_recv());
                let mut receive_command = pin!(rx.recv());
                let mut send_echo = pin!(echo_timer.tick());
                future::poll_fn(move |cx| {
                    let can_recv = received_packet.as_mut().poll(cx).is_ready();
                    let command = match receive_command.as_mut().poll(cx) {
                        Poll::Ready(Some(command)) => Some(command),
                        Poll::Ready(None) => Some(FortiTunnelCommand::Disconnect),
                        Poll::Pending => None,
                    };
                    // Flush if there's no more data to send.
                    let should_send = matches!(command, Some(FortiTunnelCommand::SendPacket(_)));
                    let send_echo = send_echo.as_mut().poll(cx).is_ready();
                    if can_recv || command.is_some() || send_echo {
                        Poll::Ready((can_recv, command, send_echo, !should_send))
                    } else if need_flush {
                        // Always flush when there are no reads or writes.
                        Poll::Ready((false, None, false, true))
                    } else {
                        Poll::Pending
                    }
                })
                .await
            };
            if can_recv {
                let mut buffer = vec![0; R];
                let event = match tunnel.try_read_packet(&mut buffer).await {
                    Ok(packet_bytes) => FortiTunnelEvent::ReceivedPacket(buffer, packet_bytes),
                    Err(err) => {
                        is_connected = false;
                        FortiTunnelEvent::Error(err.into())
                    }
                };
                if tx.send(event).await.is_err() {
                    debug!("VPN sink channel closed");
                    rx.close();
                }
            }
            match command {
                Some(FortiTunnelCommand::SendPacket(buffer)) => {
                    need_flush = true;
                    if let Err(err) = tunnel.send_packet(&buffer).await {
                        is_connected = false;
                        if tx.send(FortiTunnelEvent::Error(err.into())).await.is_err() {
                            debug!("VPN sink channel closed");
                            rx.close();
                        }
                    }
                }
                Some(FortiTunnelCommand::Disconnect) => {
                    rx.close();
                    is_connected = false;
                }
                None => {}
            }
            if send_echo {
                need_flush = true;
                if let Err(err) = tunnel.process_echo().await {
                    if tx
                        .send(FortiTunnelEvent::EchoFailed(err.into()))
                        .await
                        .is_err()
                    {
                        debug!("VPN sink channel closed");
                        rx.close();
                    }
                }
            }
            if flush {
                if let Err(err) = tunnel.flush().await {
                    is_connected = false;
                    if tx.send(FortiTunnelEvent::Error(err.into())).await.is_err() {
                        debug!("VPN sink channel closed");
                        rx.close();
                    }
                }
                need_flush = false;
            }
        }

        Ok(tunnel.terminate().await?)
    }

    pub fn start_connection(&mut self, rt: &runtime::Handle) {
        let (service_tx, service_rx) = mpsc::channel(self.recv_queue);
        let (tunnel_tx, mut tunnel_rx) = mpsc::channel(self.send_queue);
        let config = self.config.clone();
        self.tunnel_rx = Some(service_rx);
        self.tunnel_tx = Some(tunnel_tx);
        self.tunnel_task = Some(rt.spawn(async move {
            loop {
                let result = Self::run_tunnel(config.clone(), &service_tx, &mut tunnel_rx).await;
                if service_tx
                    .send(FortiTunnelEvent::Disconnected)
                    .await
                    .is_err()
                {
                    debug!("VPN sink channel closed");
                    tunnel_rx.close();
                }
                if let Err(err) = result.as_ref() {
                    warn!("VPN channel closed with error: {}", err)
                }
                if tunnel_rx.is_closed() {
                    debug!("VPN listener is terminated");
                    return Ok(());
                }
            }
        }));
    }

    fn process_connection_event(&mut self, event: &FortiTunnelEvent) {
        match event {
            FortiTunnelEvent::Disconnected => {
                self.ip_configuration = None;
            }
            FortiTunnelEvent::Connected(ip_addr, ref dns) => {
                self.ip_configuration = Some((*ip_addr, dns.to_vec()));
            }
            _ => {}
        }
    }

    pub async fn next_event(&mut self) -> Result<FortiTunnelEvent, VpnServiceError> {
        if let Some(tunnel_rx) = self.tunnel_rx.as_mut() {
            let event = if let Some(event) = tunnel_rx.recv().await {
                event
            } else {
                return Err("VPN receiver closed".into());
            };
            self.process_connection_event(&event);
            Ok(event)
        } else if let Some(tunnel_task) = self.tunnel_task.as_mut() {
            let result = tunnel_task.await;
            self.tunnel_task = None;
            match result {
                Ok(Ok(())) => Ok(FortiTunnelEvent::Disconnected),
                Ok(Err(err)) => Err(err),
                Err(err) => Err(err.into()),
            }
        } else {
            Err("VPN client is stopped".into())
        }
    }

    pub async fn next_events(
        &mut self,
        buffer: &mut Vec<FortiTunnelEvent>,
    ) -> Result<(), VpnServiceError> {
        buffer.clear();
        if let Some(tunnel_rx) = self.tunnel_rx.as_mut() {
            let count = tunnel_rx.recv_many(buffer, buffer.capacity()).await;
            if count == 0 {
                return Err("VPN receiver closed".into());
            };
            buffer
                .iter()
                .for_each(|event| self.process_connection_event(event));
            Ok(())
        } else if let Some(tunnel_task) = self.tunnel_task.as_mut() {
            let result = tunnel_task.await;
            self.tunnel_task = None;
            match result {
                Ok(Ok(())) => {
                    buffer.push(FortiTunnelEvent::Disconnected);
                    Ok(())
                }
                Ok(Err(err)) => Err(err),
                Err(err) => Err(err.into()),
            }
        } else {
            Err("VPN client is stopped".into())
        }
    }
    pub async fn start_disconnection(&mut self) -> Result<(), VpnServiceError> {
        if let Some(tx) = self.tunnel_tx.take() {
            self.tunnel_rx = None;
            if tx.send(FortiTunnelCommand::Disconnect).await.is_err() {
                if let Some(tunnel_task) = self.tunnel_task.take() {
                    tunnel_task.abort();
                }
                Err("Receiver for VPN disconnection command closed".into())
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    pub async fn send_packet(&mut self, data: &[u8]) -> Result<(), VpnServiceError> {
        if let Some(tx) = self.tunnel_tx.as_mut() {
            let mut buffer = Vec::with_capacity(S);
            if data.len() > buffer.capacity() {
                warn!(
                    "ESP packet ({}) exceeds PPP MTU {}",
                    data.len(),
                    buffer.capacity()
                );
                // Just drop the packet.
                return Ok(());
            }
            buffer.extend_from_slice(data);
            if tx
                .send(FortiTunnelCommand::SendPacket(buffer))
                .await
                .is_err()
            {
                Err("VPN channel closed".into())
            } else {
                Ok(())
            }
        } else {
            Err("VPN client service is not running".into())
        }
    }

    pub fn mtu(&self) -> u16 {
        self.config.mtu
    }

    pub fn ip_configuration(&self) -> Option<(IpAddr, &[IpAddr])> {
        if let Some((ip_addr, dns)) = &self.ip_configuration {
            Some((*ip_addr, dns))
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub enum VpnServiceError {
    Internal(&'static str),
    FortiVpn(super::FortiError),
    Join(tokio::task::JoinError),
}

impl fmt::Display for VpnServiceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Internal(msg) => f.write_str(msg),
            Self::FortiVpn(ref e) => write!(f, "VPN client error: {}", e),
            Self::Join(ref e) => write!(f, "Tokio join error: {}", e),
        }
    }
}

impl error::Error for VpnServiceError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Self::Internal(_msg) => None,
            Self::FortiVpn(ref err) => Some(err),
            Self::Join(ref err) => Some(err),
        }
    }
}

impl From<&'static str> for VpnServiceError {
    fn from(msg: &'static str) -> VpnServiceError {
        Self::Internal(msg)
    }
}

impl From<super::FortiError> for VpnServiceError {
    fn from(err: super::FortiError) -> VpnServiceError {
        Self::FortiVpn(err)
    }
}

impl From<tokio::task::JoinError> for VpnServiceError {
    fn from(err: tokio::task::JoinError) -> VpnServiceError {
        Self::Join(err)
    }
}
