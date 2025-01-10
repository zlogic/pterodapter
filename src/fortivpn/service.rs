use std::{error, fmt, net::IpAddr};

use log::{debug, info, warn};
use tokio::{runtime, task::JoinHandle, time::Interval};

use super::{Config, FortiVPNTunnel};

const FLUSH_INTERVAL: usize = 5;

struct ConnectedData {
    tunnel: FortiVPNTunnel,
    echo_timer: Interval,
    need_echo: bool,
    unflushed_writes: usize,
}

enum ConnectionState {
    Disconnected,
    Connecting(JoinHandle<Result<FortiVPNTunnel, VpnServiceError>>),
    Connected(ConnectedData),
}

pub struct FortiService {
    config: Config,
    state: ConnectionState,
}

impl FortiService {
    pub fn new(config: Config) -> FortiService {
        FortiService {
            config,
            state: ConnectionState::Disconnected,
        }
    }

    pub fn is_connected(&self) -> bool {
        matches!(self.state, ConnectionState::Connected(_))
    }

    async fn connect(config: Config) -> Result<FortiVPNTunnel, VpnServiceError> {
        let sslvpn_cookie = super::get_oauth_cookie(&config).await?;
        debug!("VPN cookie received");
        Ok(FortiVPNTunnel::new(&config, sslvpn_cookie).await?)
    }

    pub async fn wait_event(&mut self, buf: &mut [u8]) -> Result<(), VpnServiceError> {
        use std::future::{self, Future};
        use std::pin::pin;
        use std::task::Poll;

        match &mut self.state {
            ConnectionState::Disconnected => {
                let rt = runtime::Handle::current();
                let connect_handle = rt.spawn(Self::connect(self.config.clone()));
                self.state = ConnectionState::Connecting(connect_handle);
                Ok(())
            }
            ConnectionState::Connecting(join_handle) => match join_handle.await? {
                Ok(tunnel) => {
                    info!("VPN service is connected");
                    let mut echo_timer = tokio::time::interval(super::ECHO_SEND_INTERVAL);
                    echo_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    self.state = ConnectionState::Connected(ConnectedData {
                        tunnel,
                        echo_timer,
                        need_echo: false,
                        unflushed_writes: 0,
                    });
                    Ok(())
                }
                Err(err) => {
                    self.state = ConnectionState::Disconnected;
                    Err(err)
                }
            },
            ConnectionState::Connected(connected_data) => {
                // TLS cannot read and write at the same time.
                let (send_echo, packet_available) = {
                    let mut send_echo = pin!(connected_data.echo_timer.tick());
                    let mut received_packet = pin!(connected_data.tunnel.read_data(buf));
                    future::poll_fn(move |cx| {
                        let send_echo = send_echo.as_mut().poll(cx);
                        let packet_available = received_packet.as_mut().poll(cx);
                        if send_echo.is_ready() || packet_available.is_ready() {
                            let packet_available = match packet_available {
                                Poll::Ready(packet_available) => Some(packet_available),
                                Poll::Pending => None,
                            };
                            Poll::Ready((send_echo.is_ready(), packet_available))
                        } else {
                            Poll::Pending
                        }
                    })
                    .await
                };
                connected_data.need_echo = send_echo;
                if let Some(Err(err)) = packet_available {
                    warn!(
                        "Failed to check if next packet from VPN is available: {}",
                        err
                    );
                    self.state = ConnectionState::Disconnected;
                    Err(err.into())
                } else {
                    Ok(())
                }
            }
        }
    }

    pub async fn read_packet<'a>(
        &mut self,
        buffer: &'a mut [u8],
    ) -> Result<&'a [u8], VpnServiceError> {
        if let ConnectionState::Connected(state) = &mut self.state {
            match state.tunnel.try_read_packet(buffer).await {
                Ok(data) => Ok(data),
                Err(err) => {
                    self.state = ConnectionState::Disconnected;
                    Err(err.into())
                }
            }
        } else {
            Ok(&[])
        }
    }

    pub async fn process_events(
        &mut self,
        send_data: Option<&[u8]>,
    ) -> Result<(), VpnServiceError> {
        if let ConnectionState::Connected(state) = &mut self.state {
            if let Some(send_data) = send_data {
                match state.tunnel.write_data(send_data).await {
                    Ok(()) => {
                        state.unflushed_writes += 1;
                    }
                    Err(err) => {
                        warn!("Failed to send packet to VPN: {}", err);
                        self.state = ConnectionState::Disconnected;
                        return Err(err.into());
                    }
                }
            }
            if state.need_echo {
                state.need_echo = false;
                if let Err(err) = state.tunnel.process_echo().await {
                    warn!("Echo request timed out: {}", err);
                    self.state = ConnectionState::Disconnected;
                    return Err(err.into());
                }
            }
            if state.unflushed_writes > FLUSH_INTERVAL
                || (state.unflushed_writes > 0 && send_data.is_none())
            {
                if let Err(err) = state.tunnel.flush().await {
                    warn!("Failed to flush data to VPN: {}", err);
                    self.state = ConnectionState::Disconnected;
                    return Err(err.into());
                }
            }
        }
        Ok(())
    }

    pub async fn terminate(&mut self) -> Result<(), VpnServiceError> {
        match &mut self.state {
            ConnectionState::Connected(state) => {
                let result = state.tunnel.terminate().await;
                self.state = ConnectionState::Disconnected;
                Ok(result?)
            }
            _ => Ok(()),
        }
    }

    pub fn mtu(&self) -> u16 {
        self.config.mtu
    }

    pub fn ip_configuration(&self) -> Option<(IpAddr, &[IpAddr])> {
        match self.state {
            ConnectionState::Connected(ref state) => {
                Some((state.tunnel.ip_addr(), state.tunnel.dns()))
            }
            _ => None,
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
