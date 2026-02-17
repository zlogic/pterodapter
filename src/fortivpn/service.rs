use std::net::IpAddr;

use log::{debug, info, warn};
use tokio::{runtime, task::JoinHandle, time::Interval};

use crate::{pcap, uplink};

use super::{Config, FortiVPNTunnel};

const FLUSH_INTERVAL: usize = 5;

struct ConnectingData {
    tunnel: FortiVPNTunnel,
    cookie_client_ip: IpAddr,
}

struct ConnectedData {
    tunnel: FortiVPNTunnel,
    cookie_client_ip: IpAddr,
    echo_timer: Interval,
    need_echo: bool,
    unflushed_writes: usize,
}

enum ConnectionState {
    Disconnected,
    Connecting(JoinHandle<Result<ConnectingData, uplink::UplinkError>>),
    Connected(Box<ConnectedData>),
}

pub struct FortiService {
    config: Config,
    state: ConnectionState,
    pcap_sender: Option<pcap::PcapSender>,
}

impl FortiService {
    pub fn new(config: Config, pcap_sender: Option<pcap::PcapSender>) -> FortiService {
        FortiService {
            config,
            state: ConnectionState::Disconnected,
            pcap_sender,
        }
    }

    async fn connect(config: Config) -> Result<ConnectingData, uplink::UplinkError> {
        let (sslvpn_cookie, cookie_client_ip) = super::get_oauth_cookie(&config).await?;
        debug!("VPN cookie received");
        let vpn_tunnel = FortiVPNTunnel::new(&config, sslvpn_cookie).await?;
        Ok(ConnectingData {
            tunnel: vpn_tunnel,
            cookie_client_ip,
        })
    }

    pub fn cookie_client_ip(&self) -> Option<IpAddr> {
        if let ConnectionState::Connected(connected_data) = &self.state {
            Some(connected_data.cookie_client_ip)
        } else {
            None
        }
    }
}

impl uplink::UplinkService for FortiService {
    fn is_connected(&self) -> bool {
        matches!(self.state, ConnectionState::Connected(_))
    }

    fn ip_configuration(&self) -> Option<(IpAddr, &[IpAddr])> {
        match self.state {
            ConnectionState::Connected(ref state) => {
                Some((state.tunnel.ip_addr(), state.tunnel.dns()))
            }
            _ => None,
        }
    }

    async fn wait_event(&mut self, buf: &mut [u8]) -> Result<(), uplink::UplinkError> {
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
                Ok(connecting_data) => {
                    info!("VPN service is connected");
                    let mut echo_timer = tokio::time::interval(super::ECHO_SEND_INTERVAL);
                    echo_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    self.state = ConnectionState::Connected(Box::new(ConnectedData {
                        tunnel: connecting_data.tunnel,
                        cookie_client_ip: connecting_data.cookie_client_ip,
                        echo_timer,
                        need_echo: false,
                        unflushed_writes: 0,
                    }));
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
                    warn!("Failed to check if next packet from VPN is available: {err}");
                    self.state = ConnectionState::Disconnected;
                    Err(err.into())
                } else {
                    Ok(())
                }
            }
        }
    }

    async fn read_packet<'a>(
        &mut self,
        buffer: &'a mut [u8],
    ) -> Result<&'a [u8], uplink::UplinkError> {
        if let ConnectionState::Connected(state) = &mut self.state {
            match state.tunnel.try_read_packet(buffer).await {
                Ok(data) => {
                    if let Some(pcap_sender) = &mut self.pcap_sender {
                        pcap_sender.send_packet(data);
                    }
                    Ok(data)
                }
                Err(err) => {
                    self.state = ConnectionState::Disconnected;
                    Err(err.into())
                }
            }
        } else {
            Ok(&[])
        }
    }

    async fn process_events(&mut self, send_slices: &[&[u8]]) -> Result<(), uplink::UplinkError> {
        if let ConnectionState::Connected(state) = &mut self.state {
            let mut sent_data = false;
            for send_data in send_slices {
                if send_data.is_empty() {
                    continue;
                }
                if let Some(pcap_sender) = &mut self.pcap_sender {
                    pcap_sender.send_packet(send_data);
                }
                sent_data = true;
                match state.tunnel.write_data(send_data).await {
                    Ok(()) => {
                        state.unflushed_writes += 1;
                    }
                    Err(err) => {
                        warn!("Failed to send packet to VPN: {err}");
                        self.state = ConnectionState::Disconnected;
                        return Err(err.into());
                    }
                }
            }
            if state.need_echo {
                state.need_echo = false;
                if let Err(err) = state.tunnel.process_echo().await {
                    warn!("Echo request timed out: {err}");
                    self.state = ConnectionState::Disconnected;
                    return Err(err.into());
                }
            }
            if (state.unflushed_writes > FLUSH_INTERVAL
                || (state.unflushed_writes > 0 && !sent_data))
                && let Err(err) = state.tunnel.flush().await
            {
                warn!("Failed to flush data to VPN: {err}");
                self.state = ConnectionState::Disconnected;
                return Err(err.into());
            }
        }
        Ok(())
    }

    async fn terminate(&mut self) -> Result<(), uplink::UplinkError> {
        match &mut self.state {
            ConnectionState::Connected(state) => {
                let result = state.tunnel.terminate().await;
                self.state = ConnectionState::Disconnected;
                Ok(result?)
            }
            _ => Ok(()),
        }
    }
}
