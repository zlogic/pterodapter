use std::{
    error, fmt, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use log::{debug, info, warn};
use rand::Rng;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    runtime,
    sync::mpsc,
    task::JoinHandle,
    time::{Duration, Instant},
};
use tokio_rustls::rustls;

use crate::http;
use crate::ppp;

#[derive(Clone)]
pub struct Config {
    pub tls_config: Arc<rustls::client::ClientConfig>,
    pub destination_addr: SocketAddr,
    pub destination_hostport: String,
    pub mtu: u16,
}

// PPP_MTU specifies is the MTU excluding IP, TCP, TLS, FortiVPN and PPP encapsulation headers.
// When running locally, using this MTU adjusts to the FortiVPN stream MTU.
pub const PPP_MTU: u16 = 1500 - 20 - 20 - 5 - 6 - 4;

// ESP_MTU specifies the typical MTU used by most IKEv2 clients.
// By aligning to this value, fragmentation can be significantly reduced.
pub const ESP_MTU: u16 = 1280;

const MAX_MTU: usize = PPP_MTU as usize;

// TODO: check how FortiVPN chooses the listen port - is it fixed or sent as a parameter?
const REDIRECT_ADDRESS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8020);

const ECHO_TIMEOUT: Duration = Duration::from_secs(60);
const ECHO_SEND_INTERVAL: Duration = Duration::from_secs(10);

async fn get_oauth_cookie(config: &Config) -> Result<String, FortiError> {
    println!(
        "Please open https://{}/remote/saml/start?redirect=1 in your browser...",
        config.destination_hostport
    );

    let listener = match TcpListener::bind(REDIRECT_ADDRESS).await {
        Ok(listener) => listener,
        Err(err) => {
            warn!("Failed to bind listener on {}: {}", REDIRECT_ADDRESS, err);
            return Err("Failed to bind listener".into());
        }
    };
    let socket = match listener.accept().await {
        Ok((socket, addr)) => {
            debug!("New connection on SAML redirect port from {}", addr);
            socket
        }
        Err(err) => {
            warn!("Failed to accept incoming connection: {}", err);
            return Err("Failed to accept incoming connection".into());
        }
    };
    let mut socket = BufReader::new(socket);
    let headers = http::read_headers(&mut socket).await?;
    let token_id = headers.lines().next().and_then(|line| {
        if !line.starts_with("GET /?id=") {
            return None;
        }
        let start_index = line.find("=")?;
        let line = &line[start_index + 1..];
        let end_index = line.find(" ")?;
        Some(line[..end_index].to_string())
    });

    let token_id = if let Some(token_id) = token_id {
        token_id
    } else {
        return Err("No token found in request".into());
    };

    // Get real token based on token ID.
    let cookie = {
        let domain = if let Some(separator) = config.destination_hostport.find(":") {
            &config.destination_hostport[..separator]
        } else {
            &config.destination_hostport
        };
        let mut socket =
            FortiVPNTunnel::connect(&config.destination_addr, domain, config.tls_config.clone())
                .await?;
        debug!("Connected to cookie retrieval host");
        socket
            .write_all(
                http::build_request(
                    format!("GET /remote/saml/auth_id?id={}", token_id).as_str(),
                    domain,
                    None,
                    0,
                )
                .as_bytes(),
            )
            .await?;
        socket.flush().await?;
        let mut cookie = None;
        debug!("Reading cookie response");
        let headers = http::read_headers(&mut socket).await?;
        http::validate_response_code(&headers)?;
        for line in headers.lines() {
            if cookie.is_none() && line.starts_with("Set-Cookie: SVPNCOOKIE=") {
                if let Some(start_index) = line.find(":") {
                    let line = &line[start_index + 2..];
                    if let Some(end_index) = line.find("; ") {
                        cookie = Some(line[..end_index].to_string());
                    }
                }
            }
        }
        if let Some(cookie) = cookie {
            cookie
        } else {
            return Err("Response has no cookie".into());
        }
    };

    debug!("Successfully obtained cookie");

    let response = include_bytes!("static/token.html");
    http::write_sso_response(&mut socket, response).await?;

    Ok(cookie)
}

struct IpConfig {
    addr: IpAddr,
    dns: Vec<IpAddr>,
}

pub struct FortiVPNTunnel {
    socket: BufTlsStream,
    ip_config: IpConfig,
    ppp_state: PPPState,
    ppp_magic: u32,
    ppp_identifier: u8,
    last_echo_sent: Instant,
    last_echo_reply: Instant,
}

impl FortiVPNTunnel {
    pub async fn new(config: &Config, cookie: String) -> Result<FortiVPNTunnel, FortiError> {
        let domain = if let Some(separator) = config.destination_hostport.find(":") {
            &config.destination_hostport[..separator]
        } else {
            &config.destination_hostport
        };
        let mut socket =
            Self::connect(&config.destination_addr, domain, config.tls_config.clone()).await?;
        debug!("Connected to VPN host");
        let ip_config = Self::request_vpn_allocation(domain, &mut socket, &cookie).await?;
        Self::start_vpn_tunnel(domain, &mut socket, &cookie).await?;

        let mtu = config.mtu;
        let mut ppp_state = PPPState::new();
        let ppp_magic = Self::start_ppp(&mut socket, &mut ppp_state, mtu).await?;
        Self::start_ipcp(&mut socket, &mut ppp_state, ip_config.addr).await?;
        Ok(FortiVPNTunnel {
            socket,
            ip_config,
            ppp_state,
            ppp_magic,
            ppp_identifier: 2,
            last_echo_sent: Instant::now(),
            last_echo_reply: Instant::now(),
        })
    }

    pub fn ip_addr(&self) -> IpAddr {
        self.ip_config.addr
    }

    pub fn dns(&self) -> &[IpAddr] {
        &self.ip_config.dns
    }

    async fn connect(
        hostport: &SocketAddr,
        domain: &str,
        tls_config: Arc<rustls::client::ClientConfig>,
    ) -> Result<BufTlsStream, FortiError> {
        let connector = tokio_rustls::TlsConnector::from(tls_config);
        let dnsname = rustls::pki_types::ServerName::try_from(domain.to_owned())?;

        let socket = TcpStream::connect(&hostport).await?;
        let socket = connector.connect(dnsname, socket).await?;
        Ok(BufReader::new(socket))
    }

    async fn request_vpn_allocation(
        domain: &str,
        socket: &mut BufTlsStream,
        cookie: &str,
    ) -> Result<IpConfig, FortiError> {
        let req = http::build_request("GET /remote/fortisslvpn_xml", domain, Some(cookie), 0);
        socket.write_all(req.as_bytes()).await?;
        socket.flush().await?;

        let headers = http::read_headers(socket).await?;
        http::validate_response_code(&headers)?;
        let content = http::read_content(socket, headers.as_str()).await?;

        let addr = {
            const IPV4_ADDRESS_PREFIX: &str = "<assigned-addr ipv4='";
            let ipv4_addr_start = if let Some(start) = content.find(IPV4_ADDRESS_PREFIX) {
                start
            } else {
                debug!("Unsupported config format: {}", content);
                return Err("Cannot find IPv4 address in config".into());
            };
            let content = &content[ipv4_addr_start + IPV4_ADDRESS_PREFIX.len()..];
            let ipv4_addr_end = if let Some(start) = content.find("'") {
                start
            } else {
                debug!("Unsupported config format: {}", content);
                return Err("Cannot find IPv4 address in config".into());
            };
            IpAddr::from_str(&content[..ipv4_addr_end]).map_err(|err| {
                debug!("Failed to parse IPv4 address: {}", err);
                "Failed to parse IPv4 address"
            })?
        };

        const DNS_PREFIX: &str = "<dns ip='";
        let mut dns = vec![];
        let mut content = content.as_str();
        while let Some(dns_start) = content.find(DNS_PREFIX) {
            content = &content[dns_start + DNS_PREFIX.len()..];
            let dns_end = if let Some(start) = content.find("'") {
                start
            } else {
                debug!("Unsupported config format: {}", content);
                return Err("Cannot find DNS address in config".into());
            };
            let dns_addr = IpAddr::from_str(&content[..dns_end]).map_err(|err| {
                debug!("Failed to parse DNS address: {}", err);
                "Failed to parse DNS address"
            })?;
            dns.push(dns_addr);
        }
        Ok(IpConfig { addr, dns })
    }

    async fn start_vpn_tunnel(
        domain: &str,
        socket: &mut BufTlsStream,
        cookie: &str,
    ) -> Result<(), FortiError> {
        let req = http::build_request("GET /remote/sslvpn-tunnel", domain, Some(cookie), 0);
        socket.write_all(req.as_bytes()).await?;
        Ok(socket.flush().await?)
    }

    async fn start_ppp(
        socket: &mut BufTlsStream,
        ppp_state: &mut PPPState,
        mtu: u16,
    ) -> Result<u32, FortiError> {
        // Open PPP link; 200 bytes should fit any PPP packet.
        // This is an oversimplified implementation of the RFC 1661 state machine.
        let mut req = [0u8; 20];
        let mut resp = [0u8; 200];
        let identifier = 1;
        let magic = rand::thread_rng().gen::<u32>();
        let opts = [
            ppp::LcpOptionData::MaximumReceiveUnit(mtu),
            ppp::LcpOptionData::MagicNumber(magic),
        ];
        let length =
            ppp::encode_lcp_config(&mut req, ppp::LcpCode::CONFIGURE_REQUEST, identifier, &opts)
                .map_err(|err| {
                    debug!("Failed to encode LCP Configure-Request: {}", err);
                    "Failed to encode LCP Configure-Request"
                })?;
        Self::send_ppp_packet(socket, ppp::Protocol::LCP, &req[..length]).await?;
        socket.flush().await?;

        let mut local_acked = false;
        let mut remote_acked = false;
        while !(local_acked && remote_acked) {
            ppp_state.read_header(socket).await.map_err(|err| {
                debug!("Failed to read PPP header: {}", err);
                "Failed to read PPP header"
            })?;
            let protocol = if let Some(protocol) = ppp_state.read_protocol() {
                protocol
            } else {
                return Err("Unable to read PPP protocol".into());
            };
            let length = Self::read_ppp_packet(socket, ppp_state, &mut resp).await?;
            let response = ppp::Packet::from_bytes(protocol, &resp[..length]).map_err(|err| {
                debug!("Failed to decode PPP packet: {}", err);
                "Failed to decode PPP packet"
            })?;
            debug!("Received LCP packet: {:?}", response);
            let lcp_packet = match response.to_lcp() {
                Ok(lcp) => lcp,
                Err(err) => {
                    debug!(
                        "Received unexpected PPP packet during LCP handshake: {} (error {})",
                        response, err
                    );
                    continue;
                }
            };
            match lcp_packet.code() {
                ppp::LcpCode::CONFIGURE_ACK => {
                    let received_opts = lcp_packet
                        .iter_options()
                        .collect::<Result<Vec<_>, ppp::FormatError>>();
                    let options_match = match received_opts {
                        Ok(received_opts) => opts == received_opts.as_slice(),
                        Err(err) => {
                            debug!("Failed to decode LCP Ack options: {}", err);
                            return Err("Failed to decode LCP Ack options".into());
                        }
                    };
                    if !options_match {
                        return Err("Configure Ack has unexpected LCP options".into());
                    }
                    local_acked = true;
                }
                ppp::LcpCode::CONFIGURE_REQUEST => {
                    lcp_packet
                        .iter_options()
                        .map(|opt| {
                            let opt = match opt {
                                Ok(opt) => opt,
                                Err(err) => {
                                    debug!(
                                        "Remote side sent invalid LCP configuration option: {}",
                                        err
                                    );
                                    return Err(
                                        "Remote side sent invalid LCP configuration option".into(),
                                    );
                                }
                            };
                            match opt {
                                ppp::LcpOptionData::MaximumReceiveUnit(offered_mtu) => {
                                    if offered_mtu <= mtu {
                                        Ok(opt)
                                    } else {
                                        debug!("Remote side sent unacceptable MTU: {}", mtu);
                                        Err("Remote side sent unacceptable MTU".into())
                                    }
                                }
                                ppp::LcpOptionData::MagicNumber(_) => Ok(opt),
                                _ => {
                                    debug!(
                                        "Remote side sent unsupported LCP configuration option: {}",
                                        opt
                                    );
                                    Err("Remote side sent unsupported LCP configuration option"
                                        .into())
                                }
                            }
                        })
                        .collect::<Result<Vec<_>, FortiError>>()?;
                    let length = ppp::encode_lcp_data(
                        &mut req,
                        ppp::LcpCode::CONFIGURE_ACK,
                        lcp_packet.identifier(),
                        lcp_packet.read_options(),
                    )
                    .map_err(|err| {
                        debug!("Failed to encode LCP Configure-Ack: {}", err);
                        "Failed to encode LCP Configure-Ack"
                    })?;
                    Self::send_ppp_packet(socket, ppp::Protocol::LCP, &req[..length]).await?;
                    socket.flush().await?;
                    remote_acked = true;
                }
                ppp::LcpCode::CONFIGURE_NAK => {
                    debug!("Remote side Nak'd LCP configuration: {}", response);
                    return Err("Remote side Nak'd LCP configuration".into());
                }
                ppp::LcpCode::CONFIGURE_REJECT => {
                    debug!("Remote side rejected LCP configuration: {}", response);
                    return Err("Remote side rejected LCP configuration".into());
                }
                _ => {
                    debug!("Received unexpected PPP packet: {}", response);
                    return Err("Unexpected PPP packet received".into());
                }
            }
        }

        Ok(magic)
    }

    async fn start_ipcp(
        socket: &mut BufTlsStream,
        ppp_state: &mut PPPState,
        addr: IpAddr,
    ) -> Result<(), FortiError> {
        // Open IPCP link; 20 bytes should fit any IPCP packet.
        // This is an oversimplified implementation of the RFC 1661 state machine.
        let mut req = [0u8; 20];
        let mut resp = [0u8; 200];
        let identifier = 1;
        let addr = match addr {
            IpAddr::V4(addr) => addr,
            _ => return Ok(()),
        };
        let opts = [ppp::IpcpOptionData::IpAddress(addr)];
        let length =
            ppp::encode_ipcp_config(&mut req, ppp::LcpCode::CONFIGURE_REQUEST, identifier, &opts)
                .map_err(|err| {
                debug!("Failed to encode IPCP Configure-Request: {}", err);
                "Failed to encode IPCP Configure-Request"
            })?;
        let mut opts = [0u8; 100];
        let opts_len = length - 4;
        opts[..opts_len].copy_from_slice(&req[4..length]);
        Self::send_ppp_packet(socket, ppp::Protocol::IPV4CP, &req[..length]).await?;
        socket.flush().await?;

        let mut local_acked = false;
        let mut remote_acked = false;
        while !(local_acked && remote_acked) {
            ppp_state.read_header(socket).await.map_err(|err| {
                debug!("Failed to read PPP header: {}", err);
                "Failed to read PPP header"
            })?;
            let protocol = if let Some(protocol) = ppp_state.read_protocol() {
                protocol
            } else {
                return Err("Unable to read PPP protocol".into());
            };
            let length = Self::read_ppp_packet(socket, ppp_state, &mut resp).await?;
            let response = ppp::Packet::from_bytes(protocol, &resp[..length]).map_err(|err| {
                debug!("Failed to decode PPP packet: {}", err);
                "Failed to decode PPP packet"
            })?;
            debug!("Received IPCP packet: {:?}", response);
            let ipcp_packet = match response.to_ipcp() {
                Ok(lcp) => lcp,
                Err(err) => {
                    debug!(
                        "Received unexpected PPP packet during handshake: {} (error {})",
                        response, err
                    );
                    continue;
                }
            };
            match ipcp_packet.code() {
                ppp::LcpCode::CONFIGURE_ACK => {
                    if ipcp_packet.read_options() != &opts[..opts_len] {
                        return Err("Configure Ack has unexpected IPCP options".into());
                    }
                    local_acked = true;
                }
                ppp::LcpCode::CONFIGURE_REQUEST => {
                    ipcp_packet
                        .iter_options()
                        .map(|opt| {
                            let opt = match opt {
                                Ok(opt) => opt,
                                Err(err) => {
                                    debug!(
                                        "Remote side sent invalid IPCP configuration option: {}",
                                        err
                                    );
                                    return Err(
                                        "Remote side sent invalid IPCP configuration option".into(),
                                    );
                                }
                            };
                            match opt {
                                ppp::IpcpOptionData::IpAddress(_) => Ok(opt),
                                ppp::IpcpOptionData::PrimaryDns(_) => Ok(opt),
                                ppp::IpcpOptionData::SecondaryDns(_) => Ok(opt),
                                _ => {
                                    debug!(
                                        "Remote side sent unsupported IPCP configuration option: {}",
                                        opt
                                    );
                                    Err("Remote side sent unsupported IPCP configuration option".into())
                                }
                            }
                        })
                        .collect::<Result<Vec<_>, FortiError>>()?;
                    let length = ppp::encode_lcp_data(
                        &mut req,
                        ppp::LcpCode::CONFIGURE_ACK,
                        ipcp_packet.identifier(),
                        ipcp_packet.read_options(),
                    )
                    .map_err(|err| {
                        debug!("Failed to encode IPCP Configure-Ack: {}", err);
                        "Failed to encode IPCP Configure-Ack"
                    })?;
                    Self::send_ppp_packet(socket, ppp::Protocol::IPV4CP, &req[..length]).await?;
                    socket.flush().await?;
                    remote_acked = true;
                }
                ppp::LcpCode::CONFIGURE_NAK => {
                    debug!("Remote side Nak'd IPCP configuration: {}", response);
                    return Err("Remote side Nak'd IPCP configuration".into());
                }
                ppp::LcpCode::CONFIGURE_REJECT => {
                    debug!("Remote side rejected IPCP configuration: {}", response);
                    return Err("Remote side rejected IPCP configuration".into());
                }
                _ => {
                    debug!("Received unexpected PPP packet: {}", response);
                    return Err("Unexpected PPP packet received".into());
                }
            }
        }

        Ok(())
    }

    async fn send_ppp_packet(
        socket: &mut BufTlsStream,
        protocol: ppp::Protocol,
        ppp_data: &[u8],
    ) -> Result<(), FortiError> {
        // FortiVPN encapsulation.
        let mut packet = [0u8; 8 + MAX_MTU];
        let ppp_packet_length = ppp_data.len() + 2;
        packet[0..2].copy_from_slice(&(6 + ppp_packet_length as u16).to_be_bytes());
        packet[2..4].copy_from_slice(&[0x50, 0x50]);
        packet[4..6].copy_from_slice(&(ppp_packet_length as u16).to_be_bytes());
        // PPP encapsulation.
        packet[6..8].copy_from_slice(&protocol.value().to_be_bytes());

        // Data.
        packet[8..8 + ppp_data.len()].copy_from_slice(ppp_data);
        let packet = &packet[..8 + ppp_data.len()];
        Ok(socket.write_all(packet).await?)
    }

    async fn read_ppp_packet(
        socket: &mut BufTlsStream,
        state: &mut PPPState,
        dest: &mut [u8],
    ) -> Result<usize, FortiError> {
        state.read_header(socket).await.map_err(|err| {
            debug!("Failed to read PPP header: {}", err);
            "Failed to read PPP header"
        })?;
        let mut received_data = 0;
        if state.remaining_bytes() > dest.len() {
            warn!(
                "Destination buffer ({} bytes) is smaller than the traferred packet ({} bytes), discarding it",
                dest.len(),
                state.remaining_bytes()
            );
            // Drain packet to prepare for reading the next one.
            while state.remaining_bytes() > 0 {
                let bytes_transferred = socket.read(dest).await?;
                state.consume_bytes(bytes_transferred)?;
            }
        } else {
            // Read all data to the end.
            while state.remaining_bytes() > 0 {
                let bytes_transferred = socket
                    .read(&mut dest[received_data..received_data + state.remaining_bytes()])
                    .await?;
                state.consume_bytes(bytes_transferred)?;
                received_data += bytes_transferred;
            }
        }
        Ok(received_data)
    }

    async fn send_echo(&mut self, code: ppp::LcpCode, identifier: u8) -> Result<(), FortiError> {
        let mut req = [0u8; 8];
        let data = self.ppp_magic.to_be_bytes();
        let length = ppp::encode_lcp_data(&mut req, code, identifier, &data).map_err(|err| {
            debug!("Failed to encode {}: {}", code, err);
            "Failed to encode Echo message"
        })?;
        Self::send_ppp_packet(&mut self.socket, ppp::Protocol::LCP, &req[..length]).await?;
        Ok(self.socket.flush().await?)
    }

    async fn send_echo_request(&mut self) -> Result<(), FortiError> {
        self.send_echo(ppp::LcpCode::ECHO_REQUEST, self.ppp_identifier)
            .await?;
        self.ppp_identifier = self.ppp_identifier.overflowing_add(1).0;
        self.last_echo_sent = Instant::now();
        Ok(())
    }

    pub async fn process_echo(&mut self) -> Result<(), FortiError> {
        let last_echo_sent = self.last_echo_sent;
        if last_echo_sent + ECHO_SEND_INTERVAL < Instant::now() {
            // Only send echo if it's time.
            self.send_echo_request().await?;
        }
        if self.last_echo_reply + ECHO_TIMEOUT < last_echo_sent {
            Err("No echo replies received".into())
        } else {
            Ok(())
        }
    }

    pub async fn send_packet(&mut self, data: &[u8]) -> Result<(), FortiError> {
        Self::send_ppp_packet(&mut self.socket, ppp::Protocol::IPV4, data).await
    }

    pub async fn flush(&mut self) -> Result<(), FortiError> {
        Ok(self.socket.flush().await?)
    }

    async fn process_control_packet(&mut self) -> Result<(), FortiError> {
        let protocol = match self.ppp_state.read_protocol() {
            Some(ppp::Protocol::IPV4) => return Ok(()),
            Some(protocol) => protocol,
            None => return Ok(()),
        };
        // 200 bytes should fit any PPP packet.
        let mut dest = [0u8; 200];
        let length =
            Self::read_ppp_packet(&mut self.socket, &mut self.ppp_state, &mut dest).await?;

        match protocol {
            ppp::Protocol::LCP => {
                let packet = match ppp::Packet::from_bytes(protocol, &dest[..length]) {
                    Ok(packet) => packet,
                    Err(err) => {
                        info!("Failed to decode PPP packet: {}", err);
                        return Err("Failed to decode PPP packet".into());
                    }
                };
                let packet = packet
                    .to_lcp()
                    .map_err(|_| "Failed to convert packet to LCP")?;
                match packet.code() {
                    ppp::LcpCode::ECHO_REPLY => {
                        self.last_echo_reply = Instant::now();
                    }
                    ppp::LcpCode::ECHO_REQUEST => {
                        self.send_echo(ppp::LcpCode::ECHO_REPLY, packet.identifier())
                            .await
                            .map_err(|err| {
                                debug!("Failed to reply to echo {}", err);
                                err
                            })?;
                    }
                    _ => {
                        info!("Received unexpected LCP packet {}, ignoring", packet.code());
                    }
                }
            }
            _ => {
                info!("Received unexpected PPP packet {}, ignoring", protocol);
            }
        }
        Ok(())
    }

    pub async fn peek_recv(&mut self) -> Result<(), FortiError> {
        self.ppp_state.peek_data(&mut self.socket).await
    }

    pub async fn try_read_packet(&mut self, dest: &mut [u8]) -> Result<usize, FortiError> {
        // Peek header if not yet available - to get the protocol.
        self.ppp_state
            .read_header(&mut self.socket)
            .await
            .map_err(|err| {
                info!("Failed to read PPP header: {}", err);
                "Failed to read PPP header"
            })?;
        let protocol = match self.ppp_state.read_protocol() {
            Some(protocol) => protocol,
            None => {
                return Err("Unknown PPP protocol, possibly a framing error".into());
            }
        };
        match protocol {
            ppp::Protocol::LCP => {
                self.process_control_packet().await?;
                Ok(0)
            }
            ppp::Protocol::IPV4 | ppp::Protocol::IPV6 => {
                Ok(Self::read_ppp_packet(&mut self.socket, &mut self.ppp_state, dest).await?)
            }
            _ => {
                info!("Received unexpected PPP packet {}, ignoring", protocol);
                Ok(0)
            }
        }
    }

    pub async fn terminate(&mut self) -> Result<(), FortiError> {
        let mut req = [0u8; 4];
        // Ensure that any stray IP packets are accepted.
        let mut resp = [0u8; MAX_MTU + 8];
        let length = ppp::encode_lcp_data(
            &mut req,
            ppp::LcpCode::TERMINATE_REQUEST,
            self.ppp_identifier,
            &[],
        )
        .map_err(|err| {
            debug!("Failed to encode Terminate-Request: {}", err);
            "Failed to encode Terminate-Request message"
        })?;
        Self::send_ppp_packet(&mut self.socket, ppp::Protocol::LCP, &req[..length]).await?;
        self.socket.flush().await?;

        loop {
            self.ppp_state
                .read_header(&mut self.socket)
                .await
                .map_err(|err| {
                    debug!("Failed to read PPP header: {}", err);
                    "Failed to read PPP header"
                })?;
            let protocol = if let Some(protocol) = self.ppp_state.read_protocol() {
                protocol
            } else {
                return Err("Unable to read PPP protocol".into());
            };
            let length =
                Self::read_ppp_packet(&mut self.socket, &mut self.ppp_state, &mut resp).await?;
            let response = ppp::Packet::from_bytes(protocol, &resp[..length]).map_err(|err| {
                debug!("Failed to decode PPP packet: {}", err);
                "Failed to decode PPP packet"
            })?;
            let lcp_packet = match response.to_lcp() {
                Ok(lcp) => lcp,
                Err(err) => {
                    debug!(
                        "Received unexpected PPP packet during termination: {} (error {})",
                        response, err
                    );
                    continue;
                }
            };
            debug!("Received LCP packet: {:?}", response);
            if lcp_packet.code() == ppp::LcpCode::TERMINATE_ACK {
                break;
            }
        }

        self.socket.shutdown().await?;
        Ok(())
    }
}

struct PPPState {
    ppp_header: [u8; 8],
    ppp_header_length: usize,
    bytes_remaining: usize,
    first_packet: bool,
}

impl PPPState {
    fn new() -> PPPState {
        PPPState {
            ppp_header: [0u8; 8],
            ppp_header_length: 0,
            bytes_remaining: 0,
            first_packet: true,
        }
    }

    async fn peek_data(&mut self, socket: &mut BufTlsStream) -> Result<(), FortiError> {
        if self.bytes_remaining > 0 {
            return Ok(());
        }
        // If no data is available, this will return immediately.
        while self.ppp_header_length < self.ppp_header.len() {
            match socket
                .read(&mut self.ppp_header[self.ppp_header_length..])
                .await
            {
                Ok(bytes_read) => {
                    if bytes_read > 0 {
                        self.ppp_header_length += bytes_read;
                    } else {
                        return Err("TLS reader is closed".into());
                    }
                }
                Err(err) => {
                    debug!("Failed to read PPP header: {}", err);
                    return Err("Failed to read PPP header".into());
                }
            }
        }
        Ok(())
    }

    async fn read_header(&mut self, socket: &mut BufTlsStream) -> Result<(), FortiError> {
        self.peek_data(socket).await?;
        self.validate_link(socket).await?;

        let mut ppp_size = [0u8; 2];
        ppp_size.copy_from_slice(&self.ppp_header[..2]);
        let ppp_size = u16::from_be_bytes(ppp_size);
        let mut data_size = [0u8; 2];
        data_size.copy_from_slice(&self.ppp_header[4..6]);
        let data_size = u16::from_be_bytes(data_size);
        let magic = &self.ppp_header[2..4];
        if ppp_size != data_size + 6 {
            debug!(
                "Conflicting packet size data: PPP packet size is {}, data size is {}",
                ppp_size, data_size
            );
            return Err("Header has conflicting length data".into());
        }
        if magic != [0x50, 0x50] {
            debug!(
                "Found {:x}{:x} instead of magic",
                self.ppp_header[2], self.ppp_header[3]
            );
            return Err("Magic not found".into());
        }
        self.bytes_remaining = data_size as usize - 2;
        Ok(())
    }

    fn remaining_bytes(&self) -> usize {
        self.bytes_remaining
    }

    fn consume_bytes(&mut self, count: usize) -> Result<(), FortiError> {
        if self.bytes_remaining < count {
            Err("Consumed more bytes than were available".into())
        } else {
            self.bytes_remaining -= count;
            if self.bytes_remaining == 0 {
                self.ppp_header_length = 0;
            }
            Ok(())
        }
    }

    fn read_protocol(&self) -> Option<ppp::Protocol> {
        if self.ppp_header_length == 8 {
            Some(ppp::Protocol::from_be_slice(&self.ppp_header[6..]))
        } else {
            None
        }
    }

    async fn validate_link(&mut self, socket: &mut BufTlsStream) -> Result<(), FortiError> {
        const FALL_BACK_TO_HTTP: &[u8] = "HTTP/1".as_bytes();
        if !self.first_packet {
            return Ok(());
        }
        self.first_packet = false;
        if &self.ppp_header[..FALL_BACK_TO_HTTP.len()] == FALL_BACK_TO_HTTP {
            // FortiVPN will return an HTTP response if something goes wrong on setup.
            let headers = http::read_headers(socket).await?;
            debug!("Tunnel not active, error response: {}", headers);
            let content = http::read_content(socket, headers.as_str()).await?;
            debug!("Error contents: {}", content);
            Err("Tunnel refused to establish link".into())
        } else {
            Ok(())
        }
    }
}

pub enum FortiTunnelEvent {
    Connected(IpAddr, Vec<IpAddr>),
    ReceivedPacket(Vec<u8>, usize),
    Error(FortiError),
    Disconnected,
    EchoFailed(FortiError),
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
    tunnel_task: Option<JoinHandle<Result<(), FortiError>>>,
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
    ) -> Result<String, FortiError> {
        use std::future::{self, Future};
        use std::pin::pin;
        use std::task::Poll;
        loop {
            let (sslvpn_cookie, received_cancel) = {
                let mut sslvpn_cookie = pin!(get_oauth_cookie(config));
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
    ) -> Result<FortiVPNTunnel, FortiError> {
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
    ) -> Result<(), FortiError> {
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
        let mut echo_timer = tokio::time::interval(ECHO_SEND_INTERVAL);
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
                        FortiTunnelEvent::Error(err)
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
                        if tx.send(FortiTunnelEvent::Error(err)).await.is_err() {
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
                    if tx.send(FortiTunnelEvent::EchoFailed(err)).await.is_err() {
                        debug!("VPN sink channel closed");
                        rx.close();
                    }
                }
            }
            if flush {
                if let Err(err) = tunnel.flush().await {
                    is_connected = false;
                    if tx.send(FortiTunnelEvent::Error(err)).await.is_err() {
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

    pub async fn next_event(&mut self) -> Result<FortiTunnelEvent, FortiError> {
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
                Ok(Err(err)) => Err(err.into()),
                Err(err) => Err(err.into()),
            }
        } else {
            Err("VPN client is stopped".into())
        }
    }

    pub async fn next_events(
        &mut self,
        buffer: &mut Vec<FortiTunnelEvent>,
    ) -> Result<(), FortiError> {
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
                Ok(Err(err)) => Err(err.into()),
                Err(err) => Err(err.into()),
            }
        } else {
            Err("VPN client is stopped".into())
        }
    }
    pub async fn start_disconnection(&mut self) -> Result<(), FortiError> {
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

    pub async fn send_packet(&mut self, data: &[u8]) -> Result<(), FortiError> {
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

type BufTlsStream = BufReader<tokio_rustls::client::TlsStream<TcpStream>>;

#[derive(Debug)]
pub enum FortiError {
    Internal(&'static str),
    Io(io::Error),
    Tls(rustls::Error),
    Dns(rustls::pki_types::InvalidDnsNameError),
    Http(http::HttpError),
    Join(tokio::task::JoinError),
}

impl fmt::Display for FortiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Internal(msg) => f.write_str(msg),
            Self::Io(ref e) => write!(f, "IO error: {}", e),
            Self::Tls(ref e) => write!(f, "TLS error: {}", e),
            Self::Dns(ref e) => write!(f, "DNS error: {}", e),
            Self::Http(ref e) => write!(f, "HTTP error: {}", e),
            Self::Join(ref e) => write!(f, "Tokio join error: {}", e),
        }
    }
}

impl error::Error for FortiError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Self::Internal(_msg) => None,
            Self::Io(ref err) => Some(err),
            Self::Tls(ref err) => Some(err),
            Self::Dns(ref err) => Some(err),
            Self::Http(ref err) => Some(err),
            Self::Join(ref err) => Some(err),
        }
    }
}

impl From<&'static str> for FortiError {
    fn from(msg: &'static str) -> FortiError {
        Self::Internal(msg)
    }
}

impl From<io::Error> for FortiError {
    fn from(err: io::Error) -> FortiError {
        Self::Io(err)
    }
}

impl From<rustls::Error> for FortiError {
    fn from(err: rustls::Error) -> FortiError {
        Self::Tls(err)
    }
}

impl From<rustls::pki_types::InvalidDnsNameError> for FortiError {
    fn from(err: rustls::pki_types::InvalidDnsNameError) -> FortiError {
        Self::Dns(err)
    }
}

impl From<crate::http::HttpError> for FortiError {
    fn from(err: crate::http::HttpError) -> FortiError {
        Self::Http(err)
    }
}

impl From<tokio::task::JoinError> for FortiError {
    fn from(err: tokio::task::JoinError) -> FortiError {
        Self::Join(err)
    }
}
