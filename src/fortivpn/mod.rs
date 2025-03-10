use std::{
    error, fmt, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use log::{debug, info, warn};
use rand::Rng;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader, BufStream},
    net::{TcpListener, TcpStream},
    time::{Duration, Instant},
};
use tokio_rustls::rustls;

use crate::http;
use crate::ppp;

pub(crate) mod service;

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

// ESP_MTU specifies the MTU matching the ESP slice size.
// It's set the the UDP buffer size, with reserved space for ESP headers [8] and
// cryptography nonce [8] + padding [8] + tag [16] (for AES GCM),
// or IV [16] + padding [32] + authentication hash [12] (for AES CBC).
pub const ESP_MTU: u16 = 1500 - 8 - 8 - 8 - 16;

// PPP_HEADER_SIZE specifies the PPP header size, which is always prepended to the destination
// buffer.
pub const PPP_HEADER_SIZE: usize = 8;

const MAX_MTU: usize = ESP_MTU as usize;

// TODO: check how FortiVPN chooses the listen port - is it fixed or sent as a parameter?
const REDIRECT_ADDRESS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8020);

const ECHO_TIMEOUT: Duration = Duration::from_secs(60);
pub(crate) const ECHO_SEND_INTERVAL: Duration = Duration::from_secs(10);

pub async fn get_oauth_cookie(config: &Config) -> Result<String, FortiError> {
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

    let response = include_bytes!("../static/token.html");
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
        Ok(BufStream::new(socket))
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
        // TODO FUTUREHEAP
        let mut req = [0u8; 20];
        let mut resp = [0u8; 200];
        let identifier = 1;
        let magic = rand::rng().random::<u32>();
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
            ppp_state
                .read_header(socket, &mut resp)
                .await
                .map_err(|err| {
                    debug!("Failed to read PPP header: {}", err);
                    "Failed to read PPP header"
                })?;
            let protocol = if let Some(protocol) = ppp_state.read_protocol(&resp) {
                protocol
            } else {
                return Err("Unable to read PPP protocol".into());
            };
            let resp = Self::read_ppp_packet(socket, ppp_state, &mut resp).await?;
            let response = ppp::Packet::from_bytes(protocol, resp).map_err(|err| {
                debug!("Failed to decode PPP packet: {}", err);
                "Failed to decode PPP packet"
            })?;
            debug!("Received PPP packet: {}", response);
            let lcp_packet = match &response {
                ppp::Packet::Lcp(lcp) => lcp,
                ppp::Packet::Unknown(_) | ppp::Packet::Ipcp(_) => {
                    debug!(
                        "Received unexpected PPP packet during LCP handshake: {}",
                        response
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
        // TODO FUTUREHEAP
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
        // TODO FUTUREHEAP
        let mut opts = [0u8; 100];
        let opts_len = length - 4;
        opts[..opts_len].copy_from_slice(&req[4..length]);
        Self::send_ppp_packet(socket, ppp::Protocol::IPV4CP, &req[..length]).await?;
        socket.flush().await?;

        let mut local_acked = false;
        let mut remote_acked = false;
        while !(local_acked && remote_acked) {
            ppp_state
                .read_header(socket, &mut resp)
                .await
                .map_err(|err| {
                    debug!("Failed to read PPP header: {}", err);
                    "Failed to read PPP header"
                })?;
            let protocol = if let Some(protocol) = ppp_state.read_protocol(&resp) {
                protocol
            } else {
                return Err("Unable to read PPP protocol".into());
            };
            let resp = Self::read_ppp_packet(socket, ppp_state, &mut resp).await?;
            let response = ppp::Packet::from_bytes(protocol, resp).map_err(|err| {
                debug!("Failed to decode PPP packet: {}", err);
                "Failed to decode PPP packet"
            })?;
            debug!("Received PPP packet: {}", response);
            let ipcp_packet = match &response {
                ppp::Packet::Ipcp(ipcp_packet) => ipcp_packet,
                ppp::Packet::Unknown(_) | ppp::Packet::Lcp(_) => {
                    debug!(
                        "Received unexpected PPP packet during handshake: {}",
                        response
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

    fn write_ppp_header(protocol: ppp::Protocol, length: usize) -> [u8; PPP_HEADER_SIZE] {
        // FortiVPN encapsulation.
        let mut ppp_header = [0u8; PPP_HEADER_SIZE];
        let ppp_packet_length = length + 2;
        ppp_header[0..2].copy_from_slice(&(6 + ppp_packet_length as u16).to_be_bytes());
        ppp_header[2..4].copy_from_slice(&[0x50, 0x50]);
        ppp_header[4..6].copy_from_slice(&(ppp_packet_length as u16).to_be_bytes());
        // PPP encapsulation.
        ppp_header[6..8].copy_from_slice(&protocol.value().to_be_bytes());
        ppp_header
    }

    async fn send_ppp_packet(
        socket: &mut BufTlsStream,
        protocol: ppp::Protocol,
        ppp_data: &[u8],
    ) -> Result<(), FortiError> {
        let ppp_header = Self::write_ppp_header(protocol, ppp_data.len());

        socket.write_all(&ppp_header).await?;
        Ok(socket.write_all(ppp_data).await?)
    }

    async fn read_ppp_packet<'a>(
        socket: &mut BufTlsStream,
        state: &mut PPPState,
        dest: &'a mut [u8],
    ) -> Result<&'a [u8], FortiError> {
        state.read_header(socket, dest).await.map_err(|err| {
            debug!("Failed to read PPP header: {}", err);
            "Failed to read PPP header"
        })?;
        // Read all data to the end.
        while state.have_more_data(dest) {
            state.read_data(socket, dest).await?;
        }
        Ok(state.consume_packet(dest))
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

    pub async fn write_data(&mut self, data: &[u8]) -> Result<(), FortiError> {
        let ppp_header = Self::write_ppp_header(ppp::Protocol::IPV4, data.len());

        self.socket.write_all(&ppp_header).await?;
        Ok(self.socket.write_all(data).await?)
    }

    pub async fn flush(&mut self) -> Result<(), FortiError> {
        Ok(self.socket.flush().await?)
    }

    async fn process_lcp_packet(&mut self, buf: &mut [u8]) -> Result<(), FortiError> {
        let dest = Self::read_ppp_packet(&mut self.socket, &mut self.ppp_state, buf).await?;

        let packet = match ppp::Packet::from_bytes(ppp::Protocol::LCP, dest) {
            Ok(packet) => packet,
            Err(err) => {
                info!("Failed to decode PPP packet: {}", err);
                return Err("Failed to decode PPP packet".into());
            }
        };
        let packet = match &packet {
            ppp::Packet::Lcp(packet) => packet,
            ppp::Packet::Unknown(_) | ppp::Packet::Ipcp(_) => {
                return Err("Failed to convert packet to LCP".into());
            }
        };
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
        Ok(())
    }

    pub async fn read_data(&mut self, buf: &mut [u8]) -> Result<(), FortiError> {
        self.ppp_state.read_data(&mut self.socket, buf).await
    }

    pub async fn try_read_packet<'a>(
        &mut self,
        dest: &'a mut [u8],
    ) -> Result<&'a [u8], FortiError> {
        let protocol = match self.ppp_state.read_protocol(dest) {
            Some(protocol) => protocol,
            None => return Ok(&[]),
        };
        match protocol {
            ppp::Protocol::LCP => {
                self.process_lcp_packet(dest).await?;
                Ok(&[])
            }
            ppp::Protocol::IPV4 | ppp::Protocol::IPV6 => Ok(self.ppp_state.consume_packet(dest)),
            _ => {
                info!("Received unexpected PPP packet {}, ignoring", protocol);
                Ok(&[])
            }
        }
    }

    pub async fn terminate(&mut self) -> Result<(), FortiError> {
        let mut req = [0u8; 4];
        // Ensure that any stray IP packets are accepted.
        // TODO FUTUREHEAP
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
                .read_header(&mut self.socket, &mut resp)
                .await
                .map_err(|err| {
                    debug!("Failed to read PPP header: {}", err);
                    "Failed to read PPP header"
                })?;
            let protocol = if let Some(protocol) = self.ppp_state.read_protocol(&resp) {
                protocol
            } else {
                return Err("Unable to read PPP protocol".into());
            };
            let resp =
                Self::read_ppp_packet(&mut self.socket, &mut self.ppp_state, &mut resp).await?;
            let response = ppp::Packet::from_bytes(protocol, resp).map_err(|err| {
                debug!("Failed to decode PPP packet: {}", err);
                "Failed to decode PPP packet"
            })?;
            debug!("Received PPP packet: {}", response);
            let lcp_packet = match &response {
                ppp::Packet::Lcp(lcp) => lcp,
                ppp::Packet::Unknown(_) | ppp::Packet::Ipcp(_) => {
                    debug!(
                        "Received unexpected PPP packet during termination: {}",
                        response
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
    bytes_consumed: usize,
    first_packet: bool,
}

impl PPPState {
    fn new() -> PPPState {
        PPPState {
            bytes_consumed: 0,
            first_packet: true,
        }
    }

    async fn read_data(
        &mut self,
        socket: &mut BufTlsStream,
        buf: &mut [u8],
    ) -> Result<(), FortiError> {
        // This will read the next bytes (PPP header or remaining packet data).
        let packet_size = self.read_packet_size(buf);
        let read_range = if buf.len() < packet_size {
            warn!(
                "Destination buffer ({} bytes) is smaller than the traferred packet ({} bytes), discarding it",
                buf.len(),
                packet_size
            );
            // Drain packet to prepare for reading the next one.
            let remaining_bytes = packet_size - self.bytes_consumed;
            PPP_HEADER_SIZE..remaining_bytes
        } else {
            self.bytes_consumed..packet_size
        };
        if !read_range.is_empty() {
            match socket.read(&mut buf[read_range]).await {
                Ok(bytes_read) => {
                    if bytes_read > 0 {
                        self.bytes_consumed += bytes_read;
                    } else {
                        return Err("TLS reader is closed".into());
                    }
                }
                Err(err) => {
                    debug!("Failed to read PPP data: {}", err);
                    return Err("Failed to read PPP data".into());
                }
            }
        }
        Ok(())
    }

    async fn read_header(
        &mut self,
        socket: &mut BufTlsStream,
        buf: &mut [u8],
    ) -> Result<(), FortiError> {
        while self.bytes_consumed < PPP_HEADER_SIZE {
            self.read_data(socket, buf).await?;
        }
        self.validate_link(socket, buf).await?;

        let mut ppp_size = [0u8; 2];
        ppp_size.copy_from_slice(&buf[..2]);
        let ppp_size = u16::from_be_bytes(ppp_size);
        let mut data_size = [0u8; 2];
        data_size.copy_from_slice(&buf[4..6]);
        let data_size = u16::from_be_bytes(data_size);
        let magic = &buf[2..4];
        if ppp_size != data_size + 6 {
            debug!(
                "Conflicting packet size data: PPP packet size is {}, data size is {}",
                ppp_size, data_size
            );
            return Err("Header has conflicting length data".into());
        }
        if magic != [0x50, 0x50] {
            debug!("Found {:x}{:x} instead of magic", buf[2], buf[3]);
            return Err("Magic not found".into());
        }
        Ok(())
    }

    fn read_protocol(&self, buf: &[u8]) -> Option<ppp::Protocol> {
        if self.bytes_consumed >= PPP_HEADER_SIZE {
            Some(ppp::Protocol::from_be_slice(&buf[6..8]))
        } else {
            None
        }
    }

    fn read_packet_size(&self, buf: &[u8]) -> usize {
        if self.bytes_consumed >= PPP_HEADER_SIZE {
            let mut ppp_size = [0u8; 2];
            ppp_size.copy_from_slice(&buf[..2]);
            u16::from_be_bytes(ppp_size) as usize
        } else {
            PPP_HEADER_SIZE
        }
    }

    fn have_more_data(&self, buf: &[u8]) -> bool {
        self.bytes_consumed < self.read_packet_size(buf)
    }

    fn consume_packet<'a>(&mut self, buf: &'a [u8]) -> &'a [u8] {
        let packet_size = self.read_packet_size(buf);
        if self.bytes_consumed >= packet_size {
            self.bytes_consumed = 0;
            if self.bytes_consumed > buf.len() {
                // Return empty packet if data was drained.
                &[]
            } else {
                &buf[PPP_HEADER_SIZE..packet_size]
            }
        } else {
            &[]
        }
    }

    async fn validate_link(
        &mut self,
        socket: &mut BufTlsStream,
        buf: &[u8],
    ) -> Result<(), FortiError> {
        const FALL_BACK_TO_HTTP: &[u8] = "HTTP/1".as_bytes();
        if !self.first_packet {
            return Ok(());
        }
        self.first_packet = false;
        if &buf[..FALL_BACK_TO_HTTP.len()] == FALL_BACK_TO_HTTP {
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

type BufTlsStream = BufStream<tokio_rustls::client::TlsStream<TcpStream>>;

#[derive(Debug)]
pub enum FortiError {
    Internal(&'static str),
    Io(io::Error),
    Tls(rustls::Error),
    Dns(rustls::pki_types::InvalidDnsNameError),
    Http(http::HttpError),
}

impl fmt::Display for FortiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Internal(msg) => f.write_str(msg),
            Self::Io(ref e) => write!(f, "IO error: {}", e),
            Self::Tls(ref e) => write!(f, "TLS error: {}", e),
            Self::Dns(ref e) => write!(f, "DNS error: {}", e),
            Self::Http(ref e) => write!(f, "HTTP error: {}", e),
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
