use std::{
    error, fmt, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use log::{debug, warn};
use rand::Rng;
use tokio::net::{TcpListener, TcpStream};
use tokio_native_tls::native_tls;

use crate::http::{
    build_http_request, read_content, read_http_headers, write_http_response, BufferedTlsStream,
};
use crate::ppp;

pub struct Config {
    pub destination_addr: SocketAddr,
    pub destination_hostport: String,
}

// TODO: allow this to be configured.
// PPP_MTU specifies is the MTU excluding IP, TCP, TLS, FortiVPN and PPP encapsulation headers.
const PPP_MTU: u16 = 1500 - 20 - 20 - 5 - 6 - 4;

// TODO: check how FortiVPN chooses the listen port - is it fixed or sent as a parameter?
const REDIRECT_ADDRESS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8020);

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
    let mut socket = BufferedTlsStream::new(socket);
    let headers = read_http_headers(&mut socket).await?;
    let token_id = headers
        .lines()
        .next()
        .map(|line| {
            if !line.starts_with("GET /?id=") {
                return None;
            }
            let start_index = line.find("=")?;
            let line = &line[start_index + 1..];
            let end_index = line.find(" ")?;
            Some((&line[..end_index]).to_string())
        })
        .flatten();

    let token_id = if let Some(token_id) = token_id {
        token_id
    } else {
        return Err("No token found in request".into());
    };

    // Get real token based on token ID.
    let cookie = {
        let socket = TcpStream::connect(&config.destination_addr).await?;
        let connector = native_tls::TlsConnector::builder().build()?;
        let connector = tokio_native_tls::TlsConnector::from(connector);
        let domain = if let Some(separator) = config.destination_hostport.find(":") {
            &config.destination_hostport[..separator]
        } else {
            &config.destination_hostport
        };
        let socket = connector.connect(domain, socket).await?;
        let mut socket = BufferedTlsStream::new(socket);
        debug!("Connected to cookie retrieval host");
        socket
            .write_all(
                build_http_request(
                    format!("GET /remote/saml/auth_id?id={}", token_id).as_str(),
                    domain,
                    None,
                    0,
                )
                .as_bytes(),
            )
            .await?;
        let mut cookie = None;
        debug!("Reading cookie response");
        let headers = read_http_headers(&mut socket).await?;
        for line in headers.lines() {
            if cookie.is_none() && line.starts_with("Set-Cookie: SVPNCOOKIE=") {
                if let Some(start_index) = line.find(":") {
                    let line = &line[start_index + 2..];
                    if let Some(end_index) = line.find("; ") {
                        cookie = Some((&line[..end_index]).to_string());
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
    write_http_response(&mut socket, response).await?;

    Ok(cookie)
}

pub struct FortiVPNTunnel {
    socket: FortiTlsStream,
    addr: IpAddr,
    mtu: usize,
    ppp_state: PPPState,
    ppp_magic: u32,
    ppp_identifier: u8,
}

impl FortiVPNTunnel {
    pub async fn new(config: &Config, cookie: String) -> Result<FortiVPNTunnel, FortiError> {
        let domain = if let Some(separator) = config.destination_hostport.find(":") {
            &config.destination_hostport[..separator]
        } else {
            &config.destination_hostport
        };
        let mut socket = FortiVPNTunnel::connect(&config.destination_hostport, domain).await?;
        let addr = FortiVPNTunnel::request_vpn_allocation(domain, &mut socket, &cookie).await?;
        FortiVPNTunnel::start_vpn_tunnel(domain, &mut socket, &cookie).await?;

        let mut ppp_state = PPPState::new();
        let ppp_magic = FortiVPNTunnel::start_ppp(&mut socket, &mut ppp_state).await?;
        FortiVPNTunnel::start_ipcp(&mut socket, &mut ppp_state, addr).await?;
        Ok(FortiVPNTunnel {
            socket,
            addr,
            mtu: PPP_MTU as usize,
            ppp_state,
            ppp_magic,
            ppp_identifier: 2,
        })
    }

    pub fn ip_addr(&self) -> IpAddr {
        self.addr
    }

    pub fn mtu(&self) -> usize {
        self.mtu as usize
    }

    async fn connect(hostport: &str, domain: &str) -> Result<FortiTlsStream, FortiError> {
        let socket = TcpStream::connect(hostport).await?;
        let connector = native_tls::TlsConnector::builder().build()?;
        let connector = tokio_native_tls::TlsConnector::from(connector);
        let socket = connector.connect(domain, socket).await?;
        let socket = BufferedTlsStream::new(socket);
        debug!("Connected to VPN host");

        Ok(socket)
    }

    async fn request_vpn_allocation(
        domain: &str,
        socket: &mut FortiTlsStream,
        cookie: &str,
    ) -> Result<IpAddr, FortiError> {
        let req = build_http_request("GET /remote/fortisslvpn_xml", domain, Some(cookie), 0);
        socket.write_all(req.as_bytes()).await?;
        socket.flush().await?;

        let headers = read_http_headers(socket).await?;
        let content = read_content(socket, headers.as_str()).await?;

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
        Ok(IpAddr::from_str(&content[..ipv4_addr_end]).map_err(|err| {
            debug!("Failed to parse IPv4 address: {}", err);
            "Failed to parse IPv4 address"
        })?)
    }

    async fn start_vpn_tunnel(
        domain: &str,
        socket: &mut FortiTlsStream,
        cookie: &str,
    ) -> Result<(), FortiError> {
        let req = build_http_request("GET /remote/sslvpn-tunnel", domain, Some(cookie), 0);
        socket.write_all(req.as_bytes()).await?;
        Ok(socket.flush().await?)
    }

    async fn start_ppp(
        socket: &mut FortiTlsStream,
        ppp_state: &mut PPPState,
    ) -> Result<u32, FortiError> {
        // Open PPP link; 200 bytes should fit any PPP packet.
        // This is an oversimplified implementation of the RFC 1661 state machine.
        let mut req = [0u8; 20];
        let mut resp = [0u8; 200];
        let identifier = 1;
        let magic = rand::thread_rng().gen::<u32>();
        let opts = [
            ppp::LcpOptionData::MaximumReceiveUnit(PPP_MTU),
            ppp::LcpOptionData::MagicNumber(magic),
        ];
        let length =
            ppp::encode_lcp_config(&mut req, ppp::LcpCode::CONFIGURE_REQUEST, identifier, &opts)
                .map_err(|err| {
                    debug!("Failed to encode LCP Configure-Request: {}", err);
                    "Failed to encode LCP Configure-Request"
                })?;
        FortiVPNTunnel::send_ppp_packet(socket, ppp::Protocol::LCP, &req[..length]).await?;

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
            let length = FortiVPNTunnel::read_ppp_packet(socket, ppp_state, &mut resp).await?;
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
                        Ok(received_opts) => &opts == received_opts.as_slice(),
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
                                ppp::LcpOptionData::MaximumReceiveUnit(mtu) => {
                                    if mtu <= PPP_MTU {
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
                    FortiVPNTunnel::send_ppp_packet(socket, ppp::Protocol::LCP, &req[..length])
                        .await?;
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
        socket: &mut FortiTlsStream,
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
        FortiVPNTunnel::send_ppp_packet(socket, ppp::Protocol::IPV4CP, &req[..length]).await?;

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
            let length = FortiVPNTunnel::read_ppp_packet(socket, ppp_state, &mut resp).await?;
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
                    FortiVPNTunnel::send_ppp_packet(socket, ppp::Protocol::IPV4CP, &req[..length])
                        .await?;
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
        socket: &mut FortiTlsStream,
        protocol: ppp::Protocol,
        ppp_data: &[u8],
    ) -> Result<(), FortiError> {
        // FortiVPN encapsulation.
        let mut packet_header = [0u8; 8];
        let ppp_packet_length = ppp_data.len() + 2;
        packet_header[..2].copy_from_slice(&(6 + ppp_packet_length as u16).to_be_bytes());
        packet_header[2..4].copy_from_slice(&[0x50, 0x50]);
        packet_header[4..6].copy_from_slice(&(ppp_packet_length as u16).to_be_bytes());
        // PPP encapsulation.
        packet_header[6..].copy_from_slice(&protocol.value().to_be_bytes());

        socket.write_all(&packet_header).await?;
        socket.write_all(&ppp_data).await?;
        Ok(socket.flush().await?)
    }

    async fn read_ppp_packet(
        socket: &mut FortiTlsStream,
        state: &mut PPPState,
        dest: &mut [u8],
    ) -> Result<usize, FortiError> {
        state.read_header(socket).await.map_err(|err| {
            debug!("Failed to read PPP header: {}", err);
            "Failed to read PPP header"
        })?;
        if state.remaining_bytes() > dest.len() {
            debug!(
                "Destination buffer ({} bytes) is smaller than the traferred packet ({} bytes)",
                dest.len(),
                state.remaining_bytes()
            );
            return Err("Destination buffer not large enough to fit all data".into());
        }
        // TODO: check if perhaps sending partial data is acceptable?
        let mut received_data = 0;
        while state.remaining_bytes() > 0 {
            let bytes_transferred = socket
                .read(&mut dest[received_data..received_data + state.remaining_bytes()])
                .await?;
            state.consume_bytes(bytes_transferred)?;
            received_data += bytes_transferred;
        }
        Ok(received_data)
    }

    pub async fn send_echo(&mut self) -> Result<(), FortiError> {
        let mut req = [0u8; 8];
        let data = self.ppp_magic.to_be_bytes();
        let length = ppp::encode_lcp_data(
            &mut req,
            ppp::LcpCode::ECHO_REQUEST,
            self.ppp_identifier,
            &data,
        )
        .map_err(|err| {
            debug!("Failed to encode Echo-Request: {}", err);
            "Failed to encode Echo-Request"
        })?;
        self.ppp_identifier += 1;
        FortiVPNTunnel::send_ppp_packet(&mut self.socket, ppp::Protocol::LCP, &req[..length]).await
    }

    pub async fn send_packet(&mut self, data: &[u8]) -> Result<(), FortiError> {
        FortiVPNTunnel::send_ppp_packet(&mut self.socket, ppp::Protocol::IPV4, data).await
    }

    pub async fn try_next_ip_packet(
        &mut self,
        timeout: Option<Duration>,
    ) -> Result<usize, FortiError> {
        // Peek header if not yet available - to get the protocol.
        if let Some(timeout) = timeout {
            match tokio::time::timeout(timeout, self.ppp_state.read_header(&mut self.socket)).await
            {
                Ok(res) => res,
                Err(_) => return Ok(0),
            }
        } else {
            self.ppp_state.read_header(&mut self.socket).await
        }
        .map_err(|err| {
            debug!("Failed to read PPP header: {}", err);
            "Failed to read PPP header"
        })?;
        match self.ppp_state.read_protocol() {
            Some(ppp::Protocol::IPV4) => Ok(self.ppp_state.remaining_bytes()),
            _ => Ok(0),
        }
    }

    pub async fn try_read_packet(
        &mut self,
        dest: &mut [u8],
        timeout: Option<Duration>,
    ) -> Result<usize, FortiError> {
        // Peek header if not yet available - to get the protocol.
        if let Some(timeout) = timeout {
            match tokio::time::timeout(timeout, self.ppp_state.read_header(&mut self.socket)).await
            {
                Ok(res) => res,
                Err(_) => return Ok(0),
            }
        } else {
            self.ppp_state.read_header(&mut self.socket).await
        }
        .map_err(|err| {
            debug!("Failed to read PPP header: {}", err);
            "Failed to read PPP header"
        })?;
        let protocol = match self.ppp_state.read_protocol() {
            Some(protocol) => protocol,
            None => {
                return Err("Unknown PPP protocol, possibly a framing error".into());
            }
        };
        let length =
            FortiVPNTunnel::read_ppp_packet(&mut self.socket, &mut self.ppp_state, dest).await?;
        match protocol {
            ppp::Protocol::LCP => {
                // TODO: handle echo requests/responsed here.
                let packet = match ppp::Packet::from_bytes(protocol, &dest[..length]) {
                    Ok(packet) => packet,
                    Err(err) => {
                        debug!("Failed to decode PPP packet: {}", err);
                        return Err("Failed to decode PPP packet".into());
                    }
                };
                println!("Packet= {}", packet);
                Ok(0)
            }
            ppp::Protocol::IPV4 | ppp::Protocol::IPV6 => Ok(length),
            _ => {
                println!("Received unexpected PPP packet {}, ignoring", protocol);
                Ok(0)
            }
        }
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

    async fn read_header(&mut self, socket: &mut FortiTlsStream) -> Result<(), FortiError> {
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
                    self.ppp_header_length += bytes_read;
                    if self.ppp_header_length >= self.ppp_header.len() {
                        println!("Have header {} bytes", self.ppp_header_length);
                        break;
                    } else {
                        println!("Have {} bytes", self.ppp_header_length);
                    }
                }
                Err(err) => {
                    debug!("Failed to read PPP header {}", err);
                    return Err("Failed to read PPP header".into());
                }
            }
        }
        println!("Packet ready");
        if let Err(err) = self.validate_link(socket).await {
            return Err(err);
        }

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
        if magic != &[0x50, 0x50] {
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

    async fn validate_link(&mut self, socket: &mut FortiTlsStream) -> Result<(), FortiError> {
        const FALL_BACK_TO_HTTP: &[u8] = "HTTP/1".as_bytes();
        if !self.first_packet {
            return Ok(());
        }
        self.first_packet = false;
        if &self.ppp_header[..FALL_BACK_TO_HTTP.len()] == FALL_BACK_TO_HTTP {
            // FortiVPN will return an HTTP response if something goes wrong on setup.
            let headers = read_http_headers(socket).await?;
            debug!("Tunnel not active, error response: {}", headers);
            let content = read_content(socket, headers.as_str()).await?;
            debug!("Error contents: {}", content);
            Err("Tunnel refused to establish link".into())
        } else {
            Ok(())
        }
    }
}

type FortiTlsStream = BufferedTlsStream<tokio_native_tls::TlsStream<TcpStream>>;

#[derive(Debug)]
pub enum FortiError {
    Internal(&'static str),
    Io(io::Error),
    Tls(native_tls::Error),
    Http(crate::http::HttpError),
}

impl fmt::Display for FortiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Internal(msg) => f.write_str(msg),
            Self::Io(ref e) => {
                write!(f, "IO error: {}", e)
            }
            Self::Tls(ref e) => {
                write!(f, "TLS error: {}", e)
            }
            Self::Http(ref e) => {
                write!(f, "HTTP error: {}", e)
            }
        }
    }
}

impl error::Error for FortiError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Self::Internal(_msg) => None,
            Self::Io(ref err) => Some(err),
            Self::Tls(ref err) => Some(err),
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

impl From<native_tls::Error> for FortiError {
    fn from(err: native_tls::Error) -> FortiError {
        Self::Tls(err)
    }
}

impl From<crate::http::HttpError> for FortiError {
    fn from(err: crate::http::HttpError) -> FortiError {
        Self::Http(err)
    }
}
