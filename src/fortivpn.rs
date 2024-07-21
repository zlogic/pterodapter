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
const PPP_MTU: u16 = 1400; //1500 - 20 - 20 - 5 - 6 - 4;

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
        println!("Cookie headers are {}", headers);
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
        let ppp_magic = FortiVPNTunnel::start_ppp(&mut socket).await?;
        FortiVPNTunnel::start_ipcp(&mut socket, addr).await?;
        Ok(FortiVPNTunnel {
            socket,
            addr,
            mtu: PPP_MTU as usize,
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
        debug!("Connected to VPN host host");

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
        socket.flush().await?;

        Ok(())
    }

    async fn start_ppp(socket: &mut FortiTlsStream) -> Result<u32, FortiError> {
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
                    debug!("Failed to encode Configure-Request: {}", err);
                    "Failed to encode Configure-Request"
                })?;
        {
            let mut pack = [0u8; 200];
            pack[..2].copy_from_slice(&ppp::Protocol::LCP.value().to_be_bytes());
            pack[2..length + 2].copy_from_slice(&req[..length]);

            println!(
                "Encoded packet: {:?}",
                ppp::Packet::from_bytes(&pack[..length + 2])
            );
        }
        FortiVPNTunnel::send_ppp_packet(socket, ppp::Protocol::LCP, &req[..length]).await?;

        let mut local_acked = false;
        let mut remote_acked = false;
        while !(local_acked && remote_acked) {
            let length = FortiVPNTunnel::read_ppp_packet(socket, &mut resp, true).await?;
            let response = &resp[..length];
            println!("Read packet: {:?}", response);
            let response = ppp::Packet::from_bytes(&resp[..length]).map_err(|err| {
                debug!("Failed to decode PPP packet: {}", err);
                "Failed to decode PPP packet"
            })?;
            println!("Decoded packet: {}", response);
            let lcp_packet = match response.to_lcp() {
                Ok(lcp) => lcp,
                Err(err) => {
                    debug!(
                        "Received unexpected PPP packet during handshake: {} (error {})",
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
                            debug!("Failed to decode Ack options: {}", err);
                            return Err("Failed to decode Ack options".into());
                        }
                    };
                    if !options_match {
                        return Err("Configure Ack has unexpected options".into());
                    }
                    local_acked = true;
                }
                ppp::LcpCode::CONFIGURE_REQUEST => {
                    let received_opts = lcp_packet
                        .iter_options()
                        .map(|opt| {
                            let opt = match opt {
                                Ok(opt) => opt,
                                Err(err) => {
                                    debug!(
                                        "Remote side sent invalid configuration option: {}",
                                        err
                                    );
                                    return Err(
                                        "Remote side sent invalid configuration option".into()
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
                                ppp::LcpOptionData::MagicNumber(magic) => Ok(opt),
                                _ => {
                                    debug!(
                                        "Remote side sent unsupported configuration option: {}",
                                        opt
                                    );
                                    Err("Remote side sent unsupported configuration option".into())
                                }
                            }
                        })
                        .collect::<Result<Vec<_>, FortiError>>();
                    match received_opts {
                        Ok(opts) => {
                            let length = ppp::encode_lcp_data(
                                &mut req,
                                ppp::LcpCode::CONFIGURE_ACK,
                                lcp_packet.identifier(),
                                lcp_packet.read_options(),
                            )
                            .map_err(|err| {
                                debug!("Failed to encode Configure-Ack: {}", err);
                                "Failed to encode Configure-Ack"
                            })?;
                            FortiVPNTunnel::send_ppp_packet(
                                socket,
                                ppp::Protocol::LCP,
                                &req[..length],
                            )
                            .await?;
                            remote_acked = true;
                        }
                        Err(err) => {
                            return Err(err);
                        }
                    }
                }
                ppp::LcpCode::CONFIGURE_NAK => {
                    debug!("Remote side Nak'd configuration: {}", response);
                    return Err("Remote side Nak'd configuration".into());
                }
                ppp::LcpCode::CONFIGURE_REJECT => {
                    debug!("Remote side rejected configuration: {}", response);
                    return Err("Remote side rejected configuration".into());
                }
                _ => {
                    debug!("Received unexpected PPP packet: {}", response);
                    return Err("Unexpected PPP packet received".into());
                }
            }
        }

        Ok(magic)
    }

    async fn start_ipcp(socket: &mut FortiTlsStream, addr: IpAddr) -> Result<(), FortiError> {
        // Open IPCP link; 20 bytes should fit any IPCP packet.
        // This is an oversimplified implementation of the RFC 1661 state machine.
        let mut req = [0u8; 100];
        let mut resp = [0u8; 200];
        let mut identifier = 1;
        let addr = match addr {
            IpAddr::V4(addr) => addr,
            _ => return Ok(()),
        };
        let opts = [
            ppp::IpcpOptionData::IpAddress(addr),
            //ppp::IpcpOptionData::PrimaryDns(Ipv4Addr::UNSPECIFIED),
            //ppp::IpcpOptionData::SecondaryDns(Ipv4Addr::UNSPECIFIED),
        ];
        let length =
            ppp::encode_ipcp_config(&mut req, ppp::LcpCode::CONFIGURE_REQUEST, identifier, &opts)
                .map_err(|err| {
                debug!("Failed to encode Configure-Request: {}", err);
                "Failed to encode Configure-Request"
            })?;
        {
            let mut pack = [0u8; 200];
            pack[..2].copy_from_slice(&ppp::Protocol::IPV4CP.value().to_be_bytes());
            pack[2..length + 2].copy_from_slice(&req[..length]);

            println!(
                "Encoded packet: {:?}",
                ppp::Packet::from_bytes(&pack[..length + 2])
            );
        }
        let mut opts = [0u8; 100];
        let mut opts_len = length - 4;
        opts[..opts_len].copy_from_slice(&req[4..length]);
        FortiVPNTunnel::send_ppp_packet(socket, ppp::Protocol::IPV4CP, &req[..length]).await?;

        let mut local_acked = false;
        let mut remote_acked = false;
        while !(local_acked && remote_acked) {
            let length = FortiVPNTunnel::read_ppp_packet(socket, &mut resp, true).await?;
            let response = &resp[..length];
            println!("Read packet: {:?}", response);
            let response = ppp::Packet::from_bytes(&resp[..length]).map_err(|err| {
                debug!("Failed to decode PPP packet: {}", err);
                "Failed to decode PPP packet"
            })?;
            println!("Decoded packet: {}", response);
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
                        return Err("Configure Ack has unexpected options".into());
                    }
                    local_acked = true;
                }
                ppp::LcpCode::CONFIGURE_REQUEST => {
                    let received_opts = ipcp_packet
                        .iter_options()
                        .map(|opt| {
                            let opt = match opt {
                                Ok(opt) => opt,
                                Err(err) => {
                                    debug!(
                                        "Remote side sent invalid configuration option: {}",
                                        err
                                    );
                                    return Err(
                                        "Remote side sent invalid configuration option".into()
                                    );
                                }
                            };
                            match opt {
                                ppp::IpcpOptionData::IpAddress(ip) => Ok(opt),
                                ppp::IpcpOptionData::PrimaryDns(ip) => Ok(opt),
                                ppp::IpcpOptionData::SecondaryDns(ip) => Ok(opt),
                                _ => {
                                    debug!(
                                        "Remote side sent unsupported configuration option: {}",
                                        opt
                                    );
                                    Err("Remote side sent unsupported configuration option".into())
                                }
                            }
                        })
                        .collect::<Result<Vec<_>, FortiError>>();
                    match received_opts {
                        Ok(_) => {
                            let length = ppp::encode_lcp_data(
                                &mut req,
                                ppp::LcpCode::CONFIGURE_ACK,
                                ipcp_packet.identifier(),
                                ipcp_packet.read_options(),
                            )
                            .map_err(|err| {
                                debug!("Failed to encode Configure-Ack: {}", err);
                                "Failed to encode Configure-Ack"
                            })?;
                            FortiVPNTunnel::send_ppp_packet(
                                socket,
                                ppp::Protocol::IPV4CP,
                                &req[..length],
                            )
                            .await?;
                            remote_acked = true;
                        }
                        Err(err) => {
                            return Err(err);
                        }
                    }
                }
                ppp::LcpCode::CONFIGURE_NAK => {
                    debug!("Remote side Nak'd configuration: {}", response);
                    let received_opts = ipcp_packet
                        .iter_options()
                        .map(|opt| {
                            let opt = match opt {
                                Ok(opt) => opt,
                                Err(err) => {
                                    debug!(
                                        "Remote side sent invalid configuration option: {}",
                                        err
                                    );
                                    return Err(
                                        "Remote side sent invalid configuration option".into()
                                    );
                                }
                            };
                            match opt {
                                ppp::IpcpOptionData::IpAddress(ip) => Ok(opt),
                                ppp::IpcpOptionData::PrimaryDns(ip) => Ok(opt),
                                ppp::IpcpOptionData::SecondaryDns(ip) => Ok(opt),
                                _ => {
                                    debug!(
                                        "Remote side sent unsupported configuration option: {}",
                                        opt
                                    );
                                    Err("Remote side sent unsupported configuration option".into())
                                }
                            }
                        })
                        .collect::<Result<Vec<_>, FortiError>>();
                    match received_opts {
                        Ok(_) => {
                            opts_len = ipcp_packet.read_options().len();
                            opts[..opts_len].copy_from_slice(ipcp_packet.read_options());
                            identifier += 1;

                            let length = ppp::encode_lcp_data(
                                &mut req,
                                ppp::LcpCode::CONFIGURE_REQUEST,
                                identifier,
                                &opts[..opts_len],
                            )
                            .map_err(|err| {
                                debug!("Failed to encode Configure-Request: {}", err);
                                "Failed to encode Configure-Request"
                            })?;
                            FortiVPNTunnel::send_ppp_packet(
                                socket,
                                ppp::Protocol::IPV4CP,
                                &req[..length],
                            )
                            .await?;
                        }
                        Err(err) => {
                            return Err(err);
                        }
                    }
                }
                ppp::LcpCode::CONFIGURE_REJECT => {
                    debug!("Remote side rejected configuration: {}", response);
                    return Err("Remote side rejected configuration".into());
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
        let mut buf = String::new();
        ppp::fmt_slice_hex(ppp_data, &mut buf);
        println!("About to send packet {:?}, {}", buf, protocol.value());
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
        dest: &mut [u8],
        first_packet: bool,
    ) -> Result<usize, FortiError> {
        let mut packet_header = [0u8; 6];
        println!("Reading packet");
        // If no data is available, this will return immediately.
        match tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                match socket.read_peek(packet_header.len()).await {
                    Ok(header) => {
                        if header.len() >= packet_header.len() {
                            println!("Have header {} bytes", header.len());
                            return;
                        } else {
                            println!("Have {} bytes", header.len());
                        }
                    }
                    Err(err) => {
                        println!("Failed to read header {}", err);
                        return;
                    }
                }
            }
        })
        .await
        {
            Ok(_) => {}
            Err(_) => {
                println!("Read timed out");
                return Ok(0);
            }
        }
        println!("Packet ready");

        if first_packet {
            if let Err(err) = FortiVPNTunnel::validate_link(socket, &packet_header[..6]).await {
                return Err(err);
            }
        }

        socket.read(&mut packet_header).await?;
        let mut ppp_size = [0u8; 2];
        ppp_size.copy_from_slice(&packet_header[..2]);
        let ppp_size = u16::from_be_bytes(ppp_size);
        let mut data_size = [0u8; 2];
        data_size.copy_from_slice(&packet_header[4..6]);
        let data_size = u16::from_be_bytes(data_size);
        let magic = &packet_header[2..4];
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
                packet_header[2], packet_header[3]
            );
            return Err("Magic not found".into());
        }
        let data_size = data_size as usize;
        if data_size > dest.len() {
            debug!(
                "Destination buffer ({} bytes) is smaller than the traferred packet ({} bytes)",
                dest.len(),
                data_size
            );
            return Err("Destination buffer not large enough to fit all data".into());
        }
        let mut received_data = 0usize;
        while received_data < data_size {
            received_data += socket.read(&mut dest[received_data..]).await?;
        }
        Ok(data_size)
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

    pub async fn read_packet(&mut self, dest: &mut [u8]) -> Result<usize, FortiError> {
        // TODO: handle async PPP packets.
        let length = FortiVPNTunnel::read_ppp_packet(&mut self.socket, dest, false).await?;
        if length == 0 {
            return Ok(0);
        }
        let packet = match ppp::Packet::from_bytes(&dest[..length]) {
            Ok(packet) => packet,
            Err(err) => {
                debug!("Failed to decode PPP packet: {}", err);
                return Err("Failed to decode PPP packet".into());
            }
        };
        println!("Packet= {}", packet);

        if packet.read_protocol() == ppp::Protocol::IPV4 {
            // TODO: improve this
            dest.copy_within(2..length, 0);
            Ok(length - 2)
        } else {
            Ok(0)
        }
    }

    async fn validate_link(
        socket: &mut FortiTlsStream,
        packet_header: &[u8],
    ) -> Result<(), FortiError> {
        const FALL_BACK_TO_HTTP: &[u8] = "HTTP/1".as_bytes();
        if packet_header == FALL_BACK_TO_HTTP {
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
