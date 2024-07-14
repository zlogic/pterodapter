use std::{
    error, fmt, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use log::{debug, warn};
use tokio::net::{TcpListener, TcpStream};
use tokio_native_tls::native_tls;

use crate::http::{
    build_http_request, read_content, read_http_headers, write_http_response, BufferedTlsStream,
};

pub struct Config {
    pub destination_addr: SocketAddr,
    pub destination_hostport: String,
}

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
    first_packet: bool,
    tunnel_failed: bool,
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
        Ok(FortiVPNTunnel {
            socket,
            addr,
            first_packet: true,
            tunnel_failed: true,
        })
    }

    pub fn ip_addr(&self) -> IpAddr {
        self.addr
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
        println!("Starting VPN is {}?", req);
        socket.write_all(req.as_bytes()).await?;
        socket.flush().await?;

        Ok(())
    }

    pub async fn send_packet(&mut self, data: &[u8]) -> Result<(), FortiError> {
        println!("About to send packet {:?}", data);
        // PPP packets are surprisingly basic.
        let mut packet_header = [0u8; 6];
        packet_header[..2].copy_from_slice(&(6 + data.len() as u16).to_be_bytes());
        packet_header[2..4].copy_from_slice(&[0x50, 0x50]);
        packet_header[4..].copy_from_slice(&(data.len() as u16).to_be_bytes());

        // TODO: replace with a version that needs less allocations
        /*
        let packet_data = Vec::from(data);
        let data = match hdlc::encode(&packet_data, hdlc::SpecialChars::default()) {
            Ok(encoded) => encoded,
            Err(err) => {
                debug!("Failed to encode HDLC packet: {}", err);
                return Err("Failed to encode HDLC packet".into());
            }
        };
        */

        self.socket.write_all(&packet_header).await?;
        Ok(self.socket.write_all(&data).await?)
    }

    pub async fn read_packet(&mut self, dest: &mut [u8]) -> Result<usize, FortiError> {
        let socket = &mut self.socket;
        let mut packet_header = [0u8; 6];
        println!("Reading packet");
        // If no data is available, this will return immediately.
        match tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                //println!("stupid loop");
                if let Ok(header) = socket.read_peek(6).await {
                    if header.len() >= 6 {
                        println!("Have header {} bytes", header.len());
                        return;
                    } else {
                        println!("Have {} bytes", header.len());
                    }
                } else {
                    return;
                };
            }
        })
        .await
        {
            Ok(_) => {}
            Err(_) => return Ok(0),
        }
        println!("Packet not ready");

        socket.read(&mut packet_header).await?;
        if self.first_packet {
            self.first_packet = false;
            if let Err(err) = FortiVPNTunnel::validate_link(socket, &packet_header).await {
                self.tunnel_failed = true;
                return Err(err);
            }
        }
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
