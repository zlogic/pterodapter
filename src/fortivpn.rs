use std::{
    error, fmt, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
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

pub struct FortiVPNTunnel {}

impl FortiVPNTunnel {
    pub async fn new(config: &Config, cookie: String) -> Result<FortiVPNTunnel, FortiError> {
        let domain = if let Some(separator) = config.destination_hostport.find(":") {
            &config.destination_hostport[..separator]
        } else {
            &config.destination_hostport
        };
        let mut socket = FortiVPNTunnel::connect(&config.destination_hostport, domain).await?;
        FortiVPNTunnel::request_vpn_allocation(domain, &mut socket, &cookie).await?;
        FortiVPNTunnel::start_vpn_tunnel(domain, &mut socket, &cookie).await?;
        Ok(FortiVPNTunnel {})
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
    ) -> Result<(), FortiError> {
        let req = build_http_request("GET /remote/fortisslvpn_xml", domain, Some(cookie), 0);
        println!("Requesrt is {}", req);
        socket.write_all(req.as_bytes()).await?;

        let headers = read_http_headers(socket).await?;
        println!("Headers = {}", headers);
        let content = read_content(socket, headers.as_str()).await?;
        println!("Content = {}", content);

        Ok(())
    }

    async fn start_vpn_tunnel(
        domain: &str,
        socket: &mut FortiTlsStream,
        cookie: &str,
    ) -> Result<(), FortiError> {
        let req = build_http_request("GET /remote/sslvpn-tunnel", domain, Some(cookie), 0);
        println!("Starting VPN is {}", req);
        socket.write_all(req.as_bytes()).await?;

        let mut buf = [0u8; 16];
        loop {
            let data_read = socket.read(&mut buf).await?;

            println!("Received packet from FortiVPN {:?}", &buf[..data_read]);
        }

        Ok(())
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
