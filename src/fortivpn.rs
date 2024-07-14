use std::{
    error, fmt, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use log::{debug, warn};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter},
    net::{tcp::OwnedWriteHalf, TcpListener, TcpStream},
};
use tokio_native_tls::native_tls;

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
            debug!("New connection on token port from {}", addr);
            socket
        }
        Err(err) => {
            warn!("Failed to accept incoming connection: {}", err);
            return Err("Failed to accept incoming connection".into());
        }
    };
    let (reader, writer) = socket.into_split();
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);
    let mut line = String::new();
    let mut token_id = None;
    while reader.read_line(&mut line).await? > 0 {
        if line == "\r\n" {
            break;
        }
        if token_id.is_none() && line.starts_with("GET /?id=") {
            if let Some(start_index) = line.find("=") {
                let line = &line[start_index + 1..];
                if let Some(end_index) = line.find(" ") {
                    token_id = Some((&line[..end_index]).to_string());
                }
            }
        }
        line.clear();
    }

    let token_id = if let Some(token_id) = token_id {
        token_id
    } else {
        return Err("No token found in request".into());
    };

    debug!("Successfully received token");

    // Get real token based on token ID.
    let socket = TcpStream::connect(&config.destination_addr).await?;
    let connector = native_tls::TlsConnector::builder().build()?;
    let connector = tokio_native_tls::TlsConnector::from(connector);
    let domain = if let Some(separator) = config.destination_hostport.find(":") {
        &config.destination_hostport[..separator]
    } else {
        &config.destination_hostport
    };
    let mut socket = connector.connect(domain, socket).await?;
    debug!("Connected to cookie retrieval host");
    socket
        .write_all(
            build_http_request(
                format!("GET /remote/saml/auth_id?id={}", token_id).as_str(),
                domain,
            )
            .as_bytes(),
        )
        .await?;
    let mut reader = BufReader::new(socket);
    let mut cookie = None;
    debug!("Reading cookie response");
    while reader.read_line(&mut line).await? > 0 {
        if line == "\r\n" {
            break;
        }
        if cookie.is_none() && line.starts_with("Set-Cookie: SVPNCOOKIE=") {
            if let Some(start_index) = line.find("=") {
                let line = &line[start_index + 1..];
                if let Some(end_index) = line.find("; ") {
                    cookie = Some((&line[..end_index]).to_string());
                }
            }
        }
        line.clear();
    }

    let cookie = if let Some(cookie) = cookie {
        cookie
    } else {
        return Err("Response has no cookie".into());
    };
    debug!("Successfully obtained cookie");

    let response = include_bytes!("static/token.html");
    write_http_response(&mut writer, response).await?;

    Ok(cookie)
}

async fn write_http_response(
    writer: &mut BufWriter<OwnedWriteHalf>,
    data: &[u8],
) -> Result<(), FortiError> {
    writer
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\n\
            Content-Type: text/html\r\n\
            Content-Length: {}\r\n\
            \r\n",
                data.len()
            )
            .as_bytes(),
        )
        .await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

fn build_http_request(verb: &str, host: &str) -> String {
    format!(
        "{} HTTP/1.1\r\n\
            Host: {}\r\n\
            User-Agent: Mozilla/5.0 SV1\r\n\
            Accent: */*\r\n\
            Accept-Encoding: identity\r\n\
            Pragma: no-cache\r\n\
            Cache-Control: no-store, no-cache, must-revalidate\r\n\
            If-Modified-Since: Sat, 1 Jan 2000 00:00:00 GMT\r\n\
            Content-Type: application/x-www-form-urlencoded\r\n\
            Content-Length: 0\r\n\
            \r\n",
        verb, host
    )
}

#[derive(Debug)]
pub enum FortiError {
    Internal(&'static str),
    Io(io::Error),
    Tls(native_tls::Error),
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
        }
    }
}

impl error::Error for FortiError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Self::Internal(_msg) => None,
            Self::Io(ref err) => Some(err),
            Self::Tls(ref err) => Some(err),
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
