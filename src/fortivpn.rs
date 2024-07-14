use std::{
    error, fmt, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use log::{debug, warn};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
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
                )
                .as_bytes(),
            )
            .await?;
        let mut cookie = None;
        debug!("Reading cookie response");
        let headers = read_http_headers(&mut socket).await?;
        for line in headers.lines() {
            if cookie.is_none() && line.starts_with("Set-Cookie: SVPNCOOKIE=") {
                if let Some(start_index) = line.find("=") {
                    let line = &line[start_index + 1..];
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

struct Buffer<const S: usize> {
    data: [u8; S],
    read_start: usize,
    write_start: usize,
    move_threshold: usize,
}

impl<const S: usize> Buffer<S> {
    fn new() -> Buffer<S> {
        Buffer {
            data: [0u8; S],
            read_start: 0,
            write_start: 0,
            move_threshold: 3 * S / 4,
        }
    }

    fn read(&mut self, dest: &mut [u8]) -> usize {
        let source_range = if self.read_start + dest.len() > self.write_start {
            self.read_start..self.write_start
        } else {
            self.read_start..(self.read_start + dest.len()).min(self.data.len())
        };
        dest[..source_range.len()].copy_from_slice(&self.data[source_range.clone()]);
        self.read_start = source_range.end;
        if self.read_start > self.move_threshold {
            // This is not the best ring buffer implementation, hope this trick avoids copying too much data.
            // Only do a memmove if a smaller portion of data needs to be relocated.
            // This means that the buffer's capacity needs to be larger than usual.
            self.data.copy_within(self.read_start..self.write_start, 0);
            self.write_start -= self.read_start;
            self.read_start = 0;
        }

        source_range.len()
    }

    fn peek(&self) -> &[u8] {
        &self.data[self.read_start..self.write_start]
    }

    fn write_slice(&mut self) -> &mut [u8] {
        &mut self.data[self.write_start..]
    }

    fn advance_write(&mut self, bytes: usize) {
        self.write_start += bytes
    }
}

struct BufferedTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream: S,
    buffer: Buffer<4096>,
}

impl<S> BufferedTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn new(stream: S) -> BufferedTlsStream<S> {
        BufferedTlsStream {
            stream,
            buffer: Buffer::new(),
        }
    }

    async fn read_peek(&mut self) -> Result<&[u8], FortiError> {
        let write_slice = self.buffer.write_slice();
        if !write_slice.is_empty() {
            let bytes_read = self.stream.read(write_slice).await?;
            self.buffer.advance_write(bytes_read);
        }
        Ok(self.buffer.peek())
    }

    async fn read(&mut self, dest: &mut [u8]) -> Result<usize, FortiError> {
        if self.buffer.peek().is_empty() {
            let write_slice = self.buffer.write_slice();
            if !write_slice.is_empty() {
                let bytes_read = self.stream.read(write_slice).await?;
                self.buffer.advance_write(bytes_read);
            }
        }
        Ok(self.buffer.read(dest))
    }

    async fn write_all(&mut self, data: &[u8]) -> Result<(), FortiError> {
        Ok(self.stream.write_all(data).await?)
    }

    async fn flush(&mut self) -> Result<(), FortiError> {
        Ok(self.stream.flush().await?)
    }
}

struct FortiVPNTunnel {}

async fn read_http_headers<S>(socket: &mut BufferedTlsStream<S>) -> Result<String, FortiError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut result = vec![];
    loop {
        let headers = socket.read_peek().await?;
        let result_len = result.len();
        let found = if let Some(header_end) = find_header_end(result.as_slice(), headers) {
            result.resize(result.len() + header_end, 0u8);
            true
        } else {
            result.resize(result.len() + headers.len(), 0u8);
            false
        };
        socket.read(&mut result[result_len..]).await?;
        if found {
            break;
        }
    }
    Ok(String::from_utf8(result).map_err(|err| {
        warn!("Failed to decode headers as UTF-8: {}", err);
        "Failed to decode headers as UTF-8"
    })?)
}

fn find_header_end(previous_chunk: &[u8], data: &[u8]) -> Option<usize> {
    const HEADER_END_MARKER: &[u8] = "\r\n\r\n".as_bytes();
    // First character doesn't count, only extras are relevant.
    for i in 0..data.len() {
        if i < 3 {
            let mut merged_chunk = [0u8; 4];
            let previous_bytes = 3 - i;
            if previous_chunk.len() < previous_bytes {
                continue;
            }
            merged_chunk[..previous_bytes]
                .copy_from_slice(&previous_chunk[previous_chunk.len() - previous_bytes..]);
            merged_chunk[previous_bytes..].copy_from_slice(&data[..=i]);
            if &merged_chunk == HEADER_END_MARKER {
                return Some(i + 1);
            }
        } else {
            if &data[i - 3..=i] == HEADER_END_MARKER {
                return Some(i + 1);
            }
        }
    }
    None
}

async fn write_http_response<S>(
    writer: &mut BufferedTlsStream<S>,
    data: &[u8],
) -> Result<(), FortiError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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
