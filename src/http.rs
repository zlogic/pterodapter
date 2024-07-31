use std::{error, fmt, io};

use log::{debug, warn};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::rustls;

const HEADER_END_MARKER: &str = "\r\n\r\n";
const BUFFER_SIZE: usize = 256;

pub async fn read_headers<S>(socket: &mut S) -> Result<String, HttpError>
where
    // TODO: use trait aliases once they become available.
    S: AsyncRead + AsyncBufRead + AsyncWrite + Unpin,
{
    read_until(socket, HEADER_END_MARKER).await
}

pub async fn read_headers_unbuffered(
    socket: &mut TcpStream,
    dest: &mut Vec<u8>,
) -> Result<(), HttpError> {
    read_until_unbuffered(socket, HEADER_END_MARKER, dest).await
}

async fn read_until<S>(socket: &mut S, end_of_message: &str) -> Result<String, HttpError>
where
    S: AsyncBufRead + AsyncWrite + Unpin,
{
    let mut result = String::new();
    while !result.ends_with(end_of_message) {
        if socket.read_line(&mut result).await? == 0 {
            // EOF reached.
            break;
        }
    }
    Ok(result)
}

async fn read_until_unbuffered(
    socket: &mut TcpStream,
    end_of_message: &str,
    dest: &mut Vec<u8>,
) -> Result<(), HttpError> {
    let mut current_length = dest.len();
    loop {
        dest.resize(current_length + BUFFER_SIZE, 0);
        let bytes_read = socket.peek(&mut dest[current_length..]).await?;
        dest.truncate(current_length + bytes_read);
        let mut found_index = None;
        for i in current_length.saturating_sub(end_of_message.len())
            ..=dest.len().saturating_sub(end_of_message.len())
        {
            if &dest[i..i + end_of_message.len()] == end_of_message.as_bytes() {
                found_index = Some(i);
                break;
            }
        }
        if let Some(found_index) = found_index {
            dest.truncate(found_index + end_of_message.len());
            socket.read_exact(&mut dest[current_length..]).await?;
            return Ok(());
        } else {
            socket.read_exact(&mut dest[current_length..]).await?;
            current_length = dest.len();
        }
    }
}

async fn read_chunked_content<S>(socket: &mut S) -> Result<String, HttpError>
where
    S: AsyncRead + AsyncBufRead + AsyncWrite + Unpin,
{
    let mut result = vec![];
    loop {
        let mut chunk_length = String::new();
        socket.read_line(&mut chunk_length).await?;
        let chunk_length = chunk_length.trim();
        let chunk_length = match <usize>::from_str_radix(chunk_length, 16) {
            Ok(chunk_length) => chunk_length,
            Err(err) => {
                debug!("Failed to parse chunk length {}: {}", chunk_length, err);
                return Err("Failed to parse chunk length".into());
            }
        };
        if chunk_length > 0 {
            let dest = result.len()..result.len() + chunk_length;
            result.resize(dest.end, 0);
            socket.read_exact(&mut result[dest]).await?;
        }
        // Consume and verify CRLF.
        let mut crlf = [0u8; 2];
        socket.read_exact(&mut crlf).await?;
        if &crlf != b"\r\n" {
            return Err("Missing CRLF chunk trailer".into());
        }
        if chunk_length == 0 {
            break;
        }
    }

    Ok(String::from_utf8(result).map_err(|err| {
        debug!("Failed to decode content as UTF-8: {}", err);
        "Failed to decode content as UTF-8"
    })?)
}

pub async fn read_content<S>(socket: &mut S, headers: &str) -> Result<String, HttpError>
where
    S: AsyncRead + AsyncBufRead + AsyncWrite + Unpin,
{
    if headers.contains("Transfer-Encoding: chunked") {
        return read_chunked_content(socket).await;
    }
    let content_length = match find_content_length(headers) {
        Some(content_length) => content_length,
        None => {
            return Err("Failed to extract content length".into());
        }
    };
    let mut buf = vec![0; content_length];
    socket.read_exact(&mut buf).await?;

    Ok(String::from_utf8(buf).map_err(|err| {
        warn!("Failed to decode headers as UTF-8: {}", err);
        "Failed to decode headers as UTF-8"
    })?)
}

pub fn find_content_length(headers: &str) -> Option<usize> {
    const CONTENT_LENGTH_HEADER: &str = "Content-Length: ";
    for line in headers.lines() {
        if let Some(content_length) = line.strip_prefix(CONTENT_LENGTH_HEADER) {
            match content_length.parse::<usize>() {
                Ok(content_length) => return Some(content_length),
                Err(err) => {
                    warn!("Failed to parse content-length: {}", err);
                    continue;
                }
            }
        }
    }
    None
}

pub fn extract_response_code(headers: &str) -> Option<u16> {
    // Normalize reponse to remove HTTP-Version if present.
    let code_start = if let Some(headers) = headers.strip_prefix("HTTP/1.1 ") {
        headers
    } else {
        headers
    };
    if let Some((code, _)) = code_start.split_once(" ") {
        code.parse::<u16>().ok()
    } else {
        None
    }
}

pub fn validate_response_code(headers: &str) -> Result<(), HttpError> {
    match extract_response_code(headers) {
        Some(200) => Ok(()),
        Some(code) => {
            debug!("Received unexpected HTTP response code: {}", code);
            Err("Received unexpected HTTP response code".into())
        }
        None => Err("Unable to read HTTP response code".into()),
    }
}

pub async fn write_sso_response<S>(writer: &mut S, data: &[u8]) -> Result<(), HttpError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    writer
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\n\
            Content-Type: text/html\r\n\
            Cache-Control: no-store\r\n\
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

pub async fn write_pac_response<S>(writer: &mut S, data: &[u8]) -> Result<(), HttpError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    writer
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\n\
            Content-Type: application/x-ns-proxy-autoconfig\r\n\
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

pub fn build_request(
    verb: &str,
    host: &str,
    cookie: Option<&str>,
    content_length: usize,
) -> String {
    let cookie = if let Some(cookie) = cookie {
        format!("Cookie: {}\r\n", cookie)
    } else {
        "".to_string()
    };
    let content_length = if content_length > 0 {
        format!("Content-Length: {}\r\n", content_length)
    } else {
        "".to_string()
    };
    format!(
        "{} HTTP/1.1\r\n\
            Host: {}\r\n\
            User-Agent: Mozilla/5.0 SV1\r\n\
            Accept: */*\r\n\
            {}{}\r\n",
        verb, host, cookie, content_length
    )
}

pub fn extract_connect_host(headers: &str) -> Option<&str> {
    const HOST_HEADER: &str = "Host: ";
    let mut lines = headers.lines();
    if let Some(request_line) = lines.next() {
        if let Some(remain) = request_line.strip_prefix("CONNECT ") {
            if let Some((request_host, _)) = remain.split_once(' ') {
                return Some(request_host);
            }
        }
    }
    for line in lines {
        if let Some(request_host) = line.strip_prefix(HOST_HEADER) {
            return Some(request_host);
        }
    }
    None
}

pub fn extract_proxy_host(headers: &str) -> (String, Option<&str>) {
    const HOST_HEADER: &str = "Host: ";
    let mut result = String::new();
    let mut lines = headers.lines();
    let mut host = None;
    if let Some(request_line) = lines.next() {
        if let Some((verb, remain)) = request_line.split_once(' ') {
            result.push_str(verb);
            result.push(' ');
            let remain = if let Some(schema_pos) = remain.find("://") {
                &remain[schema_pos + 3..]
            } else {
                remain
            };
            if let Some((request_host, path)) = remain.split_once('/') {
                host = Some(request_host);
                // Keep the path only.
                result.push('/');
                result.push_str(path);
            } else {
                // Pass remainder as-is.
                result.push_str(remain);
            }
        } else {
            // Pass request line as-is.
            result.push_str(request_line);
        }
        result.push('\n');
    }
    for line in lines {
        if line.starts_with("Proxy-Authorization: ") || line.starts_with("Proxy-Connection: ") {
            continue;
        }
        result.push_str(line);
        result.push('\n');
        if let Some(request_host) = line.strip_prefix(HOST_HEADER) {
            host = Some(request_host);
        }
    }
    (result, host)
}

#[derive(Debug)]
pub enum HttpError {
    Internal(&'static str),
    Io(io::Error),
    Tls(rustls::Error),
}

impl fmt::Display for HttpError {
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

impl error::Error for HttpError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Self::Internal(_msg) => None,
            Self::Io(ref err) => Some(err),
            Self::Tls(ref err) => Some(err),
        }
    }
}

impl From<&'static str> for HttpError {
    fn from(msg: &'static str) -> HttpError {
        Self::Internal(msg)
    }
}

impl From<io::Error> for HttpError {
    fn from(err: io::Error) -> HttpError {
        Self::Io(err)
    }
}

impl From<rustls::Error> for HttpError {
    fn from(err: rustls::Error) -> HttpError {
        Self::Tls(err)
    }
}
