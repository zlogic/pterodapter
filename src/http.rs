use std::{error, fmt, io};

use log::warn;
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_native_tls::native_tls;

const HEADER_END_MARKER: &str = "\r\n\r\n";
const CHUNKS_END_MARKER: &str = "\r\n0\r\n\r\n";

pub async fn read_headers<S>(socket: &mut S) -> Result<String, HttpError>
where
    // TODO: use trait aliases once they become available.
    S: AsyncRead + AsyncBufRead + AsyncWrite + Unpin,
{
    read_until(socket, HEADER_END_MARKER).await
}

async fn read_until<S>(socket: &mut S, end_of_message: &str) -> Result<String, HttpError>
where
    S: AsyncBufRead + AsyncWrite + Unpin,
{
    let mut result = String::new();
    while !result.ends_with(end_of_message) {
        // TODO: detect chunk start/end and discard; count number of bytes read.
        if socket.read_line(&mut result).await? == 0 {
            // EOF reached.
            break;
        }
    }
    Ok(result)
}

pub async fn read_content<S>(socket: &mut S, headers: &str) -> Result<String, HttpError>
where
    S: AsyncRead + AsyncBufRead + AsyncWrite + Unpin,
{
    if headers.contains("Transfer-Encoding: chunked") {
        // This is super janky, but should work if chunks are small enough.
        // openfortivpn works the same way.
        return read_until(socket, CHUNKS_END_MARKER).await;
    }
    let content_length = match read_content_length(headers) {
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

pub fn read_content_length(headers: &str) -> Option<usize> {
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

pub fn read_host(headers: &str) -> Option<&str> {
    const HOST_HEADER: &str = "Host: ";
    for line in headers.lines() {
        if let Some(host) = line.strip_prefix(HOST_HEADER) {
            return Some(host);
        }
    }
    None
}

pub async fn read_unbuffered_chunk(
    socket: &mut TcpStream,
    dest: &mut Vec<u8>,
) -> Result<(), HttpError> {
    const BUFFER_SIZE: usize = 3;
    let mut current_length = dest.len();
    loop {
        dest.resize(current_length + BUFFER_SIZE, 0);
        let bytes_read = socket.peek(&mut dest[current_length..]).await?;
        dest.truncate(current_length + bytes_read);
        let mut found_index = None;
        for i in current_length.saturating_sub(HEADER_END_MARKER.len())
            ..=dest.len().saturating_sub(HEADER_END_MARKER.len())
        {
            if &dest[i..i + HEADER_END_MARKER.len()] == HEADER_END_MARKER.as_bytes() {
                found_index = Some(i);
                break;
            }
        }
        if let Some(found_index) = found_index {
            dest.truncate(found_index + HEADER_END_MARKER.len());
            socket.read_exact(&mut dest[current_length..]).await?;
            return Ok(());
        } else {
            socket.read_exact(&mut dest[current_length..]).await?;
            current_length = dest.len();
        }
    }
}

pub async fn write_response<S>(writer: &mut S, data: &[u8]) -> Result<(), HttpError>
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

#[derive(Debug)]
pub enum HttpError {
    Internal(&'static str),
    Io(io::Error),
    Tls(native_tls::Error),
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

impl From<native_tls::Error> for HttpError {
    fn from(err: native_tls::Error) -> HttpError {
        Self::Tls(err)
    }
}
