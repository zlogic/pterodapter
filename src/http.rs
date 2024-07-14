use std::{error, fmt, io};

use log::warn;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_native_tls::native_tls;

const HEADER_END_MARKER: &[u8] = "\r\n\r\n".as_bytes();
const CHUNKS_END_MARKER: &[u8] = "\r\n0\r\n\r\n".as_bytes();

pub async fn read_http_headers<S>(socket: &mut BufferedTlsStream<S>) -> Result<String, HttpError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    read_http_chunk(socket, HEADER_END_MARKER).await
}

async fn read_http_chunk<S>(
    socket: &mut BufferedTlsStream<S>,
    separator: &[u8],
) -> Result<String, HttpError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut result = vec![];
    loop {
        let chunk = socket.read_peek(result.len() + 1).await?;
        let result_len = result.len();
        let found = if let Some(header_end) = find_chunk_end(separator, result.as_slice(), chunk) {
            result.resize(result.len() + header_end, 0u8);
            true
        } else {
            result.resize(result.len() + chunk.len(), 0u8);
            false
        };
        socket.read(&mut result[result_len..]).await?;
        if found {
            break;
        }
    }
    Ok(String::from_utf8(result).map_err(|err| {
        warn!("Failed to decode chunk as UTF-8: {}", err);
        "Failed to decode chunk as UTF-8"
    })?)
}

pub async fn read_content<S>(
    socket: &mut BufferedTlsStream<S>,
    headers: &str,
) -> Result<String, HttpError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if headers.find("Transfer-Encoding: chunked").is_some() {
        // This is super janky, but should work if chunks are small enough.
        // openfortivpn works the same way.
        return read_http_chunk(socket, CHUNKS_END_MARKER).await;
    }
    let content_length = match read_content_length(headers) {
        Some(content_length) => content_length,
        None => {
            return Err("Failed to extract content length".into());
        }
    };
    let mut buf = vec![0; content_length];
    let mut received_data = 0;
    while received_data < buf.len() {
        received_data += socket.read(&mut buf[received_data..]).await?;
    }

    Ok(String::from_utf8(buf).map_err(|err| {
        warn!("Failed to decode headers as UTF-8: {}", err);
        "Failed to decode headers as UTF-8"
    })?)
}

fn find_chunk_end(separator: &[u8], current_data: &[u8], new_data: &[u8]) -> Option<usize> {
    // First character doesn't count, only extras are relevant.
    let mut merged_chunk = vec![0; separator.len()];
    for i in 0..new_data.len() {
        if i < separator.len() - 1 {
            let previous_bytes = separator.len() - 1 - i;
            if current_data.len() < previous_bytes {
                continue;
            }
            merged_chunk[..previous_bytes]
                .copy_from_slice(&current_data[current_data.len() - previous_bytes..]);
            merged_chunk[previous_bytes..].copy_from_slice(&new_data[..=i]);
            if &merged_chunk == separator {
                return Some(i + 1);
            }
        } else {
            if &new_data[i + 1 - separator.len()..=i] == separator {
                return Some(i + 1);
            }
        }
    }
    None
}

pub fn read_content_length(headers: &str) -> Option<usize> {
    const CONTENT_LENGTH_HEADER: &str = "Content-Length: ";
    for line in headers.lines() {
        if line.starts_with(CONTENT_LENGTH_HEADER) {
            match &line[CONTENT_LENGTH_HEADER.len()..].parse::<usize>() {
                Ok(content_length) => return Some(*content_length),
                Err(err) => {
                    warn!("Failed to parse content-length: {}", err);
                    continue;
                }
            }
        }
    }
    None
}

pub async fn write_http_response<S>(
    writer: &mut BufferedTlsStream<S>,
    data: &[u8],
) -> Result<(), HttpError>
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

pub fn build_http_request(
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
            // This is not the best circular buffer implementation, hope this trick avoids copying too much data.
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

pub struct BufferedTlsStream<S>
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
    pub fn new(stream: S) -> BufferedTlsStream<S> {
        BufferedTlsStream {
            stream,
            buffer: Buffer::new(),
        }
    }

    pub async fn read_peek(&mut self, need_bytes: usize) -> Result<&[u8], HttpError> {
        let need_more_data = self.buffer.peek().len() < need_bytes;
        let write_slice = self.buffer.write_slice();
        if need_more_data && !write_slice.is_empty() {
            let bytes_read = self.stream.read(write_slice).await?;
            self.buffer.advance_write(bytes_read);
        }
        Ok(self.buffer.peek())
    }

    pub async fn read(&mut self, dest: &mut [u8]) -> Result<usize, HttpError> {
        if self.buffer.peek().is_empty() {
            let write_slice = self.buffer.write_slice();
            if !write_slice.is_empty() {
                let bytes_read = self.stream.read(write_slice).await?;
                self.buffer.advance_write(bytes_read);
            }
        }
        Ok(self.buffer.read(dest))
    }

    pub async fn write_all(&mut self, data: &[u8]) -> Result<(), HttpError> {
        Ok(self.stream.write_all(data).await?)
    }

    pub async fn flush(&mut self) -> Result<(), HttpError> {
        Ok(self.stream.flush().await?)
    }
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
