use std::{error, fmt, io, ops::Range, task::Poll};

use crate::logger::fmt_slice_hex;

use super::{Checksum, IpError, IpPacket, TransportProtocolType};

pub struct Refragmenter<const B: usize, const F: usize> {
    mtu: usize,
    buf: [u8; B],
    header_len: usize,
    fragments: [DataFragment; F],
    fragments_len: usize,
    current_fragment: usize,
}

impl<const N: usize, const F: usize> Refragmenter<N, F> {
    pub fn new(mtu: usize) -> Refragmenter<N, F> {
        Refragmenter {
            mtu,
            buf: [0u8; N],
            header_len: 0,
            fragments: [DataFragment::new(); F],
            fragments_len: 0,
            current_fragment: 0,
        }
    }

    pub fn poll_recv<R>(
        &mut self,
        cx: &mut std::task::Context<'_>,
        dest: &mut [u8],
        recv: R,
    ) -> Poll<Result<usize, TsoError>>
    where
        R: FnOnce(&mut std::task::Context<'_>, &mut [u8]) -> Poll<Result<Range<usize>, io::Error>>,
    {
        if self.current_fragment < self.fragments_len {
            return Poll::Ready(Ok(self.next_fragment(dest)));
        }
        let data_range = match recv(cx, &mut self.buf) {
            Poll::Ready(Ok(data_range)) => data_range,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err.into())),
            Poll::Pending => return Poll::Pending,
        };
        self.header_len = 0;
        self.fragments_len = 0;
        self.current_fragment = 0;
        if data_range.end <= self.mtu {
            println!("FUll {}", fmt_slice_hex(&self.buf[data_range.clone()]));
            dest[..data_range.end].copy_from_slice(&self.buf[..data_range.end]);
            return Poll::Ready(Ok(data_range.end));
        }
        let packet = match IpPacket::from_data(&self.buf[data_range.clone()]) {
            Ok(packet) => packet,
            Err(err) => return Poll::Ready(Err(err.into())),
        };
        let transport_protocol = packet.transport_protocol_data();
        if transport_protocol.protocol() != TransportProtocolType::TCP {
            // Copy non-TCP packets as-is (in truncated form).
            let data_len = dest.len().min(data_range.end);
            dest[..data_len].copy_from_slice(&self.buf[..data_len]);
            return Poll::Ready(Ok(data_len));
        }
        // With TSO, Windows and/or Linux might only be providing partial checksums (pseudoheader only).
        // It's potentially impossible to verify validity of TCP checksums in this scenario.
        let pseudo_checksum = packet.pseudo_checksum();
        println!("Split {}", fmt_slice_hex(&self.buf[data_range.clone()]));
        let data_range = data_range.end - transport_protocol.payload_data().len()..data_range.end;
        let tcp_range = data_range.end - transport_protocol.full_data().len()..data_range.start;
        self.init_fragments(tcp_range, data_range, pseudo_checksum);
        Poll::Ready(Ok(self.next_fragment(dest)))
    }

    fn next_fragment(&mut self, dest: &mut [u8]) -> usize {
        if self.current_fragment >= self.fragments_len {
            return 0;
        }
        let fragment = self.fragments[self.current_fragment];
        let fragment_data = &self.buf[fragment.range()];
        self.current_fragment += 1;
        // TODO GATEWAY: update IP headers if needed.
        dest[0..self.header_len].copy_from_slice(&self.buf[0..self.header_len]);
        dest[self.header_len..self.header_len + fragment.len()].copy_from_slice(fragment_data);
        self.header_len + fragment.len()
    }

    fn init_fragments(
        &mut self,
        tcp_range: Range<usize>,
        data_range: Range<usize>,
        pseudo_checksum: Option<Checksum>,
    ) {
        self.header_len = data_range.start;
        let tcp_header = &self.buf[tcp_range.clone()];
        let chunk_size = ((self.mtu - self.header_len) / 4) * 4;
        let mut aggregated_checksum = if let Some(mut checksum) = pseudo_checksum {
            checksum.fold();
            println!("Pseudo checksum {}", checksum.value());
            let mut orig_checksum = [0u8; 2];
            orig_checksum.copy_from_slice(&tcp_header[16..18]);
            let orig_checksum = !u16::from_be_bytes(orig_checksum);
            println!("Orig checksum {orig_checksum}");
            let orig_checksum = Checksum::from_inverted(orig_checksum);

            checksum.add_slice(tcp_header);
            println!("tcp checksum {}", checksum.value());
            checksum.incremental_update(orig_checksum, Checksum::new());
            checksum.fold();
            Some(checksum)
        } else {
            None
        };
        self.fragments_len = 0;
        for start in (data_range.start..data_range.end).step_by(chunk_size) {
            let end = (start + chunk_size).min(data_range.end);

            let mut checksum = Checksum::new();
            checksum.add_slice(&self.buf[start..end]);
            checksum.fold();
            if let Some(aggregated_checksum) = &mut aggregated_checksum {
                aggregated_checksum.incremental_update(Checksum::new(), checksum);
            }
            let checksum = checksum.value();
            // TODO GATEWAY: check for overflow
            self.fragments[self.fragments_len].update(start..end, checksum);
            self.fragments_len += 1;
        }

        if let Some(mut checksum) = aggregated_checksum {
            checksum.fold();
            if checksum.value() != 0x0000 {
                println!("Checksum mismatch {}", checksum.value());
            }
        }
        println!("Checksum OK");
    }
}

#[derive(Clone, Copy)]
struct DataFragment {
    checksum: u16,
    start: usize,
    end: usize,
}

impl DataFragment {
    fn new() -> DataFragment {
        DataFragment {
            checksum: 0,
            start: 0,
            end: 0,
        }
    }

    fn update(&mut self, offset: Range<usize>, checksum: u16) {
        self.start = offset.start;
        self.end = offset.end;
        self.checksum = checksum;
    }

    fn range(&self) -> Range<usize> {
        self.start..self.end
    }

    fn len(&self) -> usize {
        self.end - self.start
    }
}

#[derive(Debug)]
pub enum TsoError {
    Internal(&'static str),
    Ip(IpError),
    Io(io::Error),
}

impl fmt::Display for TsoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Internal(msg) => f.write_str(msg),
            Self::Ip(e) => write!(f, "IP error: {e}"),
            Self::Io(e) => write!(f, "IO error: {e}"),
        }
    }
}

impl error::Error for TsoError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Internal(_msg) => None,
            Self::Ip(err) => Some(err),
            Self::Io(err) => Some(err),
        }
    }
}

impl From<super::IpError> for TsoError {
    fn from(err: super::IpError) -> TsoError {
        Self::Ip(err)
    }
}

impl From<io::Error> for TsoError {
    fn from(err: io::Error) -> TsoError {
        Self::Io(err)
    }
}

impl From<&'static str> for TsoError {
    fn from(msg: &'static str) -> TsoError {
        Self::Internal(msg)
    }
}
