use std::{error, fmt, io, ops::Range, task::Poll};

use log::{debug, warn};

use super::{Checksum, IpError, IpPacket, TransportProtocolType};

pub struct Refragmenter<const B: usize, const F: usize> {
    mtu: usize,
    buf: [u8; B],
    header_len: usize,
    fragments: [DataFragment; F],
    fragments_len: usize,
    current_fragment: usize,
}

impl<const B: usize, const F: usize> Refragmenter<B, F> {
    pub fn new(mtu: usize) -> Refragmenter<B, F> {
        Refragmenter {
            mtu,
            buf: [0u8; B],
            header_len: 0,
            fragments: [DataFragment::new(); F],
            fragments_len: 0,
            current_fragment: 0,
        }
    }

    fn reset(&mut self) {
        self.header_len = 0;
        self.fragments_len = 0;
        self.current_fragment = 0;
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
        self.reset();
        let packet = match IpPacket::from_data(&self.buf[data_range.clone()]) {
            Ok(packet) => packet,
            Err(err) => return Poll::Ready(Err(err.into())),
        };
        let transport_protocol = packet.transport_protocol_data();
        if transport_protocol.protocol() != TransportProtocolType::TCP {
            return self.return_passthrough(data_range, dest);
        }
        let pseudo_checksum = if let Some(mut pseudo_checksum) = packet.pseudo_checksum() {
            pseudo_checksum.fold();
            pseudo_checksum
        } else {
            debug!("Received fragmented packet, skipping GRO reassembly");
            return self.return_passthrough(data_range, dest);
        };
        let payload_data_range =
            data_range.end - transport_protocol.payload_data().len()..data_range.end;
        let tcp_range =
            data_range.end - transport_protocol.full_data().len()..payload_data_range.start;
        if let Err(err) = self.init_fragments(tcp_range, payload_data_range, pseudo_checksum) {
            Poll::Ready(Err(err))
        } else {
            Poll::Ready(Ok(self.next_fragment(dest)))
        }
    }

    fn return_passthrough(
        &self,
        data_range: Range<usize>,
        dest: &mut [u8],
    ) -> Poll<Result<usize, TsoError>> {
        // Copy packets as-is (even if truncated).
        let data_len = dest.len().min(data_range.end);
        dest[..data_len].copy_from_slice(&self.buf[..data_len]);
        Poll::Ready(Ok(data_len))
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
        dest[self.header_len..self.header_len + fragment_data.len()].copy_from_slice(fragment_data);
        self.header_len + fragment_data.len()
    }

    fn init_fragments(
        &mut self,
        tcp_range: Range<usize>,
        data_range: Range<usize>,
        pseudo_checksum: Checksum,
    ) -> Result<(), TsoError> {
        self.header_len = data_range.start;
        let tcp_header = &mut self.buf[tcp_range.clone()];
        let fragment_size = ((self.mtu - self.header_len) / 4) * 4;
        if fragment_size == 0 {
            return Err("Not enough remaining space to fit payload fragment data".into());
        }
        let fragments_count = (data_range.len() + fragment_size - 1) / fragment_size;
        let orig_checksum = {
            let mut orig_checksum = [0u8; 2];
            orig_checksum.copy_from_slice(&tcp_header[16..18]);
            Checksum::from_inverted(u16::from_be_bytes(orig_checksum))
        };
        let mut aggregated_checksum = {
            // With TSO, Windows and/or Linux might only be providing partial checksums (pseudoheader only).
            // For more information, see the "Partial Checksums" explanation in the Wireshark documentation.
            // It's potentially impossible to verify validity of full TCP checksums in this scenario.
            if pseudo_checksum.value() == !orig_checksum.value() {
                debug!("Packet has a partial checksum, skipping payload validation");
                None
            } else {
                let mut checksum = pseudo_checksum;
                tcp_header[16..18].fill(0);
                checksum.add_slice(tcp_header);
                Some(checksum)
            }
        };
        self.fragments_len = fragments_count.min(self.fragments.len());
        for (i, fragment) in self.fragments.iter_mut().enumerate() {
            let start = data_range.start + fragment_size * i;
            if start >= data_range.end {
                break;
            }
            let end = (start + fragment_size).min(data_range.end);

            let mut checksum = Checksum::from_slice(&self.buf[start..end]);
            checksum.fold();
            if let Some(aggregated_checksum) = &mut aggregated_checksum {
                aggregated_checksum.incremental_update(Checksum::new(), checksum);
            }
            fragment.update(start..end, !checksum.value());
        }

        if fragments_count > self.fragments_len {
            let total_bytes = data_range.len();
            let max_bytes = fragment_size * self.fragments_len;
            warn!(
                "Not enough capacity to store all fragments, lost {} bytes",
                total_bytes - max_bytes
            );
            // Continue calculating checksum if it's available.
            if let Some(mut checksum) = aggregated_checksum {
                let start = data_range.start + fragment_size * self.fragments_len;
                let end = data_range.end;
                checksum.add_slice(&self.buf[start..end])
            }
        }
        if let Some(mut checksum) = aggregated_checksum {
            checksum.fold();
            if checksum.value() != orig_checksum.value() {
                self.reset();
                Err("Packet has invalid payload checksum".into())
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
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
