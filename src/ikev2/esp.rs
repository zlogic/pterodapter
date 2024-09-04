use std::{
    error, fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use log::warn;

use super::{crypto, message};

pub type SecurityAssociationID = u32;

pub struct SecurityAssociation {
    ts_local: Vec<message::TrafficSelector>,
    ts_remote: Vec<message::TrafficSelector>,
    local_spi: u32,
    remote_spi: u32,
    crypto_stack: crypto::CryptoStack,
    signature_length: usize,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    replay_window: ReplayWindow,
    local_seq: u32,
}

impl SecurityAssociation {
    pub fn new(
        ts_local: Vec<message::TrafficSelector>,
        ts_remote: Vec<message::TrafficSelector>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        local_spi: u32,
        remote_spi: u32,
        crypto_stack: crypto::CryptoStack,
        params: &crypto::TransformParameters,
    ) -> SecurityAssociation {
        let signature_length = if let Some(signature_length) = params.auth_signature_length() {
            signature_length / 8
        } else {
            0
        };
        SecurityAssociation {
            ts_local,
            ts_remote,
            local_spi,
            remote_spi,
            local_addr,
            remote_addr,
            crypto_stack,
            signature_length,
            replay_window: ReplayWindow::new(),
            local_seq: 0,
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    pub fn encoded_length(&self, msg_len: usize) -> usize {
        8 + self.crypto_stack.encrypted_payload_length(msg_len)
    }

    pub fn accepts_esp_to_vpn(&self, hdr: &IpHeader) -> bool {
        ts_accepts_header(&self.ts_local, &hdr, TsCheck::Destination)
            && ts_accepts_header(&self.ts_remote, &hdr, TsCheck::Source)
    }

    pub fn accepts_vpn_to_esp(&self, hdr: &IpHeader) -> bool {
        ts_accepts_header(&self.ts_remote, &hdr, TsCheck::Destination)
            && ts_accepts_header(&self.ts_local, &hdr, TsCheck::Source)
    }

    pub fn handle_esp<'a>(&mut self, data: &'a mut [u8]) -> Result<&'a [u8], EspError> {
        if data.len() < 8 + self.signature_length {
            return Err("Not enough data in ESP packet".into());
        }
        let mut local_spi = [0u8; 4];
        local_spi.copy_from_slice(&data[..4]);
        let local_spi = u32::from_be_bytes(local_spi);
        if self.local_spi != local_spi {
            return Err("Received packet for another local SPI".into());
        }
        let mut sequence_number = [0u8; 4];
        sequence_number.copy_from_slice(&data[4..8]);
        let sequence_number = u32::from_be_bytes(sequence_number);
        if !self.replay_window.is_unique(sequence_number) {
            return Err("Received packet with replayed Sequence Number".into());
        }
        let signed_data_len = data.len() - self.signature_length;
        let valid_signature = self.crypto_stack.validate_signature(data);
        if !valid_signature {
            return Err("Packet has invalid signature".into());
        }
        let mut associated_data = [0u8; 8];
        let associated_data = if self.signature_length == 0 {
            associated_data.copy_from_slice(&data[0..8]);
            &associated_data[..]
        } else {
            &[]
        };
        match self.crypto_stack.decrypt_data(
            &mut data[8..signed_data_len],
            signed_data_len - 8,
            associated_data,
        ) {
            Ok(data) => {
                self.replay_window.update(sequence_number);
                Ok(data)
            }
            Err(err) => {
                warn!("Failed to decrypt ESP packet: {}", err);
                return Err("Failed to decrypt ESP packet".into());
            }
        }
    }

    pub fn handle_vpn<'a>(
        &mut self,
        data: &'a mut [u8],
        msg_len: usize,
    ) -> Result<&'a [u8], EspError> {
        if data.len() < msg_len + 8 + self.signature_length {
            return Err("Not enough data in ESP packet".into());
        }
        if self.local_seq == u32::MAX {
            return Err("Sequence number overflow".into());
        }
        data.copy_within(..msg_len, 8);
        data[0..4].copy_from_slice(&self.remote_spi.to_be_bytes());
        data[4..8].copy_from_slice(&self.local_seq.to_be_bytes());
        self.local_seq += 1;
        let mut associated_data = [0u8; 8];
        let associated_data = if self.signature_length == 0 {
            associated_data.copy_from_slice(&data[0..8]);
            &associated_data[..]
        } else {
            &[]
        };
        match self
            .crypto_stack
            .encrypt_data(&mut data[8..], msg_len, &associated_data)
        {
            Ok(encrypted_data) => {
                let encrypted_data_len = 8 + encrypted_data.len();
                let encrypted_data = &data[..encrypted_data_len];
                Ok(encrypted_data)
            }
            Err(err) => {
                warn!("Failed to encrypt ESP packet: {}", err);
                Err("Failed to encrypt ESP packet".into())
            }
        }
    }
}

pub fn ts_accepts(ts: &[message::TrafficSelector], addr: &SocketAddr) -> bool {
    ts.iter()
        .any(|ts| ts.addr_range().contains(&addr.ip()) && ts.port_range().contains(&addr.port()))
}

enum TsCheck {
    Source,
    Destination,
}

fn ts_accepts_header(ts: &[message::TrafficSelector], hdr: &IpHeader, ts_check: TsCheck) -> bool {
    ts.iter().any(|ts| {
        let accepts_procotol = ts.ip_protocol() == message::IPProtocolType::ANY
            || ts.ip_protocol() == hdr.transport_protocol;
        if !accepts_procotol {
            return false;
        }
        let check_addr = match ts_check {
            TsCheck::Source => &hdr.src_addr,
            TsCheck::Destination => &hdr.dst_addr,
        };
        if !ts.addr_range().contains(check_addr) {
            return false;
        }
        let check_port = match ts_check {
            TsCheck::Source => hdr.src_port.as_ref(),
            TsCheck::Destination => hdr.dst_port.as_ref(),
        };
        if let Some(check_port) = check_port {
            ts.port_range().contains(check_port)
        } else {
            // If no port specified for TCP or UDP, this is an error.
            hdr.transport_protocol != message::IPProtocolType::TCP
                && hdr.transport_protocol != message::IPProtocolType::UDP
        }
    })
}

pub struct IpHeader {
    src_addr: IpAddr,
    dst_addr: IpAddr,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    transport_protocol: message::IPProtocolType,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Ipv6NextHeader(u8);

impl Ipv6NextHeader {
    const HOP_BY_HOP_OPTIONS: Ipv6NextHeader = Ipv6NextHeader(0);
    const ROUTING: Ipv6NextHeader = Ipv6NextHeader(43);
    const FRAGMENT: Ipv6NextHeader = Ipv6NextHeader(44);
    const DESTINATION_OPTIONS: Ipv6NextHeader = Ipv6NextHeader(60);
    const NO_NEXT_HEADER: Ipv6NextHeader = Ipv6NextHeader(59);
}

impl Ipv6NextHeader {
    fn length(&self, data: &[u8]) -> Option<usize> {
        match *self {
            Self::HOP_BY_HOP_OPTIONS => Some(data[1] as usize + 1),
            Self::ROUTING => Some(data[1] as usize + 1),
            Self::FRAGMENT => Some(8),
            Self::DESTINATION_OPTIONS => Some(data[1] as usize + 1),
            Self::NO_NEXT_HEADER => None,
            _ => None,
        }
    }

    fn min_bytes(&self) -> usize {
        match *self {
            Self::HOP_BY_HOP_OPTIONS => 2,
            Self::ROUTING => 2,
            Self::FRAGMENT => 8,
            Self::DESTINATION_OPTIONS => 2,
            Self::NO_NEXT_HEADER => 0,
            _ => 0,
        }
    }
}

impl IpHeader {
    pub fn from_packet(data: &[u8]) -> Result<IpHeader, EspError> {
        if data.is_empty() {
            return Err("IP packet is empty, cannot extract header data".into());
        }
        match data[0] >> 4 {
            4 => Self::from_ipv4_packet(data),
            6 => Self::from_ipv6_packet(data),
            _ => {
                warn!("ESP IP packet is not a supported IP version: {:x}", data[0]);
                return Err("Unsupported IP prococol version".into());
            }
        }
    }

    fn from_ipv4_packet(data: &[u8]) -> Result<IpHeader, EspError> {
        if data.len() < 20 {
            return Err("Not enough bytes in IPv4 header".into());
        }
        let header_length = (data[0] & 0x0f) as usize * 4;
        if data.len() < header_length {
            return Err("IPv4 header length overflow".into());
        }
        let transport_protocol = message::IPProtocolType::from_u8(data[9]);
        let (src_port, dst_port) = match transport_protocol {
            message::IPProtocolType::TCP | message::IPProtocolType::UDP => {
                Self::extract_ports(&data[header_length..])?
            }
            message::IPProtocolType::ANY => return Err("IPv4 protocol is 0".into()),
            _ => (None, None),
        };
        let mut src_addr = [0u8; 4];
        src_addr.copy_from_slice(&data[12..16]);
        let src_addr = IpAddr::V4(Ipv4Addr::from(src_addr));
        let mut dst_addr = [0u8; 4];
        dst_addr.copy_from_slice(&data[16..20]);
        let dst_addr = IpAddr::V4(Ipv4Addr::from(dst_addr));
        Ok(IpHeader {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            transport_protocol,
        })
    }

    fn from_ipv6_packet(data: &[u8]) -> Result<IpHeader, EspError> {
        if data.len() < 40 {
            return Err("Not enough bytes in IPv6 header".into());
        }
        // TODO: test that this works.
        let mut next_header = Ipv6NextHeader(data[6]);
        let mut next_header_start = 40;
        loop {
            if next_header_start + next_header.min_bytes() > data.len() {
                return Err("IPv6 header length overlow".into());
            }
            if let Some(header_length) = next_header.length(&data[next_header_start..]) {
                next_header = Ipv6NextHeader(data[next_header_start]);
                next_header_start += header_length;
            } else {
                break;
            }
        }
        let transport_protocol = message::IPProtocolType::from_u8(next_header.0);
        let (src_port, dst_port) = match transport_protocol {
            message::IPProtocolType::TCP | message::IPProtocolType::UDP => {
                Self::extract_ports(&data[next_header_start..])?
            }
            message::IPProtocolType::ANY => return Err("IPv4 protocol is 0".into()),
            _ => (None, None),
        };
        let mut src_addr = [0u8; 16];
        src_addr.copy_from_slice(&data[8..24]);
        let src_addr = IpAddr::V6(Ipv6Addr::from(src_addr));
        let mut dst_addr = [0u8; 16];
        dst_addr.copy_from_slice(&data[24..40]);
        let dst_addr = IpAddr::V6(Ipv6Addr::from(dst_addr));
        Ok(IpHeader {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            transport_protocol,
        })
    }

    fn extract_ports(data: &[u8]) -> Result<(Option<u16>, Option<u16>), EspError> {
        if data.len() < 4 {
            return Err("Not enough data in transport layer to extract ports".into());
        }
        let mut src_port = [0u8; 2];
        src_port.copy_from_slice(&data[0..2]);
        let src_port = u16::from_be_bytes(src_port);
        let mut dst_port = [0u8; 2];
        dst_port.copy_from_slice(&data[2..4]);
        let dst_port = u16::from_be_bytes(dst_port);
        Ok((Some(src_port), Some(dst_port)))
    }
}

impl fmt::Display for IpHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(src_port) = self.src_port {
            write!(
                f,
                "{} {}:{} -> ",
                self.transport_protocol, self.src_addr, src_port
            )?;
        } else {
            write!(f, "{} {} -> ", self.transport_protocol, self.src_addr)?;
        }
        if let Some(dst_port) = self.dst_port {
            write!(f, "{}:{}", self.dst_addr, dst_port)?;
        } else {
            write!(f, "{}", self.dst_addr)?;
        }
        Ok(())
    }
}

const REPLAY_WINDOW_SIZE: usize = 1024;
const REPLAY_WINDOW_BLOCK_SIZE: usize = usize::BITS as usize;

struct ReplayWindow {
    last_seq: Option<u32>,
    window: [usize; REPLAY_WINDOW_SIZE / REPLAY_WINDOW_BLOCK_SIZE],
}

impl ReplayWindow {
    fn new() -> ReplayWindow {
        // Inspired by RFC 6479 (but better :).
        ReplayWindow {
            last_seq: None,
            window: [0usize; REPLAY_WINDOW_SIZE / REPLAY_WINDOW_BLOCK_SIZE],
        }
    }

    fn is_unique(&self, seq_num: u32) -> bool {
        let last_seq = if let Some(last_seq) = self.last_seq {
            last_seq
        } else {
            // First packet.
            return true;
        };
        if seq_num > last_seq {
            // Higher than all all previously received packets.
            return true;
        }
        if seq_num == u32::MAX {
            // Maxed out, cannot continue further.
            return false;
        }
        if seq_num.abs_diff(last_seq) as usize > REPLAY_WINDOW_SIZE {
            // Behind window, too old.
            return false;
        };

        // For this to work correctly, REPLAY_WINDOW_SIZE must be a multiple of REPLAY_WINDOW_BLOCK_SIZE.
        // In case bit shifting consumes multiple cycles, consider using a static lookup table?
        let bit_mask = 1 << (seq_num as usize % REPLAY_WINDOW_BLOCK_SIZE);
        let block_index = (seq_num as usize % REPLAY_WINDOW_SIZE) / REPLAY_WINDOW_BLOCK_SIZE;

        self.window[block_index] & bit_mask == 0
    }

    fn update(&mut self, seq_num: u32) {
        let current_block_index = if let Some(last_seq) = self.last_seq {
            (last_seq as usize % REPLAY_WINDOW_SIZE) / REPLAY_WINDOW_BLOCK_SIZE
        } else {
            // First packet.
            0
        };

        let bit_mask = 1 << (seq_num as usize % REPLAY_WINDOW_BLOCK_SIZE);
        let block_index = (seq_num as usize % REPLAY_WINDOW_SIZE) / REPLAY_WINDOW_BLOCK_SIZE;

        // This is 0 if seq_num is behind last_seq; wrapping prevents unnecessary loops.
        let add_blocks = block_index.saturating_sub(current_block_index) % self.window.len();
        for i in 1..=add_blocks {
            self.window[(current_block_index + i) % self.window.len()] = 0;
        }
        self.window[block_index] |= bit_mask;

        self.last_seq = self
            .last_seq
            .map(|last_seq| seq_num.max(last_seq))
            .or(Some(seq_num))
    }
}

#[derive(Debug)]
pub enum EspError {
    Internal(&'static str),
}

impl fmt::Display for EspError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Internal(msg) => f.write_str(msg),
        }
    }
}

impl error::Error for EspError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Self::Internal(_msg) => None,
        }
    }
}

impl From<&'static str> for EspError {
    fn from(msg: &'static str) -> EspError {
        Self::Internal(msg)
    }
}
