use std::{error, fmt, net::SocketAddr};

use log::warn;

use super::{crypto, ip, message};

pub type SecurityAssociationID = u32;

pub struct SecurityAssociation {
    network: ip::Network,
    ts_remote: Vec<message::TrafficSelector>,
    local_spi: u32,
    remote_spi: u32,
    crypto_stack: crypto::CryptoStack,
    signature_length: usize,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    replay_window: ReplayWindow,
    local_seq: u32,
    index: usize,
}

impl SecurityAssociation {
    pub fn new(
        local_config: (ip::Network, SocketAddr, u32),
        remote_config: (Vec<message::TrafficSelector>, SocketAddr, u32),
        crypto_stack: crypto::CryptoStack,
        params: &crypto::TransformParameters,
        index: usize,
    ) -> SecurityAssociation {
        let signature_length = if let Some(signature_length) = params.auth_signature_length() {
            signature_length / 8
        } else {
            0
        };
        let (network, local_addr, local_spi) = local_config;
        let (ts_remote, remote_addr, remote_spi) = remote_config;
        SecurityAssociation {
            network,
            ts_remote,
            local_spi,
            remote_spi,
            local_addr,
            remote_addr,
            crypto_stack,
            signature_length,
            replay_window: ReplayWindow::new(),
            local_seq: 0,
            index,
        }
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn is_active(&self) -> bool {
        self.local_seq > 0 || self.replay_window.last_seq.is_some()
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

    pub fn accepts_esp_to_vpn(&self, hdr: &ip::IpHeader) -> bool {
        ts_accepts_header(self.network.ts_local(), hdr, TsCheck::Destination)
            && ts_accepts_header(&self.ts_remote, hdr, TsCheck::Source)
    }

    pub fn accepts_vpn_to_esp(&self, hdr: &ip::IpHeader) -> bool {
        ts_accepts_header(&self.ts_remote, hdr, TsCheck::Destination)
            && ts_accepts_header(self.network.ts_local(), hdr, TsCheck::Source)
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
        let (associated_data, data) = if self.signature_length == 0 {
            data.split_at_mut(8)
        } else {
            data.split_at_mut(0)
        };
        match self.crypto_stack.decrypt_data(
            &mut data[..signed_data_len - associated_data.len()],
            signed_data_len - associated_data.len(),
            associated_data,
        ) {
            Ok(data) => {
                self.replay_window.update(sequence_number);
                Ok(data)
            }
            Err(err) => {
                warn!("Failed to decrypt ESP packet: {}", err);
                Err("Failed to decrypt ESP packet".into())
            }
        }
    }

    pub fn handle_vpn<'a>(
        &mut self,
        data: &'a mut [u8],
        msg_len: usize,
    ) -> Result<&'a [u8], EspError> {
        if self.encoded_length(msg_len) > data.len() {
            return Err("Not enough capacity in ESP packet buffer".into());
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
            .encrypt_data(data, msg_len, associated_data)
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

    pub fn nat_to_vpn<'a>(
        &mut self,
        packet: ip::IpPacket<'a>,
        buf: &'a mut [u8],
    ) -> Result<ip::RoutingDecision<'a>, EspError> {
        Ok(self.network.translate_packet_from_esp(packet, buf)?)
    }
}

enum TsCheck {
    Source,
    Destination,
}

fn ts_accepts_header(
    ts: &[message::TrafficSelector],
    hdr: &ip::IpHeader,
    ts_check: TsCheck,
) -> bool {
    ts.iter().any(|ts| {
        let accepts_procotol = ts.ip_protocol() == message::IPProtocolType::ANY
            || hdr.transport_protocol() == ts.ip_protocol();
        if !accepts_procotol {
            return false;
        }
        let check_addr = match ts_check {
            TsCheck::Source => hdr.src_addr(),
            TsCheck::Destination => hdr.dst_addr(),
        };
        if !ts.addr_range().contains(check_addr) {
            return false;
        }
        let check_port = match ts_check {
            TsCheck::Source => hdr.src_port(),
            TsCheck::Destination => hdr.dst_port(),
        };
        if let Some(check_port) = check_port.as_ref() {
            ts.port_range().contains(check_port)
        } else {
            // If no port specified for TCP or UDP, this is an error.
            hdr.transport_protocol() != ip::TransportProtocolType::TCP
                && hdr.transport_protocol() != ip::TransportProtocolType::UDP
        }
    })
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
    Ip(ip::IpError),
}

impl fmt::Display for EspError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Internal(msg) => f.write_str(msg),
            Self::Ip(ref err) => write!(f, "IP error {}", err),
        }
    }
}

impl error::Error for EspError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Self::Internal(_msg) => None,
            Self::Ip(ref err) => Some(err),
        }
    }
}

impl From<ip::IpError> for EspError {
    fn from(err: ip::IpError) -> EspError {
        Self::Ip(err)
    }
}

impl From<&'static str> for EspError {
    fn from(msg: &'static str) -> EspError {
        Self::Internal(msg)
    }
}
