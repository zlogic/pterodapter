use std::{error, fmt, net::SocketAddr};

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
            local_seq: 0,
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    pub fn headers_size(&self) -> usize {
        8 + self.signature_length
    }

    fn contains(&self, remote_addr: &SocketAddr, local_addr: &SocketAddr) -> bool {
        ts_accepts(&self.ts_remote, remote_addr) && ts_accepts(&self.ts_local, local_addr)
    }

    pub fn handle_esp<'a>(&self, data: &'a mut [u8]) -> Result<&'a [u8], EspError> {
        if data.len() < 8 + self.signature_length {
            return Err("Not enough data in ESP packet".into());
        }
        let mut local_spi = [0u8; 4];
        local_spi.copy_from_slice(&data[..4]);
        let local_spi = u32::from_be_bytes(local_spi);
        if self.local_spi != local_spi {
            return Err("Received packet for another local SPI".into());
        }
        let mut sequence_id = [0u8; 4];
        sequence_id.copy_from_slice(&data[4..8]);
        // TODO: validate that sequence ID is not reused, as defined in https://datatracker.ietf.org/doc/html/rfc6479
        // let sequence_id = u32::from_be_bytes(sequence_id);
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
            Ok(data) => Ok(data),
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
        if data.len() < msg_len + 8 + self.signature_length {
            return Err("Not enough data in ESP packet".into());
        }
        if self.local_seq >= u32::MAX {
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
