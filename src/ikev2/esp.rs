use std::{
    error, fmt,
    hash::{Hash, Hasher},
    net::SocketAddr,
};

use log::warn;

use super::{crypto, message};

#[derive(Clone, Copy)]
pub struct SecurityAssociationID {
    local_spi: u32,
    remote_addr: SocketAddr,
}

impl SecurityAssociationID {
    pub fn from_datagram(local_spi: u32, remote_addr: SocketAddr) -> SecurityAssociationID {
        SecurityAssociationID {
            local_spi,
            remote_addr,
        }
    }
}

impl PartialEq for SecurityAssociationID {
    fn eq(&self, other: &Self) -> bool {
        // Ignore remote SPI, as ESP packets only include destination SPI.
        self.local_spi == other.local_spi && self.remote_addr == other.remote_addr
    }
}

impl Eq for SecurityAssociationID {}

impl Hash for SecurityAssociationID {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.local_spi.hash(state);
        self.remote_addr.hash(state);
    }
}

impl SecurityAssociationID {
    pub fn from_transform_params(
        remote_addr: SocketAddr,
        transform_params: &crypto::TransformParameters,
    ) -> Result<SecurityAssociationID, EspError> {
        match transform_params.local_spi() {
            message::Spi::U32(local_spi) => Ok(SecurityAssociationID {
                local_spi,
                remote_addr,
            }),
            _ => Err("Security Association has unsupported local SPI type".into()),
        }
    }
}

pub struct SecurityAssociation {
    ts_local: Vec<message::TrafficSelector>,
    ts_remote: Vec<message::TrafficSelector>,
    crypto_stack: crypto::CryptoStack,
    signature_length: usize,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl SecurityAssociation {
    pub fn new(
        ts_local: Vec<message::TrafficSelector>,
        ts_remote: Vec<message::TrafficSelector>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
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
            local_addr,
            remote_addr,
            crypto_stack,
            signature_length,
        }
    }

    fn contains(&self, remote_addr: &SocketAddr, local_addr: &SocketAddr) -> bool {
        self.ts_local.iter().any(|ts_local| {
            ts_local.addr_range().contains(&local_addr.ip())
                && ts_local.port_range().contains(&local_addr.port())
        }) && self.ts_remote.iter().any(|ts_remote| {
            ts_remote.addr_range().contains(&remote_addr.ip())
                && ts_remote.port_range().contains(&remote_addr.port())
        })
    }

    pub fn handle_esp<'a>(&self, data: &'a mut [u8]) -> Result<&'a [u8], EspError> {
        if data.len() < 8 + self.signature_length {
            return Err("Not enough data in ESP packet".into());
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
