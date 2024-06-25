use log::{debug, info, warn};
use rand::Rng;
use std::{
    collections::HashMap,
    error, fmt,
    hash::{Hash, Hasher},
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{net::UdpSocket, signal, task::JoinHandle};

const MAX_DATAGRAM_SIZE: usize = 1500;

pub struct Server {
    listen_ips: Vec<IpAddr>,
}

impl Server {
    pub fn new(listen_ips: Vec<IpAddr>) -> Server {
        Server { listen_ips }
    }

    async fn listen_socket(listen_ip: IpAddr) -> Result<(), IKEv2Error> {
        let socket = match UdpSocket::bind((listen_ip, 500)).await {
            Ok(socket) => socket,
            Err(err) => {
                log::error!("Failed to open listener on {}: {}", listen_ip, err);
                return Err(err.into());
            }
        };
        info!("Started server on {}", listen_ip);
        let mut buf = [0u8; MAX_DATAGRAM_SIZE];
        // TODO: share sessions between all threads: either using an async mutex, or by forwarding all messages to the same mpsc channel.
        let mut sessions = Sessions::new();
        loop {
            let (bytes_res, remote_addr) = socket.recv_from(&mut buf).await?;
            let datagram_bytes = &mut buf[..bytes_res];
            sessions
                .process_message(datagram_bytes, remote_addr)
                .await?;
        }
    }

    async fn wait_termination(
        handles: Vec<JoinHandle<Result<(), IKEv2Error>>>,
    ) -> Result<(), IKEv2Error> {
        signal::ctrl_c().await?;
        handles.iter().for_each(|handle| handle.abort());
        Ok(())
    }

    pub fn run(&self) -> Result<(), IKEv2Error> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()?;
        let handles = self
            .listen_ips
            .iter()
            .map(|listen_ip| rt.spawn(Server::listen_socket(listen_ip.to_owned())))
            .collect::<Vec<_>>();
        rt.block_on(Server::wait_termination(handles))?;
        rt.shutdown_timeout(Duration::from_secs(60));

        info!("Stopped server");
        Ok(())
    }
}

#[derive(PartialEq, Eq)]
struct IKEExchangeType(u8);

impl IKEExchangeType {
    const IKE_SA_INIT: IKEExchangeType = IKEExchangeType(34);
    const IKE_AUTH: IKEExchangeType = IKEExchangeType(35);
    const CREATE_CHILD_SA: IKEExchangeType = IKEExchangeType(36);
    const INFORMATIONAL: IKEExchangeType = IKEExchangeType(37);

    fn from_u8(value: u8) -> Result<IKEExchangeType, FormatError> {
        if value >= Self::IKE_SA_INIT.0 && value <= Self::INFORMATIONAL.0 {
            Ok(IKEExchangeType(value))
        } else {
            debug!("Unsupported IKEv2 Exchange Type {}", value);
            Err("Unsupported IKEv2 Exchange Type".into())
        }
    }
}

impl fmt::Display for IKEExchangeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::IKE_SA_INIT => write!(f, "IKE_SA_INIT")?,
            Self::IKE_AUTH => write!(f, "IKE_AUTH")?,
            Self::CREATE_CHILD_SA => write!(f, "CREATE_CHILD_SA")?,
            Self::INFORMATIONAL => write!(f, "INFORMATIONAL")?,
            _ => write!(f, "Unknown exchange type {}", self.0)?,
        }
        Ok(())
    }
}

#[derive(PartialEq, Eq)]
struct IKEFlags(u8);

impl IKEFlags {
    const INITIATOR: IKEFlags = IKEFlags(1 << 3);
    const VERSION: IKEFlags = IKEFlags(1 << 4);
    const RESPONSE: IKEFlags = IKEFlags(1 << 5);

    fn from_u8(value: u8) -> Result<IKEFlags, FormatError> {
        const RESERVED_MASK: u8 =
            0xff & !IKEFlags::INITIATOR.0 & !IKEFlags::VERSION.0 & !IKEFlags::RESPONSE.0;
        if value & RESERVED_MASK != 0x00 {
            debug!("IKEv2 reserved flags are set {}", value & RESERVED_MASK);
            return Err("IKEv2 reserved flags are set".into());
        }
        Ok(IKEFlags(value))
    }

    fn has(&self, flag: IKEFlags) -> bool {
        self.0 & flag.0 != 0
    }
}

impl fmt::Display for IKEFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.has(IKEFlags::INITIATOR) {
            f.write_str("Initiator")?;
        }
        if self.has(IKEFlags::VERSION) {
            f.write_str("Version")?;
        }
        if self.has(IKEFlags::RESPONSE) {
            f.write_str("Response")?;
        }
        Ok(())
    }
}

struct IKEv2Message<'a> {
    data: &'a [u8],
}

// Parse and validate using spec from RFC 7296, Section 3.
impl IKEv2Message<'_> {
    fn from_datagram<'a>(p: &'a [u8]) -> IKEv2Message<'a> {
        IKEv2Message { data: p }
    }

    fn read_initiator_spi(&self) -> u64 {
        let mut result = [0u8; 8];
        result.copy_from_slice(&self.data[0..8]);
        u64::from_be_bytes(result)
    }

    fn read_responder_spi(&self) -> u64 {
        let mut result = [0u8; 8];
        result.copy_from_slice(&self.data[8..16]);
        u64::from_be_bytes(result)
    }

    fn read_next_payload(&self) -> u8 {
        self.data[16]
    }

    fn read_version(&self) -> (u8, u8) {
        let version = self.data[17];
        let major_version = version >> 4 & 0x0f;
        let minor_version = version & 0x0f;
        (major_version, minor_version)
    }

    fn read_exchange_type(&self) -> Result<IKEExchangeType, FormatError> {
        IKEExchangeType::from_u8(self.data[18])
    }

    fn read_flags(&self) -> Result<IKEFlags, FormatError> {
        IKEFlags::from_u8(self.data[19])
    }

    fn read_message_id(&self) -> u32 {
        let mut result = [0u8; 4];
        result.copy_from_slice(&self.data[20..24]);
        u32::from_be_bytes(result)
    }

    fn read_length(&self) -> u32 {
        let mut result = [0u8; 4];
        result.copy_from_slice(&self.data[24..28]);
        u32::from_be_bytes(result)
    }

    fn is_valid(&self) -> bool {
        // TODO: validate all required fields.
        // TODO: return status in notification (e.g. INVALID_MAJOR_VERSION).
        let mut valid = true;
        if self.read_initiator_spi() == 0 {
            debug!("Empty initiator SPI");
            valid = false;
        }
        if self.read_responder_spi() != 0 {
            debug!("Unexpected, non-empty responder SPI");
            valid = false;
        }
        {
            let (major_version, minor_version) = self.read_version();
            if major_version != 2 {
                debug!(
                    "Unsupported major version {}.{}",
                    major_version, minor_version
                );
                valid = false;
            }
        }
        if let Err(err) = self.read_exchange_type() {
            debug!("Error parsing exchange type {}", err);
            valid = false;
        }
        if let Err(err) = self.read_flags() {
            debug!("Error parsing flags {}", err);
            valid = false;
        }
        {
            let client_length = self.read_length();
            if self.data.len() != client_length as usize {
                debug!(
                    "Packet length mismatch (received {} bytes, client specified {} bytes)",
                    self.data.len(),
                    client_length
                );
                valid = false;
            }
        }
        valid
    }

    fn iter_payloads(&self) -> IKEv2PayloadIter {
        IKEv2PayloadIter {
            next_payload: self.read_next_payload(),
            data: &self.data[28..],
        }
    }
}

struct IKEv2Payload<'a> {
    payload_type: IKEv2PayloadType,
    critical: bool,
    data: &'a [u8],
}

impl IKEv2Payload<'_> {
    fn to_security_association(&self) -> Option<IKEv2PayloadSecurityAssociation> {
        if self.payload_type == IKEv2PayloadType::SECURITY_ASSOCIATION {
            Some(IKEv2PayloadSecurityAssociation { data: self.data })
        } else {
            None
        }
    }
}

struct IKEv2PayloadIter<'a> {
    next_payload: u8,
    data: &'a [u8],
}

impl<'a> Iterator for IKEv2PayloadIter<'a> {
    type Item = Result<IKEv2Payload<'a>, FormatError>;

    fn next(&mut self) -> Option<Self::Item> {
        const CRITICAL_BIT: u8 = 1 << 7;
        if self.next_payload == 0 {
            if self.data.len() != 0 {
                debug!("Packet has unaccounted data");
            }
            return None;
        }
        if self.data.len() < 4 {
            debug!("Not enough data in payload");
            return None;
        }
        let next_payload = self.data[0];
        let payload_flags = self.data[1];
        let mut payload_length = [0u8; 2];
        payload_length.copy_from_slice(&self.data[2..4]);
        let payload_length = u16::from_be_bytes(payload_length) as usize;
        let critical = match payload_flags {
            0x00 => false,
            CRITICAL_BIT => true,
            _ => {
                debug!(
                    "Unsupported payload {} reserved flags: {}",
                    self.next_payload, payload_flags
                );
                self.next_payload = next_payload;
                self.data = &self.data[payload_length..];
                return Some(Err("Unsupported payload reserved flags".into()));
            }
        };

        if self.data.len() < payload_length {
            debug!("Payload overflow");
            return None;
        }
        let payload_type = match IKEv2PayloadType::from_u8(self.next_payload) {
            Ok(payload_type) => payload_type,
            Err(err) => return Some(Err(err)),
        };
        let item = IKEv2Payload {
            payload_type,
            critical,
            data: &self.data[4..payload_length],
        };
        self.next_payload = next_payload;
        self.data = &self.data[payload_length..];
        Some(Ok(item))
    }
}

#[derive(PartialEq, Eq)]
struct IKEv2PayloadType(u8);

impl IKEv2PayloadType {
    const NONE: IKEv2PayloadType = IKEv2PayloadType(0);
    const SECURITY_ASSOCIATION: IKEv2PayloadType = IKEv2PayloadType(33);
    const KEY_EXCHANGE: IKEv2PayloadType = IKEv2PayloadType(34);
    const ID_INITIATOR: IKEv2PayloadType = IKEv2PayloadType(35);
    const ID_RESPONDER: IKEv2PayloadType = IKEv2PayloadType(36);
    const CERTIFICATE: IKEv2PayloadType = IKEv2PayloadType(37);
    const CERTIFICATE_REQUEST: IKEv2PayloadType = IKEv2PayloadType(38);
    const AUTHENTICATION: IKEv2PayloadType = IKEv2PayloadType(39);
    const NONCE: IKEv2PayloadType = IKEv2PayloadType(40);
    const NOTIFY: IKEv2PayloadType = IKEv2PayloadType(41);
    const DELETE: IKEv2PayloadType = IKEv2PayloadType(42);
    const VENDOR_ID: IKEv2PayloadType = IKEv2PayloadType(43);
    const TRAFFIC_SELECTOR_INITIATOR: IKEv2PayloadType = IKEv2PayloadType(44);
    const TRAFFIC_SELECTOR_RESPONSER: IKEv2PayloadType = IKEv2PayloadType(45);
    const ENCRYPTED_AND_AUTHENTICATED: IKEv2PayloadType = IKEv2PayloadType(46);
    const CONFIGURATION: IKEv2PayloadType = IKEv2PayloadType(47);
    const EXTENSIBLE_AUTHENTICATION: IKEv2PayloadType = IKEv2PayloadType(48);

    fn from_u8(value: u8) -> Result<IKEv2PayloadType, FormatError> {
        if (value >= Self::SECURITY_ASSOCIATION.0 && value <= Self::EXTENSIBLE_AUTHENTICATION.0)
            || value == Self::NONE.0
        {
            Ok(IKEv2PayloadType(value))
        } else {
            debug!("Unsupported IKEv2 Payload Type {}", value);
            Err("Unsupported IKEv2 Payload Type".into())
        }
    }
}

impl fmt::Display for IKEv2PayloadType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::NONE => write!(f, "No Next Payload")?,
            Self::SECURITY_ASSOCIATION => write!(f, "Security Association")?,
            Self::KEY_EXCHANGE => write!(f, "Key Exchange")?,
            Self::ID_INITIATOR => write!(f, "Identification - Initiator")?,
            Self::ID_RESPONDER => write!(f, "Identification - Responder")?,
            Self::CERTIFICATE => write!(f, "Certificate")?,
            Self::CERTIFICATE_REQUEST => write!(f, "Certificate Request")?,
            Self::AUTHENTICATION => write!(f, "Authentication")?,
            Self::NONCE => write!(f, "Nonce")?,
            Self::NOTIFY => write!(f, "Notify")?,
            Self::DELETE => write!(f, "Delete")?,
            Self::VENDOR_ID => write!(f, "Vendor ID")?,
            Self::TRAFFIC_SELECTOR_INITIATOR => write!(f, "Traffic Selector - Initiator")?,
            Self::TRAFFIC_SELECTOR_RESPONSER => write!(f, "Traffic Selector - Responder")?,
            Self::ENCRYPTED_AND_AUTHENTICATED => write!(f, "Encrypted and Authenticated")?,
            Self::CONFIGURATION => write!(f, "Configuration")?,
            Self::EXTENSIBLE_AUTHENTICATION => write!(f, "Extensible Authentication")?,
            _ => write!(f, "Unknown exchange type {}", self.0)?,
        }
        Ok(())
    }
}

struct IKEv2PayloadSecurityAssociation<'a> {
    data: &'a [u8],
}

impl<'a> IKEv2PayloadSecurityAssociation<'a> {
    fn iter_proposals(&self) -> IKEv2SecurityAssociationIter {
        IKEv2SecurityAssociationIter { data: self.data }
    }
}

#[derive(PartialEq, Eq)]
struct IPSecProtocolID(u8);

impl IPSecProtocolID {
    const IKE: IPSecProtocolID = IPSecProtocolID(1);
    const AH: IPSecProtocolID = IPSecProtocolID(2);
    const ESP: IPSecProtocolID = IPSecProtocolID(3);

    fn from_u8(value: u8) -> Result<IPSecProtocolID, FormatError> {
        if value >= Self::IKE.0 && value <= Self::ESP.0 {
            Ok(IPSecProtocolID(value))
        } else {
            debug!("Unsupported IKEv2 IPSec Protocol ID {}", value);
            Err("Unsupported IKEv2 IPSec Protocol ID".into())
        }
    }
}

impl fmt::Display for IPSecProtocolID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::IKE => write!(f, "IKE")?,
            Self::AH => write!(f, "AH")?,
            Self::ESP => write!(f, "ESP")?,
            _ => write!(f, "Unknown IPSec Protocol ID {}", self.0)?,
        }
        Ok(())
    }
}

struct IKEv2SecurityAssociationIter<'a> {
    data: &'a [u8],
}

impl<'a> Iterator for IKEv2SecurityAssociationIter<'a> {
    type Item = Result<IKEv2SecurityAssociationProposal<'a>, FormatError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }
        if self.data.len() < 8 {
            debug!("Not enough data in security association");
            return None;
        }
        let last_substruct = self.data[0];
        let mut proposal_length = [0u8; 2];
        proposal_length.copy_from_slice(&self.data[2..4]);
        let proposal_length = u16::from_be_bytes(proposal_length) as usize;
        if last_substruct == 0 && self.data.len() != proposal_length {
            debug!("Unaccounted proposal bytes");
            return None;
        }
        if last_substruct == 2 && proposal_length >= self.data.len() {
            debug!("Unexpected proposal last substruc {}", last_substruct);
            return None;
        }
        if self.data.len() < proposal_length {
            debug!("Proposal overflow");
            return None;
        }
        let proposal_num = self.data[4];
        let protocol_id = match IPSecProtocolID::from_u8(self.data[5]) {
            Ok(protocol_id) => protocol_id,
            Err(err) => {
                debug!("Unsupported protocol ID: {}", err);
                self.data = &self.data[proposal_length..];
                return Some(Err("Unsupported protocol ID".into()));
            }
        };
        let spi_size = self.data[6] as usize;
        let num_transforms = self.data[7] as usize;
        let spi = &self.data[8..8 + spi_size];
        let item = IKEv2SecurityAssociationProposal {
            proposal_num,
            protocol_id,
            num_transforms,
            spi,
            data: &self.data[8 + spi_size..proposal_length],
        };
        self.data = &self.data[proposal_length..];
        Some(Ok(item))
    }
}

struct IKEv2SecurityAssociationProposal<'a> {
    proposal_num: u8,
    protocol_id: IPSecProtocolID,
    num_transforms: usize,
    spi: &'a [u8],
    data: &'a [u8],
}

impl<'a> IKEv2SecurityAssociationProposal<'a> {
    fn iter_transforms(&self) -> IKEv2SecurityAssociationTransformIter {
        IKEv2SecurityAssociationTransformIter {
            num_transforms: self.num_transforms,
            data: self.data,
        }
    }
}

#[derive(PartialEq, Eq)]
struct IKEv2TransformType(u8, u16);

// See http://www.iana.org/assignments/ikev2-parameters/ for additional values.
impl IKEv2TransformType {
    const ENCR_DES_IV64: IKEv2TransformType = IKEv2TransformType(1, 1);
    const ENCR_DES: IKEv2TransformType = IKEv2TransformType(1, 2);
    const ENCR_3DES: IKEv2TransformType = IKEv2TransformType(1, 3);
    const ENCR_RC5: IKEv2TransformType = IKEv2TransformType(1, 4);
    const ENCR_IDEA: IKEv2TransformType = IKEv2TransformType(1, 5);
    const ENCR_CAST: IKEv2TransformType = IKEv2TransformType(1, 6);
    const ENCR_BLOWFISH: IKEv2TransformType = IKEv2TransformType(1, 7);
    const ENCR_3IDEA: IKEv2TransformType = IKEv2TransformType(1, 8);
    const ENCR_DES_IV32: IKEv2TransformType = IKEv2TransformType(1, 9);
    const ENCR_NULL: IKEv2TransformType = IKEv2TransformType(1, 11);
    const ENCR_AES_CBC: IKEv2TransformType = IKEv2TransformType(1, 12);
    const ENCR_AES_CTR: IKEv2TransformType = IKEv2TransformType(1, 13);

    const PRF_HMAC_MD5: IKEv2TransformType = IKEv2TransformType(2, 1);
    const PRF_HMAC_SHA1: IKEv2TransformType = IKEv2TransformType(2, 2);
    const PRF_HMAC_TIGER: IKEv2TransformType = IKEv2TransformType(2, 3);

    const AUTH_NONE: IKEv2TransformType = IKEv2TransformType(3, 0);
    const AUTH_HMAC_MD5_96: IKEv2TransformType = IKEv2TransformType(3, 1);
    const AUTH_HMAC_SHA1_96: IKEv2TransformType = IKEv2TransformType(3, 2);
    const AUTH_DES_MAC: IKEv2TransformType = IKEv2TransformType(3, 3);
    const AUTH_KPDK_MD5: IKEv2TransformType = IKEv2TransformType(3, 4);
    const AUTH_AES_XCBC_96: IKEv2TransformType = IKEv2TransformType(3, 5);

    const DH_NONE: IKEv2TransformType = IKEv2TransformType(4, 0);
    const DH_768: IKEv2TransformType = IKEv2TransformType(4, 1);
    const DH_1024: IKEv2TransformType = IKEv2TransformType(4, 2);
    const DH_1536: IKEv2TransformType = IKEv2TransformType(4, 5);
    const DH_2048: IKEv2TransformType = IKEv2TransformType(4, 14);
    const DH_3072: IKEv2TransformType = IKEv2TransformType(4, 15);
    const DH_4096: IKEv2TransformType = IKEv2TransformType(4, 16);
    const DH_6144: IKEv2TransformType = IKEv2TransformType(4, 17);
    const DH_8192: IKEv2TransformType = IKEv2TransformType(4, 18);

    const NO_ESN: IKEv2TransformType = IKEv2TransformType(5, 0);
    const ESN: IKEv2TransformType = IKEv2TransformType(5, 1);

    fn from_raw(transform_type: u8, transform_id: u16) -> Result<IKEv2TransformType, FormatError> {
        if transform_type >= 1 && transform_type <= 5 {
            Ok(IKEv2TransformType(transform_type, transform_id))
        } else {
            debug!(
                "Unsupported IKEv2 Transform Type {} ID {}",
                transform_type, transform_id
            );
            Err("Unsupported IKEv2 Transform Type".into())
        }
    }
}

impl fmt::Display for IKEv2TransformType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::ENCR_DES_IV64 => write!(f, "ENCR_DES_IV64")?,
            Self::ENCR_DES => write!(f, "ENCR_DES")?,
            Self::ENCR_3DES => write!(f, "ENCR_3DES")?,
            Self::ENCR_RC5 => write!(f, "ENCR_RC5")?,
            Self::ENCR_IDEA => write!(f, "ENCR_IDEA")?,
            Self::ENCR_CAST => write!(f, "ENCR_CAST")?,
            Self::ENCR_BLOWFISH => write!(f, "ENCR_BLOWFISH")?,
            Self::ENCR_3IDEA => write!(f, "ENCR_3IDEA")?,
            Self::ENCR_DES_IV32 => write!(f, "ENCR_DES_IV32")?,
            Self::ENCR_NULL => write!(f, "ENCR_NULL")?,
            Self::ENCR_AES_CBC => write!(f, "ENCR_AES_CBC")?,
            Self::ENCR_AES_CTR => write!(f, "ENCR_AES_CTR")?,
            Self::PRF_HMAC_MD5 => write!(f, "PRF_HMAC_MD5")?,
            Self::PRF_HMAC_SHA1 => write!(f, "PRF_HMAC_SHA1")?,
            Self::PRF_HMAC_TIGER => write!(f, "PRF_HMAC_TIGER")?,
            Self::AUTH_NONE => write!(f, "AUTH_NONE")?,
            Self::AUTH_HMAC_MD5_96 => write!(f, "AUTH_HMAC_MD5_96")?,
            Self::AUTH_HMAC_SHA1_96 => write!(f, "AUTH_HMAC_SHA1_96")?,
            Self::AUTH_DES_MAC => write!(f, "AUTH_DES_MAC")?,
            Self::AUTH_KPDK_MD5 => write!(f, "AUTH_KPDK_MD5")?,
            Self::AUTH_AES_XCBC_96 => write!(f, "AUTH_AES_XCBC_96")?,
            Self::DH_NONE => write!(f, "DH_NONE")?,
            Self::DH_768 => write!(f, "DH_768")?,
            Self::DH_1024 => write!(f, "DH_1024")?,
            Self::DH_1536 => write!(f, "DH_1536")?,
            Self::DH_2048 => write!(f, "DH_2048")?,
            Self::DH_3072 => write!(f, "DH_3072")?,
            Self::DH_4096 => write!(f, "DH_4096")?,
            Self::DH_6144 => write!(f, "DH_6144")?,
            Self::DH_8192 => write!(f, "DH_8192")?,
            Self::NO_ESN => write!(f, "NO_ESN")?,
            Self::ESN => write!(f, "ESN")?,
            _ => write!(f, "Unknown transform type {} id {}", self.0, self.1)?,
        }
        Ok(())
    }
}

struct IKEv2SecurityAssociationTransformIter<'a> {
    num_transforms: usize,
    data: &'a [u8],
}

impl<'a> Iterator for IKEv2SecurityAssociationTransformIter<'a> {
    type Item = Result<IKEv2SecurityAssociationTransform<'a>, FormatError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            if self.num_transforms != 0 {
                debug!("Packet is missing {} transforms", self.num_transforms);
            }
            return None;
        }
        if self.data.len() < 8 {
            debug!("Not enough data in security association transform");
            return None;
        }
        let last_substruct = self.data[0];
        let mut transform_length = [0u8; 2];
        transform_length.copy_from_slice(&self.data[2..4]);
        let transform_length = u16::from_be_bytes(transform_length) as usize;
        if last_substruct == 0 && self.data.len() != transform_length {
            debug!("Unaccounted transform bytes");
            return None;
        }
        if last_substruct == 3 && transform_length >= self.data.len() {
            debug!("Unexpected transform last substruc {}", last_substruct);
            return None;
        }
        if self.data.len() < transform_length {
            debug!("Transform overflow");
            return None;
        }
        let transform_type = self.data[4];
        let mut transform_id = [0u8; 2];
        transform_id.copy_from_slice(&self.data[6..8]);
        let transform_id = u16::from_be_bytes(transform_id);
        let transform_type = match IKEv2TransformType::from_raw(transform_type, transform_id) {
            Ok(transform_type) => transform_type,
            Err(err) => {
                debug!("Unsupported transform type: {}", err);
                self.data = &self.data[transform_length..];
                return Some(Err("Unsupported transform type".into()));
            }
        };
        let item = IKEv2SecurityAssociationTransform {
            transform_type,
            data: &self.data[8..transform_length],
        };
        self.data = &self.data[transform_length..];
        if self.num_transforms <= 0 {
            debug!("Packet has unaccounted transforms");
        } else {
            self.num_transforms -= 1;
        }
        Some(Ok(item))
    }
}

struct IKEv2SecurityAssociationTransform<'a> {
    transform_type: IKEv2TransformType,
    data: &'a [u8],
}

impl<'a> IKEv2SecurityAssociationTransform<'a> {
    fn iter_attributes(&self) -> IKEv2SecurityAssociationTransformAttributesIter {
        IKEv2SecurityAssociationTransformAttributesIter { data: self.data }
    }
}

struct IKEv2SecurityAssociationTransformAttributesIter<'a> {
    data: &'a [u8],
}

impl<'a> Iterator for IKEv2SecurityAssociationTransformAttributesIter<'a> {
    type Item = IKEv2SecurityAssociationTransformAttribute<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        const ATTRIBUTE_FORMAT_TV: u16 = 1 << 15;
        const ATTRIBUTE_TYPE_MASK: u16 = !ATTRIBUTE_FORMAT_TV;
        if self.data.is_empty() {
            return None;
        }
        if self.data.len() < 4 {
            debug!("Not enough data in security association transform attribute");
            return None;
        }
        let mut attribute_type = [0u8; 2];
        attribute_type.copy_from_slice(&self.data[0..2]);
        let attribute_type = u16::from_be_bytes(attribute_type);
        if attribute_type & ATTRIBUTE_FORMAT_TV != 0 {
            let attribute_type = attribute_type & ATTRIBUTE_TYPE_MASK;
            let item = IKEv2SecurityAssociationTransformAttribute {
                attribute_type,
                data: &self.data[2..4],
            };
            self.data = &self.data[4..];
            Some(item)
        } else {
            let mut attribute_length = [0u8; 2];
            attribute_length.copy_from_slice(&self.data[2..4]);
            let attribute_length = u16::from_be_bytes(attribute_length) as usize;
            if self.data.len() < attribute_length {
                debug!("Transform attribute overflow");
                return None;
            }
            let item = IKEv2SecurityAssociationTransformAttribute {
                attribute_type,
                data: &self.data[4..attribute_length],
            };
            self.data = &self.data[attribute_length..];
            Some(item)
        }
    }
}

struct IKEv2SecurityAssociationTransformAttribute<'a> {
    attribute_type: u16,
    data: &'a [u8],
}

struct SessionID {
    remote_spi: u64,
    local_spi: u64,
}

impl PartialEq for SessionID {
    fn eq(&self, other: &Self) -> bool {
        self.remote_spi == other.remote_spi && self.local_spi == other.local_spi
    }
}

impl Eq for SessionID {}

impl Hash for SessionID {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.remote_spi.hash(state);
        self.local_spi.hash(state);
    }
}

impl SessionID {
    fn from_message(message: &IKEv2Message) -> Result<SessionID, FormatError> {
        let local_spi = if message.read_exchange_type()? == IKEExchangeType::IKE_SA_INIT {
            rand::thread_rng().gen::<u64>()
        } else {
            message.read_responder_spi()
        };
        let remote_spi = message.read_initiator_spi();
        Ok(SessionID {
            remote_spi,
            local_spi,
        })
    }
}

struct Sessions {
    sessions: HashMap<SessionID, IKEv2Session>,
}

impl Sessions {
    fn new() -> Sessions {
        Sessions {
            sessions: HashMap::new(),
        }
    }

    fn get(
        &mut self,
        message: &IKEv2Message,
        remote_addr: SocketAddr,
    ) -> Result<&mut IKEv2Session, FormatError> {
        let id = SessionID::from_message(message)?;
        Ok(self
            .sessions
            .entry(id)
            .or_insert_with(|| IKEv2Session::new(remote_addr)))
    }

    async fn process_message(
        &mut self,
        datagram_bytes: &[u8],
        remote_addr: SocketAddr,
    ) -> Result<(), IKEv2Error> {
        let ikev2_message = IKEv2Message::from_datagram(datagram_bytes);
        if !ikev2_message.is_valid() {
            warn!("Invalid IKEv2 message from {}", remote_addr);
            return Err("Invalid message received".into());
        }
        let session = self.get(&ikev2_message, remote_addr)?;
        session.process_message(&ikev2_message);
        Ok(())
    }
}

struct IKEv2Session {
    remote_addr: SocketAddr,
}

impl IKEv2Session {
    fn new(remote_addr: SocketAddr) -> IKEv2Session {
        IKEv2Session { remote_addr }
    }

    fn process_message(&mut self, message: &IKEv2Message) {
        debug!("Received packet from {} {:?}", self.remote_addr, message);
        // TODO: process message if exchange type is supported
        // TODO: return error if payload type is critical but not recognized
    }
}

impl fmt::Debug for IKEv2Message<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "IKEv2 message")?;
        writeln!(f, "  Initiator SPI {:x}", self.read_initiator_spi())?;
        writeln!(f, "  Responder SPI {:x}", self.read_responder_spi())?;
        writeln!(f, "  Next payload {}", self.read_next_payload())?;
        {
            let version = self.read_version();
            writeln!(f, "  Version {}.{}", version.0, version.1)?;
        }
        match self.read_exchange_type() {
            Ok(t) => writeln!(f, "  Exchange type {}", t),
            Err(err) => writeln!(f, "  Exchange type {}", err),
        }?;
        match self.read_flags() {
            Ok(t) => writeln!(f, "  Flags {}", t),
            Err(err) => writeln!(f, "  Flags {}", err),
        }?;
        writeln!(f, "  Message ID {}", self.read_message_id())?;
        writeln!(f, "  Length {}", self.read_length())?;
        for pl in self.iter_payloads() {
            let pl = match pl {
                Ok(pl) => pl,
                Err(err) => {
                    writeln!(f, "  Payload data invalid {}", err)?;
                    continue;
                }
            };
            let critical = if pl.critical {
                "critical"
            } else {
                "not critical"
            };
            writeln!(f, "  Payload type {}, {}", pl.payload_type, critical)?;
            if let Some(pl_sa) = pl.to_security_association() {
                for prop in pl_sa.iter_proposals() {
                    let prop = match prop {
                        Ok(prop) => prop,
                        Err(err) => {
                            writeln!(f, "    Proposal invalid {}", err)?;
                            continue;
                        }
                    };
                    writeln!(
                        f,
                        "    Proposal {} protocol ID {} SPI {:?}",
                        prop.proposal_num, prop.protocol_id, prop.spi
                    )?;
                    for tf in prop.iter_transforms() {
                        let tf = match tf {
                            Ok(tf) => tf,
                            Err(err) => {
                                writeln!(f, "      Transform invalid {}", err)?;
                                continue;
                            }
                        };
                        writeln!(f, "      Transform type {}", tf.transform_type)?;
                        for attr in tf.iter_attributes() {
                            writeln!(
                                f,
                                "        Attribute {} value {:?}",
                                attr.attribute_type, attr.data
                            )?;
                        }
                    }
                }
            } else {
                writeln!(f, "    Data {:?}", pl.data)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct FormatError {
    msg: &'static str,
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl error::Error for FormatError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(self)
    }
}

impl From<&'static str> for FormatError {
    fn from(msg: &'static str) -> FormatError {
        FormatError { msg }
    }
}

#[derive(Debug)]
pub enum IKEv2Error {
    Internal(&'static str),
    Format(FormatError),
    Join(tokio::task::JoinError),
    Io(io::Error),
}

impl fmt::Display for IKEv2Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            IKEv2Error::Internal(msg) => f.write_str(msg),
            IKEv2Error::Format(ref e) => write!(f, "Format error: {}", e),
            IKEv2Error::Join(ref e) => write!(f, "Tokio join error: {}", e),
            IKEv2Error::Io(ref e) => {
                write!(f, "IO error: {}", e)
            }
        }
    }
}

impl error::Error for IKEv2Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            IKEv2Error::Internal(_msg) => None,
            IKEv2Error::Format(ref err) => Some(err),
            IKEv2Error::Join(ref err) => Some(err),
            IKEv2Error::Io(ref err) => Some(err),
        }
    }
}

impl From<&'static str> for IKEv2Error {
    fn from(msg: &'static str) -> IKEv2Error {
        IKEv2Error::Internal(msg)
    }
}

impl From<FormatError> for IKEv2Error {
    fn from(err: FormatError) -> IKEv2Error {
        IKEv2Error::Format(err)
    }
}

impl From<tokio::task::JoinError> for IKEv2Error {
    fn from(err: tokio::task::JoinError) -> IKEv2Error {
        IKEv2Error::Join(err)
    }
}

impl From<io::Error> for IKEv2Error {
    fn from(err: io::Error) -> IKEv2Error {
        IKEv2Error::Io(err)
    }
}
