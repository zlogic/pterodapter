use std::{error, fmt};

use log::debug;

use super::crypto;

#[derive(PartialEq, Eq)]
pub struct ExchangeType(u8);

impl ExchangeType {
    pub const IKE_SA_INIT: ExchangeType = ExchangeType(34);
    pub const IKE_AUTH: ExchangeType = ExchangeType(35);
    pub const CREATE_CHILD_SA: ExchangeType = ExchangeType(36);
    pub const INFORMATIONAL: ExchangeType = ExchangeType(37);

    fn from_u8(value: u8) -> Result<ExchangeType, FormatError> {
        if (Self::IKE_SA_INIT.0..=Self::INFORMATIONAL.0).contains(&value) {
            Ok(ExchangeType(value))
        } else {
            debug!("Unsupported IKEv2 Exchange Type {}", value);
            Err("Unsupported IKEv2 Exchange Type".into())
        }
    }
}

impl fmt::Display for ExchangeType {
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
struct Flags(u8);

impl Flags {
    const INITIATOR: Flags = Flags(1 << 3);
    const VERSION: Flags = Flags(1 << 4);
    const RESPONSE: Flags = Flags(1 << 5);

    fn from_u8(value: u8) -> Result<Flags, FormatError> {
        const RESERVED_MASK: u8 = !Flags::INITIATOR.0 & !Flags::VERSION.0 & !Flags::RESPONSE.0;
        if value & RESERVED_MASK != 0x00 {
            debug!("IKEv2 reserved flags are set {}", value & RESERVED_MASK);
            return Err("IKEv2 reserved flags are set".into());
        }
        Ok(Flags(value))
    }

    fn has(&self, flag: Flags) -> bool {
        self.0 & flag.0 != 0
    }
}

impl fmt::Display for Flags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.has(Flags::INITIATOR) {
            f.write_str("Initiator")?;
        }
        if self.has(Flags::VERSION) {
            f.write_str("Version")?;
        }
        if self.has(Flags::RESPONSE) {
            f.write_str("Response")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SPI {
    None,
    U32(u32),
    U64(u64),
}

impl SPI {
    fn from_slice(spi: &[u8]) -> Result<SPI, FormatError> {
        if spi.len() == 4 {
            let mut value = [0u8; 4];
            value.copy_from_slice(spi);
            let value = u32::from_be_bytes(value);
            Ok(Self::U32(value))
        } else if spi.len() == 4 {
            let mut value = [0u8; 8];
            value.copy_from_slice(spi);
            let value = u64::from_be_bytes(value);
            Ok(Self::U64(value))
        } else if spi.is_empty() {
            Ok(Self::None)
        } else {
            debug!("Unexpected SPI size {}", spi.len());
            Err("Unexpected SPI size".into())
        }
    }

    fn write_to(&self, dest: &mut [u8]) {
        match *self {
            Self::None => {}
            Self::U32(val) => dest.copy_from_slice(&val.to_be_bytes()),
            Self::U64(val) => dest.copy_from_slice(&val.to_be_bytes()),
        }
    }

    pub fn length(&self) -> usize {
        match *self {
            Self::None => 0,
            Self::U32(_) => 4,
            Self::U64(_) => 8,
        }
    }
}

impl fmt::Display for SPI {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::None => Ok(()),
            Self::U32(val) => write!(f, "{:x}", val),
            Self::U64(val) => write!(f, "{:x}", val),
        }
    }
}

impl fmt::Debug for SPI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

pub struct InputMessage<'a> {
    data: &'a [u8],
}

// Parse and validate using spec from RFC 7296, Section 3.
impl InputMessage<'_> {
    pub fn from_datagram(p: &[u8]) -> Result<InputMessage, FormatError> {
        if p.len() < 28 {
            debug!("Not enough data in message");
            Err("Not enough data in message".into())
        } else {
            Ok(InputMessage { data: p })
        }
    }

    pub fn read_initiator_spi(&self) -> u64 {
        let mut result = [0u8; 8];
        result.copy_from_slice(&self.data[0..8]);
        u64::from_be_bytes(result)
    }

    pub fn read_responder_spi(&self) -> u64 {
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

    pub fn read_exchange_type(&self) -> Result<ExchangeType, FormatError> {
        ExchangeType::from_u8(self.data[18])
    }

    fn read_flags(&self) -> Result<Flags, FormatError> {
        Flags::from_u8(self.data[19])
    }

    pub fn read_message_id(&self) -> u32 {
        let mut result = [0u8; 4];
        result.copy_from_slice(&self.data[20..24]);
        u32::from_be_bytes(result)
    }

    fn read_length(&self) -> u32 {
        let mut result = [0u8; 4];
        result.copy_from_slice(&self.data[24..28]);
        u32::from_be_bytes(result)
    }

    pub fn is_valid(&self) -> bool {
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

    pub fn iter_payloads(&self) -> PayloadIter {
        PayloadIter {
            next_payload: self.read_next_payload(),
            data: &self.data[28..],
        }
    }
}

pub struct MessageWriter<'a> {
    dest: &'a mut [u8],
    next_payload_index: usize,
    cursor: usize,
}

impl MessageWriter<'_> {
    pub fn new(dest: &mut [u8]) -> Result<MessageWriter, NotEnoughSpaceError> {
        if dest.len() < 28 {
            return Err(NotEnoughSpaceError {});
        }
        let next_payload_index = 16;
        let cursor = 0;
        Ok(MessageWriter {
            dest,
            next_payload_index,
            cursor,
        })
    }

    pub fn write_header(
        &mut self,
        initiator_spi: u64,
        responder_spi: u64,
        exchange_type: ExchangeType,
        is_request: bool,
        message_id: u32,
    ) -> Result<(), NotEnoughSpaceError> {
        if self.dest.len() < 28 {
            return Err(NotEnoughSpaceError {});
        }
        self.dest[0..8].copy_from_slice(&initiator_spi.to_be_bytes());
        self.dest[8..16].copy_from_slice(&responder_spi.to_be_bytes());
        // Version 2.0.
        self.dest[17] = 2 << 4;
        self.dest[18] = exchange_type.0;
        self.dest[19] = if is_request {
            Flags::INITIATOR.0
        } else {
            Flags::RESPONSE.0
        };
        self.dest[20..24].copy_from_slice(&message_id.to_be_bytes());
        self.dest[24..28].copy_from_slice(&0u32.to_be_bytes());

        self.next_payload_index = 16;
        self.cursor = 28;
        Ok(())
    }

    pub fn write_notify_payload(
        &mut self,
        protocol_id: Option<IPSecProtocolID>,
        spi: &[u8],
        notify_message_type: NotifyMessageType,
        data: &[u8],
    ) -> Result<(), NotEnoughSpaceError> {
        let next_payload_slice =
            self.next_payload_slice(PayloadType::NOTIFY, 4 + spi.len() + data.len())?;
        next_payload_slice[0] = if let Some(protocol_id) = protocol_id {
            protocol_id.0
        } else {
            0
        };
        next_payload_slice[1] = spi.len() as u8;
        next_payload_slice[2..4].copy_from_slice(&notify_message_type.0.to_be_bytes());
        next_payload_slice[4..4 + spi.len()].copy_from_slice(spi);
        next_payload_slice[4 + spi.len()..].copy_from_slice(data);
        Ok(())
    }

    pub fn write_accept_proposal(
        &mut self,
        proposal_num: u8,
        proposal: &crypto::TransformParameters,
    ) -> Result<(), NotEnoughSpaceError> {
        const ATTRIBUTE_FORMAT_TV: u16 = 1 << 15;
        const ATTRIBUTE_TYPE_KEY_LENGTH: [u8; 2] =
            (TransformAttributeType::KEY_LENGTH.0 | ATTRIBUTE_FORMAT_TV).to_be_bytes();
        let (num_transforms, data_len) = proposal
            .iter_parameters()
            .map(|param| {
                if param.key_length().is_some() {
                    (1, 8 + 4)
                } else {
                    (1, 8)
                }
            })
            .fold((0, 0), |acc, e| (acc.0 + e.0, acc.1 + e.1));
        let spi = proposal.spi();
        let proposal_len = 8 + spi.length() + data_len;
        let next_payload_slice =
            self.next_payload_slice(PayloadType::SECURITY_ASSOCIATION, proposal_len)?;
        next_payload_slice[0] = 0;
        next_payload_slice[1] = 0;
        next_payload_slice[2..4].copy_from_slice(&(proposal_len as u16).to_be_bytes());
        next_payload_slice[4] = proposal_num;
        next_payload_slice[5] = proposal.protocol_id().0;
        next_payload_slice[6] = spi.length() as u8;
        next_payload_slice[7] = num_transforms as u8;
        spi.write_to(&mut next_payload_slice[8..8 + spi.length()]);
        let mut next_payload_offset = 8 + spi.length();
        proposal
            .iter_parameters()
            .enumerate()
            .for_each(|(i, param)| {
                let transform_len = if param.key_length().is_some() {
                    8 + 4
                } else {
                    8
                };
                let next_payload_slice = &mut next_payload_slice
                    [next_payload_offset..next_payload_offset + transform_len];
                next_payload_offset += transform_len;
                next_payload_slice[0] = if i + 1 < num_transforms { 3 } else { 0 };
                next_payload_slice[1] = 0;
                next_payload_slice[2..4].copy_from_slice(&(transform_len as u16).to_be_bytes());
                let (transform_type, transform_id) = param.transform_type().type_id();
                next_payload_slice[4] = transform_type;
                next_payload_slice[5] = 0;
                next_payload_slice[6..8].copy_from_slice(&transform_id.to_be_bytes());
                if let Some(key_length) = param.key_length() {
                    next_payload_slice[8..10].copy_from_slice(&ATTRIBUTE_TYPE_KEY_LENGTH);
                    next_payload_slice[10..12].copy_from_slice(&key_length.to_be_bytes());
                }
            });
        Ok(())
    }

    pub fn next_payload_slice(
        &mut self,
        payload_type: PayloadType,
        data_length: usize,
    ) -> Result<&mut [u8], NotEnoughSpaceError> {
        let next_data = self.cursor + 4..self.cursor + 4 + data_length;
        if next_data.end > self.dest.len() {
            return Err(NotEnoughSpaceError {});
        }
        {
            let next_header = &mut self.dest[self.cursor..self.cursor + 4];
            next_header[0] = PayloadType::NONE.0;
            // Not critical.
            next_header[1] = 0;
            let full_payload_length = data_length as u16 + 4;
            next_header[2..4].copy_from_slice(&full_payload_length.to_be_bytes());
        }
        self.dest[self.next_payload_index] = payload_type.0;
        self.next_payload_index = self.cursor;
        self.cursor = next_data.end;
        Ok(&mut self.dest[next_data])
    }

    pub fn complete_message(&mut self) -> usize {
        let message_length = self.cursor as u32;
        self.dest[24..28].copy_from_slice(&message_length.to_be_bytes());
        self.cursor
    }
}

pub struct Payload<'a> {
    payload_type: PayloadType,
    critical: bool,
    data: &'a [u8],
}

impl Payload<'_> {
    pub fn payload_type(&self) -> PayloadType {
        self.payload_type
    }

    pub fn to_security_association(&self) -> Result<PayloadSecurityAssociation, FormatError> {
        if self.payload_type == PayloadType::SECURITY_ASSOCIATION {
            Ok(PayloadSecurityAssociation { data: self.data })
        } else {
            Err("Payload type is not SECURITY_ASSOCIATION".into())
        }
    }

    fn to_key_exchange(&self) -> Result<PayloadKeyExchange, FormatError> {
        if self.payload_type == PayloadType::KEY_EXCHANGE {
            PayloadKeyExchange::from_payload(self.data)
        } else {
            Err("Payload type is not KEY_EXCHANGE".into())
        }
    }

    fn to_nonce(&self) -> Result<PayloadNonce, FormatError> {
        if self.payload_type == PayloadType::NONCE {
            Ok(PayloadNonce { data: self.data })
        } else {
            Err("Payload type is not NONCE".into())
        }
    }

    fn to_notify(&self) -> Result<PayloadNotify, FormatError> {
        if self.payload_type == PayloadType::NOTIFY {
            PayloadNotify::from_payload(self.data)
        } else {
            Err("Payload type is not NOTIFY".into())
        }
    }
}

pub struct PayloadIter<'a> {
    next_payload: u8,
    data: &'a [u8],
}

impl<'a> Iterator for PayloadIter<'a> {
    type Item = Result<Payload<'a>, FormatError>;

    fn next(&mut self) -> Option<Self::Item> {
        const CRITICAL_BIT: u8 = 1 << 7;
        if self.next_payload == 0 {
            if !self.data.is_empty() {
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
        let payload_type = match PayloadType::from_u8(self.next_payload) {
            Ok(payload_type) => payload_type,
            Err(err) => return Some(Err(err)),
        };
        let item = Payload {
            payload_type,
            critical,
            data: &self.data[4..payload_length],
        };
        self.next_payload = next_payload;
        self.data = &self.data[payload_length..];
        Some(Ok(item))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PayloadType(u8);

impl PayloadType {
    pub const NONE: PayloadType = PayloadType(0);
    pub const SECURITY_ASSOCIATION: PayloadType = PayloadType(33);
    pub const KEY_EXCHANGE: PayloadType = PayloadType(34);
    pub const ID_INITIATOR: PayloadType = PayloadType(35);
    pub const ID_RESPONDER: PayloadType = PayloadType(36);
    pub const CERTIFICATE: PayloadType = PayloadType(37);
    pub const CERTIFICATE_REQUEST: PayloadType = PayloadType(38);
    pub const AUTHENTICATION: PayloadType = PayloadType(39);
    pub const NONCE: PayloadType = PayloadType(40);
    pub const NOTIFY: PayloadType = PayloadType(41);
    pub const DELETE: PayloadType = PayloadType(42);
    pub const VENDOR_ID: PayloadType = PayloadType(43);
    pub const TRAFFIC_SELECTOR_INITIATOR: PayloadType = PayloadType(44);
    pub const TRAFFIC_SELECTOR_RESPONSER: PayloadType = PayloadType(45);
    pub const ENCRYPTED_AND_AUTHENTICATED: PayloadType = PayloadType(46);
    pub const CONFIGURATION: PayloadType = PayloadType(47);
    pub const EXTENSIBLE_AUTHENTICATION: PayloadType = PayloadType(48);

    fn from_u8(value: u8) -> Result<PayloadType, FormatError> {
        if (Self::SECURITY_ASSOCIATION.0..=Self::EXTENSIBLE_AUTHENTICATION.0).contains(&value)
            || value == Self::NONE.0
        {
            Ok(PayloadType(value))
        } else {
            debug!("Unsupported IKEv2 Payload Type {}", value);
            Err("Unsupported IKEv2 Payload Type".into())
        }
    }
}

impl fmt::Display for PayloadType {
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

pub struct PayloadSecurityAssociation<'a> {
    data: &'a [u8],
}

impl<'a> PayloadSecurityAssociation<'a> {
    pub fn iter_proposals(&self) -> SecurityAssociationIter {
        SecurityAssociationIter {
            data: self.data,
            next_proposal_num: 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IPSecProtocolID(u8);

impl IPSecProtocolID {
    pub const IKE: IPSecProtocolID = IPSecProtocolID(1);
    pub const AH: IPSecProtocolID = IPSecProtocolID(2);
    pub const ESP: IPSecProtocolID = IPSecProtocolID(3);

    fn from_u8(value: u8) -> Result<IPSecProtocolID, FormatError> {
        if (Self::IKE.0..=Self::ESP.0).contains(&value) {
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

pub struct SecurityAssociationIter<'a> {
    next_proposal_num: u8,
    data: &'a [u8],
}

impl<'a> Iterator for SecurityAssociationIter<'a> {
    type Item = Result<SecurityAssociationProposal<'a>, FormatError>;

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
        if proposal_num != self.next_proposal_num {
            debug!(
                "Unexpected proposal num {} (should be {})",
                proposal_num, self.next_proposal_num
            );
            self.data = &self.data[proposal_length..];
            return Some(Err("Unexpected proposal number".into()));
        }
        self.next_proposal_num += 1;
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
        if self.data.len() < 8 + spi_size {
            debug!("Proposal SPI overflow");
            return None;
        }
        let spi = &self.data[8..8 + spi_size];
        let spi = match SPI::from_slice(spi) {
            Ok(spi) => spi,
            Err(_) => {
                self.data = &self.data[proposal_length..];
                return Some(Err("Unsupported SPI format".into()));
            }
        };
        let item = SecurityAssociationProposal {
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

pub struct SecurityAssociationProposal<'a> {
    proposal_num: u8,
    protocol_id: IPSecProtocolID,
    num_transforms: usize,
    spi: SPI,
    data: &'a [u8],
}

impl<'a> SecurityAssociationProposal<'a> {
    pub fn iter_transforms(&self) -> SecurityAssociationTransformIter {
        SecurityAssociationTransformIter {
            num_transforms: self.num_transforms,
            data: self.data,
        }
    }

    pub fn proposal_num(&self) -> u8 {
        self.proposal_num
    }

    pub fn protocol_id(&self) -> IPSecProtocolID {
        self.protocol_id
    }

    pub fn spi(&self) -> SPI {
        self.spi
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TransformType {
    Encryption(u16),
    PseudorandomFunction(u16),
    IntegrityAlgorithm(u16),
    DiffieHellman(u16),
    ExtendedSequenceNumbers(u16),
}

// See http://www.iana.org/assignments/ikev2-parameters/ for additional values.
impl TransformType {
    pub const ENCR_DES_IV64: TransformType = TransformType::Encryption(1);
    pub const ENCR_DES: TransformType = TransformType::Encryption(2);
    pub const ENCR_3DES: TransformType = TransformType::Encryption(3);
    pub const ENCR_RC5: TransformType = TransformType::Encryption(4);
    pub const ENCR_IDEA: TransformType = TransformType::Encryption(5);
    pub const ENCR_CAST: TransformType = TransformType::Encryption(6);
    pub const ENCR_BLOWFISH: TransformType = TransformType::Encryption(7);
    pub const ENCR_3IDEA: TransformType = TransformType::Encryption(8);
    pub const ENCR_DES_IV32: TransformType = TransformType::Encryption(9);
    pub const ENCR_NULL: TransformType = TransformType::Encryption(11);
    pub const ENCR_AES_CBC: TransformType = TransformType::Encryption(12);
    pub const ENCR_AES_CTR: TransformType = TransformType::Encryption(13);

    pub const ENCR_AES_GCM_16: TransformType = TransformType::Encryption(20);

    pub const PRF_HMAC_MD5: TransformType = TransformType::PseudorandomFunction(1);
    pub const PRF_HMAC_SHA1: TransformType = TransformType::PseudorandomFunction(2);
    pub const PRF_HMAC_TIGER: TransformType = TransformType::PseudorandomFunction(3);

    pub const PRF_HMAC_SHA2_256: TransformType = TransformType::PseudorandomFunction(5);
    pub const PRF_HMAC_SHA2_384: TransformType = TransformType::PseudorandomFunction(6);

    pub const AUTH_NONE: TransformType = TransformType::IntegrityAlgorithm(0);
    pub const AUTH_HMAC_MD5_96: TransformType = TransformType::IntegrityAlgorithm(1);
    pub const AUTH_HMAC_SHA1_96: TransformType = TransformType::IntegrityAlgorithm(2);
    pub const AUTH_DES_MAC: TransformType = TransformType::IntegrityAlgorithm(3);
    pub const AUTH_KPDK_MD5: TransformType = TransformType::IntegrityAlgorithm(4);
    pub const AUTH_AES_XCBC_96: TransformType = TransformType::IntegrityAlgorithm(5);

    pub const AUTH_HMAC_SHA2_256_128: TransformType = TransformType::IntegrityAlgorithm(12);
    pub const AUTH_HMAC_SHA2_384_192: TransformType = TransformType::IntegrityAlgorithm(13);

    pub const DH_NONE: TransformType = TransformType::DiffieHellman(0);
    pub const DH_768_MODP: TransformType = TransformType::DiffieHellman(1);
    pub const DH_1024_MODP: TransformType = TransformType::DiffieHellman(2);
    pub const DH_1536_MODP: TransformType = TransformType::DiffieHellman(5);
    pub const DH_2048_MODP: TransformType = TransformType::DiffieHellman(14);
    pub const DH_3072_MODP: TransformType = TransformType::DiffieHellman(15);
    pub const DH_4096_MODP: TransformType = TransformType::DiffieHellman(16);
    pub const DH_6144_MODP: TransformType = TransformType::DiffieHellman(17);
    pub const DH_8192_MODP: TransformType = TransformType::DiffieHellman(18);

    pub const DH_256_ECP: TransformType = TransformType::DiffieHellman(19);

    pub const NO_ESN: TransformType = TransformType::ExtendedSequenceNumbers(0);
    pub const ESN: TransformType = TransformType::ExtendedSequenceNumbers(1);

    fn from_raw(transform_type: u8, transform_id: u16) -> Result<TransformType, FormatError> {
        match transform_type {
            1 => Ok(Self::Encryption(transform_id)),
            2 => Ok(Self::PseudorandomFunction(transform_id)),
            3 => Ok(Self::IntegrityAlgorithm(transform_id)),
            4 => Ok(Self::DiffieHellman(transform_id)),
            5 => Ok(Self::ExtendedSequenceNumbers(transform_id)),
            _ => {
                debug!(
                    "Unsupported IKEv2 Transform Type {} ID {}",
                    transform_type, transform_id
                );
                Err("Unsupported IKEv2 Transform Type".into())
            }
        }
    }

    fn type_id(&self) -> (u8, u16) {
        match *self {
            TransformType::Encryption(id) => (1, id),
            TransformType::PseudorandomFunction(id) => (2, id),
            TransformType::IntegrityAlgorithm(id) => (3, id),
            TransformType::DiffieHellman(id) => (4, id),
            TransformType::ExtendedSequenceNumbers(id) => (5, id),
        }
    }
}

impl fmt::Display for TransformType {
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
            Self::ENCR_AES_GCM_16 => write!(f, "ENCR_AES_GCM_16")?,
            Self::PRF_HMAC_MD5 => write!(f, "PRF_HMAC_MD5")?,
            Self::PRF_HMAC_SHA1 => write!(f, "PRF_HMAC_SHA1")?,
            Self::PRF_HMAC_TIGER => write!(f, "PRF_HMAC_TIGER")?,
            Self::PRF_HMAC_SHA2_256 => write!(f, "PRF_HMAC_SHA2_256")?,
            Self::PRF_HMAC_SHA2_384 => write!(f, "PRF_HMAC_SHA2_384")?,
            Self::AUTH_NONE => write!(f, "AUTH_NONE")?,
            Self::AUTH_HMAC_MD5_96 => write!(f, "AUTH_HMAC_MD5_96")?,
            Self::AUTH_HMAC_SHA1_96 => write!(f, "AUTH_HMAC_SHA1_96")?,
            Self::AUTH_DES_MAC => write!(f, "AUTH_DES_MAC")?,
            Self::AUTH_KPDK_MD5 => write!(f, "AUTH_KPDK_MD5")?,
            Self::AUTH_AES_XCBC_96 => write!(f, "AUTH_AES_XCBC_96")?,
            Self::AUTH_HMAC_SHA2_256_128 => write!(f, "AUTH_HMAC_SHA2_256_128")?,
            Self::AUTH_HMAC_SHA2_384_192 => write!(f, "AUTH_HMAC_SHA2_384_192")?,
            Self::DH_NONE => write!(f, "DH_NONE")?,
            Self::DH_768_MODP => write!(f, "DH_768_MODP")?,
            Self::DH_1024_MODP => write!(f, "DH_1024_MODP")?,
            Self::DH_1536_MODP => write!(f, "DH_1536_MODP")?,
            Self::DH_2048_MODP => write!(f, "DH_2048_MODP")?,
            Self::DH_3072_MODP => write!(f, "DH_3072_MODP")?,
            Self::DH_4096_MODP => write!(f, "DH_4096_MODP")?,
            Self::DH_6144_MODP => write!(f, "DH_6144_MODP")?,
            Self::DH_8192_MODP => write!(f, "DH_8192_MODP")?,
            Self::DH_256_ECP => write!(f, "DH_256_ECP")?,
            Self::NO_ESN => write!(f, "NO_ESN")?,
            Self::ESN => write!(f, "ESN")?,
            TransformType::Encryption(id) => write!(f, "Unknown Encryption Algorithm {}", id)?,
            TransformType::PseudorandomFunction(id) => {
                write!(f, "Unknown Pseudorandom Function {}", id)?
            }
            TransformType::IntegrityAlgorithm(id) => {
                write!(f, "Unknown Integrity Algorithm {}", id)?
            }
            TransformType::DiffieHellman(id) => write!(f, "Unknown Diffie-Hellman Group {}", id)?,
            TransformType::ExtendedSequenceNumbers(id) => {
                write!(f, "Unknown Extended Sequence Numbers {}", id)?
            }
        }
        Ok(())
    }
}

pub struct SecurityAssociationTransformIter<'a> {
    num_transforms: usize,
    data: &'a [u8],
}

impl<'a> Iterator for SecurityAssociationTransformIter<'a> {
    type Item = Result<SecurityAssociationTransform<'a>, FormatError>;

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
        let transform_type = match TransformType::from_raw(transform_type, transform_id) {
            Ok(transform_type) => transform_type,
            Err(err) => {
                debug!("Unsupported transform type: {}", err);
                self.data = &self.data[transform_length..];
                return Some(Err("Unsupported transform type".into()));
            }
        };
        let item = SecurityAssociationTransform {
            transform_type,
            data: &self.data[8..transform_length],
        };
        self.data = &self.data[transform_length..];
        if self.num_transforms == 0 && !self.data.is_empty() {
            debug!("Packet has unaccounted transforms");
        }
        self.num_transforms = self.num_transforms.saturating_sub(1);
        Some(Ok(item))
    }
}

pub struct SecurityAssociationTransform<'a> {
    transform_type: TransformType,
    data: &'a [u8],
}

impl<'a> SecurityAssociationTransform<'a> {
    pub fn transform_type(&self) -> TransformType {
        self.transform_type
    }

    pub fn iter_attributes(&self) -> SecurityAssociationTransformAttributesIter {
        SecurityAssociationTransformAttributesIter { data: self.data }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TransformAttributeType(u16);

impl TransformAttributeType {
    pub const KEY_LENGTH: TransformAttributeType = TransformAttributeType(14);

    fn from_u16(value: u16) -> Result<TransformAttributeType, FormatError> {
        if value == Self::KEY_LENGTH.0 {
            Ok(TransformAttributeType(value))
        } else {
            debug!("Unsupported IKEv2 Transform Attribute Type {}", value);
            Err("Unsupported IKEv2 Transform Attribute Type".into())
        }
    }
}

impl fmt::Display for TransformAttributeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::KEY_LENGTH => write!(f, "Key Length")?,
            _ => write!(f, "Unknown Transform Attribute Type {}", self.0)?,
        }
        Ok(())
    }
}

pub struct SecurityAssociationTransformAttributesIter<'a> {
    data: &'a [u8],
}

impl<'a> Iterator for SecurityAssociationTransformAttributesIter<'a> {
    type Item = Result<SecurityAssociationTransformAttribute<'a>, FormatError>;

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
        let attribute_format_tv = attribute_type & ATTRIBUTE_FORMAT_TV != 0;
        let data = if attribute_format_tv {
            let data = &self.data[2..4];
            self.data = &self.data[4..];
            data
        } else {
            let mut attribute_length = [0u8; 2];
            attribute_length.copy_from_slice(&self.data[2..4]);
            let attribute_length = u16::from_be_bytes(attribute_length) as usize;
            if self.data.len() < attribute_length {
                debug!("Transform attribute overflow");
                return None;
            }
            let data = &self.data[4..attribute_length];
            self.data = &self.data[attribute_length..];
            data
        };
        let attribute_type =
            match TransformAttributeType::from_u16(attribute_type & ATTRIBUTE_TYPE_MASK) {
                Ok(attribute_type) => attribute_type,
                Err(err) => {
                    debug!("Unsupported attribute type: {}", err);
                    return Some(Err("Unsupported attribute type".into()));
                }
            };
        Some(Ok(SecurityAssociationTransformAttribute {
            attribute_type,
            data,
        }))
    }
}

pub struct SecurityAssociationTransformAttribute<'a> {
    attribute_type: TransformAttributeType,
    data: &'a [u8],
}

impl<'a> SecurityAssociationTransformAttribute<'a> {
    pub fn attribute_type(&self) -> TransformAttributeType {
        self.attribute_type
    }

    pub fn value(&self) -> &[u8] {
        self.data
    }
}

struct PayloadKeyExchange<'a> {
    data: &'a [u8],
}

impl<'a> PayloadKeyExchange<'a> {
    fn from_payload(data: &'a [u8]) -> Result<PayloadKeyExchange<'a>, FormatError> {
        if data.len() < 4 {
            debug!("Not enough data in key exchange payload");
            Err("Not enough data in key exchange payload".into())
        } else {
            Ok(PayloadKeyExchange { data })
        }
    }

    fn read_group_num(&self) -> u16 {
        // TODO: verify this matches SA proposal group number.
        let mut dh_group_num = [0u8; 2];
        dh_group_num.copy_from_slice(&self.data[0..2]);
        u16::from_be_bytes(dh_group_num)
    }

    fn read_value(&self) -> &[u8] {
        &self.data[4..]
    }
}

struct PayloadNonce<'a> {
    data: &'a [u8],
}

impl<'a> PayloadNonce<'a> {
    fn read_value(&self) -> &[u8] {
        self.data
    }
}

#[derive(PartialEq, Eq)]
pub struct NotifyMessageType(u16);

impl NotifyMessageType {
    pub const UNSUPPORTED_CRITICAL_PAYLOAD: NotifyMessageType = NotifyMessageType(1);
    pub const INVALID_IKE_SPI: NotifyMessageType = NotifyMessageType(4);
    pub const INVALID_MAJOR_VERSION: NotifyMessageType = NotifyMessageType(5);
    pub const INVALID_SYNTAX: NotifyMessageType = NotifyMessageType(7);
    pub const INVALID_MESSAGE_ID: NotifyMessageType = NotifyMessageType(9);
    pub const INVALID_SPI: NotifyMessageType = NotifyMessageType(11);
    pub const NO_PROPOSAL_CHOSEN: NotifyMessageType = NotifyMessageType(14);
    pub const INVALID_KE_PAYLOAD: NotifyMessageType = NotifyMessageType(17);
    pub const AUTHENTICATION_FAILED: NotifyMessageType = NotifyMessageType(24);
    pub const SINGLE_PAIR_REQUIRED: NotifyMessageType = NotifyMessageType(34);
    pub const NO_ADDITIONAL_SAS: NotifyMessageType = NotifyMessageType(35);
    pub const INTERNAL_ADDRESS_FAILURE: NotifyMessageType = NotifyMessageType(36);
    pub const FAILED_CP_REQUIRED: NotifyMessageType = NotifyMessageType(37);
    pub const TS_UNACCEPTABLE: NotifyMessageType = NotifyMessageType(38);
    pub const INVALID_SELECTORS: NotifyMessageType = NotifyMessageType(39);
    pub const TEMPORARY_FAILURE: NotifyMessageType = NotifyMessageType(43);
    pub const CHILD_SA_NOT_FOUND: NotifyMessageType = NotifyMessageType(44);

    pub const INITIAL_CONTACT: NotifyMessageType = NotifyMessageType(16384);
    pub const SET_WINDOW_SIZE: NotifyMessageType = NotifyMessageType(16385);
    pub const ADDITIONAL_TS_POSSIBLE: NotifyMessageType = NotifyMessageType(16386);
    pub const IPCOMP_SUPPORTED: NotifyMessageType = NotifyMessageType(16387);
    pub const NAT_DETECTION_SOURCE_IP: NotifyMessageType = NotifyMessageType(16388);
    pub const NAT_DETECTION_DESTINATION_IP: NotifyMessageType = NotifyMessageType(16389);
    pub const COOKIE: NotifyMessageType = NotifyMessageType(16390);
    pub const USE_TRANSPORT_MODE: NotifyMessageType = NotifyMessageType(16391);
    pub const HTTP_CERT_LOOKUP_SUPPORTED: NotifyMessageType = NotifyMessageType(16392);
    pub const REKEY_SA: NotifyMessageType = NotifyMessageType(16393);
    pub const ESP_TFC_PADDING_NOT_SUPPORTED: NotifyMessageType = NotifyMessageType(16394);
    pub const NON_FIRST_FRAGMENTS_ALSO: NotifyMessageType = NotifyMessageType(16395);

    const REDIRECT_SUPPORTED: NotifyMessageType = NotifyMessageType(16406);
    const IKEV2_FRAGMENTATION_SUPPORTED: NotifyMessageType = NotifyMessageType(16430);

    fn from_u16(value: u16) -> NotifyMessageType {
        NotifyMessageType(value)
    }
}

impl fmt::Display for NotifyMessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::UNSUPPORTED_CRITICAL_PAYLOAD => write!(f, "UNSUPPORTED_CRITICAL_PAYLOAD")?,
            Self::INVALID_IKE_SPI => write!(f, "INVALID_IKE_SPI")?,
            Self::INVALID_MAJOR_VERSION => write!(f, "INVALID_MAJOR_VERSION")?,
            Self::INVALID_SYNTAX => write!(f, "INVALID_SYNTAX")?,
            Self::INVALID_MESSAGE_ID => write!(f, "INVALID_MESSAGE_ID")?,
            Self::INVALID_SPI => write!(f, "INVALID_SPI")?,
            Self::NO_PROPOSAL_CHOSEN => write!(f, "NO_PROPOSAL_CHOSEN")?,
            Self::INVALID_KE_PAYLOAD => write!(f, "INVALID_KE_PAYLOAD")?,
            Self::AUTHENTICATION_FAILED => write!(f, "AUTHENTICATION_FAILED")?,
            Self::SINGLE_PAIR_REQUIRED => write!(f, "SINGLE_PAIR_REQUIRED")?,
            Self::NO_ADDITIONAL_SAS => write!(f, "NO_ADDITIONAL_SAS")?,
            Self::INTERNAL_ADDRESS_FAILURE => write!(f, "INTERNAL_ADDRESS_FAILURE")?,
            Self::FAILED_CP_REQUIRED => write!(f, "FAILED_CP_REQUIRED")?,
            Self::TS_UNACCEPTABLE => write!(f, "TS_UNACCEPTABLE")?,
            Self::INVALID_SELECTORS => write!(f, "INVALID_SELECTORS")?,
            Self::TEMPORARY_FAILURE => write!(f, "TEMPORARY_FAILURE")?,
            Self::CHILD_SA_NOT_FOUND => write!(f, "CHILD_SA_NOT_FOUND")?,
            Self::INITIAL_CONTACT => write!(f, "INITIAL_CONTACT")?,
            Self::SET_WINDOW_SIZE => write!(f, "SET_WINDOW_SIZE")?,
            Self::ADDITIONAL_TS_POSSIBLE => write!(f, "ADDITIONAL_TS_POSSIBLE")?,
            Self::IPCOMP_SUPPORTED => write!(f, "IPCOMP_SUPPORTED")?,
            Self::NAT_DETECTION_SOURCE_IP => write!(f, "NAT_DETECTION_SOURCE_IP")?,
            Self::NAT_DETECTION_DESTINATION_IP => write!(f, "NAT_DETECTION_DESTINATION_IP")?,
            Self::COOKIE => write!(f, "COOKIE")?,
            Self::USE_TRANSPORT_MODE => write!(f, "USE_TRANSPORT_MODE")?,
            Self::HTTP_CERT_LOOKUP_SUPPORTED => write!(f, "HTTP_CERT_LOOKUP_SUPPORTED")?,
            Self::REKEY_SA => write!(f, "REKEY_SA")?,
            Self::ESP_TFC_PADDING_NOT_SUPPORTED => write!(f, "ESP_TFC_PADDING_NOT_SUPPORTED")?,
            Self::NON_FIRST_FRAGMENTS_ALSO => write!(f, "NON_FIRST_FRAGMENTS_ALSO")?,
            Self::REDIRECT_SUPPORTED => write!(f, "REDIRECT_SUPPORTED")?,
            Self::IKEV2_FRAGMENTATION_SUPPORTED => write!(f, "IKEV2_FRAGMENTATION_SUPPORTED")?,
            _ => write!(f, "Unknown Notify Message Type {}", self.0)?,
        }
        Ok(())
    }
}
struct PayloadNotify<'a> {
    protocol_id: Option<IPSecProtocolID>,
    message_type: NotifyMessageType,
    spi: &'a [u8],
    data: &'a [u8],
}

impl<'a> PayloadNotify<'a> {
    fn from_payload(data: &'a [u8]) -> Result<PayloadNotify<'a>, FormatError> {
        if data.len() < 4 {
            debug!("Not enough data in notify payload");
            return Err("Not enough data in key exchange payload".into());
        }
        let protocol_id = data[0];
        let protocol_id = if protocol_id != 0 {
            Some(IPSecProtocolID::from_u8(protocol_id)?)
        } else {
            None
        };
        let spi_size = data[1] as usize;
        if data.len() < 4 + spi_size {
            return Err("Notify SPI oveflow".into());
        }
        let mut message_type = [0u8; 2];
        message_type.copy_from_slice(&data[2..4]);
        let message_type = u16::from_be_bytes(message_type);
        let message_type = NotifyMessageType::from_u16(message_type);
        let spi = &data[4..4 + spi_size];
        Ok(PayloadNotify {
            protocol_id,
            message_type,
            spi,
            data: &data[4 + spi_size..],
        })
    }

    fn read_value(&self) -> &[u8] {
        self.data
    }
}

impl fmt::Debug for InputMessage<'_> {
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
            if let Ok(pl_sa) = pl.to_security_association() {
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
                            let attr = match attr {
                                Ok(attr) => attr,
                                Err(err) => {
                                    writeln!(f, "        Attribute type invalid {}", err)?;
                                    continue;
                                }
                            };
                            writeln!(
                                f,
                                "        Attribute {} value {:?}",
                                attr.attribute_type, attr.data
                            )?;
                        }
                    }
                }
            } else if let Ok(pl_kex) = pl.to_key_exchange() {
                writeln!(
                    f,
                    "    DH Group num {} value {:?}",
                    pl_kex.read_group_num(),
                    pl_kex.read_value()
                )?;
            } else if let Ok(pl_nonce) = pl.to_nonce() {
                writeln!(f, "    Value {:?}", pl_nonce.read_value(),)?;
            } else if let Ok(pl_notify) = pl.to_notify() {
                writeln!(
                    f,
                    "    Notify protocol ID {:?} SPI {:?} type {} value {:?}",
                    pl_notify.protocol_id,
                    pl_notify.spi,
                    pl_notify.message_type,
                    pl_notify.read_value(),
                )?;
            } else {
                writeln!(f, "    Data {:?}", pl.data)?;
            }
        }
        Ok(())
    }
}

pub struct FormatError {
    msg: &'static str,
    error_code: Option<NotifyMessageType>,
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)?;
        if let Some(error_code) = &self.error_code {
            write!(f, " ({})", error_code)?;
        }
        Ok(())
    }
}

impl fmt::Debug for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl error::Error for FormatError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(self)
    }
}

impl From<&'static str> for FormatError {
    fn from(msg: &'static str) -> FormatError {
        FormatError {
            msg,
            error_code: None,
        }
    }
}

pub struct NotEnoughSpaceError {}

impl fmt::Display for NotEnoughSpaceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Not enough space in buffer")
    }
}

impl fmt::Debug for NotEnoughSpaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl error::Error for NotEnoughSpaceError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(self)
    }
}
