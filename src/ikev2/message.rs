use std::{
    error, fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::RangeInclusive,
};

use log::{debug, warn};

use crate::logger::fmt_slice_hex;

use super::{crypto, ip::IpNetmask};

#[derive(Clone, Copy, PartialEq, Eq)]
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
            warn!("Unsupported IKEv2 Exchange Type {}", value);
            Err("Unsupported IKEv2 Exchange Type".into())
        }
    }
}

impl fmt::Display for ExchangeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::IKE_SA_INIT => write!(f, "IKE_SA_INIT"),
            Self::IKE_AUTH => write!(f, "IKE_AUTH"),
            Self::CREATE_CHILD_SA => write!(f, "CREATE_CHILD_SA"),
            Self::INFORMATIONAL => write!(f, "INFORMATIONAL"),
            _ => write!(f, "Unknown exchange type {}", self.0),
        }
    }
}

#[derive(PartialEq, Eq)]
pub struct Flags(u8);

impl Flags {
    pub const INITIATOR: Flags = Flags(1 << 3);
    const VERSION: Flags = Flags(1 << 4);
    pub const RESPONSE: Flags = Flags(1 << 5);

    fn from_u8(value: u8) -> Result<Flags, FormatError> {
        const RESERVED_MASK: u8 = !Flags::INITIATOR.0 & !Flags::VERSION.0 & !Flags::RESPONSE.0;
        if value & RESERVED_MASK != 0x00 {
            debug!("IKEv2 reserved flags are set {}", value & RESERVED_MASK);
            return Err("IKEv2 reserved flags are set".into());
        }
        Ok(Flags(value))
    }

    pub fn has(&self, flag: Flags) -> bool {
        self.0 & flag.0 != 0
    }
}

impl fmt::Display for Flags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.has(Flags::INITIATOR) {
            f.write_str("Initiator")?;
        } else {
            f.write_str("Responder")?;
        }
        if self.has(Flags::VERSION) {
            f.write_str("Version")?;
        }
        if self.has(Flags::RESPONSE) {
            f.write_str("Response")
        } else {
            f.write_str("Request")
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Spi {
    None,
    U32(u32),
    U64(u64),
}

impl Spi {
    fn from_slice(spi: &[u8]) -> Result<Spi, FormatError> {
        if spi.len() == 4 {
            let mut value = [0u8; 4];
            value.copy_from_slice(spi);
            let value = u32::from_be_bytes(value);
            Ok(Self::U32(value))
        } else if spi.len() == 8 {
            let mut value = [0u8; 8];
            value.copy_from_slice(spi);
            let value = u64::from_be_bytes(value);
            Ok(Self::U64(value))
        } else if spi.is_empty() {
            Ok(Self::None)
        } else {
            warn!("Unexpected SPI size {}", spi.len());
            Err("Unexpected SPI size".into())
        }
    }

    pub fn write_to(&self, dest: &mut [u8]) {
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

impl fmt::Display for Spi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::None => Ok(()),
            Self::U32(val) => write!(f, "{:x}", val),
            Self::U64(val) => write!(f, "{:x}", val),
        }
    }
}

impl fmt::Debug for Spi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

pub struct InputMessage<'a> {
    data: &'a [u8],
    is_nat: bool,
}

// Parse and validate using spec from RFC 7296, Section 3.
impl InputMessage<'_> {
    pub fn from_datagram(p: &[u8], is_nat: bool) -> Result<InputMessage, FormatError> {
        let data = if is_nat { &p[4..] } else { p };
        if p.len() < 28 {
            warn!("Not enough data in message");
            Err("Not enough data in message".into())
        } else {
            Ok(InputMessage { data, is_nat })
        }
    }

    pub fn is_nat(&self) -> bool {
        self.is_nat
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

    fn read_next_payload(&self) -> PayloadType {
        PayloadType::from_u8(self.data[16])
    }

    fn read_version(&self) -> (u8, u8) {
        let version = self.data[17];
        let major_version = (version >> 4) & 0x0f;
        let minor_version = version & 0x0f;
        (major_version, minor_version)
    }

    pub fn read_exchange_type(&self) -> Result<ExchangeType, FormatError> {
        ExchangeType::from_u8(self.data[18])
    }

    pub fn read_flags(&self) -> Result<Flags, FormatError> {
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

    pub fn header(&self) -> [u8; 28] {
        let mut header = [0u8; 28];
        header[16] = PayloadType::NONE.0;
        // Don't copy length to keep it empty.
        header[..24].copy_from_slice(&self.data[..24]);
        header
    }

    pub fn is_valid(&self) -> bool {
        // TODO: validate all required fields.
        // TODO: return status in notification (e.g. INVALID_MAJOR_VERSION).
        let mut valid = true;
        let is_sa_init = match self.read_exchange_type() {
            Ok(exchange_type) => exchange_type == ExchangeType::IKE_SA_INIT,
            Err(err) => {
                warn!("Error parsing exchange type {}", err);
                valid = false;
                false
            }
        };
        let message_id = self.read_message_id();
        if is_sa_init && message_id != 0 {
            warn!("Message ID for IKE_SA_INIT is not 0: {}", message_id);
            valid = false;
        }
        if self.read_initiator_spi() == 0 {
            warn!("Empty initiator SPI");
            valid = false;
        }
        if is_sa_init && self.read_responder_spi() != 0 {
            warn!("Unexpected, non-empty responder SPI");
            valid = false;
        } else if !is_sa_init && self.read_responder_spi() == 0 {
            warn!("Empty responder SPI");
            valid = false;
        }
        {
            let (major_version, minor_version) = self.read_version();
            if major_version != 2 {
                warn!(
                    "Unsupported major version {}.{}",
                    major_version, minor_version
                );
                valid = false;
            }
        }
        if let Err(err) = self.read_flags() {
            warn!("Error parsing flags {}", err);
            valid = false;
        }
        {
            let client_length = self.read_length();
            if self.data.len() != client_length as usize {
                warn!(
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
            start_offset: 28,
            next_payload: self.read_next_payload(),
            payload_encrypted: false,
            data: &self.data[28..],
        }
    }

    pub fn signature_data(
        &self,
        encrypted_message: &EncryptedMessage,
        include_encrypted: bool,
    ) -> &[u8] {
        let signed_length = 4 + if include_encrypted {
            // Separate integrity checksum.
            encrypted_message.data.len()
        } else {
            // AEAD message - include payload header in signature.
            0
        };
        let signature_range =
            ..(encrypted_message.start_offset + signed_length).min(self.data.len());
        &self.data[signature_range]
    }

    pub fn raw_data(&self) -> &[u8] {
        self.data
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
        let cursor = 28;
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
            // Since all IKE SAs are established by client, all flags should be empty.
            0
        } else {
            Flags::RESPONSE.0
        };
        self.dest[20..24].copy_from_slice(&message_id.to_be_bytes());
        self.dest[24..28].copy_from_slice(&0u32.to_be_bytes());

        self.next_payload_index = 16;
        self.cursor = 28;
        Ok(())
    }

    pub fn update_header(header: &mut [u8; 28], next_payload: PayloadType, length: u32) {
        header[16] = next_payload.0;
        header[24..28].copy_from_slice(&length.to_be_bytes());
    }

    pub fn clone_header<'a>(
        &self,
        dest: &'a mut [u8],
    ) -> Result<MessageWriter<'a>, NotEnoughSpaceError> {
        let mut new_writer = Self::new(dest)?;
        new_writer.next_payload_index = 16;
        new_writer.cursor = 28;
        new_writer.dest[16] = PayloadType::NONE.0;
        new_writer.dest[..24].copy_from_slice(&self.dest[..24]);
        new_writer.dest[24..28].fill(0);
        Ok(new_writer)
    }

    fn sa_parameters_len(params: &crypto::TransformParameters) -> (usize, usize) {
        let (num_transforms, data_len) = params
            .iter_parameters()
            .map(|param| {
                if param.key_length().is_some() {
                    (1, 8 + 4)
                } else {
                    (1, 8)
                }
            })
            .fold((0, 0), |acc, e| (acc.0 + e.0, acc.1 + e.1));
        let proposal_len = 8 + params.local_spi().length() + data_len;
        (num_transforms, proposal_len)
    }

    fn write_sa_params(
        dest: &mut [u8],
        proposal_num: u8,
        proposal: &crypto::TransformParameters,
        is_last: bool,
    ) -> usize {
        const ATTRIBUTE_FORMAT_TV: u16 = 1 << 15;
        const ATTRIBUTE_TYPE_KEY_LENGTH: [u8; 2] =
            (TransformAttributeType::KEY_LENGTH.0 | ATTRIBUTE_FORMAT_TV).to_be_bytes();
        let (num_transforms, proposal_len) = Self::sa_parameters_len(proposal);
        let spi = proposal.local_spi();
        dest[0] = if is_last { 0 } else { 2 };
        dest[2..4].copy_from_slice(&(proposal_len as u16).to_be_bytes());
        dest[4] = proposal_num;
        dest[5] = proposal.protocol_id().0;
        dest[6] = spi.length() as u8;
        dest[7] = num_transforms as u8;
        spi.write_to(&mut dest[8..8 + spi.length()]);
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
                let next_payload_slice =
                    &mut dest[next_payload_offset..next_payload_offset + transform_len];
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
        proposal_len
    }

    pub fn write_security_association(
        &mut self,
        proposals: &[(&crypto::TransformParameters, u8)],
    ) -> Result<(), NotEnoughSpaceError> {
        let proposals_len = proposals
            .iter()
            .map(|params| Self::sa_parameters_len(params.0).1)
            .sum();
        let mut next_payload_slice =
            self.next_payload_slice(PayloadType::SECURITY_ASSOCIATION, proposals_len)?;
        for (proposal, proposal_num) in proposals {
            let is_last = *proposal_num as usize == proposals.len();
            let proposal_len =
                Self::write_sa_params(next_payload_slice, *proposal_num, proposal, is_last);
            next_payload_slice = &mut next_payload_slice[proposal_len..];
        }
        Ok(())
    }

    pub fn write_key_exchange_payload(
        &mut self,
        dh_group: u16,
        public_key: &[u8],
    ) -> Result<(), NotEnoughSpaceError> {
        let next_payload_slice =
            self.next_payload_slice(PayloadType::KEY_EXCHANGE, 4 + public_key.len())?;
        next_payload_slice[0..2].copy_from_slice(&dh_group.to_be_bytes());
        next_payload_slice[2] = 0;
        next_payload_slice[3] = 0;
        next_payload_slice[4..].copy_from_slice(public_key);
        Ok(())
    }

    pub fn write_certificate_payload(
        &mut self,
        certificate_encoding: CertificateEncoding,
        certificate_data: &[u8],
    ) -> Result<(), NotEnoughSpaceError> {
        let next_payload_slice =
            self.next_payload_slice(PayloadType::CERTIFICATE, 1 + certificate_data.len())?;
        next_payload_slice[0] = certificate_encoding.0;
        next_payload_slice[1..].copy_from_slice(certificate_data);
        Ok(())
    }

    pub fn write_certificate_request_payload(
        &mut self,
        certificate_encoding: CertificateEncoding,
        certificate_data: &[u8],
    ) -> Result<(), NotEnoughSpaceError> {
        let next_payload_slice =
            self.next_payload_slice(PayloadType::CERTIFICATE_REQUEST, 1 + certificate_data.len())?;
        next_payload_slice[0] = certificate_encoding.0;
        next_payload_slice[1..].copy_from_slice(certificate_data);
        Ok(())
    }

    pub fn write_authentication_payload_slice(
        &mut self,
        auth_method: AuthMethod,
        signature_data: &[u8],
    ) -> Result<(), NotEnoughSpaceError> {
        let next_payload_slice =
            self.next_payload_slice(PayloadType::AUTHENTICATION, 4 + signature_data.len())?;
        next_payload_slice[0] = auth_method.0;
        next_payload_slice[4..].copy_from_slice(signature_data);
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

    pub fn write_delete_payload(
        &mut self,
        protocol_id: IPSecProtocolID,
        spi: &[Spi],
    ) -> Result<(), NotEnoughSpaceError> {
        let spi_size = match protocol_id {
            IPSecProtocolID::IKE => 0,
            IPSecProtocolID::AH | IPSecProtocolID::ESP => 4,
            _ => 0,
        };
        let next_payload_slice =
            self.next_payload_slice(PayloadType::DELETE, 4 + spi_size * spi.len())?;
        next_payload_slice[0] = protocol_id.0;
        next_payload_slice[1] = spi_size as u8;
        next_payload_slice[2..4].copy_from_slice(&(spi.len() as u16).to_be_bytes());
        spi.iter().enumerate().try_for_each(|(i, spi)| {
            let start_index = 4 + i * spi_size;
            if spi.length() == spi_size {
                spi.write_to(&mut next_payload_slice[start_index..start_index + spi.length()]);
                Ok(())
            } else {
                Err(NotEnoughSpaceError {})
            }
        })
    }

    pub fn write_traffic_selector_payload(
        &mut self,
        is_initiator: bool,
        selectors: &[TrafficSelector],
    ) -> Result<(), NotEnoughSpaceError> {
        let payload_type = if is_initiator {
            PayloadType::TRAFFIC_SELECTOR_INITIATOR
        } else {
            PayloadType::TRAFFIC_SELECTOR_RESPONDER
        };
        let payload_length = selectors
            .iter()
            .map(|selector| selector.ts_type().length())
            .sum::<usize>();
        let next_payload_slice = self.next_payload_slice(payload_type, 4 + payload_length)?;
        next_payload_slice[0] = selectors.len() as u8;

        let mut next_selector_offset = 4;
        selectors.iter().for_each(|ts| {
            let ts_length = ts.ts_type.length();
            let dest =
                &mut next_payload_slice[next_selector_offset..next_selector_offset + ts_length];
            dest[0] = ts.ts_type.0;
            dest[1] = ts.ip_protocol.0;
            dest[2..4].copy_from_slice(&(ts_length as u16).to_be_bytes());
            let dest = &mut dest[4..];

            dest[0..2].copy_from_slice(&ts.port.start().to_be_bytes());
            dest[2..4].copy_from_slice(&ts.port.end().to_be_bytes());
            // Addresses are supposed to be pre-validated, but just in case specify an all-exclusive range.
            match ts.ts_type {
                TrafficSelectorType::TS_IPV4_ADDR_RANGE => {
                    if let IpAddr::V4(start_addr) = ts.addr.start() {
                        dest[4..8].copy_from_slice(&start_addr.octets());
                    } else {
                        dest[4..8].fill(255);
                    }
                    if let IpAddr::V4(end_addr) = ts.addr.end() {
                        dest[8..12].copy_from_slice(&end_addr.octets());
                    } else {
                        dest[8..12].fill(0);
                    }
                }
                TrafficSelectorType::TS_IPV6_ADDR_RANGE => {
                    if let IpAddr::V6(start_addr) = ts.addr.start() {
                        dest[4..20].copy_from_slice(&start_addr.octets());
                    } else {
                        dest[4..20].fill(255);
                    }
                    if let IpAddr::V6(end_addr) = ts.addr.end() {
                        dest[20..36].copy_from_slice(&end_addr.octets());
                    } else {
                        dest[20..36].fill(0);
                    }
                }
                _ => {}
            }
            next_selector_offset += ts_length;
        });

        Ok(())
    }

    pub fn write_configuration_payload(
        &mut self,
        ip_netmask: IpNetmask,
        dns: &[IpAddr],
        tunnel_domains: &[Vec<u8>],
    ) -> Result<(), NotEnoughSpaceError> {
        let addr_length = match ip_netmask {
            IpNetmask::Ipv4Mask(_, _) => (4 + 4) * 2,
            IpNetmask::Ipv6Prefix(_, _) => 4 + 17,
            IpNetmask::None => 0,
        };
        let dns_length = dns
            .iter()
            .map(|dns| match dns {
                IpAddr::V4(_) => 4 + 4,
                IpAddr::V6(_) => 4 + 16,
            })
            .sum::<usize>();
        let internal_dns_domain_length = tunnel_domains
            .iter()
            .map(|domain| 4 + domain.len())
            .sum::<usize>();

        let next_payload_slice = self.next_payload_slice(
            PayloadType::CONFIGURATION,
            4 + addr_length + dns_length + internal_dns_domain_length,
        )?;
        next_payload_slice[0] = ConfigurationType::CFG_REPLY.0;

        // Write IP address.
        let mut data = &mut next_payload_slice[4..];
        match ip_netmask {
            IpNetmask::Ipv4Mask(addr, netmask) => {
                data[0..2].copy_from_slice(
                    &ConfigurationAttributeType::INTERNAL_IP4_ADDRESS
                        .0
                        .to_be_bytes(),
                );
                data[2..4].copy_from_slice(&4u16.to_be_bytes());
                data[4..8].copy_from_slice(&addr.octets());
                data[8..10].copy_from_slice(
                    &ConfigurationAttributeType::INTERNAL_IP4_NETMASK
                        .0
                        .to_be_bytes(),
                );
                data[10..12].copy_from_slice(&4u16.to_be_bytes());
                data[12..16].copy_from_slice(&netmask.octets());
                data = &mut data[16..];
            }
            IpNetmask::Ipv6Prefix(addr, prefix) => {
                data[0..2].copy_from_slice(
                    &ConfigurationAttributeType::INTERNAL_IP6_ADDRESS
                        .0
                        .to_be_bytes(),
                );
                data[2..4].copy_from_slice(&17u16.to_be_bytes());
                data[4..20].copy_from_slice(&addr.octets());
                data[20] = prefix;
                data = &mut data[21..];
            }
            IpNetmask::None => {}
        };
        // Write all DNS servers.
        for addr in dns {
            match addr {
                IpAddr::V4(addr) => {
                    data[0..2].copy_from_slice(
                        &ConfigurationAttributeType::INTERNAL_IP4_DNS.0.to_be_bytes(),
                    );
                    data[2..4].copy_from_slice(&4u16.to_be_bytes());
                    data[4..8].copy_from_slice(&addr.octets());
                    data = &mut data[8..];
                }
                IpAddr::V6(addr) => {
                    data[0..2].copy_from_slice(
                        &ConfigurationAttributeType::INTERNAL_IP6_DNS.0.to_be_bytes(),
                    );
                    data[2..4].copy_from_slice(&16u16.to_be_bytes());
                    data[4..20].copy_from_slice(&addr.octets());
                    data = &mut data[20..];
                }
            }
        }

        // Write all internal domains to have split DNS in macOS (RFC 8598).
        for domain in tunnel_domains {
            data[0..2].copy_from_slice(
                &ConfigurationAttributeType::INTERNAL_DNS_DOMAIN
                    .0
                    .to_be_bytes(),
            );
            data[2..4].copy_from_slice(&(domain.len() as u16).to_be_bytes());
            data[4..4 + domain.len()].copy_from_slice(domain);
            data = &mut data[4 + domain.len()..];
        }

        Ok(())
    }

    pub fn write_encrypted_payload(
        &mut self,
        data: &[u8],
        full_encrypted_len: usize,
        next_payload: PayloadType,
        fragment_number: u16,
        total_fragments: u16,
    ) -> Result<usize, NotEnoughSpaceError> {
        if full_encrypted_len < data.len() {
            return Err(NotEnoughSpaceError {});
        }
        let encrypted_payload_start = self.cursor;
        let encrypted_data_start = if total_fragments == 1 {
            let next_payload_slice = self
                .next_payload_slice(PayloadType::ENCRYPTED_AND_AUTHENTICATED, full_encrypted_len)?;
            next_payload_slice[..data.len()].copy_from_slice(data);
            encrypted_payload_start + 4
        } else {
            let next_payload_slice = self.next_payload_slice(
                PayloadType::ENCRYPTED_AND_AUTHENTICATED_FRAGMENT,
                4 + full_encrypted_len,
            )?;
            next_payload_slice[0..2].copy_from_slice(&(fragment_number + 1).to_be_bytes());
            next_payload_slice[2..4].copy_from_slice(&total_fragments.to_be_bytes());
            next_payload_slice[4..4 + data.len()].copy_from_slice(data);
            encrypted_payload_start + 4 + 4
        };
        let next_payload = if fragment_number == 0 {
            next_payload.0
        } else {
            PayloadType::NONE.0
        };
        // First byte of encrypted payload will contain the next encrypted payload type.
        // Encrypted payloads are an exception where the Next Payload specifies the embedded
        // payload type.
        self.dest[encrypted_payload_start] = next_payload;
        Ok(encrypted_data_start)
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

    pub fn first_payload_type(&self) -> PayloadType {
        PayloadType::from_u8(self.dest[16])
    }

    pub fn complete_message(&mut self) -> usize {
        let message_length = self.cursor as u32;
        self.dest[24..28].copy_from_slice(&message_length.to_be_bytes());
        self.cursor
    }

    pub fn raw_data(&mut self) -> &[u8] {
        self.dest
    }

    pub fn payloads_data(&self) -> &[u8] {
        &self.dest[28..self.cursor]
    }
}

pub struct Payload<'a> {
    payload_type: PayloadType,
    encrypted_next_payload: Option<PayloadType>,
    critical: bool,
    data: &'a [u8],
    start_offset: usize,
}

impl Payload<'_> {
    pub fn payload_type(&self) -> PayloadType {
        self.payload_type
    }

    pub fn is_critical(&self) -> bool {
        self.critical
    }

    pub fn to_security_association(&self) -> Result<PayloadSecurityAssociation, FormatError> {
        if self.payload_type == PayloadType::SECURITY_ASSOCIATION {
            Ok(PayloadSecurityAssociation { data: self.data })
        } else {
            Err("Payload type is not SECURITY_ASSOCIATION".into())
        }
    }

    pub fn to_key_exchange(&self) -> Result<PayloadKeyExchange, FormatError> {
        if self.payload_type == PayloadType::KEY_EXCHANGE {
            PayloadKeyExchange::from_payload(self.data)
        } else {
            Err("Payload type is not KEY_EXCHANGE".into())
        }
    }

    pub fn to_identification(&self) -> Result<PayloadIdentification, FormatError> {
        if self.payload_type == PayloadType::ID_INITIATOR
            || self.payload_type == PayloadType::ID_RESPONDER
        {
            PayloadIdentification::from_payload(self.data)
        } else {
            Err("Payload type is not ID".into())
        }
    }

    pub fn to_certificate(&self) -> Result<PayloadCertificate, FormatError> {
        if self.payload_type == PayloadType::CERTIFICATE {
            PayloadCertificate::from_payload(self.data)
        } else {
            Err("Payload type is not CERTIFICATE".into())
        }
    }

    pub fn to_certificate_request(&self) -> Result<PayloadCertificateRequest, FormatError> {
        if self.payload_type == PayloadType::CERTIFICATE_REQUEST {
            PayloadCertificateRequest::from_payload(self.data)
        } else {
            Err("Payload type is not CERTIFICATE_REQUEST".into())
        }
    }

    pub fn to_authentication(&self) -> Result<PayloadAuthentication, FormatError> {
        if self.payload_type == PayloadType::AUTHENTICATION {
            PayloadAuthentication::from_payload(self.data)
        } else {
            Err("Payload type is not AUTHENTICATION".into())
        }
    }

    pub fn to_nonce(&self) -> Result<PayloadNonce, FormatError> {
        if self.payload_type == PayloadType::NONCE {
            Ok(PayloadNonce { data: self.data })
        } else {
            Err("Payload type is not NONCE".into())
        }
    }

    pub fn to_notify(&self) -> Result<PayloadNotify, FormatError> {
        if self.payload_type == PayloadType::NOTIFY {
            PayloadNotify::from_payload(self.data)
        } else {
            Err("Payload type is not NOTIFY".into())
        }
    }

    pub fn to_delete(&self) -> Result<PayloadDelete, FormatError> {
        if self.payload_type == PayloadType::DELETE {
            PayloadDelete::from_payload(self.data)
        } else {
            Err("Payload type is not DELETE".into())
        }
    }

    pub fn to_traffic_selector(&self) -> Result<PayloadTrafficSelector, FormatError> {
        if self.payload_type == PayloadType::TRAFFIC_SELECTOR_INITIATOR
            || self.payload_type == PayloadType::TRAFFIC_SELECTOR_RESPONDER
        {
            PayloadTrafficSelector::from_payload(self.data)
        } else {
            Err("Payload type is not TRAFFIC_SELECTOR".into())
        }
    }

    pub fn to_configuration(&self) -> Result<PayloadConfiguration, FormatError> {
        if self.payload_type == PayloadType::CONFIGURATION {
            PayloadConfiguration::from_payload(self.data)
        } else {
            Err("Payload type is not CONFIGURATION".into())
        }
    }

    pub fn encrypted_data(&self) -> Result<EncryptedMessage, FormatError> {
        if self.payload_type == PayloadType::ENCRYPTED_AND_AUTHENTICATED {
            let encrypted_next_payload = if let Some(next_payload) = self.encrypted_next_payload {
                next_payload
            } else {
                return Err("Unspecified next encrypted payload".into());
            };
            Ok(EncryptedMessage::from_encrypted_payload(
                encrypted_next_payload,
                self,
            ))
        } else if self.payload_type == PayloadType::ENCRYPTED_AND_AUTHENTICATED_FRAGMENT {
            let encrypted_next_payload = if let Some(next_payload) = self.encrypted_next_payload {
                next_payload
            } else {
                return Err("Unspecified next encrypted payload".into());
            };
            EncryptedMessage::from_encrypted_fragment_payload(encrypted_next_payload, self)
        } else {
            Err("Payload type is not ENCRYPTED_AND_AUTHENTICATED".into())
        }
    }
}

pub struct PayloadIter<'a> {
    start_offset: usize,
    next_payload: PayloadType,
    payload_encrypted: bool,
    data: &'a [u8],
}

impl<'a> Iterator for PayloadIter<'a> {
    type Item = Result<Payload<'a>, FormatError>;

    fn next(&mut self) -> Option<Self::Item> {
        const CRITICAL_BIT: u8 = 1 << 7;
        if self.next_payload == PayloadType::NONE || self.payload_encrypted {
            if !self.data.is_empty() {
                debug!("Packet has unaccounted data");
            }
            return None;
        }
        if self.data.len() < 4 {
            warn!("Not enough data in payload");
            return None;
        }
        let current_payload = self.next_payload;
        let start_offset = self.start_offset;
        let data = self.data;
        let next_payload = PayloadType::from_u8(self.data[0]);
        self.next_payload = next_payload;
        let payload_flags = self.data[1];
        let mut payload_length = [0u8; 2];
        payload_length.copy_from_slice(&self.data[2..4]);
        let payload_length = u16::from_be_bytes(payload_length) as usize;
        if data.len() < payload_length {
            warn!("Payload overflow");
            return None;
        }
        self.data = &self.data[payload_length..];
        self.start_offset += payload_length;
        let critical = match payload_flags {
            0x00 => false,
            CRITICAL_BIT => true,
            _ => {
                warn!(
                    "Unsupported payload {} reserved flags: {}",
                    self.next_payload, payload_flags
                );
                return Some(Err("Unsupported payload reserved flags".into()));
            }
        };
        if !next_payload.is_supported() {
            warn!("Unsupported IKEv2 Payload Type {}", self.next_payload);
            return Some(Err("Unsupported IKEv2 Payload Type".into()));
        }
        self.payload_encrypted = current_payload == PayloadType::ENCRYPTED_AND_AUTHENTICATED
            || current_payload == PayloadType::ENCRYPTED_AND_AUTHENTICATED_FRAGMENT;
        let encrypted_next_payload = if self.payload_encrypted {
            Some(self.next_payload)
        } else {
            None
        };
        let item = Payload {
            payload_type: current_payload,
            encrypted_next_payload,
            critical,
            data: &data[4..payload_length],
            start_offset,
        };
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
    pub const TRAFFIC_SELECTOR_RESPONDER: PayloadType = PayloadType(45);
    pub const ENCRYPTED_AND_AUTHENTICATED: PayloadType = PayloadType(46);
    pub const CONFIGURATION: PayloadType = PayloadType(47);
    pub const EXTENSIBLE_AUTHENTICATION: PayloadType = PayloadType(48);

    pub const ENCRYPTED_AND_AUTHENTICATED_FRAGMENT: PayloadType = PayloadType(53);

    fn from_u8(value: u8) -> PayloadType {
        PayloadType(value)
    }

    fn is_supported(&self) -> bool {
        (Self::SECURITY_ASSOCIATION.0..=Self::EXTENSIBLE_AUTHENTICATION.0).contains(&self.0)
            || self.0 == Self::NONE.0
            || self.0 == Self::ENCRYPTED_AND_AUTHENTICATED_FRAGMENT.0
    }
}

impl fmt::Display for PayloadType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::NONE => write!(f, "No Next Payload"),
            Self::SECURITY_ASSOCIATION => write!(f, "Security Association"),
            Self::KEY_EXCHANGE => write!(f, "Key Exchange"),
            Self::ID_INITIATOR => write!(f, "Identification - Initiator"),
            Self::ID_RESPONDER => write!(f, "Identification - Responder"),
            Self::CERTIFICATE => write!(f, "Certificate"),
            Self::CERTIFICATE_REQUEST => write!(f, "Certificate Request"),
            Self::AUTHENTICATION => write!(f, "Authentication"),
            Self::NONCE => write!(f, "Nonce"),
            Self::NOTIFY => write!(f, "Notify"),
            Self::DELETE => write!(f, "Delete"),
            Self::VENDOR_ID => write!(f, "Vendor ID"),
            Self::TRAFFIC_SELECTOR_INITIATOR => write!(f, "Traffic Selector - Initiator"),
            Self::TRAFFIC_SELECTOR_RESPONDER => write!(f, "Traffic Selector - Responder"),
            Self::ENCRYPTED_AND_AUTHENTICATED => write!(f, "Encrypted and Authenticated"),
            Self::CONFIGURATION => write!(f, "Configuration"),
            Self::EXTENSIBLE_AUTHENTICATION => write!(f, "Extensible Authentication"),
            Self::ENCRYPTED_AND_AUTHENTICATED_FRAGMENT => {
                write!(f, "Encrypted and Authenticated Fragment")
            }
            _ => write!(f, "Unknown exchange type {}", self.0),
        }
    }
}

pub struct PayloadSecurityAssociation<'a> {
    data: &'a [u8],
}

impl PayloadSecurityAssociation<'_> {
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
            warn!("Unsupported IKEv2 IPSec Protocol ID {}", value);
            Err("Unsupported IKEv2 IPSec Protocol ID".into())
        }
    }
}

impl fmt::Display for IPSecProtocolID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::IKE => write!(f, "IKE"),
            Self::AH => write!(f, "AH"),
            Self::ESP => write!(f, "ESP"),
            _ => write!(f, "Unknown IPSec Protocol ID {}", self.0),
        }
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
            warn!("Not enough data in security association");
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
            warn!("Unexpected proposal last substruct {}", last_substruct);
            return None;
        }
        if self.data.len() < proposal_length {
            warn!("Proposal overflow");
            return None;
        }
        let data = self.data;
        self.data = &self.data[proposal_length..];
        let proposal_num = data[4];
        if proposal_num != self.next_proposal_num {
            warn!(
                "Unexpected proposal num {} (should be {})",
                proposal_num, self.next_proposal_num
            );
            return Some(Err("Unexpected proposal number".into()));
        }
        self.next_proposal_num += 1;
        let protocol_id = match IPSecProtocolID::from_u8(data[5]) {
            Ok(protocol_id) => protocol_id,
            Err(err) => {
                warn!("Unsupported protocol ID: {}", err);
                return Some(Err("Unsupported protocol ID".into()));
            }
        };
        let spi_size = data[6] as usize;
        let num_transforms = data[7] as usize;
        if data.len() < 8 + spi_size {
            warn!("Proposal SPI overflow");
            return None;
        }
        let spi = &data[8..8 + spi_size];
        let spi = match Spi::from_slice(spi) {
            Ok(spi) => spi,
            Err(_) => {
                return Some(Err("Unsupported SPI format".into()));
            }
        };
        let item = SecurityAssociationProposal {
            proposal_num,
            protocol_id,
            num_transforms,
            spi,
            data: &data[8 + spi_size..proposal_length],
        };
        Some(Ok(item))
    }
}

pub struct SecurityAssociationProposal<'a> {
    proposal_num: u8,
    protocol_id: IPSecProtocolID,
    num_transforms: usize,
    spi: Spi,
    data: &'a [u8],
}

impl SecurityAssociationProposal<'_> {
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

    pub fn spi(&self) -> Spi {
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
                warn!(
                    "Unsupported IKEv2 Transform Type {} ID {}",
                    transform_type, transform_id
                );
                Err("Unsupported IKEv2 Transform Type".into())
            }
        }
    }

    pub fn type_id(&self) -> (u8, u16) {
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
            Self::ENCR_DES_IV64 => write!(f, "ENCR_DES_IV64"),
            Self::ENCR_DES => write!(f, "ENCR_DES"),
            Self::ENCR_3DES => write!(f, "ENCR_3DES"),
            Self::ENCR_RC5 => write!(f, "ENCR_RC5"),
            Self::ENCR_IDEA => write!(f, "ENCR_IDEA"),
            Self::ENCR_CAST => write!(f, "ENCR_CAST"),
            Self::ENCR_BLOWFISH => write!(f, "ENCR_BLOWFISH"),
            Self::ENCR_3IDEA => write!(f, "ENCR_3IDEA"),
            Self::ENCR_DES_IV32 => write!(f, "ENCR_DES_IV32"),
            Self::ENCR_NULL => write!(f, "ENCR_NULL"),
            Self::ENCR_AES_CBC => write!(f, "ENCR_AES_CBC"),
            Self::ENCR_AES_CTR => write!(f, "ENCR_AES_CTR"),
            Self::ENCR_AES_GCM_16 => write!(f, "ENCR_AES_GCM_16"),
            Self::PRF_HMAC_MD5 => write!(f, "PRF_HMAC_MD5"),
            Self::PRF_HMAC_SHA1 => write!(f, "PRF_HMAC_SHA1"),
            Self::PRF_HMAC_TIGER => write!(f, "PRF_HMAC_TIGER"),
            Self::PRF_HMAC_SHA2_256 => write!(f, "PRF_HMAC_SHA2_256"),
            Self::PRF_HMAC_SHA2_384 => write!(f, "PRF_HMAC_SHA2_384"),
            Self::AUTH_NONE => write!(f, "AUTH_NONE"),
            Self::AUTH_HMAC_MD5_96 => write!(f, "AUTH_HMAC_MD5_96"),
            Self::AUTH_HMAC_SHA1_96 => write!(f, "AUTH_HMAC_SHA1_96"),
            Self::AUTH_DES_MAC => write!(f, "AUTH_DES_MAC"),
            Self::AUTH_KPDK_MD5 => write!(f, "AUTH_KPDK_MD5"),
            Self::AUTH_AES_XCBC_96 => write!(f, "AUTH_AES_XCBC_96"),
            Self::AUTH_HMAC_SHA2_256_128 => write!(f, "AUTH_HMAC_SHA2_256_128"),
            Self::AUTH_HMAC_SHA2_384_192 => write!(f, "AUTH_HMAC_SHA2_384_192"),
            Self::DH_NONE => write!(f, "DH_NONE"),
            Self::DH_768_MODP => write!(f, "DH_768_MODP"),
            Self::DH_1024_MODP => write!(f, "DH_1024_MODP"),
            Self::DH_1536_MODP => write!(f, "DH_1536_MODP"),
            Self::DH_2048_MODP => write!(f, "DH_2048_MODP"),
            Self::DH_3072_MODP => write!(f, "DH_3072_MODP"),
            Self::DH_4096_MODP => write!(f, "DH_4096_MODP"),
            Self::DH_6144_MODP => write!(f, "DH_6144_MODP"),
            Self::DH_8192_MODP => write!(f, "DH_8192_MODP"),
            Self::DH_256_ECP => write!(f, "DH_256_ECP"),
            Self::NO_ESN => write!(f, "NO_ESN"),
            Self::ESN => write!(f, "ESN"),
            TransformType::Encryption(id) => write!(f, "Unknown Encryption Algorithm {}", id),
            TransformType::PseudorandomFunction(id) => {
                write!(f, "Unknown Pseudorandom Function {}", id)
            }
            TransformType::IntegrityAlgorithm(id) => {
                write!(f, "Unknown Integrity Algorithm {}", id)
            }
            TransformType::DiffieHellman(id) => write!(f, "Unknown Diffie-Hellman Group {}", id),
            TransformType::ExtendedSequenceNumbers(id) => {
                write!(f, "Unknown Extended Sequence Numbers {}", id)
            }
        }
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
                warn!("Packet is missing {} transforms", self.num_transforms);
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
        let data = self.data;
        self.data = &self.data[transform_length..];
        if self.num_transforms == 0 && !self.data.is_empty() {
            debug!("Packet has unaccounted transforms");
        }
        self.num_transforms = self.num_transforms.saturating_sub(1);
        let transform_type = data[4];
        let mut transform_id = [0u8; 2];
        transform_id.copy_from_slice(&data[6..8]);
        let transform_id = u16::from_be_bytes(transform_id);
        let transform_type = match TransformType::from_raw(transform_type, transform_id) {
            Ok(transform_type) => transform_type,
            Err(err) => {
                debug!("Unsupported transform type: {}", err);
                return Some(Err("Unsupported transform type".into()));
            }
        };
        let item = SecurityAssociationTransform {
            transform_type,
            data: &data[8..transform_length],
        };
        Some(Ok(item))
    }
}

pub struct SecurityAssociationTransform<'a> {
    transform_type: TransformType,
    data: &'a [u8],
}

impl SecurityAssociationTransform<'_> {
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
            Self::KEY_LENGTH => write!(f, "Key Length"),
            _ => write!(f, "Unknown Transform Attribute Type {}", self.0),
        }
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

impl SecurityAssociationTransformAttribute<'_> {
    pub fn attribute_type(&self) -> TransformAttributeType {
        self.attribute_type
    }

    pub fn value(&self) -> &[u8] {
        self.data
    }
}

pub struct PayloadKeyExchange<'a> {
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

    pub fn read_group_num(&self) -> u16 {
        // TODO: verify this matches SA proposal group number.
        let mut dh_group_num = [0u8; 2];
        dh_group_num.copy_from_slice(&self.data[0..2]);
        u16::from_be_bytes(dh_group_num)
    }

    pub fn read_value(&self) -> &[u8] {
        &self.data[4..]
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IdentificationType(u8);

impl IdentificationType {
    pub const ID_IPV4_ADDR: IdentificationType = IdentificationType(1);
    pub const ID_FQDN: IdentificationType = IdentificationType(2);
    pub const ID_RFC822_ADDR: IdentificationType = IdentificationType(3);
    pub const ID_IPV6_ADDR: IdentificationType = IdentificationType(5);
    pub const ID_DER_ASN1_DN: IdentificationType = IdentificationType(9);
    pub const ID_DER_ASN1_GN: IdentificationType = IdentificationType(10);
    pub const ID_KEY_ID: IdentificationType = IdentificationType(11);

    fn from_u8(value: u8) -> IdentificationType {
        IdentificationType(value)
    }

    pub fn type_id(&self) -> u8 {
        self.0
    }
}

impl fmt::Display for IdentificationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::ID_IPV4_ADDR => write!(f, "ID_IPV4_ADDR"),
            Self::ID_FQDN => write!(f, "ID_FQDN"),
            Self::ID_RFC822_ADDR => write!(f, "ID_RFC822_ADDR"),
            Self::ID_IPV6_ADDR => write!(f, "ID_IPV6_ADDR"),
            Self::ID_DER_ASN1_DN => write!(f, "ID_DER_ASN1_DN"),
            Self::ID_DER_ASN1_GN => write!(f, "ID_DER_ASN1_GN"),
            Self::ID_KEY_ID => write!(f, "ID_KEY_ID"),
            _ => write!(f, "Unknown Identification Type {}", self.0),
        }
    }
}

pub struct PayloadIdentification<'a> {
    data: &'a [u8],
}

impl<'a> PayloadIdentification<'a> {
    fn from_payload(data: &'a [u8]) -> Result<PayloadIdentification<'a>, FormatError> {
        if data.len() < 4 {
            debug!("Not enough data in identification payload");
            Err("Not enough data in identification payload".into())
        } else {
            Ok(PayloadIdentification { data })
        }
    }

    pub fn read_identification_type(&self) -> IdentificationType {
        IdentificationType::from_u8(self.data[0])
    }

    pub fn raw_value(&self) -> &[u8] {
        self.data
    }

    pub fn read_value(&self) -> &[u8] {
        &self.data[4..]
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CertificateEncoding(u8);

impl CertificateEncoding {
    pub const PKCS7: CertificateEncoding = CertificateEncoding(1);
    pub const PGP: CertificateEncoding = CertificateEncoding(2);
    pub const DNS_SIGNED_KEY: CertificateEncoding = CertificateEncoding(3);
    pub const X509_SIGNATURE: CertificateEncoding = CertificateEncoding(4);
    pub const KERBEROS_TOKEN: CertificateEncoding = CertificateEncoding(6);
    pub const CRL: CertificateEncoding = CertificateEncoding(7);
    pub const ARL: CertificateEncoding = CertificateEncoding(8);
    pub const SPKI: CertificateEncoding = CertificateEncoding(9);
    pub const X509_ATTRIBUTE: CertificateEncoding = CertificateEncoding(10);
    pub const DEPRECATED_RAW_RSA: CertificateEncoding = CertificateEncoding(11);
    pub const HASH_URL_X509_CERTIFICATE: CertificateEncoding = CertificateEncoding(12);
    pub const HASH_URL_X509_BUNDLE: CertificateEncoding = CertificateEncoding(13);

    fn from_u8(value: u8) -> CertificateEncoding {
        CertificateEncoding(value)
    }
}

impl fmt::Display for CertificateEncoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::PKCS7 => write!(f, "PKCS #7 wrapped X.509 certificate"),
            Self::PGP => write!(f, "PGP Certificate"),
            Self::DNS_SIGNED_KEY => write!(f, "DNS Signed Key"),
            Self::X509_SIGNATURE => write!(f, "X.509 Certificate - Signature"),
            Self::KERBEROS_TOKEN => write!(f, "Kerberos Token"),
            Self::CRL => write!(f, "Certificate Revocation List (CRL)"),
            Self::ARL => write!(f, "Authority Revocation List (ARL)"),
            Self::SPKI => write!(f, "SPKI Certificate"),
            Self::X509_ATTRIBUTE => write!(f, "X.509 Certificate - Attribute"),
            Self::DEPRECATED_RAW_RSA => write!(f, "Deprecated (was Raw RSA Key)"),
            Self::HASH_URL_X509_CERTIFICATE => write!(f, "Hash and URL of X.509 certificate"),
            Self::HASH_URL_X509_BUNDLE => write!(f, "Hash and URL of X.509 bundle"),
            _ => write!(f, "Unknown Certificate Encoding {}", self.0),
        }
    }
}

pub struct PayloadCertificate<'a> {
    encoding: CertificateEncoding,
    data: &'a [u8],
}

impl<'a> PayloadCertificate<'a> {
    fn from_payload(data: &'a [u8]) -> Result<PayloadCertificate<'a>, FormatError> {
        if data.is_empty() {
            debug!("Not enough data in certificate payload");
            return Err("Not enough data in certificate payload".into());
        }

        let encoding = CertificateEncoding::from_u8(data[0]);

        Ok(PayloadCertificate {
            encoding,
            data: &data[1..],
        })
    }

    pub fn encoding(&self) -> CertificateEncoding {
        self.encoding
    }

    pub fn read_value(&self) -> &[u8] {
        self.data
    }
}

pub struct PayloadCertificateRequest<'a> {
    data: &'a [u8],
}

impl<'a> PayloadCertificateRequest<'a> {
    fn from_payload(data: &'a [u8]) -> Result<PayloadCertificateRequest<'a>, FormatError> {
        if data.is_empty() {
            debug!("Not enough data in certificate request payload");
            Err("Not enough data in certificate request payload".into())
        } else {
            Ok(PayloadCertificateRequest { data })
        }
    }

    pub fn read_encoding(&self) -> CertificateEncoding {
        CertificateEncoding::from_u8(self.data[0])
    }

    pub fn read_value(&self) -> &[u8] {
        &self.data[1..]
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuthMethod(u8);

impl AuthMethod {
    pub const RSA_DIGITAL_SIGNATURE: AuthMethod = AuthMethod(1);
    pub const SHARED_MESSAGE_INTEGRITY_CODE: AuthMethod = AuthMethod(2);
    pub const DSS_DIGITAL_SIGNATURE: AuthMethod = AuthMethod(3);

    pub const ECDSA_SHA256_P256: AuthMethod = AuthMethod(9);
    pub const DIGITAL_SIGNATURE: AuthMethod = AuthMethod(14);

    fn from_u8(value: u8) -> AuthMethod {
        AuthMethod(value)
    }
}

impl fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::RSA_DIGITAL_SIGNATURE => write!(f, "RSA Digital Signature"),
            Self::SHARED_MESSAGE_INTEGRITY_CODE => write!(f, "Shared Key Message Integrity Code"),
            Self::DSS_DIGITAL_SIGNATURE => write!(f, "DSS Digital Signature"),
            Self::ECDSA_SHA256_P256 => write!(f, "ECDSA with SHA-256 on the P-256 curve"),
            Self::DIGITAL_SIGNATURE => write!(f, "Digital Signature"),
            _ => write!(f, "Unknown Authentication Method {}", self.0),
        }
    }
}

pub struct PayloadAuthentication<'a> {
    data: &'a [u8],
}

impl<'a> PayloadAuthentication<'a> {
    fn from_payload(data: &'a [u8]) -> Result<PayloadAuthentication<'a>, FormatError> {
        if data.len() < 4 {
            debug!("Not enough data in authentication payload");
            return Err("Not enough data in certificate payload".into());
        }

        Ok(PayloadAuthentication { data })
    }

    pub fn read_method(&self) -> AuthMethod {
        AuthMethod::from_u8(self.data[0])
    }

    pub fn read_value(&self) -> &[u8] {
        &self.data[4..]
    }
}

pub struct PayloadNonce<'a> {
    data: &'a [u8],
}

impl PayloadNonce<'_> {
    pub fn read_value(&self) -> &[u8] {
        self.data
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
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

    pub const MOBIKE_SUPPORTED: NotifyMessageType = NotifyMessageType(16396);
    pub const REDIRECT_SUPPORTED: NotifyMessageType = NotifyMessageType(16406);
    pub const IKEV2_FRAGMENTATION_SUPPORTED: NotifyMessageType = NotifyMessageType(16430);
    pub const SIGNATURE_HASH_ALGORITHMS: NotifyMessageType = NotifyMessageType(16431);

    fn from_u16(value: u16) -> NotifyMessageType {
        NotifyMessageType(value)
    }
}

impl fmt::Display for NotifyMessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::UNSUPPORTED_CRITICAL_PAYLOAD => write!(f, "UNSUPPORTED_CRITICAL_PAYLOAD"),
            Self::INVALID_IKE_SPI => write!(f, "INVALID_IKE_SPI"),
            Self::INVALID_MAJOR_VERSION => write!(f, "INVALID_MAJOR_VERSION"),
            Self::INVALID_SYNTAX => write!(f, "INVALID_SYNTAX"),
            Self::INVALID_MESSAGE_ID => write!(f, "INVALID_MESSAGE_ID"),
            Self::INVALID_SPI => write!(f, "INVALID_SPI"),
            Self::NO_PROPOSAL_CHOSEN => write!(f, "NO_PROPOSAL_CHOSEN"),
            Self::INVALID_KE_PAYLOAD => write!(f, "INVALID_KE_PAYLOAD"),
            Self::AUTHENTICATION_FAILED => write!(f, "AUTHENTICATION_FAILED"),
            Self::SINGLE_PAIR_REQUIRED => write!(f, "SINGLE_PAIR_REQUIRED"),
            Self::NO_ADDITIONAL_SAS => write!(f, "NO_ADDITIONAL_SAS"),
            Self::INTERNAL_ADDRESS_FAILURE => write!(f, "INTERNAL_ADDRESS_FAILURE"),
            Self::FAILED_CP_REQUIRED => write!(f, "FAILED_CP_REQUIRED"),
            Self::TS_UNACCEPTABLE => write!(f, "TS_UNACCEPTABLE"),
            Self::INVALID_SELECTORS => write!(f, "INVALID_SELECTORS"),
            Self::TEMPORARY_FAILURE => write!(f, "TEMPORARY_FAILURE"),
            Self::CHILD_SA_NOT_FOUND => write!(f, "CHILD_SA_NOT_FOUND"),
            Self::INITIAL_CONTACT => write!(f, "INITIAL_CONTACT"),
            Self::SET_WINDOW_SIZE => write!(f, "SET_WINDOW_SIZE"),
            Self::ADDITIONAL_TS_POSSIBLE => write!(f, "ADDITIONAL_TS_POSSIBLE"),
            Self::IPCOMP_SUPPORTED => write!(f, "IPCOMP_SUPPORTED"),
            Self::NAT_DETECTION_SOURCE_IP => write!(f, "NAT_DETECTION_SOURCE_IP"),
            Self::NAT_DETECTION_DESTINATION_IP => write!(f, "NAT_DETECTION_DESTINATION_IP"),
            Self::COOKIE => write!(f, "COOKIE"),
            Self::USE_TRANSPORT_MODE => write!(f, "USE_TRANSPORT_MODE"),
            Self::HTTP_CERT_LOOKUP_SUPPORTED => write!(f, "HTTP_CERT_LOOKUP_SUPPORTED"),
            Self::REKEY_SA => write!(f, "REKEY_SA"),
            Self::ESP_TFC_PADDING_NOT_SUPPORTED => write!(f, "ESP_TFC_PADDING_NOT_SUPPORTED"),
            Self::NON_FIRST_FRAGMENTS_ALSO => write!(f, "NON_FIRST_FRAGMENTS_ALSO"),
            Self::MOBIKE_SUPPORTED => write!(f, "MOBIKE_SUPPORTED"),
            Self::REDIRECT_SUPPORTED => write!(f, "REDIRECT_SUPPORTED"),
            Self::IKEV2_FRAGMENTATION_SUPPORTED => write!(f, "IKEV2_FRAGMENTATION_SUPPORTED"),
            Self::SIGNATURE_HASH_ALGORITHMS => write!(f, "SIGNATURE_HASH_ALGORITHMS"),
            _ => write!(f, "Unknown Notify Message Type {}", self.0),
        }
    }
}

pub struct PayloadNotify<'a> {
    protocol_id: Option<IPSecProtocolID>,
    message_type: NotifyMessageType,
    spi: Spi,
    data: &'a [u8],
}

impl<'a> PayloadNotify<'a> {
    fn from_payload(data: &'a [u8]) -> Result<PayloadNotify<'a>, FormatError> {
        if data.len() < 4 {
            debug!("Not enough data in notify payload");
            return Err("Not enough data in notify payload".into());
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
        let spi = Spi::from_slice(&data[4..4 + spi_size])?;
        Ok(PayloadNotify {
            protocol_id,
            message_type,
            spi,
            data: &data[4 + spi_size..],
        })
    }

    pub fn message_type(&self) -> NotifyMessageType {
        self.message_type
    }

    pub fn spi(&self) -> Spi {
        self.spi
    }

    fn read_value(&self) -> &[u8] {
        self.data
    }

    pub fn to_signature_hash_algorithms(&self) -> Result<SignatureHashAlgorithmIter, FormatError> {
        if self.message_type != NotifyMessageType::SIGNATURE_HASH_ALGORITHMS {
            Err("Notify type is not SIGNATURE_HASH_ALGORITHMS".into())
        } else if self.data.len() % 2 != 0 {
            Err("SIGNATURE_HASH_ALGORITHMS has an unsupported format".into())
        } else {
            Ok(SignatureHashAlgorithmIter { data: self.data })
        }
    }
}

#[derive(PartialEq, Eq)]
pub struct SignatureHashAlgorithm(u16);

impl SignatureHashAlgorithm {
    pub const RESERVED: SignatureHashAlgorithm = SignatureHashAlgorithm(0);
    pub const SHA1: SignatureHashAlgorithm = SignatureHashAlgorithm(1);
    pub const SHA2_256: SignatureHashAlgorithm = SignatureHashAlgorithm(2);
    pub const SHA2_384: SignatureHashAlgorithm = SignatureHashAlgorithm(3);
    pub const SHA2_512: SignatureHashAlgorithm = SignatureHashAlgorithm(4);

    fn from_u16(value: u16) -> SignatureHashAlgorithm {
        SignatureHashAlgorithm(value)
    }

    pub fn to_be_bytes(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

impl fmt::Display for SignatureHashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::RESERVED => write!(f, "RESERVED"),
            Self::SHA1 => write!(f, "SHA1"),
            Self::SHA2_256 => write!(f, "SHA2-256"),
            Self::SHA2_384 => write!(f, "SHA2-384"),
            Self::SHA2_512 => write!(f, "SHA2-512"),
            _ => write!(f, "Unknown Signature Hash Algorithm {}", self.0),
        }
    }
}

pub struct SignatureHashAlgorithmIter<'a> {
    data: &'a [u8],
}

impl Iterator for SignatureHashAlgorithmIter<'_> {
    type Item = SignatureHashAlgorithm;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }
        // The data length is pre-validated.
        let mut hash_algorithm = [0u8; 2];
        hash_algorithm.copy_from_slice(&self.data[..2]);
        let hash_algorithm = u16::from_be_bytes(hash_algorithm);

        self.data = &self.data[2..];
        let hash_algorithm = SignatureHashAlgorithm::from_u16(hash_algorithm);

        Some(hash_algorithm)
    }
}

pub struct PayloadDelete<'a> {
    protocol_id: IPSecProtocolID,
    data: &'a [u8],
}

impl<'a> PayloadDelete<'a> {
    fn from_payload(data: &'a [u8]) -> Result<PayloadDelete<'a>, FormatError> {
        if data.len() < 4 {
            debug!("Not enough data in delete payload");
            return Err("Not enough data in delete payload".into());
        }
        let protocol_id = IPSecProtocolID::from_u8(data[0])?;
        let spi_size = data[1] as usize;
        let mut spi_count = [0u8; 2];
        spi_count.copy_from_slice(&data[2..4]);
        let spi_count = u16::from_be_bytes(spi_count) as usize;
        if protocol_id == IPSecProtocolID::IKE {
            return if spi_size == 0 && spi_count == 0 {
                Ok(PayloadDelete {
                    protocol_id,
                    data: &[],
                })
            } else {
                Err("IKE delete payload has additional unsupported SPIs".into())
            };
        }
        if spi_size != 4 {
            return Err("Unsupported SPI size in delete payload".into());
        }
        if data.len() != 4 + spi_size * spi_count {
            return Err("Delete SPI size mismatch".into());
        }
        Ok(PayloadDelete {
            protocol_id,
            data: &data[4..],
        })
    }

    pub fn iter_spi(&self) -> DeleteSpiIter {
        DeleteSpiIter { data: self.data }
    }
}

pub struct DeleteSpiIter<'a> {
    data: &'a [u8],
}

impl Iterator for DeleteSpiIter<'_> {
    type Item = Spi;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }
        // All protocols use 4-byte SPIs (IKE has none); the data length is pre-validated.
        let mut spi = [0u8; 4];
        spi.copy_from_slice(&self.data[..4]);
        let spi = Spi::U32(u32::from_be_bytes(spi));

        self.data = &self.data[4..];

        Some(spi)
    }
}

pub struct PayloadTrafficSelector<'a> {
    data: &'a [u8],
}

impl<'a> PayloadTrafficSelector<'a> {
    fn from_payload(data: &'a [u8]) -> Result<PayloadTrafficSelector<'a>, FormatError> {
        if data.len() < 4 {
            debug!("Not enough data in traffic selector payload");
            Err("Not enough data in traffic selector payload".into())
        } else {
            Ok(PayloadTrafficSelector { data })
        }
    }

    pub fn iter_traffic_selectors(&self) -> TrafficSelectorIter {
        TrafficSelectorIter {
            num_selectors: self.data[0] as usize,
            data: &self.data[4..],
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TrafficSelectorType(u8);

impl TrafficSelectorType {
    pub const TS_IPV4_ADDR_RANGE: TrafficSelectorType = TrafficSelectorType(7);
    pub const TS_IPV6_ADDR_RANGE: TrafficSelectorType = TrafficSelectorType(8);

    fn from_u8(value: u8) -> Result<TrafficSelectorType, FormatError> {
        if (Self::TS_IPV4_ADDR_RANGE.0..=Self::TS_IPV6_ADDR_RANGE.0).contains(&value) {
            Ok(TrafficSelectorType(value))
        } else {
            debug!("Unsupported IKEv2 Traffic Selector type {}", value);
            Err("Unsupported IKEv2 Traffic Selector type".into())
        }
    }

    fn length(&self) -> usize {
        match *self {
            Self::TS_IPV4_ADDR_RANGE => 4 + 4 + 4 + 4,
            Self::TS_IPV6_ADDR_RANGE => 4 + 4 + 16 + 16,
            _ => 0,
        }
    }
}

impl fmt::Display for TrafficSelectorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::TS_IPV4_ADDR_RANGE => write!(f, "TS_IPV4_ADDR_RANGE"),
            Self::TS_IPV6_ADDR_RANGE => write!(f, "TS_IPV6_ADDR_RANGE"),
            _ => write!(f, "Unknown Traffic Select Type {}", self.0),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IPProtocolType(u8);

impl IPProtocolType {
    pub const ANY: IPProtocolType = IPProtocolType(0);
    pub const ICMP: IPProtocolType = IPProtocolType(1);
    pub const TCP: IPProtocolType = IPProtocolType(6);
    pub const UDP: IPProtocolType = IPProtocolType(17);

    fn from_u8(value: u8) -> IPProtocolType {
        IPProtocolType(value)
    }

    pub fn protocol_id(&self) -> u8 {
        self.0
    }
}

impl fmt::Display for IPProtocolType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::ANY => write!(f, "ANY"),
            Self::ICMP => write!(f, "ICMP"),
            Self::TCP => write!(f, "TCP"),
            Self::UDP => write!(f, "UDP"),
            _ => write!(f, "Unknown IP Protocol Type {}", self.0),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct TrafficSelector {
    ts_type: TrafficSelectorType,
    ip_protocol: IPProtocolType,
    addr: RangeInclusive<IpAddr>,
    port: RangeInclusive<u16>,
}

impl TrafficSelector {
    pub fn from_ip_range(
        addr_range: RangeInclusive<IpAddr>,
    ) -> Result<TrafficSelector, FormatError> {
        let ts_type = match (addr_range.start(), addr_range.end()) {
            (IpAddr::V4(_), IpAddr::V4(_)) => TrafficSelectorType::TS_IPV4_ADDR_RANGE,
            (IpAddr::V6(_), IpAddr::V6(_)) => TrafficSelectorType::TS_IPV6_ADDR_RANGE,
            _ => return Err("Traffic selector has incompatible start/end address types".into()),
        };
        Ok(TrafficSelector {
            ts_type,
            ip_protocol: IPProtocolType::ANY,
            addr: addr_range,
            port: 0..=u16::MAX,
        })
    }

    pub fn ts_type(&self) -> TrafficSelectorType {
        self.ts_type
    }

    pub fn ip_protocol(&self) -> IPProtocolType {
        self.ip_protocol
    }

    pub fn addr_range(&self) -> &RangeInclusive<IpAddr> {
        &self.addr
    }

    pub fn port_range(&self) -> &RangeInclusive<u16> {
        &self.port
    }

    pub fn contains(&self, other: &TrafficSelector) -> bool {
        self.addr.contains(other.addr.start()) && self.addr.contains(other.addr.end())
    }
}

pub struct TrafficSelectorIter<'a> {
    num_selectors: usize,
    data: &'a [u8],
}

impl Iterator for TrafficSelectorIter<'_> {
    type Item = Result<TrafficSelector, FormatError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            if self.num_selectors != 0 {
                debug!("Packet is missing {} selectors", self.num_selectors);
            }
            return None;
        }
        if self.data.len() < 6 {
            debug!("Not enough data in traffic selector");
            return None;
        }
        let mut selector_length = [0u8; 2];
        selector_length.copy_from_slice(&self.data[2..4]);
        let selector_length = u16::from_be_bytes(selector_length) as usize;
        if self.data.len() < selector_length {
            debug!("Selector overflow");
            return None;
        }

        let data = &self.data[..selector_length];
        self.data = &self.data[selector_length..];
        self.num_selectors = self.num_selectors.saturating_sub(1);
        let ts_type = match TrafficSelectorType::from_u8(data[0]) {
            Ok(ts_type) => ts_type,
            Err(err) => return Some(Err(err)),
        };
        let ip_protocol = IPProtocolType::from_u8(data[1]);
        let data = &data[4..];

        let mut start_port = [0u8; 2];
        start_port.copy_from_slice(&data[0..2]);
        let start_port = u16::from_be_bytes(start_port);
        let mut end_port = [0u8; 2];
        end_port.copy_from_slice(&data[2..4]);
        let end_port = u16::from_be_bytes(end_port);
        let port_range = start_port..=end_port;

        let addr_range = match ts_type {
            TrafficSelectorType::TS_IPV4_ADDR_RANGE => {
                if data.len() != 4 + 4 + 4 {
                    return Some(Err("Invalid IPv4 address data".into()));
                }
                let mut start_addr = [0u8; 4];
                let mut end_addr = [0u8; 4];
                start_addr.copy_from_slice(&data[4..8]);
                end_addr.copy_from_slice(&data[8..12]);
                IpAddr::V4(Ipv4Addr::from(start_addr))..=IpAddr::V4(Ipv4Addr::from(end_addr))
            }
            TrafficSelectorType::TS_IPV6_ADDR_RANGE => {
                if data.len() != 4 + 16 + 16 {
                    return Some(Err("Invalid IPv6 address data".into()));
                }
                let mut start_addr = [0u8; 16];
                let mut end_addr = [0u8; 16];
                start_addr.copy_from_slice(&data[4..20]);
                end_addr.copy_from_slice(&data[20..36]);
                IpAddr::V6(Ipv6Addr::from(start_addr))..=IpAddr::V6(Ipv6Addr::from(end_addr))
            }
            _ => return Some(Err("Unsupported traffic selector type".into())),
        };

        let selector = TrafficSelector {
            ts_type,
            ip_protocol,
            port: port_range,
            addr: addr_range,
        };

        Some(Ok(selector))
    }
}

pub struct PayloadConfiguration<'a> {
    configuration_type: ConfigurationType,
    data: &'a [u8],
}

impl<'a> PayloadConfiguration<'a> {
    fn from_payload(data: &'a [u8]) -> Result<PayloadConfiguration<'a>, FormatError> {
        if data.len() < 4 {
            debug!("Not enough data in configuration payload");
            return Err("Not enough data in configuration payload".into());
        }

        let configuration_type = ConfigurationType::from_u8(data[0])?;
        Ok(PayloadConfiguration {
            configuration_type,
            data: &data[4..],
        })
    }

    pub fn configuration_type(&self) -> ConfigurationType {
        self.configuration_type
    }

    pub fn iter_attributes(&self) -> ConfigurationAttributesIter {
        ConfigurationAttributesIter { data: self.data }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ConfigurationType(u8);

impl ConfigurationType {
    pub const CFG_REQUEST: ConfigurationType = ConfigurationType(1);
    pub const CFG_REPLY: ConfigurationType = ConfigurationType(2);
    pub const CFG_SET: ConfigurationType = ConfigurationType(3);
    pub const CFG_ACK: ConfigurationType = ConfigurationType(4);

    fn from_u8(value: u8) -> Result<ConfigurationType, FormatError> {
        if (Self::CFG_REQUEST.0..=Self::CFG_ACK.0).contains(&value) {
            Ok(ConfigurationType(value))
        } else {
            debug!("Unsupported IKEv2 Configuration Type {}", value);
            Err("Unsupported IKEv2 Configuration Type".into())
        }
    }
}

impl fmt::Display for ConfigurationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::CFG_REQUEST => write!(f, "CFG_REQUEST"),
            Self::CFG_REPLY => write!(f, "CFG_REPLY"),
            Self::CFG_SET => write!(f, "CFG_SET"),
            Self::CFG_ACK => write!(f, "CFG_ACK"),
            _ => write!(f, "Unknown Configuration Type {}", self.0),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ConfigurationAttributeType(u16);

impl ConfigurationAttributeType {
    pub const INTERNAL_IP4_ADDRESS: ConfigurationAttributeType = ConfigurationAttributeType(1);
    pub const INTERNAL_IP4_NETMASK: ConfigurationAttributeType = ConfigurationAttributeType(2);
    pub const INTERNAL_IP4_DNS: ConfigurationAttributeType = ConfigurationAttributeType(3);
    pub const INTERNAL_IP4_NBNS: ConfigurationAttributeType = ConfigurationAttributeType(4);
    pub const INTERNAL_IP4_DHCP: ConfigurationAttributeType = ConfigurationAttributeType(6);
    pub const APPLICATION_VERSION: ConfigurationAttributeType = ConfigurationAttributeType(7);
    pub const INTERNAL_IP6_ADDRESS: ConfigurationAttributeType = ConfigurationAttributeType(8);
    pub const INTERNAL_IP6_DNS: ConfigurationAttributeType = ConfigurationAttributeType(10);
    pub const INTERNAL_IP6_DHCP: ConfigurationAttributeType = ConfigurationAttributeType(12);
    pub const INTERNAL_IP4_SUBNET: ConfigurationAttributeType = ConfigurationAttributeType(13);
    pub const SUPPORTED_ATTRIBUTES: ConfigurationAttributeType = ConfigurationAttributeType(14);
    pub const INTERNAL_IP6_SUBNET: ConfigurationAttributeType = ConfigurationAttributeType(15);

    pub const INTERNAL_DNS_DOMAIN: ConfigurationAttributeType = ConfigurationAttributeType(25);

    fn from_u16(value: u16) -> ConfigurationAttributeType {
        ConfigurationAttributeType(value)
    }
}

impl fmt::Display for ConfigurationAttributeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::INTERNAL_IP4_ADDRESS => write!(f, "INTERNAL_IP4_ADDRESS"),
            Self::INTERNAL_IP4_NETMASK => write!(f, "INTERNAL_IP4_NETMASK"),
            Self::INTERNAL_IP4_DNS => write!(f, "INTERNAL_IP4_DNS"),
            Self::INTERNAL_IP4_NBNS => write!(f, "INTERNAL_IP4_NBNS"),
            Self::INTERNAL_IP4_DHCP => write!(f, "INTERNAL_IP4_DHCP"),
            Self::APPLICATION_VERSION => write!(f, "APPLICATION_VERSION"),
            Self::INTERNAL_IP6_ADDRESS => write!(f, "INTERNAL_IP6_ADDRESS"),
            Self::INTERNAL_IP6_DNS => write!(f, "INTERNAL_IP6_DNS"),
            Self::INTERNAL_IP6_DHCP => write!(f, "INTERNAL_IP6_DHCP"),
            Self::INTERNAL_IP4_SUBNET => write!(f, "INTERNAL_IP4_SUBNET"),
            Self::SUPPORTED_ATTRIBUTES => write!(f, "SUPPORTED_ATTRIBUTES"),
            Self::INTERNAL_IP6_SUBNET => write!(f, "INTERNAL_IP6_SUBNET"),
            Self::INTERNAL_DNS_DOMAIN => write!(f, "INTERNAL_DNS_DOMAIN"),
            _ => write!(f, "Unknown Configuration Attribute Type {}", self.0),
        }
    }
}

pub struct ConfigurationAttribute<'a> {
    attribute_type: ConfigurationAttributeType,
    data: &'a [u8],
}

impl ConfigurationAttribute<'_> {
    pub fn attribute_type(&self) -> ConfigurationAttributeType {
        self.attribute_type
    }

    pub fn read_value(&self) -> &[u8] {
        self.data
    }
}

pub struct ConfigurationAttributesIter<'a> {
    data: &'a [u8],
}

impl<'a> Iterator for ConfigurationAttributesIter<'a> {
    type Item = Result<ConfigurationAttribute<'a>, FormatError>;

    fn next(&mut self) -> Option<Self::Item> {
        const ATTRIBUTE_TYPE_RESERVED: u16 = 1 << 15;
        const ATTRIBUTE_TYPE_MASK: u16 = !ATTRIBUTE_TYPE_RESERVED;
        if self.data.is_empty() {
            return None;
        }
        if self.data.len() < 4 {
            debug!("Not enough data in configuration attribute");
            return None;
        }
        let mut attribute_length = [0u8; 2];
        attribute_length.copy_from_slice(&self.data[2..4]);
        let attribute_length = u16::from_be_bytes(attribute_length) as usize;
        if self.data.len() < 4 + attribute_length {
            debug!("Attribute overflow");
            return None;
        }
        let data = self.data;
        self.data = &self.data[4 + attribute_length..];

        let mut attribute_type = [0u8; 2];
        attribute_type.copy_from_slice(&data[0..2]);
        let attribute_type = u16::from_be_bytes(attribute_type);
        if attribute_type & ATTRIBUTE_TYPE_RESERVED != 0x0000 {
            debug!("Attribute type reserved flag is set {:x}", attribute_type);
            return Some(Err("Attribute type reserved flag is set".into()));
        }
        let attribute_type =
            ConfigurationAttributeType::from_u16(attribute_type & ATTRIBUTE_TYPE_MASK);

        let selector = ConfigurationAttribute {
            attribute_type,
            data: &data[4..4 + attribute_length],
        };

        Some(Ok(selector))
    }
}

pub struct EncryptedMessage<'a> {
    next_payload: PayloadType,
    data: &'a [u8],
    start_offset: usize,
    fragment_number: u16,
    total_fragments: u16,
}

impl<'a> EncryptedMessage<'a> {
    fn from_encrypted_payload(
        next_payload: PayloadType,
        payload: &'a Payload,
    ) -> EncryptedMessage<'a> {
        EncryptedMessage {
            next_payload,
            data: payload.data,
            start_offset: payload.start_offset,
            fragment_number: 1,
            total_fragments: 1,
        }
    }

    fn from_encrypted_fragment_payload(
        next_payload: PayloadType,
        payload: &'a Payload,
    ) -> Result<EncryptedMessage<'a>, FormatError> {
        let data = payload.data;
        if payload.data.len() < 4 {
            Err("Not enough data in Encrypted Fragment payload".into())
        } else {
            let mut fragment_number = [0u8; 2];
            fragment_number.copy_from_slice(&data[0..2]);
            let fragment_number = u16::from_be_bytes(fragment_number);
            let mut total_fragments = [0u8; 2];
            total_fragments.copy_from_slice(&data[2..4]);
            let total_fragments = u16::from_be_bytes(total_fragments);
            Ok(EncryptedMessage {
                next_payload,
                data: &data[4..],
                start_offset: payload.start_offset + 4,
                fragment_number,
                total_fragments,
            })
        }
    }

    pub fn next_payload(&self) -> PayloadType {
        self.next_payload
    }

    pub fn fragment_number(&self) -> u16 {
        self.fragment_number
    }

    pub fn total_fragments(&self) -> u16 {
        self.total_fragments
    }

    pub fn encrypted_data(&self) -> &[u8] {
        self.data
    }
}

impl fmt::Debug for Payload<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let critical = if self.critical {
            "critical"
        } else {
            "not critical"
        };
        writeln!(f, "  Payload type {}, {}", self.payload_type, critical)?;
        if let Ok(pl_sa) = self.to_security_association() {
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
                            "        Attribute {} value {}",
                            attr.attribute_type,
                            fmt_slice_hex(attr.data)
                        )?;
                    }
                }
            }
        } else if let Ok(pl_kex) = self.to_key_exchange() {
            writeln!(
                f,
                "    DH Group num {} value {}",
                pl_kex.read_group_num(),
                fmt_slice_hex(pl_kex.read_value())
            )?;
        } else if let Ok(pl_id) = self.to_identification() {
            let identification_type = pl_id.read_identification_type();
            writeln!(
                f,
                "    Identification type {} value {}",
                identification_type,
                fmt_slice_hex(pl_id.read_value())
            )?;
        } else if let Ok(pl_cert) = self.to_certificate() {
            writeln!(
                f,
                "    Certificate format {} data {}",
                pl_cert.encoding(),
                fmt_slice_hex(pl_cert.read_value())
            )?;
        } else if let Ok(pl_certreq) = self.to_certificate_request() {
            writeln!(
                f,
                "    Certificate request format {} data {}",
                pl_certreq.read_encoding(),
                fmt_slice_hex(pl_certreq.read_value())
            )?;
        } else if let Ok(pl_auth) = self.to_authentication() {
            writeln!(
                f,
                "    Authentication method {} data {}",
                pl_auth.read_method(),
                fmt_slice_hex(pl_auth.read_value())
            )?;
        } else if let Ok(pl_nonce) = self.to_nonce() {
            writeln!(f, "    Value {}", fmt_slice_hex(pl_nonce.read_value()))?;
        } else if let Ok(pl_notify) = self.to_notify() {
            write!(f, "    Notify protocol ID ")?;
            match pl_notify.protocol_id {
                Some(protocol) => write!(f, "{}", protocol)?,
                None => write!(f, "None")?,
            }
            write!(f, " SPI {} type {}", pl_notify.spi, pl_notify.message_type,)?;
            if pl_notify.message_type == NotifyMessageType::SIGNATURE_HASH_ALGORITHMS {
                write!(f, " list",)?;
                if let Ok(hash_algorithms) = pl_notify.to_signature_hash_algorithms() {
                    for alg in hash_algorithms {
                        write!(f, " {}", alg)?;
                    }
                } else {
                    write!(f, " error")?;
                }
                writeln!(f)?;
            } else {
                writeln!(f, " value {}", fmt_slice_hex(pl_notify.read_value()))?;
            }
        } else if let Ok(pl_delete) = self.to_delete() {
            write!(f, "    Delete protocol ID {} SPI", pl_delete.protocol_id)?;
            for delete_spi in pl_delete.iter_spi() {
                write!(f, " {}", delete_spi)?;
            }
            writeln!(f)?;
        } else if let Ok(pl_ts) = self.to_traffic_selector() {
            for ts in pl_ts.iter_traffic_selectors() {
                let ts = match ts {
                    Ok(ts) => ts,
                    Err(err) => {
                        writeln!(f, "    Traffic selector invalid {}", err)?;
                        continue;
                    }
                };
                writeln!(
                    f,
                    "    TS Type {} IP protocol {} ports {}-{} addresses {:?}-{:?}",
                    ts.ts_type,
                    ts.ip_protocol,
                    ts.port.start(),
                    ts.port.end(),
                    ts.addr.start(),
                    ts.addr.end(),
                )?;
            }
        } else if let Ok(pl_ca) = self.to_configuration() {
            writeln!(f, "    Configuration type {}", pl_ca.configuration_type())?;
            for attr in pl_ca.iter_attributes() {
                let attr = match attr {
                    Ok(attr) => attr,
                    Err(err) => {
                        writeln!(f, "      Configuration attribute invalid {}", err)?;
                        continue;
                    }
                };
                writeln!(
                    f,
                    "      Attribute Type {} value {}",
                    attr.attribute_type(),
                    fmt_slice_hex(attr.read_value()),
                )?;
            }
        } else if let Ok(pl_enc) = self.encrypted_data() {
            writeln!(
                f,
                "    Fragment {} out of {} next type {}",
                pl_enc.fragment_number(),
                pl_enc.total_fragments(),
                pl_enc.next_payload(),
            )?;
            writeln!(f, "    Data {}", fmt_slice_hex(pl_enc.encrypted_data()))?;
        } else {
            writeln!(f, "    Data {}", fmt_slice_hex(self.data))?;
        }
        Ok(())
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
            pl.fmt(f)?;
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
