use std::{
    error, fmt,
    net::{Ipv4Addr, Ipv6Addr},
    ops::RangeInclusive,
};

use log::{debug, warn};

use crate::logger::fmt_slice_hex;

use super::Nat64Prefix;

// As defined in RFC 1035, Sections 2.3.4 and 4.2.1.
pub(super) const MAX_PACKET_SIZE_IPV4: usize = 512;

// As documented in
// https://www.ietf.org/archive/id/draft-hinden-v6ops-dns-00.html#name-dns-over-udp,
// IPv6 has a larger MTU.
// Also, local-link IKEv2 has a larger MTU on IPv4 as well.
pub(super) const MAX_PACKET_SIZE_RESPONSE: usize = 1280 - 40;

// As defined in RFC 1035, Section 2.3.4 and 3.1.
// The domain length is limited by the packet size.
const MAX_DOMAIN_LENGTH: usize = 255;

// If every subdomain is a single character and the domain length
// is at maximum, every subdomain will consume 2 bytes:
// length + character, or 2-byte offset.
const MAX_DOMAIN_LABELS: usize = MAX_DOMAIN_LENGTH / 2;

// Contains a subset of RFC 5735.
const UNROUTABLE_SUBNETS: [RangeInclusive<Ipv4Addr>; 4] = [
    // "this" network that won't be used.
    Ipv4Addr::new(0, 0, 0, 0)..=Ipv4Addr::new(0, 255, 255, 255),
    // Loopback (shouldn't be routable).
    Ipv4Addr::new(127, 0, 0, 0)..=Ipv4Addr::new(127, 255, 255, 255),
    // Link-local (requires DHCP).
    Ipv4Addr::new(169, 254, 0, 0)..=Ipv4Addr::new(169, 254, 255, 255),
    // Multicast, reserved Class E and broadcast addresses.
    Ipv4Addr::new(224, 0, 0, 0)..=Ipv4Addr::new(255, 255, 255, 255),
];

pub(super) struct DnsPacket<'a> {
    data: &'a [u8],
}

#[derive(PartialEq)]
enum Qr {
    Query,
    Response,
}

impl fmt::Display for Qr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Qr::Query => write!(f, "Query"),
            Qr::Response => write!(f, "Response"),
        }
    }
}

enum Opcode {
    StandardQuery,
    InverseQuery,
    Status,
    Reserved(u8),
}

impl Opcode {
    fn from_u8(code: u8) -> Opcode {
        match code {
            0 => Opcode::StandardQuery,
            1 => Opcode::InverseQuery,
            2 => Opcode::Status,
            status => Opcode::Reserved(status),
        }
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Opcode::StandardQuery => write!(f, "Standard query"),
            Opcode::InverseQuery => write!(f, "Inverse query"),
            Opcode::Status => write!(f, "Status"),
            Opcode::Reserved(code) => write!(f, "Reserved({})", code),
        }
    }
}

enum ResponseCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    Reserved(u8),
}

impl ResponseCode {
    fn from_u8(code: u8) -> ResponseCode {
        match code {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormatError,
            2 => ResponseCode::ServerFailure,
            3 => ResponseCode::NameError,
            4 => ResponseCode::NotImplemented,
            5 => ResponseCode::Refused,
            code => ResponseCode::Reserved(code & 0x0f),
        }
    }

    fn to_u8(&self) -> u8 {
        match self {
            ResponseCode::NoError => 0,
            ResponseCode::FormatError => 1,
            ResponseCode::ServerFailure => 2,
            ResponseCode::NameError => 3,
            ResponseCode::NotImplemented => 4,
            ResponseCode::Refused => 5,
            ResponseCode::Reserved(code) => code & 0x0f,
        }
    }
}

impl fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponseCode::NoError => write!(f, "No error"),
            ResponseCode::FormatError => write!(f, "Format error"),
            ResponseCode::ServerFailure => write!(f, "Server failure"),
            ResponseCode::NameError => write!(f, "Name error"),
            ResponseCode::NotImplemented => write!(f, "Not implemented"),
            ResponseCode::Refused => write!(f, "Refused"),
            ResponseCode::Reserved(code) => write!(f, "Reserved({})", code),
        }
    }
}

struct DnsPacketFlags(u16);

impl DnsPacketFlags {
    const RESPONSE_BIT: u16 = 1 << 15;
    const AUTHORITATIVE_ANSWER: u16 = 1 << 10;
    const TRUNCATION: u16 = 1 << 9;
    const RECURSION_DESIRED: u16 = 1 << 8;
    const RECURSION_AVAILABLE: u16 = 1 << 7;

    const OPCODE_MASK: u8 = 0x0f;
    const OPCODE_OFFSET: usize = 11;
    const ZERO_BYTES_MASK: u16 = 0x07 << 4;

    const RESPONSE_CODE_MASK: u16 = 0x000f;

    fn from_data(data: &[u8]) -> DnsPacketFlags {
        let mut flag_bits = [0u8; 2];
        flag_bits.copy_from_slice(&data[2..4]);
        DnsPacketFlags(u16::from_be_bytes(flag_bits))
    }

    fn to_be_bytes(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }

    fn qr(&self) -> Qr {
        if (self.0 & Self::RESPONSE_BIT) == 0 {
            Qr::Query
        } else {
            Qr::Response
        }
    }

    fn toggle_mask(&mut self, mask: u16, enable: bool) {
        if enable {
            self.0 |= mask
        } else {
            self.0 &= !mask
        }
    }

    fn set_qr(&mut self, qr: Qr) {
        match qr {
            Qr::Query => self.toggle_mask(Self::RESPONSE_BIT, false),
            Qr::Response => self.toggle_mask(Self::RESPONSE_BIT, true),
        }
    }

    fn opcode(&self) -> Opcode {
        let opcode = (self.0 >> Self::OPCODE_OFFSET) as u8 & Self::OPCODE_MASK;
        Opcode::from_u8(opcode)
    }

    fn authoritative_answer(&self) -> bool {
        self.0 & Self::AUTHORITATIVE_ANSWER == Self::AUTHORITATIVE_ANSWER
    }

    fn truncation(&self) -> bool {
        self.0 & Self::TRUNCATION == Self::TRUNCATION
    }

    fn recursion_desired(&self) -> bool {
        self.0 & Self::RECURSION_DESIRED == Self::RECURSION_DESIRED
    }

    fn recursion_available(&self) -> bool {
        self.0 & Self::RECURSION_AVAILABLE == Self::RECURSION_AVAILABLE
    }

    fn reserved_zero(&self) -> bool {
        self.0 & Self::ZERO_BYTES_MASK == 0
    }

    fn clear_reserved_zero(&mut self) {
        self.toggle_mask(Self::ZERO_BYTES_MASK, false)
    }

    fn response_code(&self) -> ResponseCode {
        let response_code = (self.0 & Self::RESPONSE_CODE_MASK) as u8;
        ResponseCode::from_u8(response_code)
    }

    fn set_response_code(&mut self, rcode: ResponseCode) {
        self.0 = (self.0 & !Self::RESPONSE_CODE_MASK) | (rcode.to_u8() as u16)
    }
}

impl DnsPacket<'_> {
    const DNS_HEADER_SIZE: usize = 12;

    pub fn from_udp_payload(data: &[u8]) -> Result<DnsPacket, DnsError> {
        // First 8 bytes are the UDP header.
        if data.len() < Self::DNS_HEADER_SIZE {
            Err("DNS packet size is smaller than header size".into())
        } else {
            // TODO: validate all headers.
            Ok(DnsPacket { data })
        }
    }

    fn id(&self) -> u16 {
        let mut id = [0u8; 2];
        id.copy_from_slice(&self.data[0..2]);
        u16::from_be_bytes(id)
    }

    fn flags(&self) -> DnsPacketFlags {
        DnsPacketFlags::from_data(self.data)
    }

    fn iter_sections(&self) -> SectionIter {
        let mut qdcount = [0u8; 2];
        qdcount.copy_from_slice(&self.data[4..6]);
        let qdcount = u16::from_be_bytes(qdcount);

        let mut ancount = [0u8; 2];
        ancount.copy_from_slice(&self.data[6..8]);
        let ancount = u16::from_be_bytes(ancount);

        let mut nscount = [0u8; 2];
        nscount.copy_from_slice(&self.data[8..10]);
        let nscount = u16::from_be_bytes(nscount);

        let mut arcount = [0u8; 2];
        arcount.copy_from_slice(&self.data[10..12]);
        let arcount = u16::from_be_bytes(arcount);

        SectionIter {
            data: self.data,
            start_offset: Self::DNS_HEADER_SIZE,
            qdcount,
            ancount,
            nscount,
            arcount,
        }
    }

    pub fn matches_nat64(&self, suffix: &[Vec<u8>]) -> bool {
        self.iter_sections().any(|section| match section {
            Ok(Section::Question(q)) => {
                let qtype = q.qtype().to_rtype();
                if qtype == Some(RrType::SVCB) || qtype == Some(RrType::HTTPS) {
                    // Ensure macOS doesn't switdh to DoH (as documented in RFC 9461).
                    match q.iter_qname().next() {
                        Some(Ok((_, label))) => label == "_dns".as_bytes(),
                        Some(Err(err)) => {
                            warn!(
                                "Failed to parse DNS packet while checking if it's a DoH chesk: {}",
                                err
                            );
                            false
                        }
                        None => false,
                    }
                } else if qtype == Some(RrType::A) || qtype == Some(RrType::AAAA) {
                    let label = q.iter_qname();
                    let label_length = label.size_hint().0;
                    if label_length < suffix.len() {
                        false
                    } else {
                        label.skip(label_length - suffix.len()).zip(suffix).all(
                            |(label, check_label)| match label {
                                Ok((_, label)) => label.eq_ignore_ascii_case(check_label),
                                Err(err) => {
                                    warn!("Failed to parse DNS packet while checking if it matches suffix: {}", err);
                                    false
                                }
                            },
                        )
                    }
                } else {
                    false
                }
            }
            Err(err) => {
                warn!(
                    "Failed to parse DNS packet while checking if it matches suffix: {}",
                    err
                );
                false
            }
            _ => false,
        })
    }
}

impl fmt::Display for DnsPacket<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let flags = self.flags();
        write!(f, "TXID {} {}: {}", self.id(), flags.qr(), flags.opcode())?;
        if flags.authoritative_answer() {
            write!(f, ", Authoritative Answer")?;
        }
        if flags.truncation() {
            write!(f, ", Truncation")?;
        }
        if flags.recursion_desired() {
            write!(f, ", Recursion desired")?;
        }
        if flags.recursion_available() {
            write!(f, ", Recursion available")?;
        }
        if !flags.reserved_zero() {
            write!(f, ", non-zero Reserved zero")?;
        }
        write!(f, ": {}", flags.response_code())?;

        for (i, section) in self.iter_sections().enumerate() {
            if i == 0 {
                write!(f, " -> ")?;
            } else {
                write!(f, "; ")?;
            }
            match &section {
                Ok(Section::Question(q)) => write!(f, "Q: {}", q)?,
                Ok(Section::Answer(a)) => write!(f, "A: {}", a)?,
                Ok(Section::Nameserver(ns)) => write!(f, "NS: {}", ns)?,
                Ok(Section::AdditionalRecord(ar)) => write!(f, "AR: {}", ar)?,
                Err(err) => write!(f, "Error: {}", err)?,
            }
        }
        Ok(())
    }
}

struct SectionIter<'a> {
    data: &'a [u8],
    start_offset: usize,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

impl<'a> Iterator for SectionIter<'a> {
    type Item = Result<Section<'a>, DnsError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            None
        } else if self.start_offset > self.data.len() {
            self.data = &[];
            Some(Err("Section start overflow".into()))
        } else if self.qdcount > 0 {
            self.qdcount -= 1;
            let question = match Question::from_data(self.data, self.start_offset) {
                Ok(question) => question,
                Err(err) => {
                    self.data = &[];
                    return Some(Err(err));
                }
            };
            self.start_offset = question.qname_end_offset + 4;
            Some(Ok(Section::Question(question)))
        } else if self.ancount > 0 {
            self.ancount -= 1;
            let rr = match ResourceRecord::from_data(self.data, self.start_offset) {
                Ok(rr) => rr,
                Err(err) => {
                    self.data = &[];
                    return Some(Err(err));
                }
            };
            self.start_offset = rr.name_end_offset + 10 + rr.rd_length() as usize;
            Some(Ok(Section::Answer(rr)))
        } else if self.nscount > 0 {
            self.nscount -= 1;
            let rr = match ResourceRecord::from_data(self.data, self.start_offset) {
                Ok(rr) => rr,
                Err(err) => {
                    self.data = &[];
                    return Some(Err(err));
                }
            };
            self.start_offset = rr.name_end_offset + 10 + rr.rd_length() as usize;
            Some(Ok(Section::Nameserver(rr)))
        } else if self.arcount > 0 {
            self.arcount -= 1;
            let rr = match ResourceRecord::from_data(self.data, self.start_offset) {
                Ok(rr) => rr,
                Err(err) => {
                    self.data = &[];
                    return Some(Err(err));
                }
            };
            self.start_offset = rr.name_end_offset + 10 + rr.rd_length() as usize;
            Some(Ok(Section::AdditionalRecord(rr)))
        } else {
            None
        }
    }
}

enum Section<'a> {
    Question(Question<'a>),
    Answer(ResourceRecord<'a>),
    Nameserver(ResourceRecord<'a>),
    AdditionalRecord(ResourceRecord<'a>),
}

// First two bits are 11.
const LABEL_POINTER_MASK: u8 = 0xc0;

// First two bits are 11.
const LABEL_POINTER_FULL_MASK: u16 = 0xc000;

#[derive(Clone, Copy)]
struct LabelIter<'a> {
    start_offset: usize,
    data: &'a [u8],
    read_labels: u8,
}

impl<'a> Iterator for LabelIter<'a> {
    type Item = Result<(usize, &'a [u8]), DnsError>;

    fn next(&mut self) -> Option<Self::Item> {
        const POINTER_UPPER_HALF_MASK: u8 = !LABEL_POINTER_MASK;
        if self.data.is_empty() {
            return None;
        }
        if self.read_labels as usize >= MAX_DOMAIN_LABELS {
            self.data = &[];
            return Some(Err("Domain length exceeded, possible loop detected".into()));
        }
        let mut start_offset = self.start_offset;
        let mut length;

        loop {
            length = self.data[start_offset];
            let is_pointer = match length & LABEL_POINTER_MASK {
                LABEL_POINTER_MASK => true,
                0x00 => false,
                _ => {
                    self.data = &[];
                    return Some(Err("Unexpected bits in label length".into()));
                }
            };
            if self.start_offset + 1 > self.data.len() {
                self.data = &[];
                return Some(Err("Not enough data in label".into()));
            }
            if !is_pointer {
                start_offset += 1;
                break;
            } else {
                if self.start_offset + 2 > self.data.len() {
                    self.data = &[];
                    return Some(Err("Not enough data in pointer label".into()));
                }
                let pointer_offset = {
                    let upper_half = length & POINTER_UPPER_HALF_MASK;
                    let lower_half = self.data[start_offset + 1];
                    let pointer_offset = [upper_half, lower_half];
                    u16::from_be_bytes(pointer_offset) as usize
                };

                // Prevent loops as instructed in RFC 9267, Section 2.
                if pointer_offset >= start_offset {
                    self.data = &[];
                    return Some(Err(
                        "Label pointer pointing past its location, avoiding loop".into(),
                    ));
                } else if pointer_offset == 0 {
                    self.data = &[];
                    return Some(Err("Label pointer pointing beginning of packet".into()));
                }
                start_offset = pointer_offset;
            }
        }
        let length = length as usize;
        if length == 0 {
            // Last segment termination.
            return None;
        } else if start_offset > self.data.len() {
            self.data = &[];
            return Some(Err("Label start offset overflow".into()));
        } else if start_offset + length > self.data.len() {
            self.data = &[];
            return Some(Err("Label length overflow".into()));
        }

        let label = &self.data[start_offset..start_offset + length];
        self.start_offset = start_offset + length;

        // Prevent another loop - where a sequence of labels ends with a backwards pointer to the
        // first label in the sequence.
        self.read_labels += 1;

        Some(Ok((start_offset - 1, label)))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        // This can be time-consuming, better do it just once.
        let remain = self.count();
        (remain, Some(remain))
    }
}

impl LabelIter<'_> {
    fn fmt_domain(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.enumerate().try_for_each(|(i, segment)| {
            let (_, segment) = match segment {
                Ok(segment) => segment,
                Err(err) => return write!(f, "[err: {}]", err),
            };
            let segment = match std::str::from_utf8(segment) {
                Ok(segment) => segment,
                Err(err) => return write!(f, "[utf8 err: {}]", err),
            };
            if i == 0 {
                write!(f, "{}", segment)
            } else {
                write!(f, ".{}", segment)
            }
        })
    }
}

#[derive(PartialEq, Eq)]
struct RrType(u16);

impl RrType {
    const A: RrType = RrType(1);
    const NS: RrType = RrType(2);
    const MD: RrType = RrType(3);
    const MF: RrType = RrType(4);
    const CNAME: RrType = RrType(5);
    const SOA: RrType = RrType(6);
    const MB: RrType = RrType(7);
    const MG: RrType = RrType(8);
    const MR: RrType = RrType(9);
    const NULL: RrType = RrType(10);
    const WKS: RrType = RrType(11);
    const PTR: RrType = RrType(12);
    const HINFO: RrType = RrType(13);
    const MINFO: RrType = RrType(14);
    const MX: RrType = RrType(15);
    const TXT: RrType = RrType(16);

    const AAAA: RrType = RrType(28);
    const OPT: RrType = RrType(41);
    const SVCB: RrType = RrType(64);
    const HTTPS: RrType = RrType(65);

    fn from_u16(code: u16) -> RrType {
        RrType(code)
    }

    fn to_be_bytes(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }

    fn to_qtype(&self) -> RrQtype {
        RrQtype::from_u16(self.0)
    }
}

impl fmt::Display for RrType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::A => write!(f, "A"),
            Self::NS => write!(f, "NS"),
            Self::MD => write!(f, "MD"),
            Self::MF => write!(f, "MF"),
            Self::CNAME => write!(f, "CNAME"),
            Self::SOA => write!(f, "SOA"),
            Self::MB => write!(f, "MB"),
            Self::MG => write!(f, "MG"),
            Self::MR => write!(f, "MR"),
            Self::NULL => write!(f, "NULL"),
            Self::WKS => write!(f, "WKS"),
            Self::PTR => write!(f, "PTR"),
            Self::HINFO => write!(f, "HINFO"),
            Self::MINFO => write!(f, "MINFO"),
            Self::MX => write!(f, "MX"),
            Self::TXT => write!(f, "TXT"),
            Self::AAAA => write!(f, "AAAA"),
            Self::OPT => write!(f, "OPT"),
            Self::SVCB => write!(f, "SVCB"),
            Self::HTTPS => write!(f, "HTTPS"),
            RrType(code) => write!(f, "Unknown({})", code),
        }
    }
}

#[derive(PartialEq, Eq, PartialOrd)]
struct RrQtype(u16);

impl RrQtype {
    const AXFR: RrQtype = RrQtype(252);
    const MAILB: RrQtype = RrQtype(253);
    const MAILA: RrQtype = RrQtype(254);
    const ALL: RrQtype = RrQtype(255);

    fn from_u16(code: u16) -> RrQtype {
        RrQtype(code)
    }

    fn to_be_bytes(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }

    fn to_rtype(&self) -> Option<RrType> {
        if (Self::AXFR..=Self::ALL).contains(self) {
            None
        } else {
            Some(RrType::from_u16(self.0))
        }
    }
}

impl fmt::Display for RrQtype {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::AXFR => write!(f, "AXFR"),
            Self::MAILB => write!(f, "MAILB"),
            Self::MAILA => write!(f, "MAILA"),
            Self::ALL => write!(f, "*"),
            RrQtype(code) => RrType(code).fmt(f),
        }
    }
}

#[derive(PartialEq, Eq)]
struct RrClass(u16);

impl RrClass {
    const IN: RrClass = RrClass(1);
    const CS: RrClass = RrClass(2);
    const CH: RrClass = RrClass(3);
    const HS: RrClass = RrClass(4);

    fn from_u16(code: u16) -> RrClass {
        RrClass(code)
    }
}

impl fmt::Display for RrClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::IN => write!(f, "IN"),
            Self::CS => write!(f, "CS(Obsolete)"),
            Self::CH => write!(f, "CH"),
            Self::HS => write!(f, "HS"),
            RrClass(code) => write!(f, "Unknown({})", code),
        }
    }
}
#[derive(PartialEq, Eq)]
struct RrQclass(u16);

impl RrQclass {
    const ALL: RrQclass = RrQclass(255);

    fn from_u16(code: u16) -> RrQclass {
        RrQclass(code)
    }

    fn to_be_bytes(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

impl fmt::Display for RrQclass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::ALL => write!(f, "*"),
            RrQclass(code) => RrClass(code).fmt(f),
        }
    }
}

struct SoaRecord<'a> {
    mname_start_offset: usize,
    rname_start_offset: usize,
    data: &'a [u8],
    attributes: &'a [u8],
}

impl SoaRecord<'_> {
    fn from_data(data: &[u8], start_offset: usize, length: usize) -> Result<SoaRecord, DnsError> {
        if length < 22 {
            return Err("Not enough data in SOA rdata length".into());
        }
        let mname_start_offset = start_offset;
        let rname_start_offset =
            if let Some(rname_start_offset) = name_end_offset(data, mname_start_offset) {
                rname_start_offset
            } else {
                return Err("Not enough bytes in SOA MNAME length".into());
            };
        if rname_start_offset > start_offset + length {
            return Err("SOA MNAME overflow".into());
        }
        if let Some(attributes_start_offset) = name_end_offset(data, rname_start_offset) {
            if attributes_start_offset + 20 != start_offset + length {
                return Err("SOA RNAME overflow".into());
            }
        } else {
            return Err("Not enough bytes in SOA RNAME length".into());
        }
        Ok(SoaRecord {
            mname_start_offset,
            rname_start_offset,
            data,
            attributes: &data[start_offset + length - 20..start_offset + length],
        })
    }

    fn iter_mname(&self) -> LabelIter {
        LabelIter {
            start_offset: self.mname_start_offset,
            data: self.data,
            read_labels: 0,
        }
    }

    fn iter_rname(&self) -> LabelIter {
        LabelIter {
            start_offset: self.rname_start_offset,
            data: self.data,
            read_labels: 0,
        }
    }

    fn serial(&self) -> u32 {
        let mut serial = [0u8; 4];
        serial.copy_from_slice(&self.attributes[0..4]);
        u32::from_be_bytes(serial)
    }

    fn refresh(&self) -> u32 {
        let mut refresh = [0u8; 4];
        refresh.copy_from_slice(&self.attributes[4..8]);
        u32::from_be_bytes(refresh)
    }

    fn retry(&self) -> u32 {
        let mut retry = [0u8; 4];
        retry.copy_from_slice(&self.attributes[8..12]);
        u32::from_be_bytes(retry)
    }

    fn expire(&self) -> u32 {
        let mut expire = [0u8; 4];
        expire.copy_from_slice(&self.attributes[12..16]);
        u32::from_be_bytes(expire)
    }

    fn minimum(&self) -> u32 {
        let mut minimum = [0u8; 4];
        minimum.copy_from_slice(&self.attributes[16..20]);
        u32::from_be_bytes(minimum)
    }
}

impl fmt::Display for SoaRecord<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MNAME=")?;
        self.iter_mname().fmt_domain(f)?;
        write!(f, " RNAME=")?;
        self.iter_rname().fmt_domain(f)?;
        write!(
            f,
            " SERIAL={} REFRESH={} RETRY={} EXPIRE={} MINIMUM={}",
            self.serial(),
            self.refresh(),
            self.retry(),
            self.expire(),
            self.minimum()
        )
    }
}

struct Question<'a> {
    data: &'a [u8],
    start_offset: usize,
    qname_end_offset: usize,
}

fn name_end_offset(data: &[u8], start_offset: usize) -> Option<usize> {
    let mut start_offset = start_offset;
    loop {
        if start_offset + 1 > data.len() {
            return None;
        }
        let length = data[start_offset];
        start_offset += 1;
        let is_pointer = length & LABEL_POINTER_MASK == LABEL_POINTER_MASK;
        if is_pointer {
            return Some(start_offset + 1);
        } else if length == 0 {
            return Some(start_offset);
        } else {
            start_offset += length as usize;
        }
    }
}

impl Question<'_> {
    fn from_data(data: &[u8], start_offset: usize) -> Result<Question, DnsError> {
        let qname_end_offset = if let Some(qname_end_offset) = name_end_offset(data, start_offset) {
            qname_end_offset
        } else {
            return Err("Not enough bytes in QNAME length".into());
        };
        if qname_end_offset > data.len() {
            Err("QNAME overflow".into())
        } else if qname_end_offset + 4 > data.len() {
            Err("Not enough bytes in Question".into())
        } else {
            Ok(Question {
                data,
                start_offset,
                qname_end_offset,
            })
        }
    }

    fn iter_qname(&self) -> LabelIter {
        LabelIter {
            start_offset: self.start_offset,
            data: self.data,
            read_labels: 0,
        }
    }

    fn qtype(&self) -> RrQtype {
        let mut qtype = [0u8; 2];
        qtype.copy_from_slice(&self.data[self.qname_end_offset..self.qname_end_offset + 2]);
        RrQtype::from_u16(u16::from_be_bytes(qtype))
    }

    fn qclass(&self) -> RrQclass {
        let mut qclass = [0u8; 2];
        qclass.copy_from_slice(&self.data[self.qname_end_offset + 2..self.qname_end_offset + 4]);
        RrQclass::from_u16(u16::from_be_bytes(qclass))
    }
}

impl fmt::Display for Question<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.iter_qname().fmt_domain(f)?;
        write!(f, " {} {}", self.qtype(), self.qclass())
    }
}

enum Rdata<'a> {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Name(LabelIter<'a>),
    Soa(SoaRecord<'a>),
    Unknown(&'a [u8]),
}

impl fmt::Display for Rdata<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rdata::Ipv4(addr) => addr.fmt(f),
            Rdata::Ipv6(addr) => addr.fmt(f),
            Rdata::Name(label) => label.fmt_domain(f),
            Rdata::Soa(soa) => soa.fmt(f),
            Rdata::Unknown(data) => fmt_slice_hex(data).fmt(f),
        }
    }
}

struct ResourceRecord<'a> {
    data: &'a [u8],
    start_offset: usize,
    name_end_offset: usize,
}

impl ResourceRecord<'_> {
    fn from_data(data: &[u8], start_offset: usize) -> Result<ResourceRecord, DnsError> {
        let name_end_offset = if let Some(name_end_offset) = name_end_offset(data, start_offset) {
            name_end_offset
        } else {
            return Err("Not enough bytes in NAME length".into());
        };
        if name_end_offset > data.len() {
            Err("NAME overflow".into())
        } else if name_end_offset + 10 > data.len() {
            Err("Not enough bytes in Resource Record".into())
        } else {
            let rr = ResourceRecord {
                data,
                start_offset,
                name_end_offset,
            };
            let rdata_end = start_offset + 10 + rr.rd_length() as usize;
            if rdata_end > data.len() {
                Err("RDLENGTH overflow".into())
            } else {
                Ok(rr)
            }
        }
    }

    fn iter_name(&self) -> LabelIter {
        LabelIter {
            start_offset: self.start_offset,
            data: self.data,
            read_labels: 0,
        }
    }

    fn rr_type(&self) -> RrType {
        let mut rr_type = [0u8; 2];
        rr_type.copy_from_slice(&self.data[self.name_end_offset..self.name_end_offset + 2]);
        RrType::from_u16(u16::from_be_bytes(rr_type))
    }

    fn rr_class(&self) -> RrClass {
        let mut rr_class = [0u8; 2];
        rr_class.copy_from_slice(&self.data[self.name_end_offset + 2..self.name_end_offset + 4]);
        RrClass::from_u16(u16::from_be_bytes(rr_class))
    }

    fn ttl(&self) -> i32 {
        let mut ttl = [0u8; 4];
        ttl.copy_from_slice(&self.data[self.name_end_offset + 4..self.name_end_offset + 8]);
        i32::from_be_bytes(ttl)
    }

    fn rd_length(&self) -> u16 {
        let mut rdlength = [0u8; 2];
        rdlength.copy_from_slice(&self.data[self.name_end_offset + 8..self.name_end_offset + 10]);
        u16::from_be_bytes(rdlength)
    }

    fn rdata(&self) -> Result<Rdata, DnsError> {
        // This is validated in the constructor.
        let start_offset = self.name_end_offset + 10;
        let rd_length = self.rd_length() as usize;
        let data = &self.data[start_offset..start_offset + rd_length];
        match self.rr_type() {
            RrType::CNAME
            | RrType::MB
            | RrType::MD
            | RrType::MF
            | RrType::MG
            | RrType::MR
            | RrType::NS
            | RrType::PTR => Ok(Rdata::Name(LabelIter {
                start_offset,
                data: self.data,
                read_labels: 0,
            })),
            RrType::A => {
                if data.len() == 4 {
                    let mut ipv4_addr = [0u8; 4];
                    ipv4_addr.copy_from_slice(data);
                    Ok(Rdata::Ipv4(Ipv4Addr::from(ipv4_addr)))
                } else {
                    Err("Unexpected A record rdata length".into())
                }
            }
            RrType::AAAA => {
                if data.len() == 16 {
                    let mut ipv6_addr = [0u8; 16];
                    ipv6_addr.copy_from_slice(data);
                    Ok(Rdata::Ipv6(Ipv6Addr::from(ipv6_addr)))
                } else {
                    Err("Unexpected AAAA record rdata length".into())
                }
            }
            RrType::SOA => {
                if rd_length > 20 {
                    Ok(Rdata::Soa(SoaRecord::from_data(
                        self.data,
                        start_offset,
                        rd_length,
                    )?))
                } else {
                    Err("Not enough data in SOA rdata length".into())
                }
            }
            _ => Ok(Rdata::Unknown(data)),
        }
    }
}

impl fmt::Display for ResourceRecord<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.iter_name().fmt_domain(f)?;
        write!(
            f,
            " {} {} TTL={}",
            self.rr_type(),
            self.rr_class(),
            self.ttl(),
        )?;
        match self.rdata() {
            Ok(data) => write!(f, " {}", data),
            Err(err) => write!(f, " [err: {}]", err),
        }
    }
}

struct CompressionItem {
    offset: usize,
    length: u8,
}

struct CompressionMap {
    labels: Vec<CompressionItem>,
}

impl CompressionMap {
    fn new() -> CompressionMap {
        CompressionMap {
            labels: Vec::with_capacity(MAX_DOMAIN_LABELS),
        }
    }

    fn find_match(&self, domain: LabelIter, domain_length: u8) -> Option<usize> {
        self.labels
            .iter()
            .find(|check_label| {
                if check_label.length == domain_length {
                    let check_label = LabelIter {
                        start_offset: check_label.offset,
                        data: domain.data,
                        read_labels: 0,
                    };
                    check_label.zip(domain).all(|(check_label, domain_label)| {
                        if let (Ok((_, check_label)), Ok((_, domain_label))) =
                            (check_label, domain_label)
                        {
                            check_label.eq_ignore_ascii_case(domain_label)
                        } else {
                            false
                        }
                    })
                } else {
                    false
                }
            })
            .map(|found_label| found_label.offset)
    }

    fn add_label(&mut self, offset: usize, length: u8) {
        if self.labels.len() < self.labels.capacity() {
            self.labels.push(CompressionItem { offset, length })
        }
    }

    fn clear(&mut self) {
        self.labels.clear()
    }
}

pub(super) struct Dns64Translator {
    compression_map: CompressionMap,
    nat64_prefix: Nat64Prefix,
}

pub(super) enum DnsTranslationAction {
    Forward(usize),
    ReplyToSender(usize),
}

impl Dns64Translator {
    pub fn new(nat64_prefix: Nat64Prefix) -> Dns64Translator {
        Dns64Translator {
            compression_map: CompressionMap::new(),
            nat64_prefix,
        }
    }

    fn write_header(
        dest: &mut [u8],
        request_data: &[u8],
        flags: DnsPacketFlags,
        qdcount: usize,
        ancount: usize,
        nscount: usize,
        arcount: usize,
    ) {
        dest[0..2].copy_from_slice(&request_data[0..2]);
        dest[2..4].copy_from_slice(&flags.to_be_bytes());
        dest[4..6].copy_from_slice(&(qdcount as u16).to_be_bytes());
        dest[6..8].copy_from_slice(&(ancount as u16).to_be_bytes());
        dest[8..10].copy_from_slice(&(nscount as u16).to_be_bytes());
        dest[10..12].copy_from_slice(&(arcount as u16).to_be_bytes());
    }

    fn write_error_response(
        dest: &mut [u8],
        request_data: &[u8],
        rcode: ResponseCode,
        qdcount: usize,
        length: usize,
    ) -> DnsTranslationAction {
        // Keep all questions and data for the client to observe.
        let mut flags = DnsPacketFlags::from_data(request_data);
        flags.set_qr(Qr::Response);
        flags.set_response_code(rcode);
        flags.clear_reserved_zero();
        Self::write_header(dest, request_data, flags, qdcount, 0, 0, 0);
        DnsTranslationAction::ReplyToSender(length)
    }

    fn write_label(
        &mut self,
        dest: &mut [u8],
        mut length: usize,
        domain: LabelIter,
    ) -> Result<usize, DnsError> {
        let domain_length = domain.size_hint().0;
        for (label_index, label) in domain.enumerate() {
            let (start_offset, label) = label?;
            let subdomain_iter = LabelIter {
                start_offset,
                data: domain.data,
                read_labels: label_index as u8,
            };

            if let Some(found_match) = self
                .compression_map
                .find_match(subdomain_iter, (domain_length - label_index) as u8)
            {
                if length + 2 > dest.len() {
                    return Err("Not enough data to write label".into());
                }
                let label_offset = LABEL_POINTER_FULL_MASK | (found_match as u16);
                dest[length..length + 2].copy_from_slice(&label_offset.to_be_bytes());
                length += 2;
                return Ok(length);
            } else {
                if length + 1 + label.len() > dest.len() {
                    return Err("Not enough data to write label".into());
                }
                self.compression_map
                    .add_label(length, (domain_length - label_index) as u8);
                dest[length] = label.len() as u8;
                length += 1;
                dest[length..length + label.len()].copy_from_slice(label);
                length += label.len();
            }
        }
        if length + 1 >= dest.len() {
            return Err("Not enough data to complete NAME in question".into());
        }
        dest[length] = 0;
        length += 1;
        Ok(length)
    }

    fn write_question(
        &mut self,
        dest: &mut [u8],
        length: usize,
        qtype: RrQtype,
        qclass: RrQclass,
        domain: LabelIter,
    ) -> Result<usize, DnsError> {
        if dest.len() < 12 {
            return Err("Not enough data to write question".into());
        }
        let length = self.write_label(dest, length, domain)?;
        dest[length..length + 2].copy_from_slice(&qtype.to_be_bytes());
        dest[length + 2..length + 4].copy_from_slice(&qclass.to_be_bytes());
        Ok(length + 4)
    }

    pub fn translate_to_vpn(
        &mut self,
        request: &DnsPacket,
        dest: &mut [u8],
    ) -> Result<DnsTranslationAction, DnsError> {
        self.compression_map.clear();
        let mut flags = request.flags();
        // This is loosely based on RFC 6147.
        if flags.qr() == Qr::Response {
            return Err("Response requests are not supported".into());
        }
        if flags.truncation() {
            return Err("Truncated requests are not supported".into());
        }
        if dest.len() < request.data.len() {
            return Err("Destination slice cannot fit original request".into());
        }
        let mut qdcount = 0;
        let mut length = 12;
        for section in request.iter_sections() {
            match section {
                Ok(Section::Question(q)) => {
                    if qdcount > 0 {
                        // RFC 1035, Section 4.1.2 states that number of questions
                        // is usually 1, and most implementations don't support >1 questions.
                        warn!("Dropping unexpected additional question from request");
                        return Ok(Self::write_error_response(
                            dest,
                            request.data,
                            ResponseCode::FormatError,
                            qdcount,
                            length,
                        ));
                    }
                    let qtype = q.qtype().to_rtype();
                    match qtype {
                        Some(RrType::AAAA) => {
                            // Translate AAAA requests into A.
                            qdcount += 1;
                            length = self.write_question(
                                dest,
                                length,
                                RrType::A.to_qtype(),
                                q.qclass(),
                                q.iter_qname(),
                            )?
                        }
                        Some(RrType::A) => {
                            // Send empty response to A questions (IPv4 is not supported).
                            debug!(
                                "Dropping unsupported {} record in DNS question: {}",
                                q.qtype(),
                                q
                            );
                            qdcount += 1;
                            length = self.write_question(
                                dest,
                                length,
                                q.qtype(),
                                q.qclass(),
                                q.iter_qname(),
                            )?;
                            return Ok(Self::write_error_response(
                                dest,
                                request.data,
                                ResponseCode::NoError,
                                qdcount,
                                length,
                            ));
                        }
                        _ => {
                            qdcount += 1;
                            length = self.write_question(
                                dest,
                                length,
                                q.qtype(),
                                q.qclass(),
                                q.iter_qname(),
                            )?
                        }
                    };
                }
                Ok(Section::Answer(a)) => {
                    debug!("Dropping unsupported A section from request: {}", a)
                }
                Ok(Section::Nameserver(ns)) => {
                    debug!("Dropping unsupported NS section from request: {}", ns)
                }
                Ok(Section::AdditionalRecord(ar)) => {
                    debug!("Dropping unsupported AR section from request: {}", ar)
                }
                Err(err) => {
                    warn!("Failed to parse DNS section: {}", err);
                    return Ok(Self::write_error_response(
                        dest,
                        request.data,
                        ResponseCode::FormatError,
                        qdcount,
                        length,
                    ));
                }
            };
        }
        if qdcount == 0 {
            warn!("No supported question types in DNS request");
            Ok(Self::write_error_response(
                dest,
                request.data,
                ResponseCode::FormatError,
                qdcount,
                length,
            ))
        } else {
            flags.clear_reserved_zero();
            Self::write_header(dest, request.data, flags, qdcount, 0, 0, 0);
            Ok(DnsTranslationAction::Forward(length))
        }
    }

    fn write_resource_record(
        &mut self,
        dest: &mut [u8],
        mut length: usize,
        rr: &ResourceRecord,
    ) -> Result<Option<usize>, DnsError> {
        let rr_type = rr.rr_type();
        match rr.rdata()? {
            Rdata::Ipv4(addr) => {
                if UNROUTABLE_SUBNETS
                    .iter()
                    .any(|reserved_range| reserved_range.contains(&addr))
                {
                    warn!(
                        "Dropping untranslatable IPv4 address {} from response",
                        addr
                    );
                    return Ok(None);
                }
                let rr_type = if rr_type == RrType::A {
                    RrType::AAAA
                } else {
                    return Err("IPv4 address record doesn't have type A".into());
                };
                length = self.write_label(dest, length, rr.iter_name())?;
                if length + 10 + 16 > dest.len() {
                    return Err("Not enough data to write AAAA record".into());
                }
                dest[length..length + 2].copy_from_slice(&rr_type.to_be_bytes());
                // Copy all attributes except RDLENGTH.
                dest[length + 2..length + 8]
                    .copy_from_slice(&rr.data[rr.name_end_offset + 2..rr.name_end_offset + 8]);
                // Static IPv6 address RDLENGTH.
                dest[length + 8..length + 10].copy_from_slice(&16u16.to_be_bytes());
                length += 10;
                dest[length..length + 12].copy_from_slice(&self.nat64_prefix.0);
                dest[length + 12..length + 16].copy_from_slice(&addr.octets());
                length += 16;

                Ok(Some(length))
            }
            Rdata::Ipv6(_) => {
                // RFC 9461 requests to Google DNS may return AAAA records in Additional Records.
                debug!("Dropping unsupported AAAA record from response");
                Ok(None)
            }
            Rdata::Name(name_label) => {
                length = self.write_label(dest, length, rr.iter_name())?;
                if length + 12 > dest.len() {
                    return Err("Not enough data to write name record".into());
                }
                // Copy all attributes except RDLENGTH.
                dest[length..length + 8]
                    .copy_from_slice(&rr.data[rr.name_end_offset..rr.name_end_offset + 8]);
                let rdlength_start_offset = length + 8;
                length += 10;

                length = self.write_label(dest, length, name_label)?;

                let rdlength = (length - rdlength_start_offset - 2) as u16;
                dest[rdlength_start_offset..rdlength_start_offset + 2]
                    .copy_from_slice(&rdlength.to_be_bytes());

                Ok(Some(length))
            }
            Rdata::Soa(soa_record) => {
                length = self.write_label(dest, length, rr.iter_name())?;
                if length + 12 > dest.len() {
                    return Err("Not enough data to write SOA record".into());
                }
                // Copy all attributes except RDLENGTH.
                dest[length..length + 8]
                    .copy_from_slice(&rr.data[rr.name_end_offset..rr.name_end_offset + 8]);
                let rdlength_start_offset = length + 8;
                length += 10;

                length = self.write_label(dest, length, soa_record.iter_mname())?;
                length = self.write_label(dest, length, soa_record.iter_rname())?;
                dest[length..length + 20].copy_from_slice(soa_record.attributes);
                length += 20;

                let rdlength = (length - rdlength_start_offset - 2) as u16;
                dest[rdlength_start_offset..rdlength_start_offset + 2]
                    .copy_from_slice(&rdlength.to_be_bytes());

                Ok(Some(length))
            }
            Rdata::Unknown(_) => {
                // SVCB and HTTPS responses must be dropped (DoH is not supported).
                let is_doh_discovery =
                    rr.rr_type() == RrType::SVCB || rr.rr_type() == RrType::HTTPS;
                if is_doh_discovery {
                    debug!(
                        "Dropping DoH discovery {} resource record from response",
                        rr_type
                    );
                } else {
                    warn!(
                        "Dropping unsupported {} resource record from response",
                        rr_type
                    );
                }
                Ok(None)
            }
        }
    }

    pub fn translate_to_esp(
        &mut self,
        request: &DnsPacket,
        dest: &mut [u8],
    ) -> Result<usize, DnsError> {
        self.compression_map.clear();
        // This is loosely based on RFC 6147.
        let mut flags = request.flags();
        if flags.qr() == Qr::Query {
            return Err("Query responses are not supported".into());
        }
        if flags.truncation() {
            return Err("Truncated responses are not supported".into());
        }
        if dest.len() < request.data.len() {
            return Err("Destination slice cannot fit original request".into());
        }
        let mut qdcount = 0;
        let mut ancount = 0;
        let mut nscount = 0;
        let mut arcount = 0;
        let mut length = 12;
        request.iter_sections().try_for_each(|section| {
            match section? {
                Section::Question(q) => {
                    if qdcount > 0 {
                        // RFC 1035, Section 4.1.2 states that number of questions
                        // is usually 1, and most implementations don't support >1 questions.
                        warn!("Dropping unexpected additional question from request");
                        return Ok(());
                    }
                    let qtype = q.qtype().to_rtype();
                    match qtype {
                        Some(RrType::A) => {
                            // Translate A requests into AAAA.
                            qdcount += 1;
                            length = self.write_question(
                                dest,
                                length,
                                RrType::AAAA.to_qtype(),
                                q.qclass(),
                                q.iter_qname(),
                            )?
                        }
                        Some(RrType::AAAA) => {
                            // Drop AAAA questions (IPv4 is never asked for AAAA records).
                            return Err("Unsupported AAAA record in DNS response question".into());
                        }
                        _ => {
                            // Keep all other questions unchanged.
                            qdcount += 1;
                            length = self.write_question(
                                dest,
                                length,
                                q.qtype(),
                                q.qclass(),
                                q.iter_qname(),
                            )?
                        }
                    };
                }
                Section::Answer(a) => {
                    if let Some(new_length) = self.write_resource_record(dest, length, &a)? {
                        ancount += 1;
                        length = new_length;
                    }
                }
                Section::Nameserver(ns) => {
                    if let Some(new_length) = self.write_resource_record(dest, length, &ns)? {
                        nscount += 1;
                        length = new_length;
                    }
                }
                Section::AdditionalRecord(ar) => {
                    if let Some(new_length) = self.write_resource_record(dest, length, &ar)? {
                        arcount += 1;
                        length = new_length;
                    }
                }
            };
            Ok::<(), DnsError>(())
        })?;
        if qdcount == 0 {
            return Err("No supported question types in response".into());
        }
        flags.clear_reserved_zero();
        if ancount == 0 {
            flags.set_response_code(ResponseCode::NameError);
        }
        Self::write_header(
            dest,
            request.data,
            flags,
            qdcount,
            ancount,
            nscount,
            arcount,
        );
        Ok(length)
    }
}

impl Clone for Dns64Translator {
    fn clone(&self) -> Self {
        Dns64Translator::new(self.nat64_prefix.clone())
    }
}

#[derive(Debug)]
pub struct DnsError(&'static str);

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl error::Error for DnsError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<&'static str> for DnsError {
    fn from(msg: &'static str) -> DnsError {
        DnsError(msg)
    }
}
