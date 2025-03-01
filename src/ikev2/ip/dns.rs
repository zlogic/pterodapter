use std::{error, fmt};

use crate::logger::fmt_slice_hex;

use super::{IpHeader, TransportProtocolType};

pub struct DnsPacket<'a> {
    data: &'a [u8],
}

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
            code => ResponseCode::Reserved(code),
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

impl DnsPacket<'_> {
    const DNS_HEADER_SIZE: usize = 12;

    pub fn is_dns(hdr: &IpHeader) -> bool {
        hdr.transport_protocol == TransportProtocolType::UDP
            && (hdr.src_port == Some(53) || hdr.dst_port == Some(53))
    }

    pub fn from_udp_packet<'a>(data: &'a [u8]) -> Result<DnsPacket<'a>, DnsError> {
        // First 8 bytes are the UDP header.
        if data.len() < 8 + Self::DNS_HEADER_SIZE {
            Err("DNS packet size is smaller than header size".into())
        } else {
            // TODO: validate all headers.
            Ok(DnsPacket { data: &data[8..] })
        }
    }

    fn id(&self) -> u16 {
        let mut id = [0u8; 2];
        id.copy_from_slice(&self.data[0..2]);
        u16::from_be_bytes(id)
    }

    fn qr(&self) -> Qr {
        // bit 7.
        if (self.data[2] >> 7 & 0x1) == 0 {
            Qr::Query
        } else {
            Qr::Response
        }
    }

    fn opcode(&self) -> Opcode {
        // bits 6-3.
        Opcode::from_u8(self.data[2] >> 3 & 0x0f)
    }

    fn authoritative_answer(&self) -> bool {
        // bit 2.
        self.data[2] >> 2 & 0x01 == 1
    }

    fn truncation(&self) -> bool {
        // bit 1.
        self.data[2] >> 1 & 0x01 == 1
    }

    fn recursion_desired(&self) -> bool {
        // bit 0.
        self.data[2] & 0x01 == 1
    }

    fn recursion_available(&self) -> bool {
        // bit 7.
        self.data[3] >> 7 & 0x01 == 1
    }

    fn reserved_zero(&self) -> bool {
        // bits 6-4.
        self.data[3] >> 4 == 0
    }

    fn response_code(&self) -> ResponseCode {
        // bits 3-0.
        ResponseCode::from_u8(self.data[3] & 0x0f)
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

struct LabelIter<'a> {
    start_offset: usize,
    data: &'a [u8],
}

impl<'a> Iterator for LabelIter<'a> {
    type Item = Result<&'a [u8], DnsError>;

    fn next(&mut self) -> Option<Self::Item> {
        const POINTER_UPPER_HALF_MASK: u8 = !LABEL_POINTER_MASK;
        if self.data.is_empty() {
            return None;
        }
        let mut start_offset = self.start_offset;
        let mut length;
        // Detect loops similar to Wireshark - if read more data than exists in a packet, break
        // loop.
        loop {
            length = self.data[start_offset];
            let is_pointer = (length as u8) & LABEL_POINTER_MASK == LABEL_POINTER_MASK;
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

        Some(Ok(label))
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

    fn from_u16(code: u16) -> RrType {
        RrType(code)
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
            RrType(code) => write!(f, "Unknown({})", code),
        }
    }
}

#[derive(PartialEq, Eq)]
struct RrQtype(u16);

impl RrQtype {
    const AXFR: RrQtype = RrQtype(252);
    const MAILB: RrQtype = RrQtype(253);
    const MAILA: RrQtype = RrQtype(254);
    const ALL: RrQtype = RrQtype(255);

    fn from_u16(code: u16) -> RrQtype {
        RrQtype(code)
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
}

impl fmt::Display for RrQclass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::ALL => write!(f, "*"),
            RrQclass(code) => RrClass(code).fmt(f),
        }
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
        if is_pointer || length == 0 {
            break;
        } else {
            start_offset += length as usize;
        }
    }
    Some(start_offset)
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
        self.iter_qname().enumerate().try_for_each(|(i, segment)| {
            let segment = match segment {
                Ok(segment) => String::from_utf8_lossy(segment),
                Err(err) => {
                    write!(f, "err: {}", err)?;
                    return Ok(());
                }
            };
            if i == 0 {
                write!(f, "{}", segment)?;
            } else {
                write!(f, ".{}", segment)?;
            }
            Ok(())
        })?;
        write!(f, " {} {}", self.qtype(), self.qclass())
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
            Err("QNAME overflow".into())
        } else if name_end_offset + 10 > data.len() {
            Err("Not enough bytes in Question".into())
        } else {
            let rr = ResourceRecord {
                data,
                start_offset,
                name_end_offset,
            };
            let rdata_start = start_offset + 10 + rr.rd_length() as usize;
            if rdata_start > data.len() {
                Err("RDLENGTH overflow".into())
            } else {
                Ok(rr)
            }
        }
    }

    fn iter_qname(&self) -> LabelIter {
        LabelIter {
            start_offset: self.start_offset,
            data: self.data,
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
        let mut ttl = [0u8; 2];
        ttl.copy_from_slice(&self.data[self.name_end_offset + 8..self.name_end_offset + 10]);
        u16::from_be_bytes(ttl)
    }

    fn rdata(&self) -> &[u8] {
        let start_offset = self.start_offset + 10 + self.rd_length() as usize;
        &self.data[start_offset..]
    }
}

impl fmt::Display for ResourceRecord<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.iter_qname().enumerate().try_for_each(|(i, segment)| {
            let segment = match segment {
                Ok(segment) => String::from_utf8_lossy(segment),
                Err(err) => {
                    write!(f, "err: {}", err)?;
                    return Ok(());
                }
            };
            if i == 0 {
                write!(f, "{}", segment)?;
            } else {
                write!(f, ".{}", segment)?;
            }
            Ok(())
        })?;
        write!(
            f,
            " {} {} TTL {} {}",
            self.rr_type(),
            self.rr_class(),
            self.ttl(),
            fmt_slice_hex(self.rdata())
        )
    }
}

impl fmt::Display for DnsPacket<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TXID {} {}: {}", self.id(), self.qr(), self.opcode())?;
        if self.authoritative_answer() {
            write!(f, ", Authoritative Answer")?;
        }
        if self.truncation() {
            write!(f, ", Truncation")?;
        }
        if self.recursion_desired() {
            write!(f, ", Recursion desired")?;
        }
        if self.recursion_available() {
            write!(f, ", Recursion available")?;
        }
        if !self.reserved_zero() {
            write!(f, ", non-zero Reserved zero")?;
        }
        write!(f, ": {}", self.response_code())?;

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

#[derive(Debug)]
pub enum DnsError {
    Internal(&'static str),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Internal(msg) => f.write_str(msg),
        }
    }
}

impl error::Error for DnsError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Self::Internal(_msg) => None,
        }
    }
}

impl From<&'static str> for DnsError {
    fn from(msg: &'static str) -> DnsError {
        Self::Internal(msg)
    }
}
