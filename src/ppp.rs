use std::{error, fmt, net::Ipv4Addr};

use log::debug;

/*
 * PPP constants are defined in https://www.iana.org/assignments/ppp-numbers/ppp-numbers.xhtml
 */

pub struct Packet<'a> {
    protocol: Protocol,
    data: &'a [u8],
}

impl Packet<'_> {
    pub fn from_bytes(protocol: Protocol, data: &[u8]) -> Result<Packet, FormatError> {
        let packet = Packet { protocol, data };
        packet.validate()?;
        Ok(packet)
    }

    pub fn validate(&self) -> Result<(), FormatError> {
        self.protocol.validate()
    }

    pub fn to_lcp(&self) -> Result<LcpPacket, FormatError> {
        if self.protocol == Protocol::LCP {
            LcpPacket::from_bytes(self.data)
        } else {
            Err("Protocol type is not LCP".into())
        }
    }

    pub fn to_ipcp(&self) -> Result<IpcpPacket, FormatError> {
        if self.protocol == Protocol::IPV4CP {
            IpcpPacket::from_bytes(self.data)
        } else {
            Err("Protocol type is not IPCP".into())
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Protocol(u16);

impl Protocol {
    pub const IPV4: Protocol = Protocol(0x0021);
    pub const IPV6: Protocol = Protocol(0x0057);
    pub const LCP: Protocol = Protocol(0xc021);
    pub const IPV4CP: Protocol = Protocol(0x8021);

    pub fn from_be_slice(slice: &[u8]) -> Protocol {
        let mut result = [0u8; 2];
        result.copy_from_slice(slice);
        Protocol::from_u16(u16::from_be_bytes(result))
    }

    fn from_u16(value: u16) -> Protocol {
        Protocol(value)
    }

    pub fn value(&self) -> u16 {
        self.0
    }

    fn validate(&self) -> Result<(), FormatError> {
        if self.0 & 0x0001 == 0 {
            return Err("Protocol must be odd".into());
        }
        if self.0 & 0x0100 != 0 {
            return Err("Protocol group must be even".into());
        }
        Ok(())
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::IPV4 => write!(f, "Internet Protocol version 4")?,
            Self::IPV6 => write!(f, "Internet Protocol version 6")?,
            Self::LCP => write!(f, "Link Control Protocol")?,
            Self::IPV4CP => write!(f, "Internet Protocol Control Protocol")?,
            _ => write!(f, "Unknown protocol {:04x}", self.0)?,
        }
        Ok(())
    }
}

pub struct LcpPacket<'a> {
    code: LcpCode,
    identifier: u8,
    data: &'a [u8],
}

impl LcpPacket<'_> {
    fn from_bytes(data: &[u8]) -> Result<LcpPacket, FormatError> {
        if data.len() < 4 {
            debug!("Not enough data in LCP packet");
            Err("Not enough in LCP packet".into())
        } else {
            let code = LcpCode::from_u8(data[0])?;
            let identifier = data[1];
            let mut length = [0u8; 2];
            length.copy_from_slice(&data[2..4]);
            let length = u16::from_be_bytes(length) as usize;
            if data.len() < length {
                debug!(
                    "LCP data overflow: received {}, length {}",
                    data.len(),
                    length
                );
                return Err("LCP data overflow".into());
            }
            Ok(LcpPacket {
                code,
                identifier,
                data: &data[4..length],
            })
        }
    }

    pub fn code(&self) -> LcpCode {
        self.code
    }

    pub fn identifier(&self) -> u8 {
        self.identifier
    }

    pub fn read_magic(&self) -> Option<u32> {
        if !(self.code == LcpCode::ECHO_REQUEST || self.code == LcpCode::ECHO_REPLY)
            || self.data.len() < 4
        {
            return None;
        }
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&self.data[..4]);
        Some(u32::from_be_bytes(magic))
    }

    pub fn read_options(&self) -> &[u8] {
        if self.code.has_configure_options() {
            self.data
        } else {
            &[]
        }
    }

    pub fn iter_options(&self) -> LcpOptionsIter {
        LcpOptionsIter {
            data: self.read_options(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LcpCode(u8);

impl LcpCode {
    pub const CONFIGURE_REQUEST: LcpCode = LcpCode(1);
    pub const CONFIGURE_ACK: LcpCode = LcpCode(2);
    pub const CONFIGURE_NAK: LcpCode = LcpCode(3);
    pub const CONFIGURE_REJECT: LcpCode = LcpCode(4);
    pub const TERMINATE_REQUEST: LcpCode = LcpCode(5);
    pub const TERMINATE_ACK: LcpCode = LcpCode(6);
    pub const CODE_REJECT: LcpCode = LcpCode(7);
    pub const PROTOCOL_REJECT: LcpCode = LcpCode(8);
    pub const ECHO_REQUEST: LcpCode = LcpCode(9);
    pub const ECHO_REPLY: LcpCode = LcpCode(10);
    pub const DISCARD_REQUEST: LcpCode = LcpCode(11);

    fn from_u8(value: u8) -> Result<LcpCode, FormatError> {
        if (Self::CONFIGURE_REQUEST.0..=Self::DISCARD_REQUEST.0).contains(&value) {
            Ok(LcpCode(value))
        } else {
            debug!("Unsupported LCP Code: {}", value);
            Err("Unsupported LCP Code".into())
        }
    }

    fn has_configure_options(&self) -> bool {
        (Self::CONFIGURE_REQUEST.0..=LcpCode::CONFIGURE_REJECT.0).contains(&self.0)
    }
}

impl fmt::Display for LcpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::CONFIGURE_REQUEST => write!(f, "Configure-Request")?,
            Self::CONFIGURE_ACK => write!(f, "Configure-Ack")?,
            Self::CONFIGURE_NAK => write!(f, "Configure-Nak")?,
            Self::CONFIGURE_REJECT => write!(f, "Configure-Reject")?,
            Self::TERMINATE_REQUEST => write!(f, "Terminate-Request")?,
            Self::TERMINATE_ACK => write!(f, "Terminate-Ack")?,
            Self::CODE_REJECT => write!(f, "Code-Reject")?,
            Self::PROTOCOL_REJECT => write!(f, "Protocol-Reject")?,
            Self::ECHO_REQUEST => write!(f, "Echo-Request")?,
            Self::ECHO_REPLY => write!(f, "Echo-Reply")?,
            Self::DISCARD_REQUEST => write!(f, "Discard-Request")?,
            _ => write!(f, "Unknown LCP code {:02x}", self.0)?,
        }
        Ok(())
    }
}

pub struct LcpOptionsIter<'a> {
    data: &'a [u8],
}

impl<'a> Iterator for LcpOptionsIter<'a> {
    type Item = Result<LcpOptionData<'a>, FormatError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }
        if self.data.len() < 2 {
            debug!("Not enough data in LCP Configuration Option");
            self.data = &[];
            return Some(Err("Not enough data in LCP configuration option".into()));
        }
        let option_type = self.data[0];
        let length = self.data[1] as usize;
        if self.data.len() < length {
            debug!(
                "LCP option overflow: type {} available {}, length {}",
                option_type,
                self.data.len(),
                length
            );
            self.data = &[];
            return Some(Err("LCP option overflow".into()));
        }
        let data = &self.data[2..length];
        self.data = &self.data[length..];
        Some(LcpOptionData::from_data(option_type, data))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LcpOptionData<'a> {
    Reserved(),
    MaximumReceiveUnit(u16),
    AuthenticationProtocol(&'a [u8]),
    QualityProtocol(&'a [u8]),
    MagicNumber(u32),
    ProtocolFieldCompression(),
    AddressControlFieldCompression(),
    Unknown(u8, &'a [u8]),
}

impl LcpOptionData<'_> {
    fn from_data(option_type: u8, data: &[u8]) -> Result<LcpOptionData, FormatError> {
        let data = match option_type {
            0 => LcpOptionData::Reserved(),
            1 => {
                if data.len() != 2 {
                    return Err("Unexpected Maximum Receive Unit length".into());
                }
                let mut mru = [0u8; 2];
                mru.copy_from_slice(data);
                LcpOptionData::MaximumReceiveUnit(u16::from_be_bytes(mru))
            }
            3 => {
                if data.len() < 2 {
                    return Err("Unexpected Authentication Protocol length".into());
                }
                LcpOptionData::AuthenticationProtocol(data)
            }
            4 => {
                if data.len() < 2 {
                    return Err("Unexpected Quality Protocol length".into());
                }
                LcpOptionData::QualityProtocol(data)
            }
            5 => {
                if data.len() != 4 {
                    return Err("Unexpected Magic Number length".into());
                }
                let mut magic = [0u8; 4];
                magic.copy_from_slice(data);
                LcpOptionData::MagicNumber(u32::from_be_bytes(magic))
            }
            7 => {
                if !data.is_empty() {
                    return Err("Unexpected Protocol Field Compression length".into());
                }
                LcpOptionData::ProtocolFieldCompression()
            }
            8 => {
                if !data.is_empty() {
                    return Err("Unexpected Address and Protocol Field Compression length".into());
                }
                LcpOptionData::AddressControlFieldCompression()
            }
            _ => LcpOptionData::Unknown(option_type, data),
        };
        Ok(data)
    }

    pub fn option_type(&self) -> u8 {
        match *self {
            Self::Reserved() => 0,
            Self::MaximumReceiveUnit(_) => 1,
            Self::AuthenticationProtocol(_) => 3,
            Self::QualityProtocol(_) => 4,
            Self::MagicNumber(_) => 5,
            Self::ProtocolFieldCompression() => 7,
            Self::AddressControlFieldCompression() => 8,
            Self::Unknown(option_type, _) => option_type,
        }
    }

    fn length(&self) -> usize {
        2 + match *self {
            Self::Reserved() => 0,
            Self::MaximumReceiveUnit(_) => 2,
            Self::AuthenticationProtocol(data) => data.len(),
            Self::QualityProtocol(data) => data.len(),
            Self::MagicNumber(_) => 4,
            Self::ProtocolFieldCompression() => 0,
            Self::AddressControlFieldCompression() => 0,
            Self::Unknown(_, data) => data.len(),
        }
    }

    fn encode(&self, dest: &mut [u8]) {
        dest[0] = self.option_type();
        dest[1] = self.length() as u8;
        let dest = &mut dest[2..];
        match *self {
            Self::MaximumReceiveUnit(mru) => dest.copy_from_slice(&mru.to_be_bytes()),
            Self::AuthenticationProtocol(data) => dest.copy_from_slice(data),
            Self::QualityProtocol(data) => dest.copy_from_slice(data),
            Self::MagicNumber(magic) => dest.copy_from_slice(&magic.to_be_bytes()),
            Self::Unknown(_, data) => dest.copy_from_slice(data),
            _ => {}
        }
    }
}

impl fmt::Display for LcpOptionData<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::Reserved() => write!(f, "Reserved"),
            Self::MaximumReceiveUnit(mru) => write!(f, "Maximum-Receive-Unit {}", mru),
            Self::AuthenticationProtocol(data) => {
                write!(f, "Authentication-Protocol ")?;
                fmt_slice_hex(data, f)
            }
            Self::QualityProtocol(data) => {
                write!(f, "Quality-Protocol ")?;
                fmt_slice_hex(data, f)
            }
            Self::MagicNumber(magic) => write!(f, "Magic-Number {:08x}", magic),
            Self::ProtocolFieldCompression() => write!(f, "Protocol-Field-Compression"),
            Self::AddressControlFieldCompression() => {
                write!(f, "Address-and-Control-Field-Compression")
            }
            Self::Unknown(option_type, data) => {
                write!(f, "Unknown option type {} data: ", option_type)?;
                fmt_slice_hex(data, f)
            }
        }
    }
}

pub struct IpcpPacket<'a> {
    code: LcpCode,
    identifier: u8,
    data: &'a [u8],
}

impl IpcpPacket<'_> {
    fn from_bytes(data: &[u8]) -> Result<IpcpPacket, FormatError> {
        if data.len() < 4 {
            debug!("Not enough data in IPCP packet");
            Err("Not enough in IPCP packet".into())
        } else {
            let code = LcpCode::from_u8(data[0])?;
            let identifier = data[1];
            let mut length = [0u8; 2];
            length.copy_from_slice(&data[2..4]);
            let length = u16::from_be_bytes(length) as usize;
            if data.len() < length {
                debug!(
                    "LCP data overflow: received {}, length {}",
                    data.len(),
                    length
                );
                return Err("LCP data overflow".into());
            }
            Ok(IpcpPacket {
                code,
                identifier,
                data: &data[4..length],
            })
        }
    }

    pub fn code(&self) -> LcpCode {
        self.code
    }

    pub fn identifier(&self) -> u8 {
        self.identifier
    }

    pub fn read_options(&self) -> &[u8] {
        self.data
    }

    pub fn iter_options(&self) -> IpcpOptionsIter<'_> {
        IpcpOptionsIter { data: self.data }
    }
}

pub struct IpcpOptionsIter<'a> {
    data: &'a [u8],
}

impl<'a> Iterator for IpcpOptionsIter<'a> {
    type Item = Result<IpcpOptionData<'a>, FormatError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }
        if self.data.len() < 2 {
            debug!("Not enough data in IPCP Configuration Option");
            self.data = &[];
            return Some(Err("Not enough data in IPCP configuration option".into()));
        }
        let option_type = self.data[0];
        let length = self.data[1] as usize;
        if self.data.len() < length {
            debug!(
                "IPCP option overflow: type {} available {}, length {}",
                option_type,
                self.data.len(),
                length
            );
            self.data = &[];
            return Some(Err("IPCP option overflow".into()));
        }
        let data = &self.data[2..length];
        self.data = &self.data[length..];
        Some(IpcpOptionData::from_data(option_type, data))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IpcpOptionData<'a> {
    IpAddresses(),
    IpCompressionProtocol(&'a [u8]),
    IpAddress(Ipv4Addr),
    PrimaryDns(Ipv4Addr),
    PrimaryNbns(Ipv4Addr),
    SecondaryDns(Ipv4Addr),
    SecondaryNbns(Ipv4Addr),
}

impl IpcpOptionData<'_> {
    fn from_data(option_type: u8, data: &[u8]) -> Result<IpcpOptionData, FormatError> {
        let data = match option_type {
            1 => IpcpOptionData::IpAddresses(),
            2 => {
                if data.len() < 2 {
                    return Err("Unexpected IP Compression Protocol length".into());
                }
                IpcpOptionData::IpCompressionProtocol(data)
            }
            3 => {
                if data.len() != 4 {
                    return Err("Unexpected IP Address length".into());
                }
                let mut ip = [0u8; 4];
                ip.copy_from_slice(data);
                let ip = Ipv4Addr::from(ip);
                IpcpOptionData::IpAddress(ip)
            }
            129 => {
                if data.len() != 4 {
                    return Err("Unexpected Primary DNS Server Address length".into());
                }
                let mut ip = [0u8; 4];
                ip.copy_from_slice(data);
                let ip = Ipv4Addr::from(ip);
                IpcpOptionData::PrimaryDns(ip)
            }
            130 => {
                if data.len() != 4 {
                    return Err("Unexpected Primary NBNS Server Address length".into());
                }
                let mut ip = [0u8; 4];
                ip.copy_from_slice(data);
                let ip = Ipv4Addr::from(ip);
                IpcpOptionData::PrimaryNbns(ip)
            }
            131 => {
                if data.len() != 4 {
                    return Err("Unexpected Secondary DNS Server Address length".into());
                }
                let mut ip = [0u8; 4];
                ip.copy_from_slice(data);
                let ip = Ipv4Addr::from(ip);
                IpcpOptionData::SecondaryDns(ip)
            }
            132 => {
                if data.len() != 4 {
                    return Err("Unexpected Secondary NBNS Server Address length".into());
                }
                let mut ip = [0u8; 4];
                ip.copy_from_slice(data);
                let ip = Ipv4Addr::from(ip);
                IpcpOptionData::SecondaryNbns(ip)
            }
            _ => return Err("Unexpected IPCP option type".into()),
        };
        Ok(data)
    }

    pub fn option_type(&self) -> u8 {
        match *self {
            Self::IpAddresses() => 1,
            Self::IpCompressionProtocol(_) => 2,
            Self::IpAddress(_) => 3,
            Self::PrimaryDns(_) => 129,
            Self::PrimaryNbns(_) => 130,
            Self::SecondaryDns(_) => 131,
            Self::SecondaryNbns(_) => 132,
        }
    }

    fn length(&self) -> usize {
        2 + match *self {
            Self::IpAddresses() => 0,
            Self::IpCompressionProtocol(data) => data.len(),
            Self::IpAddress(ip) => ip.octets().len(),
            Self::PrimaryDns(ip) => ip.octets().len(),
            Self::PrimaryNbns(ip) => ip.octets().len(),
            Self::SecondaryDns(ip) => ip.octets().len(),
            Self::SecondaryNbns(ip) => ip.octets().len(),
        }
    }

    fn encode(&self, dest: &mut [u8]) {
        dest[0] = self.option_type();
        dest[1] = self.length() as u8;
        let dest = &mut dest[2..];
        match *self {
            Self::IpCompressionProtocol(data) => dest.copy_from_slice(data),
            Self::IpAddress(ip) => dest.copy_from_slice(&ip.octets()),
            Self::PrimaryDns(ip) => dest.copy_from_slice(&ip.octets()),
            Self::PrimaryNbns(ip) => dest.copy_from_slice(&ip.octets()),
            Self::SecondaryDns(ip) => dest.copy_from_slice(&ip.octets()),
            Self::SecondaryNbns(ip) => dest.copy_from_slice(&ip.octets()),
            _ => {}
        }
    }
}

impl fmt::Display for IpcpOptionData<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::IpAddresses() => write!(f, "IP-Addresses"),
            Self::IpCompressionProtocol(data) => {
                write!(f, "IP-Compression-Protocol ")?;
                fmt_slice_hex(data, f)
            }
            Self::IpAddress(ip) => write!(f, "IP-Address {}", ip),
            Self::PrimaryDns(ip) => write!(f, "Primary DNS Server Address {}", ip),
            Self::PrimaryNbns(ip) => write!(f, "Primary NBNS Server Address {}", ip),
            Self::SecondaryDns(ip) => write!(f, "Secondary DNS Server Address {}", ip),
            Self::SecondaryNbns(ip) => write!(f, "Secondary NBNS Server Address {}", ip),
        }
    }
}

pub fn encode_lcp_config(
    dest: &mut [u8],
    code: LcpCode,
    identifier: u8,
    options: &[LcpOptionData],
) -> Result<usize, NotEnoughSpaceError> {
    let length = 4 + options.iter().map(|opt| opt.length()).sum::<usize>();
    if dest.len() < length {
        return Err(NotEnoughSpaceError {});
    }
    dest[0] = code.0;
    dest[1] = identifier;
    dest[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    let mut dest = &mut dest[4..];
    for opt in options.iter() {
        let length = opt.length();
        opt.encode(&mut dest[..length]);
        dest = &mut dest[length..];
    }
    Ok(length)
}

pub fn encode_lcp_data(
    dest: &mut [u8],
    code: LcpCode,
    identifier: u8,
    data: &[u8],
) -> Result<usize, NotEnoughSpaceError> {
    let length = 4 + data.len();
    if dest.len() < length {
        return Err(NotEnoughSpaceError {});
    }
    dest[0] = code.0;
    dest[1] = identifier;
    dest[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    dest[4..length].copy_from_slice(data);
    Ok(length)
}

pub fn encode_ipcp_config(
    dest: &mut [u8],
    code: LcpCode,
    identifier: u8,
    options: &[IpcpOptionData],
) -> Result<usize, NotEnoughSpaceError> {
    let length = 4 + options.iter().map(|opt| opt.length()).sum::<usize>();
    if dest.len() < length {
        return Err(NotEnoughSpaceError {});
    }
    dest[0] = code.0;
    dest[1] = identifier;
    dest[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    let mut dest = &mut dest[4..];
    for opt in options.iter() {
        let length = opt.length();
        opt.encode(&mut dest[..length]);
        dest = &mut dest[length..];
    }
    Ok(length)
}

fn fmt_slice_hex(data: &[u8], f: &mut dyn std::fmt::Write) -> std::fmt::Result {
    for (i, b) in data.iter().enumerate() {
        write!(f, "{:02x}", b)?;
        if i + 1 < data.len() {
            write!(f, " ")?;
        }
    }
    Ok(())
}

impl fmt::Display for Packet<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Protocol: {}", self.protocol)?;
        if let Ok(lcp) = self.to_lcp() {
            write!(f, ", LCP code: {} id: {}", lcp.code(), lcp.identifier())?;
            for opt in lcp.iter_options() {
                match opt {
                    Ok(opt) => write!(f, " {}", opt)?,
                    Err(err) => write!(f, " invalid option: {}", err)?,
                }
            }
            if let Some(magic) = lcp.read_magic() {
                write!(f, ", magic: {:08x}", magic)?;
            }
            Ok(())
        } else if let Ok(lcp) = self.to_ipcp() {
            write!(f, ", IPCP code: {} id: {}", lcp.code(), lcp.identifier())?;
            for opt in lcp.iter_options() {
                match opt {
                    Ok(opt) => write!(f, " {}", opt)?,
                    Err(err) => write!(f, " invalid option: {}", err)?,
                }
            }
            Ok(())
        } else {
            write!(f, ", data: ")?;
            fmt_slice_hex(self.data, f)
        }
    }
}

impl fmt::Debug for Packet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

pub struct FormatError {
    msg: &'static str,
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.msg.fmt(f)
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
        FormatError { msg }
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
