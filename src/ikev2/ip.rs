use std::{
    error, fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use log::warn;

use super::message;

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
    pub fn from_packet(data: &[u8]) -> Result<IpHeader, IpError> {
        if data.is_empty() {
            return Err("IP packet is empty, cannot extract header data".into());
        }
        match data[0] >> 4 {
            4 => Self::from_ipv4_packet(data),
            6 => Self::from_ipv6_packet(data),
            _ => {
                warn!("ESP IP packet is not a supported IP version: {:x}", data[0]);
                Err("Unsupported IP prococol version".into())
            }
        }
    }

    #[inline]
    pub fn src_addr(&self) -> &IpAddr {
        &self.src_addr
    }

    #[inline]
    pub fn dst_addr(&self) -> &IpAddr {
        &self.dst_addr
    }

    #[inline]
    pub fn src_port(&self) -> Option<&u16> {
        self.src_port.as_ref()
    }

    #[inline]
    pub fn dst_port(&self) -> Option<&u16> {
        self.dst_port.as_ref()
    }

    #[inline]
    pub fn transport_protocol(&self) -> message::IPProtocolType {
        self.transport_protocol
    }

    fn from_ipv4_packet(data: &[u8]) -> Result<IpHeader, IpError> {
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

    fn from_ipv6_packet(data: &[u8]) -> Result<IpHeader, IpError> {
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

    fn extract_ports(data: &[u8]) -> Result<(Option<u16>, Option<u16>), IpError> {
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

pub struct Cidr {
    addr: IpAddr,
    prefix_len: u8,
}

impl Cidr {
    pub fn new(addr: IpAddr, prefix_len: u8) -> Cidr {
        Cidr { addr, prefix_len }
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

#[derive(Debug)]
pub enum IpError {
    Internal(&'static str),
}

impl fmt::Display for IpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Internal(msg) => f.write_str(msg),
        }
    }
}

impl error::Error for IpError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Self::Internal(_msg) => None,
        }
    }
}

impl From<&'static str> for IpError {
    fn from(msg: &'static str) -> IpError {
        Self::Internal(msg)
    }
}
