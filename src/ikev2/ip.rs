use std::{
    error, fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::RangeInclusive,
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

#[derive(Clone)]
pub struct Nat64Prefix {
    range: RangeInclusive<Ipv6Addr>,
}

impl Nat64Prefix {
    pub fn new(prefix: Ipv6Addr) -> Nat64Prefix {
        let mut start_addr = prefix.octets();
        let mut end_addr = prefix.octets();
        start_addr[12..16].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        end_addr[12..16].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        Nat64Prefix {
            range: start_addr.into()..=end_addr.into(),
        }
    }

    fn map_ipv4(&self, addr: &Ipv4Addr) -> Ipv6Addr {
        let mut segments = self.range.start().octets();
        segments[12..16].copy_from_slice(&addr.octets());
        segments.into()
    }

    fn traffic_selector(&self) -> Result<message::TrafficSelector, message::FormatError> {
        message::TrafficSelector::from_ip_range(
            IpAddr::V6(*self.range.start())..=IpAddr::V6(*self.range.end()),
        )
    }
}

pub enum IpNetmask {
    Ipv4Mask(Ipv4Addr, Ipv4Addr),
    Ipv6Prefix(Ipv6Addr, u8),
    None,
}

#[derive(Clone)]
pub struct Network {
    nat64_prefix: Option<Nat64Prefix>,
    real_ip: Option<IpAddr>,
    dns_addrs: Vec<IpAddr>,
    tunnel_domains: Vec<String>,
    tunnel_domains_idna: Vec<Vec<u8>>,
    local_ts: Vec<message::TrafficSelector>,
}

impl Network {
    pub fn new(
        nat64_prefix: Option<Nat64Prefix>,
        tunnel_domains: Vec<String>,
    ) -> Result<Network, IpError> {
        // TODO: convert domains into DNS IDNA A-label format for Unicode strings, or
        // request/validate that this is done by the end user.
        let tunnel_domains_idna = tunnel_domains
            .iter()
            .map(|domain| domain.as_bytes().to_vec())
            .collect::<Vec<_>>();
        let traffic_selectors = if let Some(nat64_prefix) = &nat64_prefix {
            vec![nat64_prefix.traffic_selector()?]
        } else {
            vec![]
        };
        Ok(Network {
            nat64_prefix,
            real_ip: None,
            dns_addrs: vec![],
            tunnel_domains,
            tunnel_domains_idna,
            local_ts: traffic_selectors,
        })
    }

    fn full_ts() -> Result<message::TrafficSelector, message::FormatError> {
        message::TrafficSelector::from_ip_range(
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))..=IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
        )
    }

    pub async fn refresh_addresses(&mut self) -> Result<(), IpError> {
        // Use a predefined port just in case.
        let addresses = self
            .tunnel_domains
            .iter()
            .map(|domain| tokio::net::lookup_host((domain.clone(), 80)))
            .collect::<Vec<_>>();

        let mut ip_addresses = vec![];
        for addrs in addresses.into_iter() {
            addrs.await?.for_each(|addr| ip_addresses.push(addr.ip()));
        }
        if ip_addresses.is_empty() {
            self.local_ts = vec![Self::full_ts()?];
        } else {
            self.local_ts = ip_addresses
                .iter()
                .map(|ip_address| {
                    message::TrafficSelector::from_ip_range(*ip_address..=*ip_address)
                })
                .collect::<Result<Vec<message::TrafficSelector>, message::FormatError>>()?;
        }
        Ok(())
    }

    pub fn is_nat64(&self) -> bool {
        self.nat64_prefix.is_some()
    }

    pub fn update_ip_configuration(&mut self, internal_addr: Option<IpAddr>, dns_addrs: &[IpAddr]) {
        self.real_ip = internal_addr;
        if let Some(nat64_prefix) = &self.nat64_prefix {
            self.dns_addrs = dns_addrs
                .iter()
                .map(|dns_addr| match dns_addr {
                    IpAddr::V4(addr) => IpAddr::V6(nat64_prefix.map_ipv4(addr)),
                    IpAddr::V6(_) => *dns_addr,
                })
                .collect::<Vec<_>>()
        } else {
            self.dns_addrs = dns_addrs.to_vec()
        }
    }

    pub fn ip_netmask(&self) -> IpNetmask {
        if let Some(nat64_prefix) = &self.nat64_prefix {
            if let Some(IpAddr::V4(addr)) = &self.real_ip {
                let addr = nat64_prefix.map_ipv4(addr);
                IpNetmask::Ipv6Prefix(addr, 96)
            } else {
                IpNetmask::None
            }
        } else {
            match self.real_ip {
                Some(IpAddr::V4(addr)) => IpNetmask::Ipv4Mask(addr, Ipv4Addr::from_bits(!0u32)),
                Some(IpAddr::V6(addr)) => IpNetmask::Ipv6Prefix(addr, 128),
                None => IpNetmask::None,
            }
        }
    }

    pub fn dns_addrs(&self) -> &[IpAddr] {
        &self.dns_addrs
    }

    pub fn ts_local(&self) -> &[message::TrafficSelector] {
        &self.local_ts
    }

    pub fn tunnel_domains(&self) -> &[Vec<u8>] {
        &self.tunnel_domains_idna
    }

    pub fn traffic_selector_type(&self) -> message::TrafficSelectorType {
        if self.nat64_prefix.is_some() {
            message::TrafficSelectorType::TS_IPV6_ADDR_RANGE
        } else {
            match &self.real_ip {
                Some(IpAddr::V6(_)) => message::TrafficSelectorType::TS_IPV6_ADDR_RANGE,
                Some(IpAddr::V4(_)) | None => message::TrafficSelectorType::TS_IPV4_ADDR_RANGE,
            }
        }
    }

    pub fn expand_local_ts(&mut self, new_local_ts: &[message::TrafficSelector]) {
        for check_ts in new_local_ts {
            if !self
                .local_ts
                .iter()
                .any(|existing_ts| existing_ts.contains(check_ts))
            {
                self.local_ts.push(check_ts.clone());
            }
        }
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
    Format(message::FormatError),
    Io(io::Error),
}

impl fmt::Display for IpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Internal(msg) => f.write_str(msg),
            Self::Format(ref e) => write!(f, "Format error: {}", e),
            Self::Io(ref e) => write!(f, "IO error: {}", e),
        }
    }
}

impl error::Error for IpError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Self::Internal(_msg) => None,
            Self::Format(ref err) => Some(err),
            Self::Io(ref err) => Some(err),
        }
    }
}

impl From<message::FormatError> for IpError {
    fn from(err: message::FormatError) -> IpError {
        Self::Format(err)
    }
}

impl From<io::Error> for IpError {
    fn from(err: io::Error) -> IpError {
        Self::Io(err)
    }
}

impl From<&'static str> for IpError {
    fn from(msg: &'static str) -> IpError {
        Self::Internal(msg)
    }
}
