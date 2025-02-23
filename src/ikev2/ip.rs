use std::{
    collections::HashMap,
    error, fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::RangeInclusive,
    time::Instant,
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
struct AddressRange {
    full_ip_range: RangeInclusive<IpAddr>,
    ranges: Vec<(RangeInclusive<IpAddr>, usize)>,
    address_count: usize,
}

impl AddressRange {
    fn new(full_ip_range: RangeInclusive<IpAddr>) -> Result<AddressRange, IpError> {
        let ranges = vec![(full_ip_range.clone(), Self::address_count(&full_ip_range))];
        let ranges = match (full_ip_range.start(), full_ip_range.end()) {
            (IpAddr::V4(_), IpAddr::V4(_)) => {
                // Exclude first and last IP address.
                let ranges = Self::exclude(ranges, *full_ip_range.start()..=*full_ip_range.start());
                Ok(Self::exclude(
                    ranges,
                    *full_ip_range.end()..=*full_ip_range.end(),
                ))
            }
            (IpAddr::V6(_), IpAddr::V6(_)) => {
                // Exclude first IP address.
                // TODO: avoid anycast addresses for IPv6 (the rules are a bit too complex for now).
                // The minimal size of an IPv6 network is /32.
                Ok(Self::exclude(
                    ranges,
                    *full_ip_range.start()..=*full_ip_range.start(),
                ))
            }
            // This should never happen (range is generated from a single address + prefix length).
            _ => Err("Address range mixes IPv4 and IPv6 addresses"),
        }?;
        let address_count = ranges.iter().map(|(_, address_count)| address_count).sum();
        Ok(AddressRange {
            full_ip_range: full_ip_range.clone(),
            ranges,
            address_count,
        })
    }

    fn next_addr(addr: &IpAddr) -> Option<IpAddr> {
        match addr {
            IpAddr::V4(addr) => {
                if addr < &Ipv4Addr::from_bits(!0u32) {
                    Some(IpAddr::V4(Ipv4Addr::from_bits(addr.to_bits() + 1)))
                } else {
                    None
                }
            }
            IpAddr::V6(addr) => {
                if addr < &Ipv6Addr::from_bits(!0u128) {
                    Some(IpAddr::V6(Ipv6Addr::from_bits(addr.to_bits() + 1)))
                } else {
                    None
                }
            }
        }
    }

    fn prev_addr(addr: &IpAddr) -> Option<IpAddr> {
        match addr {
            IpAddr::V4(addr) => {
                if addr > &Ipv4Addr::from_bits(0u32) {
                    Some(IpAddr::V4(Ipv4Addr::from_bits(addr.to_bits() - 1)))
                } else {
                    None
                }
            }
            IpAddr::V6(addr) => {
                if addr > &Ipv6Addr::from_bits(0u128) {
                    Some(IpAddr::V6(Ipv6Addr::from_bits(addr.to_bits() - 1)))
                } else {
                    None
                }
            }
        }
    }

    fn exclude(
        include_ranges: Vec<(RangeInclusive<IpAddr>, usize)>,
        exclude_range: RangeInclusive<IpAddr>,
    ) -> Vec<(RangeInclusive<IpAddr>, usize)> {
        let mut ranges = vec![];
        for (include_range, address_count) in include_ranges.into_iter() {
            let mut intersection_found = false;
            if include_range.contains(exclude_range.start()) {
                intersection_found = true;
                // If exclude_range starts at 0, clamp it to 0: the left address range will be
                // excluded entirely.
                let include_end =
                    Self::prev_addr(exclude_range.start()).unwrap_or(*exclude_range.start());
                if include_range.start() < &include_end {
                    let range = *include_range.start()..=include_end;
                    let address_count = Self::address_count(&range);
                    ranges.push((range, address_count));
                }
            }
            if include_range.contains(exclude_range.end()) {
                intersection_found = true;
                // If exclude_range ends with MAX, clamp it to MAX: the right address range will be
                // excluded entirely.
                let include_start =
                    Self::next_addr(exclude_range.end()).unwrap_or(*exclude_range.start());
                if &include_start < include_range.end() {
                    let range = include_start..=*include_range.end();
                    let address_count = Self::address_count(&range);
                    ranges.push((range, address_count));
                }
            }
            if !intersection_found {
                ranges.push((include_range, address_count));
            }
        }
        ranges
    }

    fn address_count(range: &RangeInclusive<IpAddr>) -> usize {
        match (range.start(), &range.end()) {
            (IpAddr::V4(start), IpAddr::V4(end)) => {
                let start = start.to_bits();
                let end = end.to_bits();
                if start < end {
                    (end - start) as usize
                } else {
                    0
                }
            }
            (IpAddr::V6(start), IpAddr::V6(end)) => {
                let start = start.to_bits();
                let end = end.to_bits();
                if start < end {
                    (end - start).min(usize::MAX as u128) as usize
                } else {
                    0
                }
            }
            _ => 0,
        }
    }

    fn total_address_count(&self) -> usize {
        self.address_count
    }

    fn addr(&self, i: usize) -> Option<IpAddr> {
        let mut skipped_addresses = 0;
        for (range, count) in self.ranges.iter() {
            if (skipped_addresses..skipped_addresses + count).contains(&i) {
                let offset = i - skipped_addresses;
                return match range.start() {
                    IpAddr::V4(addr) => Some(IpAddr::V4(Ipv4Addr::from_bits(
                        addr.to_bits() + offset as u32,
                    ))),
                    IpAddr::V6(addr) => Some(IpAddr::V6(Ipv6Addr::from_bits(
                        addr.to_bits() + offset as u128,
                    ))),
                };
            }
            skipped_addresses += count;
        }
        None
    }
}

struct NatTable {
    local_to_global: HashMap<IpAddr, IpAddr>,
    global_to_local: HashMap<IpAddr, IpAddr>,
    ttl: HashMap<IpAddr, Instant>,
    // TODO 0.5.0: create a translate_packet function to rewrite headers & checksum, and modify DNS requests/responses.
    // TODO 0.5.0: use same number of DNS as FortiVPN (e.g. empty), round robin, fallback, reserve fixed DNS range or only use first server?
    // TODO 0.5.0: create a next_addr function to search through address space.
}

pub enum IpNetmask {
    Ipv4Mask(Ipv4Addr, Ipv4Addr),
    Ipv6Prefix(Ipv6Addr, u8),
    None,
}

#[derive(Clone)]
pub struct Cidr {
    prefix_len: u8,
    addresses: AddressRange,
}

impl Cidr {
    pub fn new(addr: IpAddr, prefix_len: u8) -> Result<Cidr, IpError> {
        let full_ip_range = Self::full_ip_range(&addr, prefix_len);
        let addresses = AddressRange::new(full_ip_range)?;
        Ok(Cidr {
            prefix_len,
            addresses,
        })
    }

    fn addr_mask<D>(prefix_len: u8) -> D
    where
        D: std::ops::Shr<D, Output = D>
            + std::ops::Sub<D, Output = D>
            + std::ops::Not<Output = D>
            + From<u8>,
    {
        let full_mask = !D::from(0);
        full_mask >> prefix_len.into()
    }

    fn full_ip_range(addr: &IpAddr, prefix_len: u8) -> RangeInclusive<IpAddr> {
        match addr {
            IpAddr::V4(addr) => {
                let mask: u32 = Self::addr_mask(prefix_len);
                let start_addr = addr.to_bits() & (!mask);
                let end_addr = start_addr | mask;
                IpAddr::V4(Ipv4Addr::from_bits(start_addr))
                    ..=IpAddr::V4(Ipv4Addr::from_bits(end_addr))
            }
            IpAddr::V6(addr) => {
                let mask: u128 = Self::addr_mask(prefix_len);
                let start_addr = addr.to_bits() & (!mask);
                let end_addr = start_addr | mask;
                IpAddr::V6(Ipv6Addr::from_bits(start_addr))
                    ..=IpAddr::V6(Ipv6Addr::from_bits(end_addr))
            }
        }
    }

    pub fn valid_address_count(&self) -> usize {
        self.addresses.total_address_count()
    }

    fn internal_addr(&self) -> Option<IpAddr> {
        // TODO 0.5.0: reserve address from NAT block.
        self.addresses.addr(2)
    }

    fn dns_addr(&self) -> Vec<IpAddr> {
        // TODO 0.5.0: reserve address from NAT block.
        if let (Some(first), Some(second)) = (self.addresses.addr(0), self.addresses.addr(1)) {
            vec![first, second]
        } else {
            vec![]
        }
    }

    fn ip_netmask(&self) -> IpNetmask {
        match self.internal_addr() {
            Some(IpAddr::V4(addr)) => {
                let inv_mask: u32 = Self::addr_mask(self.prefix_len);
                IpNetmask::Ipv4Mask(addr, Ipv4Addr::from_bits(!inv_mask))
            }
            Some(IpAddr::V6(addr)) => IpNetmask::Ipv6Prefix(addr, self.prefix_len),
            None => IpNetmask::None,
        }
    }

    fn traffic_selector(&self) -> Result<message::TrafficSelector, message::FormatError> {
        message::TrafficSelector::from_ip_range(self.addresses.full_ip_range.clone())
    }
}

#[derive(Clone)]
pub enum NetworkMode {
    Rnat(Cidr),
    Direct(IpAddr, Vec<IpAddr>),
    None,
}

#[derive(Clone)]
pub struct Network {
    mode: NetworkMode,
    tunnel_domains: Vec<String>,
    tunnel_domains_idna: Vec<Vec<u8>>,
    local_ts: Vec<message::TrafficSelector>,
}

impl Network {
    pub fn new(mode: NetworkMode, tunnel_domains: Vec<String>) -> Result<Network, IpError> {
        // TODO: convert domains into DNS IDNA A-label format for Unicode strings.
        let tunnel_domains_idna = tunnel_domains
            .iter()
            .map(|domain| domain.as_bytes().to_vec())
            .collect::<Vec<_>>();
        match mode {
            NetworkMode::Rnat(ref cidr) => {
                let traffic_selector = cidr.traffic_selector()?;
                Ok(Network {
                    mode,
                    tunnel_domains,
                    tunnel_domains_idna,
                    local_ts: vec![traffic_selector],
                })
            }
            NetworkMode::Direct(_, _) => Ok(Network {
                mode,
                tunnel_domains,
                tunnel_domains_idna,
                local_ts: vec![],
            }),
            NetworkMode::None => Ok(Network {
                mode,
                tunnel_domains,
                tunnel_domains_idna,
                local_ts: vec![Self::full_ts()?],
            }),
        }
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

    pub fn update_ip_configuration(&mut self, internal_addr: Option<IpAddr>, dns_addrs: &[IpAddr]) {
        match self.mode {
            NetworkMode::Direct(_, _) | NetworkMode::None => {
                if let Some(internal_addr) = internal_addr {
                    self.mode = NetworkMode::Direct(internal_addr, dns_addrs.to_vec());
                } else {
                    self.mode = NetworkMode::None;
                }
            }
            NetworkMode::Rnat(_) => {}
        }
    }

    pub fn internal_addr(&self) -> Option<IpAddr> {
        match self.mode {
            NetworkMode::Rnat(ref cidr) => cidr.internal_addr(),
            NetworkMode::Direct(ip_addr, _) => Some(ip_addr),
            NetworkMode::None => None,
        }
    }

    pub fn ip_netmask(&self) -> IpNetmask {
        match &self.mode {
            NetworkMode::Rnat(cidr) => cidr.ip_netmask(),
            NetworkMode::Direct(IpAddr::V4(addr), _) => {
                IpNetmask::Ipv4Mask(*addr, Ipv4Addr::from_bits(!0u32))
            }
            NetworkMode::Direct(IpAddr::V6(addr), _) => IpNetmask::Ipv6Prefix(*addr, 128),
            NetworkMode::None => IpNetmask::None,
        }
    }

    pub fn dns_addrs(&self) -> Vec<IpAddr> {
        match &self.mode {
            NetworkMode::Rnat(cidr) => cidr.dns_addr(),
            NetworkMode::Direct(_, dns_addrs) => dns_addrs.clone(),
            NetworkMode::None => vec![],
        }
    }

    pub fn ts_local(&self) -> &[message::TrafficSelector] {
        &self.local_ts
    }

    pub fn tunnel_domains(&self) -> &[Vec<u8>] {
        &self.tunnel_domains_idna
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
