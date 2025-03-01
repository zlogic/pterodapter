use std::{
    error, fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::RangeInclusive,
};

use log::warn;

use crate::logger::fmt_slice_hex;

use super::message;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TransportProtocolType(u8);

mod dns;

pub type DnsPacket<'a> = dns::DnsPacket<'a>;

impl TransportProtocolType {
    const HOP_BY_HOP_OPTIONS: TransportProtocolType = TransportProtocolType(0);
    const ICMP: TransportProtocolType = TransportProtocolType(1);
    pub const TCP: TransportProtocolType = TransportProtocolType(6);
    pub const UDP: TransportProtocolType = TransportProtocolType(17);
    const IPV6_ROUTING: TransportProtocolType = TransportProtocolType(43);
    const IPV6_FRAGMENT: TransportProtocolType = TransportProtocolType(44);
    const IPV6_ICMP: TransportProtocolType = TransportProtocolType(58);
    const IPV6_DESTINATION_OPTIONS: TransportProtocolType = TransportProtocolType(60);
    const IPV6_NO_NEXT_HEADER: TransportProtocolType = TransportProtocolType(59);
}

impl TransportProtocolType {
    fn from_u8(value: u8) -> TransportProtocolType {
        TransportProtocolType(value)
    }

    fn length(&self, data: &[u8]) -> usize {
        match *self {
            Self::HOP_BY_HOP_OPTIONS => data[1] as usize + 1,
            Self::IPV6_ROUTING => data[1] as usize + 1,
            Self::IPV6_FRAGMENT => 8,
            Self::IPV6_DESTINATION_OPTIONS => data[1] as usize + 1,
            Self::IPV6_NO_NEXT_HEADER => data.len(),
            _ => data.len(),
        }
    }

    fn min_bytes(&self) -> usize {
        match *self {
            Self::HOP_BY_HOP_OPTIONS => 2,
            Self::IPV6_ROUTING => 2,
            Self::IPV6_FRAGMENT => 8,
            Self::IPV6_DESTINATION_OPTIONS => 2,
            Self::IPV6_NO_NEXT_HEADER => 0,
            _ => 0,
        }
    }
}

impl PartialEq<message::IPProtocolType> for TransportProtocolType {
    fn eq(&self, other: &message::IPProtocolType) -> bool {
        let protocol_id = other.protocol_id();
        protocol_id != 0 && self.0 == protocol_id
    }
}

impl fmt::Display for TransportProtocolType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::HOP_BY_HOP_OPTIONS => write!(f, "HOPOPT"),
            Self::ICMP => write!(f, "ICMP"),
            Self::TCP => write!(f, "TCP"),
            Self::UDP => write!(f, "UDP"),
            Self::IPV6_ROUTING => write!(f, "IPv6-Route"),
            Self::IPV6_FRAGMENT => write!(f, "IPv6-Frag"),
            Self::IPV6_DESTINATION_OPTIONS => write!(f, "IPv6-Opts"),
            Self::IPV6_ICMP => write!(f, "IPv6-ICMP"),
            Self::IPV6_NO_NEXT_HEADER => write!(f, "IPv6-NoNxt"),
            _ => write!(f, "Unknown IP transport protocol or header type {}", self.0),
        }
    }
}

pub struct Ipv4Packet<'a> {
    data: &'a [u8],
}

impl Ipv4Packet<'_> {
    fn from_data(data: &[u8]) -> Result<Ipv4Packet, IpError> {
        if data.len() < 20 {
            return Err("Not enough bytes in IPv4 header".into());
        }
        if data.len() < Self::header_length(data) {
            return Err("IPv4 header length overflow".into());
        }
        let packet = Ipv4Packet { data };
        if packet.transport_protocol() == TransportProtocolType::from_u8(0) {
            Err("IPv4 protocol is 0".into())
        } else {
            Ok(packet)
        }
    }

    fn header_length(data: &[u8]) -> usize {
        (data[0] & 0x0f) as usize * 4
    }

    fn src_addr(&self) -> Ipv4Addr {
        let mut src_addr = [0u8; 4];
        src_addr.copy_from_slice(&self.data[12..16]);
        Ipv4Addr::from(src_addr)
    }

    fn dst_addr(&self) -> Ipv4Addr {
        let mut dst_addr = [0u8; 4];
        dst_addr.copy_from_slice(&self.data[16..20]);
        Ipv4Addr::from(dst_addr)
    }

    fn transport_protocol(&self) -> TransportProtocolType {
        TransportProtocolType::from_u8(self.data[9])
    }

    fn transport_protocol_data(&self) -> &[u8] {
        let header_length = Self::header_length(self.data);
        &self.data[header_length..]
    }
}

pub struct Ipv6Packet<'a> {
    data: &'a [u8],
    payload_type: TransportProtocolType,
    payload_data: &'a [u8],
}

impl Ipv6Packet<'_> {
    fn from_data(data: &[u8]) -> Result<Ipv6Packet, IpError> {
        if data.len() < 40 {
            return Err("Not enough bytes in IPv6 header".into());
        }
        let last_payload = if let Some(last_payload) = Self::iter_payloads(data).last() {
            last_payload?
        } else {
            return Err("IPv6 packet has no payload".into());
        };

        Ok(Ipv6Packet {
            data,
            payload_type: last_payload.protocol_type,
            payload_data: last_payload.data,
        })
    }

    fn iter_payloads(data: &[u8]) -> Ipv6PacketIter {
        Ipv6PacketIter {
            next_payload: TransportProtocolType(data[6]),
            data: &data[40..],
        }
    }

    fn src_addr(&self) -> Ipv6Addr {
        let mut src_addr = [0u8; 16];
        src_addr.copy_from_slice(&self.data[8..24]);
        Ipv6Addr::from(src_addr)
    }

    fn dst_addr(&self) -> Ipv6Addr {
        let mut dst_addr = [0u8; 16];
        dst_addr.copy_from_slice(&self.data[24..40]);
        Ipv6Addr::from(dst_addr)
    }

    fn transport_protocol(&self) -> TransportProtocolType {
        self.payload_type
    }

    fn transport_protocol_data(&self) -> &[u8] {
        self.payload_data
    }
}

pub struct Ipv6PayloadHeader<'a> {
    protocol_type: TransportProtocolType,
    data: &'a [u8],
}

pub struct Ipv6PacketIter<'a> {
    next_payload: TransportProtocolType,
    data: &'a [u8],
}

impl<'a> Iterator for Ipv6PacketIter<'a> {
    type Item = Result<Ipv6PayloadHeader<'a>, IpError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }
        if self.data.len() < self.next_payload.min_bytes() {
            self.data = &[];
            return Some(Err("IPv6 header minimal length overlow".into()));
        }
        let header_length = self.next_payload.length(self.data);
        if self.data.len() < header_length {
            self.data = &[];
            return Some(Err("IPv6 header length overlow".into()));
        }
        let data = self.data;
        let protocol_type = self.next_payload;
        self.next_payload = TransportProtocolType(data[0]);
        self.data = &self.data[header_length..];
        Some(Ok(Ipv6PayloadHeader {
            protocol_type,
            data: &data[..header_length],
        }))
    }
}

pub enum IpPacket<'a> {
    V4(Ipv4Packet<'a>),
    V6(Ipv6Packet<'a>),
}

impl IpPacket<'_> {
    pub fn from_data(data: &[u8]) -> Result<IpPacket, IpError> {
        if data.is_empty() {
            return Err("IP packet is empty, cannot extract header data".into());
        }
        // TODO 0.5.0: Extract header here, to return error immediately and reuse results for rewriting?
        match data[0] >> 4 {
            4 => Ok(IpPacket::V4(Ipv4Packet::from_data(data)?)),
            6 => Ok(IpPacket::V6(Ipv6Packet::from_data(data)?)),
            _ => {
                warn!("ESP IP packet is not a supported IP version: {:x}", data[0]);
                Err("Unsupported IP prococol version".into())
            }
        }
    }

    pub fn src_addr(&self) -> IpAddr {
        match self {
            IpPacket::V4(packet) => IpAddr::V4(packet.src_addr()),
            IpPacket::V6(packet) => IpAddr::V6(packet.src_addr()),
        }
    }

    pub fn dst_addr(&self) -> IpAddr {
        match self {
            IpPacket::V4(packet) => IpAddr::V4(packet.dst_addr()),
            IpPacket::V6(packet) => IpAddr::V6(packet.dst_addr()),
        }
    }

    pub fn transport_protocol(&self) -> TransportProtocolType {
        match self {
            IpPacket::V4(packet) => packet.transport_protocol(),
            IpPacket::V6(packet) => packet.transport_protocol(),
        }
    }

    pub fn transport_protocol_data(&self) -> &[u8] {
        match self {
            IpPacket::V4(packet) => packet.transport_protocol_data(),
            IpPacket::V6(packet) => packet.transport_protocol_data(),
        }
    }

    pub fn src_port(&self) -> Result<Option<u16>, IpError> {
        match self.transport_protocol() {
            TransportProtocolType::TCP | TransportProtocolType::UDP => {
                let data = self.transport_protocol_data();
                if data.len() < 2 {
                    return Err("Not enough data in transport layer to extract source port".into());
                }
                let mut src_port = [0u8; 2];
                src_port.copy_from_slice(&data[0..2]);
                Ok(Some(u16::from_be_bytes(src_port)))
            }
            _ => Ok(None),
        }
    }

    pub fn dst_port(&self) -> Result<Option<u16>, IpError> {
        match self.transport_protocol() {
            TransportProtocolType::TCP | TransportProtocolType::UDP => {
                let data = self.transport_protocol_data();
                if data.len() < 4 {
                    return Err(
                        "Not enough data in transport layer to extract destination port".into(),
                    );
                }
                let mut dst_port = [0u8; 2];
                dst_port.copy_from_slice(&data[2..4]);
                Ok(Some(u16::from_be_bytes(dst_port)))
            }
            _ => Ok(None),
        }
    }

    pub fn to_header(&self) -> Result<IpHeader, IpError> {
        Ok(IpHeader {
            src_addr: self.src_addr(),
            dst_addr: self.dst_addr(),
            src_port: self.src_port()?,
            dst_port: self.dst_port()?,
            transport_protocol: self.transport_protocol(),
        })
    }
}

pub struct IpHeader {
    src_addr: IpAddr,
    dst_addr: IpAddr,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    transport_protocol: TransportProtocolType,
}

impl IpHeader {
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
    pub fn transport_protocol(&self) -> TransportProtocolType {
        self.transport_protocol
    }
}

impl fmt::Display for IpHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.src_port {
            Some(src_port) => write!(
                f,
                "{} {}:{} -> ",
                self.transport_protocol(),
                self.src_addr(),
                src_port
            )?,
            None => write!(f, "{} {} -> ", self.transport_protocol(), self.src_addr())?,
        }
        match self.dst_port {
            Some(dst_port) => writeln!(f, "{}:{}", self.dst_addr(), dst_port),
            None => writeln!(f, "{}", self.dst_addr()),
        }
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

impl fmt::Display for IpPacket<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpPacket::V4(_) => write!(f, "IPv4 ")?,
            IpPacket::V6(_) => write!(f, "IPv6 ")?,
        }
        match self.src_port() {
            Ok(Some(src_port)) => write!(
                f,
                "{} {}:{} -> ",
                self.transport_protocol(),
                self.src_addr(),
                src_port
            )?,
            Ok(None) => write!(f, "{} {} -> ", self.transport_protocol(), self.src_addr())?,
            Err(err) => write!(
                f,
                "{} {} (port {}) -> ",
                self.transport_protocol(),
                self.src_addr(),
                err
            )?,
        }
        match self.dst_port() {
            Ok(Some(dst_port)) => writeln!(f, "{}:{}", self.dst_addr(), dst_port)?,
            Ok(None) => writeln!(f, "{}", self.dst_addr())?,
            Err(err) => writeln!(f, "{} (port {}) -> ", self.dst_addr(), err)?,
        }
        write!(
            f,
            "  Transport {}",
            fmt_slice_hex(self.transport_protocol_data())
        )
    }
}

#[derive(Debug)]
pub enum IpError {
    Internal(&'static str),
    Dns(dns::DnsError),
    Format(message::FormatError),
    Io(io::Error),
}

impl fmt::Display for IpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Internal(msg) => f.write_str(msg),
            Self::Dns(ref e) => write!(f, "DNS error: {}", e),
            Self::Format(ref e) => write!(f, "Format error: {}", e),
            Self::Io(ref e) => write!(f, "IO error: {}", e),
        }
    }
}

impl error::Error for IpError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Self::Internal(_msg) => None,
            Self::Dns(ref err) => Some(err),
            Self::Format(ref err) => Some(err),
            Self::Io(ref err) => Some(err),
        }
    }
}

impl From<dns::DnsError> for IpError {
    fn from(err: dns::DnsError) -> IpError {
        Self::Dns(err)
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
