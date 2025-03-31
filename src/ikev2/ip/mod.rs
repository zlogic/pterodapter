use std::{
    error, fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::{Deref, Range},
};

use log::{trace, warn};

use crate::logger::fmt_slice_hex;

use super::message;

mod dns;
mod icmp;

// Reserve this amount of bytes for the translated IP header.
// The worst case scenario is IPv6 with fragmentation.
// Alternatively, for unfragmented UDP responses, this is the IPv6 header + UDP header.
const MAX_TRANSLATED_IP_HEADER_LENGTH: usize = 40 + 8;

// Set to 0 to stop decreasing TTL or Hop Limit.
const TTL_HOP_DECREMENT: u8 = 1;

const DEFAULT_RESPONSE_TTL: u8 = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TransportProtocolType(u8);

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

    const IPV6_AH: TransportProtocolType = TransportProtocolType(51);
    const IPV6_MOBILITY: TransportProtocolType = TransportProtocolType(135);
    const IPV6_HOST_IDENTITY_PROTOCOL: TransportProtocolType = TransportProtocolType(139);
    const IPV6_SHIM6_PROTOCOL: TransportProtocolType = TransportProtocolType(140);

    fn from_u8(value: u8) -> TransportProtocolType {
        TransportProtocolType(value)
    }

    fn length(&self, data: &[u8]) -> usize {
        match *self {
            Self::HOP_BY_HOP_OPTIONS => 8 + data[1] as usize,
            Self::IPV6_ROUTING => 8 + data[1] as usize,
            Self::IPV6_FRAGMENT => 8,
            Self::IPV6_DESTINATION_OPTIONS => 8 + data[1] as usize,
            Self::IPV6_NO_NEXT_HEADER => data.len(),
            Self::IPV6_AH => 2 + (data[1] as usize) * 4,
            Self::IPV6_MOBILITY => 8 + (data[1] as usize) * 8,
            Self::IPV6_HOST_IDENTITY_PROTOCOL => 8 + (data[1] as usize) * 8,
            Self::IPV6_SHIM6_PROTOCOL => 8 + (data[1] as usize) * 8,
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
            Self::IPV6_AH => 2 + 3 * 4,
            Self::IPV6_MOBILITY => 8,
            Self::IPV6_HOST_IDENTITY_PROTOCOL => 8 + 8 * 4,
            Self::IPV6_SHIM6_PROTOCOL => 8 + 8,
            _ => 0,
        }
    }

    fn to_u8(self) -> u8 {
        self.0
    }

    fn is_ipv6_extension(&self) -> bool {
        // Based on https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml.
        // ESP is not included, as it's identical to how IPv4 ESP works.
        matches!(
            *self,
            Self::HOP_BY_HOP_OPTIONS
                | Self::IPV6_ROUTING
                | Self::IPV6_FRAGMENT
                | Self::IPV6_DESTINATION_OPTIONS
                | Self::IPV6_NO_NEXT_HEADER
                | Self::IPV6_AH
                | Self::IPV6_MOBILITY
                | Self::IPV6_HOST_IDENTITY_PROTOCOL
                | Self::IPV6_SHIM6_PROTOCOL,
        )
    }

    fn supports_checksum(&self) -> bool {
        matches!(*self, Self::TCP | Self::UDP | Self::ICMP | Self::IPV6_ICMP)
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
            Self::IPV6_AH => write!(f, "IPv6-AH"),
            Self::IPV6_MOBILITY => write!(f, "IPv6-Mobility"),
            Self::IPV6_HOST_IDENTITY_PROTOCOL => write!(f, "IPv6-HIP"),
            Self::IPV6_SHIM6_PROTOCOL => write!(f, "IPv6-Shim6"),
            _ => write!(f, "Unknown IP transport protocol or header type {}", self.0),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct TrafficClass(u8);

impl TrafficClass {
    fn dscp(&self) -> u8 {
        (self.0 >> 2) & 0x3f
    }

    fn ecn(&self) -> u8 {
        self.0 & 0x03
    }

    fn to_u8(self) -> u8 {
        self.0
    }
}

impl fmt::Display for TrafficClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DS={} ECN={:02b}", self.dscp(), self.ecn())
    }
}

pub struct Ipv4Packet<'a> {
    data: &'a [u8],
    transport_data: TransportData<'a>,
}

impl<'a> Ipv4Packet<'a> {
    const FRAGMENT_OFFSET_MASK: u16 = 0x1fff;
    const FRAGMENT_MF_MASK: u16 = 1 << 13;
    const FRAGMENT_DF_MASK: u16 = 1 << 14;
    const FRAGMENT_USED_MASK: u16 = Self::FRAGMENT_OFFSET_MASK | Self::FRAGMENT_MF_MASK;

    fn from_data(data: &[u8]) -> Result<Ipv4Packet, IpError> {
        if data.len() < 20 {
            return Err("Not enough bytes in IPv4 header".into());
        }
        let header_length = Self::header_length(data);
        if data.len() < header_length {
            return Err("IPv4 header length overflow".into());
        }

        let protocol_type = TransportProtocolType::from_u8(data[9]);
        if protocol_type == TransportProtocolType::from_u8(0) {
            Err("IPv4 protocol is 0".into())
        } else {
            let transport_data = &data[header_length..];
            let transport_data = TransportData::from_data(protocol_type, transport_data)?;
            Ok(Ipv4Packet {
                data,
                transport_data,
            })
        }
    }

    fn into_data(self) -> &'a [u8] {
        self.data
    }

    fn header_length(data: &[u8]) -> usize {
        (data[0] & 0x0f) as usize * 4
    }

    fn total_length_header(&self) -> u16 {
        let mut total_length = [0u8; 2];
        total_length.copy_from_slice(&self.data[2..4]);
        u16::from_be_bytes(total_length)
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

    fn transport_protocol_data(&self) -> &TransportData {
        &self.transport_data
    }

    fn dscp(&self) -> u8 {
        TrafficClass(self.data[1]).dscp()
    }

    fn ecn(&self) -> u8 {
        TrafficClass(self.data[1]).ecn()
    }

    fn fragment_offset(&self) -> Option<u16> {
        let mut fragment_offset = [0u8; 2];
        fragment_offset.copy_from_slice(&self.data[6..8]);
        let fragment = u16::from_be_bytes(fragment_offset);
        let more_fragments = fragment & Self::FRAGMENT_MF_MASK == Self::FRAGMENT_MF_MASK;
        let fragment_offset = fragment & Self::FRAGMENT_OFFSET_MASK;
        if more_fragments || fragment_offset > 0 {
            Some(fragment_offset)
        } else {
            None
        }
    }

    fn ttl(&self) -> u8 {
        self.data[8]
    }

    fn pseudo_checksum(
        data: &[u8],
        transport_protocol: TransportProtocolType,
        transport_length: usize,
    ) -> Checksum {
        let mut checksum = Checksum::new();
        checksum.add_slice(&data[12..20]);
        checksum.add_slice(&[0u8, transport_protocol.to_u8()]);
        checksum.add_slice(&(transport_length as u16).to_be_bytes());
        checksum
    }

    fn validate_transport_checksum(&self) -> bool {
        if self.is_fragment_shifted() {
            return true;
        }
        let transport_data = self.transport_protocol_data();
        if let Some(checksum) = transport_data.checksum() {
            if transport_data.protocol() == TransportProtocolType::UDP && checksum == 0x0000 {
                return true;
            }
            let mut calculated_checksum = Self::pseudo_checksum(
                self.data,
                self.transport_protocol(),
                transport_data.full_data().len(),
            );
            if transport_data.protocol() == TransportProtocolType::ICMP {
                // ICMPv4 doesn't include IPv4 pseudoheaders.
                calculated_checksum = Checksum::new();
            }
            calculated_checksum.add_slice(transport_data.full_data());
            calculated_checksum.fold();
            calculated_checksum.value() == 0x0000
        } else {
            true
        }
    }

    fn validate_ip_checksum(&self) -> bool {
        let mut checksum = Checksum::new();
        checksum.add_slice(&self.data[..Self::header_length(self.data)]);
        checksum.fold();
        checksum.value() == 0x0000
    }

    fn is_fragmented(&self) -> bool {
        let mut fragment_offset = [0u8; 2];
        fragment_offset.copy_from_slice(&self.data[6..8]);
        let fragment = u16::from_be_bytes(fragment_offset);

        fragment & Self::FRAGMENT_USED_MASK != 0x0000
    }

    fn is_fragment_shifted(&self) -> bool {
        match self.fragment_offset() {
            Some(0) | None => false,
            Some(_) => true,
        }
    }

    fn write_translated_ip_header(
        &self,
        dest: &mut [u8],
        fragmentation_extension: bool,
        transport_data_len: usize,
        nat64_prefix: &Nat64Prefix,
    ) -> Result<(), IpError> {
        // RFC 7915, Section 4.1.
        if fragmentation_extension && dest.len() != 48 {
            return Err(
                "Destination slice for IPv4 to IPv6 header conversion (with fragmentation) needs exactly 48 bytes"
                    .into(),
            );
        } else if !fragmentation_extension && dest.len() != 40 {
            return Err(
                "Destination slice for IPv4 to IPv6 header conversion needs exactly 40 bytes"
                    .into(),
            );
        }

        let traffic_class = (self.data[1] as u32) << 20;
        let flow_label = (6u32 << 28) | traffic_class;
        dest[0..4].copy_from_slice(&flow_label.to_be_bytes());
        let payload_len = if fragmentation_extension { 8 } else { 0 } + transport_data_len as u16;
        dest[4..6].copy_from_slice(&payload_len.to_be_bytes());

        let transport_protocol = match self.transport_protocol() {
            TransportProtocolType::ICMP => TransportProtocolType::IPV6_ICMP,
            protocol => protocol,
        };
        let next_header = if fragmentation_extension {
            TransportProtocolType::IPV6_FRAGMENT
        } else {
            transport_protocol
        };
        dest[6] = next_header.to_u8();
        dest[7] = self.ttl().saturating_sub(TTL_HOP_DECREMENT);

        dest[8..20].copy_from_slice(nat64_prefix);
        dest[20..24].copy_from_slice(&self.data[12..16]);
        dest[24..36].copy_from_slice(nat64_prefix);
        dest[36..40].copy_from_slice(&self.data[16..20]);

        if fragmentation_extension {
            let mut fragment_offset = [0u8; 2];
            fragment_offset.copy_from_slice(&self.data[6..8]);
            let fragment = u16::from_be_bytes(fragment_offset);
            let more_fragments = fragment & Self::FRAGMENT_MF_MASK == Self::FRAGMENT_MF_MASK;
            let fragment_offset = fragment & Self::FRAGMENT_OFFSET_MASK;

            dest[40] = transport_protocol.to_u8();
            dest[41] = 0;
            let fragment_offset = (fragment_offset << 3) & (!0x0007);
            let mf_flag = if more_fragments {
                Ipv6Packet::FRAGMENT_MF_MASK
            } else {
                0x0000
            };
            let fragment_offset_ipv6 = fragment_offset | mf_flag;
            dest[42..44].copy_from_slice(&fragment_offset_ipv6.to_be_bytes());
            dest[44..46].fill(0);
            dest[46..48].copy_from_slice(&self.data[4..6]);
        }

        Ok(())
    }

    fn write_translated(
        &self,
        dest: &mut [u8],
        nat64_prefix: &Nat64Prefix,
        truncated: bool,
    ) -> Result<usize, IpError> {
        let transport_data = self.transport_data.full_data();
        let transport_protocol = self.transport_protocol();
        if transport_protocol == TransportProtocolType::IPV6_ICMP {
            return Err("ICMPv6 payload found in IPv4 packet".into());
        }
        let fragmentation_extension = self.is_fragmented();
        let header_len = if fragmentation_extension { 48 } else { 40 };
        if dest.len() < 20 + transport_data.len() {
            // RFC 7915, Section 1.4 states that a Packet Too Big should be sent here.
            // As there's enough extra space in buffers, this shouldn't be a big problem.
            return Err("Not enough space to translate from IPv4 to IPv6".into());
        }
        let transport_data_len = if truncated {
            let original_payload_length = self.total_length_header();
            let original_header_length = self.data.len() - transport_data.len();
            original_payload_length as usize - original_header_length
        } else {
            transport_data.len()
        };
        self.write_translated_ip_header(
            &mut dest[0..header_len],
            fragmentation_extension,
            transport_data_len,
            nat64_prefix,
        )?;
        dest[header_len..header_len + transport_data.len()].copy_from_slice(transport_data);
        if !self.is_fragment_shifted() && transport_protocol.supports_checksum() {
            let remove = Self::pseudo_checksum(self.data, transport_protocol, transport_data_len);
            let add = Ipv6Packet::pseudo_checksum(dest, transport_protocol, transport_data_len);
            self.transport_data.write_translated_checksum(
                &mut dest[header_len..header_len + transport_data.len()],
                remove,
                add,
            );
        }

        Ok(header_len + transport_data.len())
    }

    fn write_icmp_translated(
        &self,
        dest: &mut [u8],
        icmp_len: usize,
        nat64_prefix: &Nat64Prefix,
    ) -> Result<usize, IpError> {
        let (ip_header, icmp_data) = dest[..40 + icmp_len].split_at_mut(40);

        self.write_translated_ip_header(ip_header, false, icmp_len, nat64_prefix)?;
        let mut checksum = Ipv6Packet::pseudo_checksum(
            ip_header,
            TransportProtocolType::IPV6_ICMP,
            icmp_data.len(),
        );
        checksum.add_slice(icmp_data);
        checksum.fold();
        icmp_data[2..4].copy_from_slice(&checksum.value().to_be_bytes());

        Ok(40 + icmp_len)
    }

    fn write_icmp_response_header(
        &self,
        dest: &mut [u8],
        icmp_len: usize,
    ) -> Result<usize, IpError> {
        if dest.len() < 20 + icmp_len {
            return Err("Not enough space to write ICMPv4 response header".into());
        }
        let ip_header = &mut dest[0..20];
        ip_header[0] = (4 << 4) | 5;
        ip_header[1] = self.data[1];
        ip_header[2..4].copy_from_slice(&(icmp_len as u16 + 20u16).to_be_bytes());
        ip_header[4..6].copy_from_slice(&self.data[4..6]);
        ip_header[6..8].fill(0);
        ip_header[8] = DEFAULT_RESPONSE_TTL;
        ip_header[9] = TransportProtocolType::ICMP.to_u8();
        ip_header[10..12].fill(0);
        ip_header[12..16].copy_from_slice(&self.data[16..20]);
        ip_header[16..20].copy_from_slice(&self.data[12..16]);

        let mut checksum = Checksum::new();
        checksum.add_slice(ip_header);
        checksum.fold();
        ip_header[10..12].copy_from_slice(&checksum.value().to_be_bytes());
        Ok(20)
    }

    fn write_udp_translated(
        &self,
        dest: &mut [u8],
        data_range: Range<usize>,
        nat64_prefix: &Nat64Prefix,
    ) -> Result<usize, IpError> {
        if data_range.start < 40 + 8 {
            return Err("Not enough space to add IPv6 header in UDP translation".into());
        }
        let start_offset = data_range.start - 40 - 8;

        self.write_translated_ip_header(
            &mut dest[start_offset..start_offset + 40],
            false,
            data_range.len() + 8,
            nat64_prefix,
        )?;
        dest[start_offset + 40..start_offset + 40 + 4]
            .copy_from_slice(&self.transport_data.full_data()[0..4]);
        dest[start_offset + 40 + 4..start_offset + 40 + 6]
            .copy_from_slice(&(data_range.len() as u16 + 8).to_be_bytes());

        dest[start_offset + 40 + 6..start_offset + 40 + 8].fill(0);
        let mut checksum = Ipv6Packet::pseudo_checksum(
            &dest[start_offset..],
            self.transport_protocol(),
            data_range.len() + 8,
        );
        checksum.add_slice(&dest[start_offset + 40..data_range.end]);
        checksum.fold();

        let checksum = checksum.value();
        let checksum = if checksum == 0x0000 { 0xffff } else { checksum };
        dest[start_offset + 40 + 6..start_offset + 40 + 8].copy_from_slice(&checksum.to_be_bytes());
        Ok(start_offset)
    }

    fn write_udp_updated_payload(
        &self,
        dest: &mut [u8],
        data_range: Range<usize>,
    ) -> Result<usize, IpError> {
        if data_range.start < 20 + 8 {
            return Err("Not enough space to add IPv4 header in updated payload message".into());
        }
        let start_offset = data_range.start - 20 - 8;
        let udp_length: u16 = 8 + data_range.len() as u16;
        let mut checksum = {
            let ip_header = &mut dest[start_offset..start_offset + 20];
            ip_header[0] = (4 << 4) | 5;
            ip_header[1] = self.data[1];
            ip_header[2..4].copy_from_slice(&(udp_length + 20u16).to_be_bytes());
            ip_header[4..6].copy_from_slice(&self.data[4..6]);
            ip_header[6..8].fill(0);
            ip_header[8] = self.ttl().saturating_sub(TTL_HOP_DECREMENT);
            ip_header[9] = self.data[9];
            ip_header[10..12].fill(0);
            ip_header[12..20].copy_from_slice(&self.data[12..20]);

            let mut checksum = Checksum::new();
            checksum.add_slice(ip_header);
            checksum.fold();
            ip_header[10..12].copy_from_slice(&checksum.value().to_be_bytes());

            Ipv4Packet::pseudo_checksum(ip_header, TransportProtocolType::UDP, udp_length as usize)
        };

        checksum.add_slice(&dest[data_range.clone()]);

        let udp_header = &mut dest[start_offset + 20..start_offset + 28];
        let src_data = self.transport_data.full_data();
        udp_header[0..4].copy_from_slice(&src_data[0..4]);
        udp_header[4..6].copy_from_slice(&udp_length.to_be_bytes());
        udp_header[6..8].fill(0);

        checksum.add_slice(udp_header);
        checksum.fold();

        let checksum = checksum.value();
        let checksum = if checksum == 0x0000 { 0xffff } else { checksum };
        udp_header[6..8].copy_from_slice(&checksum.to_be_bytes());
        Ok(start_offset)
    }

    fn write_udp_response(
        &self,
        dest: &mut [u8],
        data_range: Range<usize>,
    ) -> Result<usize, IpError> {
        if data_range.start < 20 + 8 {
            return Err("Not enough space to add IPv4 header in IPv4 response message".into());
        }
        let start_offset = data_range.start - 20 - 8;
        let udp_length: u16 = 8 + data_range.len() as u16;
        let mut checksum = {
            let ip_header = &mut dest[start_offset..start_offset + 20];
            ip_header[0] = (4 << 4) | 5;
            ip_header[1] = self.data[1];
            ip_header[2..4].copy_from_slice(&(udp_length + 20u16).to_be_bytes());
            ip_header[4..6].copy_from_slice(&self.data[4..6]);
            ip_header[6..8].fill(0);

            ip_header[8] = DEFAULT_RESPONSE_TTL;
            ip_header[9] = self.data[9];
            ip_header[10..12].fill(0);
            ip_header[12..16].copy_from_slice(&self.data[16..20]);
            ip_header[16..20].copy_from_slice(&self.data[12..16]);

            let mut checksum = Checksum::new();
            checksum.add_slice(ip_header);
            checksum.fold();
            ip_header[10..12].copy_from_slice(&checksum.value().to_be_bytes());

            Ipv4Packet::pseudo_checksum(ip_header, TransportProtocolType::UDP, udp_length as usize)
        };

        checksum.add_slice(&dest[data_range.clone()]);

        let udp_header = &mut dest[start_offset + 20..start_offset + 28];
        let src_data = self.transport_data.full_data();
        udp_header[0..2].copy_from_slice(&src_data[2..4]);
        udp_header[2..4].copy_from_slice(&src_data[0..2]);
        udp_header[4..6].copy_from_slice(&udp_length.to_be_bytes());
        udp_header[6..8].fill(0);

        checksum.add_slice(udp_header);
        checksum.fold();

        let checksum = checksum.value();
        let checksum = if checksum == 0x0000 { 0xffff } else { checksum };
        udp_header[6..8].copy_from_slice(&checksum.to_be_bytes());
        Ok(start_offset)
    }
}

pub struct Ipv6Packet<'a> {
    data: &'a [u8],
    transport_data: TransportData<'a>,
    fragment_extension_data: Option<&'a [u8]>,
}

impl<'a> Ipv6Packet<'a> {
    const FRAGMENT_OFFSET_MASK: u16 = 0x1fff;
    const FRAGMENT_MF_MASK: u16 = 1;

    fn from_data(data: &[u8]) -> Result<Ipv6Packet, IpError> {
        if data.len() < 40 {
            return Err("Not enough bytes in IPv6 header".into());
        }
        let mut fragment_extension_data = None;
        let mut last_payload = None;
        for payload in Self::iter_payloads(data) {
            let payload = payload?;
            if payload.protocol_type == TransportProtocolType::IPV6_FRAGMENT {
                fragment_extension_data = Some(payload.data);
            }
            last_payload = Some(payload);
        }
        let last_payload = if let Some(last_payload) = last_payload {
            last_payload
        } else {
            return Err("IPv6 packet has no payload".into());
        };

        let transport_data =
            TransportData::from_data(last_payload.protocol_type, last_payload.data)?;

        Ok(Ipv6Packet {
            data,
            transport_data,
            fragment_extension_data,
        })
    }

    fn into_data(self) -> &'a [u8] {
        self.data
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
        self.transport_data.protocol()
    }

    fn transport_protocol_data(&self) -> &TransportData {
        &self.transport_data
    }

    fn traffic_class(&self) -> TrafficClass {
        let tc = ((self.data[0] << 4) & 0xf0) | ((self.data[1] >> 2) & 0x0f);
        TrafficClass(tc)
    }

    fn flow_label(&self) -> u32 {
        let mut fl = [0u8; 4];
        fl.copy_from_slice(&self.data[0..4]);
        let fl = u32::from_be_bytes(fl);
        (fl >> 12) & 0x03ffffff
    }

    fn payload_length_header(&self) -> u16 {
        let mut pl = [0u8; 2];
        pl.copy_from_slice(&self.data[4..6]);
        u16::from_be_bytes(pl)
    }

    fn hop_limit(&self) -> u8 {
        self.data[7]
    }

    fn fragment_offset(&self) -> Option<u16> {
        let mut fragment_offset = [0u8; 2];
        fragment_offset.copy_from_slice(&self.fragment_extension_data?[2..4]);
        fragment_offset.copy_from_slice(&self.data[6..8]);
        let fragment = u16::from_be_bytes(fragment_offset);
        let more_fragments = fragment & Self::FRAGMENT_MF_MASK == Self::FRAGMENT_MF_MASK;
        let fragment_offset = (fragment >> 3) & Self::FRAGMENT_OFFSET_MASK;
        if more_fragments || fragment_offset > 0 {
            Some(fragment_offset)
        } else {
            None
        }
    }

    fn is_fragment_shifted(&self) -> bool {
        match self.fragment_offset() {
            Some(0) | None => false,
            Some(_) => true,
        }
    }

    fn pseudo_checksum(
        data: &[u8],
        transport_protocol: TransportProtocolType,
        transport_length: usize,
    ) -> Checksum {
        let mut checksum = Checksum::new();
        checksum.add_slice(&data[8..40]);
        checksum.add_slice(&[0u8, transport_protocol.to_u8()]);
        checksum.add_slice(&(transport_length as u32).to_be_bytes());
        checksum
    }

    fn validate_transport_checksum(&self) -> bool {
        if self.is_fragment_shifted() {
            return true;
        }
        let transport_data = self.transport_protocol_data();
        if let Some(checksum) = transport_data.checksum() {
            if transport_data.protocol() == TransportProtocolType::UDP && checksum == 0x0000 {
                return true;
            }
            let mut calculated_checksum = Self::pseudo_checksum(
                self.data,
                self.transport_protocol(),
                transport_data.full_data().len(),
            );
            calculated_checksum.add_slice(transport_data.full_data());
            calculated_checksum.fold();
            calculated_checksum.value() == 0x0000
        } else {
            true
        }
    }

    fn write_translated_ip_header(
        &self,
        dest: &mut [u8],
        fragment_extension: Option<&[u8]>,
        transport_data_len: usize,
    ) -> Result<(), IpError> {
        // RFC 7915, Section 5.1.
        if dest.len() != 20 {
            return Err(
                "Destination slice for IPv6 to IPv4 header conversion needs exactly 20 bytes"
                    .into(),
            );
        }
        dest[0] = (4 << 4) | 5;
        dest[1] = self.traffic_class().to_u8();
        dest[2..4].copy_from_slice(&(transport_data_len as u16 + 20u16).to_be_bytes());
        let df_flag = if transport_data_len + 20 <= 1260 {
            0x0000u16
        } else {
            Ipv4Packet::FRAGMENT_DF_MASK
        };
        if let Some(fragment_data) = fragment_extension {
            // RFC 7915, Section 5.1.1.
            let next_header = TransportProtocolType::from_u8(fragment_data[0]);
            if next_header.is_ipv6_extension() {
                return Err("Cannot translate unsupported IPv6 extension header to IPv4".into());
            }
            dest[4..6].copy_from_slice(&fragment_data[6..8]);

            let mut fragment_offset = [0u8; 2];
            fragment_offset.copy_from_slice(&fragment_data[2..4]);

            let fragment_offset = u16::from_be_bytes(fragment_offset);
            let mf_flag = if fragment_offset & Self::FRAGMENT_MF_MASK == Self::FRAGMENT_MF_MASK {
                Ipv4Packet::FRAGMENT_MF_MASK
            } else {
                0x0000u16
            };
            let fragment_offset = (fragment_offset >> 3) & Self::FRAGMENT_OFFSET_MASK;
            let fragment_offset_ipv4 = df_flag | mf_flag | fragment_offset;
            dest[6..8].copy_from_slice(&fragment_offset_ipv4.to_be_bytes());
        } else {
            dest[4..6].fill(0);
            dest[6..8].copy_from_slice(&df_flag.to_be_bytes());
        };
        dest[8] = self.hop_limit().saturating_sub(TTL_HOP_DECREMENT);
        let transport_protocol = match self.transport_protocol() {
            TransportProtocolType::IPV6_ICMP => TransportProtocolType::ICMP,
            protocol => protocol,
        };
        dest[9] = transport_protocol.to_u8();
        dest[12..16].copy_from_slice(&self.data[20..24]);
        dest[16..20].copy_from_slice(&self.data[36..40]);

        dest[10..12].fill(0);
        let mut checksum = Checksum::new();
        checksum.add_slice(dest);
        checksum.fold();
        dest[10..12].copy_from_slice(&checksum.value().to_be_bytes());
        Ok(())
    }

    fn write_translated(&self, dest: &mut [u8], truncated: bool) -> Result<usize, IpError> {
        let transport_data = self.transport_data.full_data();
        let transport_protocol = self.transport_protocol();
        if transport_protocol == TransportProtocolType::ICMP {
            return Err("ICMPv4 payload found in IPv6 packet".into());
        }
        if dest.len() < 20 + transport_data.len() {
            // RFC 7915, Section 1.4 states that a Packet Too Big should be sent here.
            // As there's enough extra space in buffers, this shouldn't be a big problem.
            return Err("Not enough space to translate from IPv6 to IPv4".into());
        }
        let transport_data_len = if truncated {
            let original_payload_length = self.payload_length_header();
            let original_header_length = self.data.len() - transport_data.len();
            original_payload_length as usize - original_header_length
        } else {
            transport_data.len()
        };
        self.write_translated_ip_header(
            &mut dest[0..20],
            self.fragment_extension_data,
            transport_data_len,
        )?;
        dest[20..20 + transport_data.len()].copy_from_slice(transport_data);
        if !self.is_fragment_shifted() && transport_protocol.supports_checksum() {
            let remove = Self::pseudo_checksum(self.data, transport_protocol, transport_data_len);
            let add = Ipv4Packet::pseudo_checksum(dest, transport_protocol, transport_data_len);
            self.transport_data.write_translated_checksum(
                &mut dest[20..20 + transport_data.len()],
                remove,
                add,
            );
        }

        Ok(20 + transport_data.len())
    }

    fn write_icmp_translated(&self, dest: &mut [u8], icmp_len: usize) -> Result<usize, IpError> {
        let (ip_header, icmp_data) = dest[..20 + icmp_len].split_at_mut(20);
        let mut checksum = Checksum::new();
        checksum.add_slice(icmp_data);
        checksum.fold();
        icmp_data[2..4].copy_from_slice(&checksum.value().to_be_bytes());

        self.write_translated_ip_header(ip_header, None, icmp_len)?;

        Ok(20 + icmp_len)
    }

    fn write_icmp_response_header(
        &self,
        dest: &mut [u8],
        icmp_len: usize,
    ) -> Result<usize, IpError> {
        if dest.len() < 40 + icmp_len {
            return Err("Not enough space to write ICMPv6 response header".into());
        }
        let ip_header = &mut dest[0..40];
        ip_header[0..4].copy_from_slice(&self.data[0..4]);
        ip_header[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes());
        ip_header[6] = TransportProtocolType::IPV6_ICMP.to_u8();
        ip_header[7] = DEFAULT_RESPONSE_TTL;
        ip_header[8..24].copy_from_slice(&self.data[24..40]);
        ip_header[24..40].copy_from_slice(&self.data[8..24]);

        Ok(40)
    }

    fn write_udp_translated(
        &self,
        dest: &mut [u8],
        data_range: Range<usize>,
    ) -> Result<usize, IpError> {
        if data_range.start < 20 + 8 {
            return Err("Not enough space to add IPv4 header in UDP translation".into());
        }
        let start_offset = data_range.start - 28;
        self.write_translated_ip_header(
            &mut dest[start_offset..start_offset + 20],
            None,
            data_range.len() + 8,
        )?;
        dest[start_offset + 20..start_offset + 24]
            .copy_from_slice(&self.transport_data.full_data()[0..4]);
        dest[start_offset + 24..start_offset + 26]
            .copy_from_slice(&(data_range.len() as u16 + 8).to_be_bytes());

        dest[start_offset + 26..start_offset + 28].fill(0);
        let mut checksum = Ipv4Packet::pseudo_checksum(
            &dest[start_offset..start_offset + 20],
            self.transport_protocol(),
            data_range.len() + 8,
        );
        checksum.add_slice(&dest[start_offset + 20..data_range.end]);
        checksum.fold();

        let checksum = checksum.value();
        let checksum = if checksum == 0x0000 { 0xffff } else { checksum };
        dest[start_offset + 26..start_offset + 28].copy_from_slice(&checksum.to_be_bytes());

        Ok(start_offset)
    }

    fn write_udp_response(
        &self,
        dest: &mut [u8],
        data_range: Range<usize>,
    ) -> Result<usize, IpError> {
        if data_range.start < 40 + 8 {
            return Err("Not enough space to add IPv6 header in UDP response".into());
        }
        let start_offset = data_range.start - 48;
        let udp_length: u16 = 8 + data_range.len() as u16;
        let mut checksum = Checksum::new();
        checksum.add_slice(&dest[data_range.clone()]);
        {
            let ip_header = &mut dest[start_offset..start_offset + 40];
            // Keep flow label and traffic class empty.
            let tc = 0u16;
            let first = (0x06 << 12) | (tc << 4);
            ip_header[0..2].copy_from_slice(&first.to_be_bytes());
            ip_header[2..4].fill(0);
            ip_header[4..6].copy_from_slice(&udp_length.to_be_bytes());
            ip_header[6] = TransportProtocolType::UDP.to_u8();
            ip_header[7] = DEFAULT_RESPONSE_TTL;
            ip_header[8..24].copy_from_slice(&self.data[24..40]);
            ip_header[24..40].copy_from_slice(&self.data[8..24]);

            checksum.add_slice(&ip_header[8..40]);
            checksum.add_slice(&udp_length.to_be_bytes());
        }

        let udp_header = &mut dest[start_offset + 40..start_offset + 48];
        let src_data = self.transport_data.full_data();
        udp_header[0..2].copy_from_slice(&src_data[2..4]);
        udp_header[2..4].copy_from_slice(&src_data[0..2]);
        udp_header[4..6].copy_from_slice(&udp_length.to_be_bytes());
        udp_header[6..8].fill(0);

        checksum.add_slice(&[0u8, TransportProtocolType::UDP.to_u8()]);
        checksum.add_slice(udp_header);
        checksum.fold();

        let checksum = checksum.value();
        let checksum = if checksum == 0x0000 { 0xffff } else { checksum };
        udp_header[6..8].copy_from_slice(&checksum.to_be_bytes());
        Ok(start_offset)
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

impl<'a> IpPacket<'a> {
    pub fn from_data(data: &[u8]) -> Result<IpPacket, IpError> {
        if data.is_empty() {
            return Err("IP packet is empty, cannot extract header data".into());
        }
        match data[0] >> 4 {
            4 => Ok(IpPacket::V4(Ipv4Packet::from_data(data)?)),
            6 => Ok(IpPacket::V6(Ipv6Packet::from_data(data)?)),
            _ => {
                warn!("ESP IP packet is not a supported IP version: {:x}", data[0]);
                Err("Unsupported IP protocol version".into())
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

    pub fn transport_protocol_data(&self) -> &TransportData {
        match self {
            IpPacket::V4(packet) => packet.transport_protocol_data(),
            IpPacket::V6(packet) => packet.transport_protocol_data(),
        }
    }

    pub fn src_port(&self) -> Option<u16> {
        if self.is_fragment_shifted() {
            None
        } else {
            self.transport_protocol_data().src_port()
        }
    }

    pub fn dst_port(&self) -> Option<u16> {
        if self.is_fragment_shifted() {
            None
        } else {
            self.transport_protocol_data().dst_port()
        }
    }

    pub fn to_header(&self) -> IpHeader {
        IpHeader {
            src_addr: self.src_addr(),
            dst_addr: self.dst_addr(),
            src_port: self.src_port(),
            dst_port: self.dst_port(),
            transport_protocol: self.transport_protocol_data().protocol(),
        }
    }

    fn into_data(self) -> &'a [u8] {
        match self {
            IpPacket::V4(packet) => packet.into_data(),
            IpPacket::V6(packet) => packet.into_data(),
        }
    }

    fn validate_ip_checksum(&self) -> bool {
        match self {
            IpPacket::V4(packet) => packet.validate_ip_checksum(),
            IpPacket::V6(_) => true,
        }
    }

    fn validate_transport_checksum(&self) -> bool {
        match self {
            IpPacket::V4(packet) => packet.validate_transport_checksum(),
            IpPacket::V6(packet) => packet.validate_transport_checksum(),
        }
    }

    fn fragment_offset(&self) -> Option<u16> {
        match self {
            IpPacket::V4(packet) => packet.fragment_offset(),
            IpPacket::V6(packet) => packet.fragment_offset(),
        }
    }

    fn is_fragment_shifted(&self) -> bool {
        match self {
            IpPacket::V4(packet) => packet.is_fragment_shifted(),
            IpPacket::V6(packet) => packet.is_fragment_shifted(),
        }
    }

    fn write_translated_ipv4(&self, dest: &mut [u8], truncated: bool) -> Result<usize, IpError> {
        match self {
            IpPacket::V4(packet) => {
                dest[0..packet.data.len()].copy_from_slice(packet.data);
                // TODO 0.5.0: decrease TTL.
                Ok(packet.data.len())
            }
            IpPacket::V6(packet) => packet.write_translated(dest, truncated),
        }
    }

    fn write_updated_udp_ipv4(
        &self,
        dest: &mut [u8],
        data_range: Range<usize>,
    ) -> Result<usize, IpError> {
        match self {
            IpPacket::V4(packet) => packet.write_udp_updated_payload(dest, data_range),
            IpPacket::V6(packet) => packet.write_udp_translated(dest, data_range),
        }
    }

    fn write_udp_response(
        &self,
        dest: &mut [u8],
        data_range: Range<usize>,
    ) -> Result<usize, IpError> {
        match self {
            IpPacket::V4(packet) => packet.write_udp_response(dest, data_range),
            IpPacket::V6(packet) => packet.write_udp_response(dest, data_range),
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
            Some(src_port) => write!(
                f,
                "{} {}:{} -> ",
                self.transport_protocol_data().protocol(),
                self.src_addr(),
                src_port
            )?,
            None => write!(
                f,
                "{} {} -> ",
                self.transport_protocol_data().protocol(),
                self.src_addr()
            )?,
        }
        match self.dst_port() {
            Some(dst_port) => write!(f, "{}:{}", self.dst_addr(), dst_port)?,
            None => write!(f, "{}", self.dst_addr())?,
        }
        if let Some(offset) = self.fragment_offset() {
            write!(f, " F={}", offset)?;
        }
        match self {
            IpPacket::V4(packet) => write!(
                f,
                " DCSP={} ECN={:02b} L={} TTL={}",
                packet.dscp(),
                packet.ecn(),
                packet.total_length_header(),
                packet.ttl()
            )?,
            IpPacket::V6(packet) => write!(
                f,
                " {} FL={:#06X} L={} H={}",
                packet.traffic_class(),
                packet.flow_label(),
                packet.payload_length_header(),
                packet.hop_limit()
            )?,
        }
        write!(f, " {}", self.transport_protocol_data())
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
    pub fn src_addr(&self) -> &IpAddr {
        &self.src_addr
    }

    pub fn dst_addr(&self) -> &IpAddr {
        &self.dst_addr
    }

    pub fn src_port(&self) -> Option<&u16> {
        self.src_port.as_ref()
    }

    pub fn dst_port(&self) -> Option<&u16> {
        self.dst_port.as_ref()
    }

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
            Some(dst_port) => write!(f, "{}:{}", self.dst_addr(), dst_port),
            None => write!(f, "{}", self.dst_addr()),
        }
    }
}

pub enum TransportData<'a> {
    Udp(&'a [u8]),
    Tcp(&'a [u8], usize),
    Generic(TransportProtocolType, &'a [u8]),
}

impl TransportData<'_> {
    fn from_data(protocol: TransportProtocolType, data: &[u8]) -> Result<TransportData, IpError> {
        match protocol {
            TransportProtocolType::UDP => {
                if data.len() >= 4 {
                    Ok(TransportData::Udp(data))
                } else {
                    Err("Not enough data for UDP header".into())
                }
            }
            TransportProtocolType::TCP => {
                if data.len() >= 20 {
                    let data_offset = ((data[12] >> 4) & 0x0f) as usize * 4;
                    if data_offset > data.len() {
                        Err("TCP data offset overflow".into())
                    } else if data_offset < 20 {
                        Err("TCP data offset folds into the header".into())
                    } else {
                        Ok(TransportData::Tcp(data, data_offset))
                    }
                } else {
                    Err("Not enough data for TCP header".into())
                }
            }
            generic => Ok(TransportData::Generic(generic, data)),
        }
    }

    fn full_data(&self) -> &[u8] {
        match self {
            TransportData::Udp(data) => data,
            TransportData::Tcp(data, _) => data,
            TransportData::Generic(_, data) => data,
        }
    }

    fn payload_data(&self) -> &[u8] {
        match self {
            TransportData::Udp(data) => &data[8..],
            TransportData::Tcp(data, data_offset) => &data[*data_offset..],
            TransportData::Generic(_, data) => data,
        }
    }

    fn checksum(&self) -> Option<u16> {
        match self {
            TransportData::Udp(data) => {
                let mut checksum = [0u8; 2];
                checksum.copy_from_slice(&data[6..8]);
                Some(u16::from_be_bytes(checksum))
            }
            TransportData::Tcp(data, _) => {
                let mut checksum = [0u8; 2];
                checksum.copy_from_slice(&data[16..18]);
                Some(u16::from_be_bytes(checksum))
            }
            TransportData::Generic(protocol, data) => match *protocol {
                TransportProtocolType::ICMP | TransportProtocolType::IPV6_ICMP => {
                    let mut checksum = [0u8; 2];
                    checksum.copy_from_slice(&data[2..4]);
                    Some(u16::from_be_bytes(checksum))
                }
                _ => None,
            },
        }
    }

    fn write_translated_checksum(&self, dest: &mut [u8], remove: Checksum, add: Checksum) {
        match self {
            TransportData::Udp(data) => {
                let mut checksum = [0u8; 2];
                checksum.copy_from_slice(&data[6..8]);
                let checksum = u16::from_be_bytes(checksum);
                if checksum != 0x0000 {
                    let mut checksum = Checksum::from_inverted(checksum);
                    checksum.incremental_update(remove, add);
                    checksum.fold();

                    let checksum = checksum.value();
                    let checksum = if checksum == 0x0000 { 0xffff } else { checksum };
                    dest[6..8].copy_from_slice(&checksum.to_be_bytes());
                }
            }
            TransportData::Tcp(data, _) => {
                let mut checksum = [0u8; 2];
                checksum.copy_from_slice(&data[16..18]);
                let mut checksum = Checksum::from_inverted(u16::from_be_bytes(checksum));
                checksum.incremental_update(remove, add);
                checksum.fold();
                dest[16..18].copy_from_slice(&checksum.value().to_be_bytes());
            }
            TransportData::Generic(protocol, data) => {
                // Translating from ICMPv6 to ICMPv4 should drop the header checksum.
                let (remove, add) = match *protocol {
                    TransportProtocolType::IPV6_ICMP => (remove, Checksum::new()),
                    TransportProtocolType::ICMP => (Checksum::new(), add),
                    _ => (remove, add),
                };
                match *protocol {
                    TransportProtocolType::ICMP | TransportProtocolType::IPV6_ICMP => {
                        let mut checksum = [0u8; 2];
                        checksum.copy_from_slice(&data[2..4]);
                        let checksum = u16::from_be_bytes(checksum);
                        let mut checksum = Checksum::from_inverted(checksum);
                        checksum.incremental_update(remove, add);
                        checksum.fold();
                        let checksum = checksum.value();
                        dest[2..4].copy_from_slice(&checksum.to_be_bytes());
                    }
                    _ => {}
                }
            }
        }
    }

    fn protocol(&self) -> TransportProtocolType {
        match self {
            TransportData::Udp(_) => TransportProtocolType::UDP,
            TransportData::Tcp(_, _) => TransportProtocolType::TCP,
            TransportData::Generic(protocol, _) => *protocol,
        }
    }

    fn src_port(&self) -> Option<u16> {
        match self {
            TransportData::Tcp(data, _) | TransportData::Udp(data) => {
                let mut src_port = [0u8; 2];
                src_port.copy_from_slice(&data[0..2]);
                Some(u16::from_be_bytes(src_port))
            }
            TransportData::Generic(_, _) => None,
        }
    }

    fn dst_port(&self) -> Option<u16> {
        match self {
            TransportData::Tcp(data, _) | TransportData::Udp(data) => {
                let mut dst_port = [0u8; 2];
                dst_port.copy_from_slice(&data[2..4]);
                Some(u16::from_be_bytes(dst_port))
            }
            TransportData::Generic(_, _) => None,
        }
    }
}

impl fmt::Display for TransportData<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportData::Udp(data) => {
                if let Some(checksum) = self.checksum() {
                    write!(f, "UDP C={:#06X}: {}", checksum, fmt_slice_hex(data))
                } else {
                    write!(f, "UDP C=?: {}", fmt_slice_hex(data))
                }
            }
            TransportData::Tcp(data, _) => {
                if let Some(checksum) = self.checksum() {
                    write!(f, "TCP C={:#06X}: {}", checksum, fmt_slice_hex(data))
                } else {
                    write!(f, "TCP C=?: {}", fmt_slice_hex(data))
                }
            }
            TransportData::Generic(protocol, data) => match *protocol {
                TransportProtocolType::ICMP => match icmp::IcmpV4Message::from_data(data) {
                    Ok(icmp) => icmp.fmt(f),
                    Err(err) => write!(f, "ICMPv4 error: {}", err),
                },
                TransportProtocolType::IPV6_ICMP => match icmp::IcmpV6Message::from_data(data) {
                    Ok(icmp) => icmp.fmt(f),
                    Err(err) => write!(f, "ICMPv6 error: {}", err),
                },
                protocol => write!(f, "{} {}", protocol, fmt_slice_hex(data)),
            },
        }
    }
}

#[derive(Clone)]
pub struct Nat64Prefix([u8; 12]);

impl Nat64Prefix {
    pub fn new(prefix: Ipv6Addr) -> Nat64Prefix {
        let mut prefix_octets = [0u8; 12];
        prefix_octets[0..12].copy_from_slice(&prefix.octets()[0..12]);
        Nat64Prefix(prefix_octets)
    }

    fn map_ipv4(&self, addr: &Ipv4Addr) -> Ipv6Addr {
        let mut segments = [0u8; 16];
        segments[0..12].copy_from_slice(&self.0);
        segments[12..16].copy_from_slice(&addr.octets());
        segments.into()
    }

    fn traffic_selector(&self) -> message::TrafficSelector {
        let mut start_addr = [0u8; 16];
        start_addr[0..12].copy_from_slice(&self.0);
        let mut end_addr = start_addr;
        start_addr[12..16].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        end_addr[12..16].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        message::TrafficSelector::from_ipv6_range(
            Ipv6Addr::from(start_addr)..=Ipv6Addr::from(end_addr),
        )
    }
}

impl Deref for Nat64Prefix {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone)]
pub enum IpNetmask {
    Ipv4Mask(Ipv4Addr, Ipv4Addr),
    Ipv6Prefix(Ipv6Addr, u8),
}

pub struct SplitRouteRegistry {
    tunnel_domains: Vec<String>,
}

impl SplitRouteRegistry {
    pub async fn refresh_addresses(&mut self) -> Result<Vec<IpAddr>, IpError> {
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
        Ok(ip_addresses)
    }
}

#[derive(Clone)]
pub struct Network {
    nat64_prefix: Option<Nat64Prefix>,
    real_ip: Option<IpAddr>,
    ip_netmasks: Vec<IpNetmask>,
    dns_addrs: Vec<IpAddr>,
    dns_addrs_ipv4: Vec<Ipv4Addr>,
    tunnel_ips: Vec<IpAddr>,
    dns64_domains_idna: Vec<Vec<u8>>,
    dns64_domains_dns: TunnelDomainsDns,
    local_ts: Vec<message::TrafficSelector>,
    dns_translator: Option<dns::Dns64Translator>,
}

impl Network {
    pub fn new(
        nat64_prefix: Option<Nat64Prefix>,
        dns64_domains: Vec<String>,
        dns_addrs_ipv4: Vec<Ipv4Addr>,
    ) -> Result<Network, IpError> {
        let dns64_domains_idna = dns64_domains
            .iter()
            .map(|domain| domain.as_bytes().to_vec())
            .collect::<Vec<_>>();
        let dns64_domains_dns = TunnelDomainsDns::new(&dns64_domains);
        let tunnel_ips = dns_addrs_ipv4
            .iter()
            .map(|dns_addr| IpAddr::V4(*dns_addr))
            .collect::<Vec<_>>();

        let dns_translator = nat64_prefix
            .as_ref()
            .map(|nat64_prefix| dns::Dns64Translator::new(nat64_prefix.clone()));
        Ok(Network {
            nat64_prefix,
            real_ip: None,
            ip_netmasks: vec![],
            dns_addrs: vec![],
            tunnel_ips,
            dns64_domains_idna,
            dns64_domains_dns,
            dns_addrs_ipv4,
            local_ts: vec![],
            dns_translator,
        })
    }

    pub fn split_route_registry(&self, tunnel_domains: Vec<String>) -> Option<SplitRouteRegistry> {
        if tunnel_domains.is_empty() {
            None
        } else {
            Some(SplitRouteRegistry { tunnel_domains })
        }
    }

    pub fn is_nat64(&self) -> bool {
        self.nat64_prefix.is_some()
    }

    pub fn update_ip_configuration(&mut self, internal_addr: Option<IpAddr>, dns_addrs: &[IpAddr]) {
        self.real_ip = internal_addr;
        let ipv4_netmask = match internal_addr {
            Some(IpAddr::V4(addr)) => Some(IpNetmask::Ipv4Mask(addr, Ipv4Addr::from_bits(!0u32))),
            Some(IpAddr::V6(_)) | None => None,
        };
        self.ip_netmasks = if let Some(nat64_prefix) = &self.nat64_prefix {
            self.dns_addrs = dns_addrs
                .iter()
                .flat_map(|dns_addr| match dns_addr {
                    IpAddr::V4(addr) => {
                        if !self.dns_addrs_ipv4.contains(addr) {
                            Some(IpAddr::V6(nat64_prefix.map_ipv4(addr)))
                        } else {
                            None
                        }
                    }
                    IpAddr::V6(_) => Some(*dns_addr),
                })
                .collect::<Vec<_>>();
            self.dns_addrs.extend(
                self.dns_addrs_ipv4
                    .iter()
                    .map(|dns_addr| IpAddr::V4(*dns_addr)),
            );
            if let (Some(IpAddr::V4(addr)), Some(ipv4_netmask)) = (&self.real_ip, ipv4_netmask) {
                let ipv6_addr = nat64_prefix.map_ipv4(addr);
                vec![ipv4_netmask, IpNetmask::Ipv6Prefix(ipv6_addr, 96)]
            } else {
                vec![]
            }
        } else {
            self.dns_addrs = dns_addrs.to_vec();
            if let Some(ipv4_netmask) = ipv4_netmask {
                vec![ipv4_netmask]
            } else {
                vec![]
            }
        };
        self.update_local_ts();
    }

    pub fn set_split_routes(&mut self, ip_addresses: &[IpAddr]) {
        self.tunnel_ips = ip_addresses.to_vec();
        self.tunnel_ips.extend(
            self.dns_addrs_ipv4
                .iter()
                .map(|dns_addr| IpAddr::V4(*dns_addr)),
        );
        self.update_local_ts();
    }

    fn update_local_ts(&mut self) {
        self.local_ts.clear();
        if let Some(nat64_prefix) = &self.nat64_prefix {
            self.local_ts.push(nat64_prefix.traffic_selector());
            if !self.tunnel_ips.is_empty() {
                self.local_ts
                    .extend(self.tunnel_ips.iter().flat_map(|ip_address| {
                        if ip_address.is_ipv4() {
                            Some(message::TrafficSelector::from_ip(*ip_address))
                        } else {
                            None
                        }
                    }));
            }
        } else if self.tunnel_ips.is_empty() {
            let full_ts = message::TrafficSelector::from_ipv4_range(
                Ipv4Addr::new(0, 0, 0, 0)..=Ipv4Addr::new(255, 255, 255, 255),
            );
            self.local_ts.push(full_ts);
        } else {
            self.local_ts
                .extend(self.tunnel_ips.iter().filter_map(|ip_address| {
                    if ip_address.is_ipv4() {
                        Some(message::TrafficSelector::from_ip(*ip_address))
                    } else {
                        None
                    }
                }))
        }
    }

    pub fn ip_netmasks(&self) -> &[IpNetmask] {
        &self.ip_netmasks
    }

    pub fn dns_addrs(&self) -> &[IpAddr] {
        &self.dns_addrs
    }

    pub fn ts_local(&self) -> &[message::TrafficSelector] {
        &self.local_ts
    }

    pub fn dns64_domains(&self) -> &[Vec<u8>] {
        &self.dns64_domains_idna
    }

    pub fn traffic_selector_compatible(&self, ts_type: message::TrafficSelectorType) -> bool {
        if self.nat64_prefix.is_some() {
            ts_type == message::TrafficSelectorType::TS_IPV6_ADDR_RANGE
                || ts_type == message::TrafficSelectorType::TS_IPV4_ADDR_RANGE
        } else {
            match &self.real_ip {
                Some(IpAddr::V6(_)) => ts_type == message::TrafficSelectorType::TS_IPV6_ADDR_RANGE,
                Some(IpAddr::V4(_)) => ts_type == message::TrafficSelectorType::TS_IPV4_ADDR_RANGE,
                None => false,
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

    pub fn translate_ipv4_header(&self, hdr: &IpHeader) -> Option<IpHeader> {
        let nat64_prefix = self.nat64_prefix.as_ref()?;
        let src_addr = match &hdr.src_addr {
            IpAddr::V4(addr) => IpAddr::V6(nat64_prefix.map_ipv4(addr)),
            IpAddr::V6(_) => return None,
        };
        let dst_addr = match &hdr.dst_addr {
            IpAddr::V4(addr) => IpAddr::V6(nat64_prefix.map_ipv4(addr)),
            IpAddr::V6(_) => return None,
        };
        Some(IpHeader {
            src_addr,
            dst_addr,
            src_port: hdr.src_port,
            dst_port: hdr.dst_port,
            transport_protocol: hdr.transport_protocol,
        })
    }

    fn dns_matches_nat64(&self, dns_packet: &dns::DnsPacket) -> bool {
        self.dns64_domains_dns
            .domains()
            .iter()
            .any(|domain| dns_packet.matches_nat64(domain))
    }

    pub fn translate_packet_from_esp<'a>(
        &mut self,
        packet: IpPacket<'a>,
        header: IpHeader,
        out_buf: &'a mut [u8],
    ) -> Result<RoutingActionEsp<'a>, IpError> {
        if !self.is_nat64() {
            let data = packet.into_data();
            return Ok(RoutingActionEsp::Forward(data));
        };
        let is_dns_ip = self.dns_addrs.contains(header.dst_addr());
        match packet {
            IpPacket::V6(packet) => {
                if packet.hop_limit() <= TTL_HOP_DECREMENT {
                    // RFC 7915, Section 5.1:
                    // Hop limit will be reduced to 0 - will be dropped by the next hop.
                    warn!(
                        "Received packet with expired Hop limit from ESP: {}",
                        header
                    );
                    let length = icmp::ICMP_ERROR_TTL_HOP_LIMIT
                        .write_error_response(&IpPacket::V6(packet), out_buf)?;
                    return Ok(RoutingActionEsp::ReturnToSender(out_buf, length));
                }
                if header.transport_protocol() == TransportProtocolType::IPV6_ICMP {
                    return self.translate_icmp_packet_from_esp(packet, out_buf);
                }
                // TODO 0.5.0: if fragment header is followed by an unsupported extension header, drop it.
                // https://datatracker.ietf.org/doc/html/rfc7915#section-5.1.1

                if !is_dns_ip {
                    let length = packet.write_translated(out_buf, false)?;
                    debug_print_packet(&out_buf[..length]);
                    Ok(RoutingActionEsp::Forward(&out_buf[..length]))
                } else {
                    self.translate_dns_packet_from_esp(IpPacket::V6(packet), header, out_buf)
                }
            }
            IpPacket::V4(packet) => {
                if packet.ttl() <= TTL_HOP_DECREMENT {
                    // RFC 7915, Section 4.1:
                    // TTL limit will be reduced to 0 - will be dropped by the next hop.
                    warn!("Received packet with expired TTL: {}", header);
                    let length = icmp::ICMP_ERROR_TTL_HOP_LIMIT
                        .write_error_response(&IpPacket::V4(packet), out_buf)?;
                    return Ok(RoutingActionEsp::ReturnToSender(out_buf, length));
                }
                if !is_dns_ip || packet.transport_protocol() == TransportProtocolType::ICMP {
                    // TODO 0.5.0: decrease TTL.
                    Ok(RoutingActionEsp::Forward(packet.into_data()))
                } else {
                    self.translate_dns_packet_from_esp(IpPacket::V4(packet), header, out_buf)
                }
            }
        }
    }

    fn translate_dns_packet_from_esp<'a>(
        &mut self,
        packet: IpPacket<'a>,
        header: IpHeader,
        out_buf: &'a mut [u8],
    ) -> Result<RoutingActionEsp<'a>, IpError> {
        if !packet.validate_ip_checksum() {
            return Err("DNS packet has invalid IP checksum".into());
        }
        if !packet.validate_transport_checksum() {
            return Err("DNS packet has invalid UDP checksum".into());
        }
        if packet.fragment_offset().is_some() {
            return Err("DNS packet is fragmented".into());
        }
        let is_dns_port = header.transport_protocol() == TransportProtocolType::UDP
            && header.dst_port() == Some(&53);
        if !is_dns_port {
            warn!("Dropping non-standard packet to DNS server {}", header);
            let length =
                icmp::ICMP_ERROR_PORT_UNREACHABLE.write_error_response(&packet, out_buf)?;
            return Ok(RoutingActionEsp::ReturnToSender(out_buf, length));
        }
        let dns_packet =
            dns::DnsPacket::from_udp_payload(packet.transport_protocol_data().payload_data())?;
        trace!("Decoded DNS packet from ESP: {}", dns_packet);
        // Reserve space for UDP header.
        let dest_buf = &mut out_buf[MAX_TRANSLATED_IP_HEADER_LENGTH
            ..MAX_TRANSLATED_IP_HEADER_LENGTH + dns::MAX_PACKET_SIZE_IPV4];
        if !self.dns_matches_nat64(&dns_packet) {
            let length = packet.write_translated_ipv4(out_buf, false)?;
            debug_print_packet(&out_buf[..length]);
            return Ok(RoutingActionEsp::Forward(&out_buf[..length]));
        }

        let dns_translator = if let Some(dns_translator) = &mut self.dns_translator {
            dns_translator
        } else {
            return Err("DNS translator is not available".into());
        };

        let translation = dns_translator.translate_to_vpn(&dns_packet, dest_buf)?;
        let action = match translation {
            dns::DnsTranslationAction::Forward(length) => {
                if log::log_enabled!(log::Level::Trace) {
                    let dns_packet = dns::DnsPacket::from_udp_payload(&dest_buf[..length])?;
                    trace!("Rewrote DNS request from ESP: {}", dns_packet);
                }

                let start_offset = packet.write_updated_udp_ipv4(
                    out_buf,
                    MAX_TRANSLATED_IP_HEADER_LENGTH..MAX_TRANSLATED_IP_HEADER_LENGTH + length,
                )?;
                let data_end = MAX_TRANSLATED_IP_HEADER_LENGTH + length;
                debug_print_packet(&out_buf[start_offset..data_end]);
                RoutingActionEsp::Forward(&out_buf[start_offset..data_end])
            }
            dns::DnsTranslationAction::ReplyToSender(length) => {
                if log::log_enabled!(log::Level::Trace) {
                    let dns_packet = dns::DnsPacket::from_udp_payload(&dest_buf[..length])?;
                    trace!("Sending immediate DNS reply to ESP: {}", dns_packet);
                }
                let start_offset = packet.write_udp_response(
                    out_buf,
                    MAX_TRANSLATED_IP_HEADER_LENGTH..MAX_TRANSLATED_IP_HEADER_LENGTH + length,
                )?;
                let data_end = MAX_TRANSLATED_IP_HEADER_LENGTH + length;
                debug_print_packet(&out_buf[start_offset..data_end]);
                RoutingActionEsp::ReturnToSender(
                    &mut out_buf[start_offset..],
                    data_end - start_offset,
                )
            }
        };
        Ok(action)
    }

    fn translate_icmp_packet_from_esp<'a>(
        &mut self,
        packet: Ipv6Packet<'a>,
        out_buf: &'a mut [u8],
    ) -> Result<RoutingActionEsp<'a>, IpError> {
        if !packet.validate_transport_checksum() {
            return Err("ICMPv6 packet has invalid ICMP checksum".into());
        }
        if packet.fragment_offset().is_some() {
            return Err("ICMPv6 packet is fragmented".into());
        }

        let icmp_packet =
            icmp::IcmpV6Message::from_data(packet.transport_protocol_data().full_data())?;
        trace!("Decoded ICMPv6 packet {}", icmp_packet);
        // Reserve space for IPv4 header.
        let dest_buf = &mut out_buf[20..];

        let translation = icmp_packet.translate_to_vpn(dest_buf)?;
        let action = match translation {
            icmp::IcmpTranslationAction::Forward(length) => {
                if log::log_enabled!(log::Level::Trace) {
                    let icmp_packet = icmp::IcmpV4Message::from_data(&dest_buf[..length])?;
                    trace!("Rewrote ICMPv6 packet from ESP: {}", icmp_packet);
                }

                let length = packet.write_icmp_translated(out_buf, length)?;
                debug_print_packet(&out_buf[..length]);
                RoutingActionEsp::Forward(&out_buf[..length])
            }
            icmp::IcmpTranslationAction::Drop => RoutingActionEsp::Drop,
        };
        Ok(action)
    }

    pub fn translate_packet_from_vpn<'a>(
        &mut self,
        header: IpHeader,
        in_buf: &'a mut [u8],
        data_len: usize,
        out_buf: &'a mut [u8],
    ) -> Result<RoutingActionVpn<'a>, IpError> {
        let nat64_prefix = if let Some(nat64_prefix) = self.nat64_prefix.as_ref() {
            nat64_prefix.clone()
        } else {
            return Ok(RoutingActionVpn::Forward(in_buf, data_len));
        };
        let packet = IpPacket::from_data(&in_buf[..data_len])?;
        let packet = match packet {
            IpPacket::V4(packet) => packet,
            IpPacket::V6(_) => return Err("Cannot translate IPv6 packet in NAT64".into()),
        };
        let is_dns_ip = self.dns_addrs.contains(header.src_addr());
        let is_ipv4_tunnel = self.tunnel_ips.contains(header.src_addr());
        if packet.ttl() <= TTL_HOP_DECREMENT {
            // RFC 7915, Section 4.1:
            // TTL limit will be reduced to 0 - will be dropped by the next hop.
            warn!("Received packet with expired TTL: {}", header);
            let length = icmp::ICMP_ERROR_TTL_HOP_LIMIT
                .write_error_response(&IpPacket::V4(packet), out_buf)?;
            return Ok(RoutingActionVpn::ReturnToSender(&out_buf[..length]));
        }
        if is_dns_ip {
            self.translate_dns_packet_from_vpn(
                packet,
                header,
                is_ipv4_tunnel,
                &nat64_prefix,
                out_buf,
            )
        } else if is_ipv4_tunnel {
            let data = packet.into_data();
            // TODO 0.5.0: decrease TTL.
            out_buf[..data.len()].copy_from_slice(data);
            Ok(RoutingActionVpn::Forward(out_buf, data.len()))
        } else if packet.transport_protocol() == TransportProtocolType::ICMP {
            self.translate_icmp_packet_from_vpn(packet, out_buf, &nat64_prefix)
        } else {
            let length = packet.write_translated(out_buf, &nat64_prefix, false)?;
            debug_print_packet(&out_buf[..length]);
            Ok(RoutingActionVpn::Forward(out_buf, length))
        }
    }

    fn translate_dns_packet_from_vpn<'a>(
        &mut self,
        packet: Ipv4Packet<'a>,
        header: IpHeader,
        is_ipv4_tunnel: bool,
        nat_prefix: &Nat64Prefix,
        out_buf: &'a mut [u8],
    ) -> Result<RoutingActionVpn<'a>, IpError> {
        if !packet.validate_ip_checksum() {
            return Err("DNS packet has invalid IP checksum".into());
        }
        if !packet.validate_transport_checksum() {
            return Err("DNS packet has invalid UDP checksum".into());
        }
        if packet.fragment_offset().is_some() {
            return Err("DNS packet is fragmented".into());
        }
        let is_dns_port = header.transport_protocol() == TransportProtocolType::UDP
            && header.src_port() == Some(&53);
        if !is_dns_port {
            warn!("Dropping non-standard packet from DNS server {}", header);
            let length = icmp::ICMP_ERROR_COMMUNICATION_PROHIBITED
                .write_error_response(&IpPacket::V4(packet), out_buf)?;
            return Ok(RoutingActionVpn::ReturnToSender(&out_buf[..length]));
        }
        let dns_packet =
            dns::DnsPacket::from_udp_payload(packet.transport_protocol_data().payload_data())?;
        trace!("Decoded DNS packet from VPN: {}", dns_packet);
        // Reserve space for UDP header.
        if !self.dns_matches_nat64(&dns_packet) {
            let length = if is_ipv4_tunnel {
                let data = packet.into_data();
                out_buf[..data.len()].copy_from_slice(data);
                data.len()
            } else {
                let length = packet.write_translated(out_buf, nat_prefix, false)?;
                debug_print_packet(&out_buf[..length]);
                length
            };
            return Ok(RoutingActionVpn::Forward(out_buf, length));
        }

        let dest_buf = &mut out_buf[MAX_TRANSLATED_IP_HEADER_LENGTH
            ..MAX_TRANSLATED_IP_HEADER_LENGTH + dns::MAX_PACKET_SIZE_RESPONSE];
        let dns_translator = if let Some(dns_translator) = &mut self.dns_translator {
            dns_translator
        } else {
            return Err("DNS translator is not available".into());
        };

        trace!("Applying DNS64 translation to response");
        let length = dns_translator.translate_to_esp(&dns_packet, dest_buf)?;
        if log::log_enabled!(log::Level::Trace) {
            let dns_packet = dns::DnsPacket::from_udp_payload(&dest_buf[..length])?;
            trace!("Rewrote DNS response from VPN: {}", dns_packet);
        }

        if is_ipv4_tunnel {
            let start_offset = packet.write_udp_updated_payload(
                out_buf,
                MAX_TRANSLATED_IP_HEADER_LENGTH..MAX_TRANSLATED_IP_HEADER_LENGTH + length,
            )?;
            let data_end = MAX_TRANSLATED_IP_HEADER_LENGTH + length;
            debug_print_packet(&out_buf[start_offset..data_end]);
            Ok(RoutingActionVpn::Forward(
                &mut out_buf[start_offset..],
                data_end - start_offset,
            ))
        } else {
            let start_offset = packet.write_udp_translated(
                out_buf,
                MAX_TRANSLATED_IP_HEADER_LENGTH..MAX_TRANSLATED_IP_HEADER_LENGTH + length,
                nat_prefix,
            )?;
            let data_end = MAX_TRANSLATED_IP_HEADER_LENGTH + length;
            debug_print_packet(&out_buf[start_offset..data_end]);
            Ok(RoutingActionVpn::Forward(
                &mut out_buf[start_offset..],
                data_end - start_offset,
            ))
        }
    }

    fn translate_icmp_packet_from_vpn<'a>(
        &mut self,
        packet: Ipv4Packet<'a>,
        out_buf: &'a mut [u8],
        nat64_prefix: &Nat64Prefix,
    ) -> Result<RoutingActionVpn<'a>, IpError> {
        if !packet.validate_ip_checksum() {
            return Err("ICMPv4 packet has invalid IP checksum".into());
        }
        if !packet.validate_transport_checksum() {
            return Err("ICMPv4 packet has invalid ICMP checksum".into());
        }
        if packet.fragment_offset().is_some() {
            return Err("ICMPv4 packet is fragmented".into());
        }
        let icmp_packet =
            icmp::IcmpV4Message::from_data(packet.transport_protocol_data().full_data())?;
        trace!("Decoded ICMPv4 packet {}", icmp_packet);
        // Reserve space for IPv6 header.
        let dest_buf = &mut out_buf[40..];

        let translation = icmp_packet.translate_to_esp(dest_buf, nat64_prefix)?;
        let action = match translation {
            icmp::IcmpTranslationAction::Forward(length) => {
                if log::log_enabled!(log::Level::Trace) {
                    let icmp_packet = icmp::IcmpV6Message::from_data(&dest_buf[..length])?;
                    trace!("Rewrote ICMPv4 packet from VPN: {}", icmp_packet);
                }

                let length = packet.write_icmp_translated(out_buf, length, nat64_prefix)?;
                debug_print_packet(&out_buf[..length]);
                RoutingActionVpn::Forward(out_buf, length)
            }
            icmp::IcmpTranslationAction::Drop => RoutingActionVpn::Drop,
        };
        Ok(action)
    }
}

pub enum RoutingActionEsp<'a> {
    Forward(&'a [u8]),
    ReturnToSender(&'a mut [u8], usize),
    Drop,
}

pub enum RoutingActionVpn<'a> {
    Forward(&'a mut [u8], usize),
    ReturnToSender(&'a [u8]),
    Drop,
}

struct Checksum(u32);

impl Checksum {
    fn new() -> Checksum {
        Checksum(0)
    }

    fn from_inverted(inv: u16) -> Checksum {
        Checksum((!inv) as u32)
    }

    #[inline]
    fn fold(&mut self) {
        let mut sum = self.0;
        // RFC 1071 uses a loop, but at most two adds are needed:
        // 0xffff + 0xffff = 0x1fffe, 0x1+0xfffe = ffff
        sum = (sum >> 16) + (sum & 0x0000ffffu32);
        sum = (sum >> 16) + (sum & 0x0000ffffu32);
        self.0 = sum;
    }

    fn add_slice(&mut self, add: &[u8]) {
        // As seen on https://www.nickwilcox.com/blog/autovec/:
        // LLVM auto-vectorizes the loop, validated with https://godbolt.org/.
        // Using the following complier args:
        // "-O -C target-cpu=x86-64-v3" for x86
        // "-O --target=aarch64-apple-darwin -C target-cpu=apple-m4" for ARM64
        let mut iter = add.chunks_exact(2);
        let full_sum = iter
            .by_ref()
            .map(|bytes| ((bytes[0] as u32) << 8) | (bytes[1] as u32))
            .sum::<u32>();
        let remain_sum = match *iter.remainder() {
            [high] => (high as u32) << 8,
            [] => 0u32,
            _ => panic!("Checksum chunks_exact returned unexpected slice size"),
        };

        self.0 += full_sum + remain_sum;
    }

    fn value(&self) -> u16 {
        // Must fold before calling!
        !((self.0 & 0x0000ffff) as u16)
    }

    fn incremental_update(&mut self, mut remove: Checksum, add: Checksum) {
        // There's a lot of discussion how to optimally/correctly update checksums with limited
        // data. RFC 1624 appears to be undisputed and corrects errors in previous publications.

        // Use first form of Eqn. 3 for simplicity (same as RFC 1071 incremental update formula).
        remove.fold();
        let remove = (!remove.0) & 0x0000ffff;
        self.0 += remove + add.0;
    }
}

type DomainLabels = Vec<Vec<u8>>;

#[derive(Clone)]
struct TunnelDomainsDns {
    tunnel_domains: Vec<DomainLabels>,
}

impl TunnelDomainsDns {
    fn new(tunnel_domains: &[String]) -> TunnelDomainsDns {
        let tunnel_domains = tunnel_domains
            .iter()
            .map(|tunnel_domain| {
                tunnel_domain
                    .split(".")
                    .map(|label| label.as_bytes().to_vec())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        TunnelDomainsDns { tunnel_domains }
    }

    fn domains(&self) -> &[DomainLabels] {
        &self.tunnel_domains
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
        match self {
            Self::Internal(msg) => f.write_str(msg),
            Self::Dns(e) => write!(f, "DNS error: {}", e),
            Self::Format(e) => write!(f, "Format error: {}", e),
            Self::Io(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl error::Error for IpError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Internal(_msg) => None,
            Self::Dns(err) => Some(err),
            Self::Format(err) => Some(err),
            Self::Io(err) => Some(err),
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

fn debug_print_packet(data: &[u8]) {
    // TODO 0.5.0: Remove this debug code once everything's ready.
    let packet = match IpPacket::from_data(data) {
        Ok(packet) => packet,
        Err(err) => {
            println!("Error validating packet: {}\n{}", err, fmt_slice_hex(data));
            return;
        }
    };

    if packet.fragment_offset().is_some() {
        println!("> Packet is fragmented: {}", fmt_slice_hex(data));
    }
    match &packet {
        IpPacket::V4(packet) => {
            let valid_transport = packet.validate_transport_checksum();
            let valid_ip = packet.validate_ip_checksum();
            if !valid_transport || !valid_ip {
                println!(
                    "! Checksum validation failed: transport={} ip={} packet: {}",
                    valid_transport,
                    valid_ip,
                    fmt_slice_hex(data)
                );
            }
        }
        IpPacket::V6(packet) => {
            if !packet.validate_transport_checksum() {
                println!(
                    "! Checksum validation for transport failed, packet: {}",
                    fmt_slice_hex(data)
                )
            }
        }
    }
}
