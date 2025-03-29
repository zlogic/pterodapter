use std::{fmt, ops::Deref};

use log::{debug, warn};

use crate::logger::fmt_slice_hex;

use super::{IpError, IpPacket, Ipv4Packet, Ipv6Packet, Nat64Prefix, TransportProtocolType};

enum IcmpV4 {
    EchoReply,
    EchoRequest,
    DestinationUnreachable(IcmpV4DestinationUnreachable),
    TimeExceeded(IcmpV4TimeExceeded),
    ParameterProblem(IcmpV4ParameterProblem),
    Unknown(u8, u8),
}

struct IcmpV4DestinationUnreachable(u8);

impl fmt::Display for IcmpV4DestinationUnreachable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            0 => f.write_str("Destination network unreachable"),
            1 => f.write_str("Destination host unreachable"),
            2 => f.write_str("Destination protocol unreachable"),
            3 => f.write_str("Destination port unreachable"),
            4 => f.write_str("Fragmentation required, and DF flag set"),
            5 => f.write_str("Source route failed"),
            6 => f.write_str("Destination network unknown"),
            7 => f.write_str("Destination host unknown"),
            8 => f.write_str("Source host isolated"),
            9 => f.write_str("Network administratively prohibited"),
            10 => f.write_str("Host administratively prohibited"),
            11 => f.write_str("Network unreachable for ToS"),
            12 => f.write_str("Host unreachable for ToS"),
            13 => f.write_str("Communication administratively prohibited"),
            14 => f.write_str("Host Precedence Violation"),
            15 => f.write_str("Precedence cutoff in effect"),
            other => write!(f, "{}", other),
        }
    }
}

struct IcmpV4TimeExceeded(u8);

impl fmt::Display for IcmpV4TimeExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            0 => f.write_str("Time to live (TTL) expired in transit"),
            1 => f.write_str("Fragment reassembly time exceeded"),
            other => write!(f, "{}", other),
        }
    }
}

struct IcmpV4ParameterProblem(u8);

impl fmt::Display for IcmpV4ParameterProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            0 => f.write_str("Pointer indicates the error"),
            1 => f.write_str("Missing a required option"),
            2 => f.write_str("Bad length"),
            other => write!(f, "{}", other),
        }
    }
}

impl fmt::Display for IcmpV4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IcmpV4::EchoReply => write!(f, "Echo Reply"),
            IcmpV4::EchoRequest => write!(f, "Echo Request"),
            IcmpV4::DestinationUnreachable(code) => write!(f, "Destination Unreachable ({})", code),
            IcmpV4::TimeExceeded(code) => write!(f, "Time Exceeded ({})", code),
            IcmpV4::ParameterProblem(code) => write!(f, "Parameter Problem ({})", code),
            IcmpV4::Unknown(t, code) => write!(f, "{} ({})", t, code),
        }
    }
}

enum IcmpV6 {
    EchoRequest,
    EchoReply,
    DestinationUnreachable(IcmpV6DestinationUnreachable),
    PacketTooBig,
    TimeExceeded(IcmpV6TimeExceeded),
    ParameterProblem(IcmpV6ParameterProblem),
    Unknown(u8, u8),
}

struct IcmpV6DestinationUnreachable(u8);

impl fmt::Display for IcmpV6DestinationUnreachable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            0 => f.write_str("No route to destination"),
            1 => f.write_str("Communication with destination administratively prohibited"),
            2 => f.write_str("Beyond scope of source address"),
            3 => f.write_str("Address unreachable"),
            4 => f.write_str("Port unreachable"),
            5 => f.write_str("Source address failed ingress/egress policy"),
            6 => f.write_str("Reject route to destination"),
            7 => f.write_str("Error in Source Routing Header"),
            other => write!(f, "{}", other),
        }
    }
}

struct IcmpV6TimeExceeded(u8);

impl fmt::Display for IcmpV6TimeExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            0 => f.write_str("Hop limit exceeded in transit"),
            1 => f.write_str("Fragment reassembly time exceeded"),
            other => write!(f, "{}", other),
        }
    }
}

struct IcmpV6ParameterProblem(u8);

impl fmt::Display for IcmpV6ParameterProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            0 => f.write_str("Erroneous header field encountered"),
            1 => f.write_str("Unrecognized Next Header type encountered"),
            2 => f.write_str("Unrecognized IPv6 option encountered"),
            other => write!(f, "{}", other),
        }
    }
}

impl fmt::Display for IcmpV6 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IcmpV6::EchoRequest => write!(f, "Echo Request"),
            IcmpV6::EchoReply => write!(f, "Echo Reply"),
            IcmpV6::DestinationUnreachable(code) => write!(f, "Destination Unreachable ({})", code),
            IcmpV6::PacketTooBig => write!(f, "Packet Too Big"),
            IcmpV6::TimeExceeded(code) => write!(f, "Time Exceeded ({})", code),
            IcmpV6::ParameterProblem(code) => write!(f, "Parameter Problem ({})", code),
            IcmpV6::Unknown(t, code) => write!(f, "{} ({})", t, code),
        }
    }
}

pub(super) enum IcmpTranslationAction {
    Forward(usize),
    Drop,
}

pub(super) struct IcmpV4Message<'a>(&'a [u8]);

impl IcmpV4Message<'_> {
    const ICMPV6_ORIGINAL_MESSAGE_LIMIT: usize = 1280 - 8 - 40;

    pub fn from_data(data: &[u8]) -> Result<IcmpV4Message, IpError> {
        if data.len() >= 8 {
            Ok(IcmpV4Message(data))
        } else {
            Err("Not enough data in ICMPv4 header".into())
        }
    }

    fn icmp_type(&self) -> IcmpV4 {
        let icmp_type = self[0];
        let icmp_code = self[1];
        match icmp_type {
            0 => IcmpV4::EchoReply,
            3 => IcmpV4::DestinationUnreachable(IcmpV4DestinationUnreachable(icmp_code)),
            8 => IcmpV4::EchoRequest,
            11 => IcmpV4::TimeExceeded(IcmpV4TimeExceeded(icmp_code)),
            12 => IcmpV4::ParameterProblem(IcmpV4ParameterProblem(icmp_code)),
            icmp_type => IcmpV4::Unknown(icmp_type, icmp_code),
        }
    }

    fn checksum(&self) -> u16 {
        let mut checksum = [0u8; 2];
        checksum.copy_from_slice(&self[2..4]);
        u16::from_be_bytes(checksum)
    }

    fn check_translate_echo(
        original_packet: &Ipv4Packet,
        dest: &mut [u8],
        nat64_prefix: Nat64Prefix,
    ) -> Option<usize> {
        if original_packet.transport_protocol() != TransportProtocolType::ICMP
            || dest.len() < 40 + 8
        {
            return None;
        }
        // Reserve space for IPv6 header.
        let out_buf = &mut dest[40..];
        let original_icmp =
            match IcmpV4Message::from_data(original_packet.transport_protocol_data().full_data()) {
                Ok(icmp) => icmp,
                Err(_) => return None,
            };
        let length = match original_icmp.icmp_type() {
            IcmpV4::EchoRequest => {
                out_buf[0] = 128;
                out_buf[1..4].fill(0);
                let copy_bytes = out_buf.len().min(original_icmp[..].len());
                out_buf[4..copy_bytes].copy_from_slice(&original_icmp[4..copy_bytes]);
                Some(copy_bytes)
            }
            IcmpV4::EchoReply => {
                out_buf[0] = 129;
                out_buf[1..4].fill(0);
                let copy_bytes = out_buf.len().min(original_icmp[..].len());
                out_buf[4..copy_bytes].copy_from_slice(&original_icmp[4..copy_bytes]);
                Some(copy_bytes)
            }
            _ => None,
        }?;
        original_packet
            .write_icmp_translated(dest, length, nat64_prefix)
            .map_err(|err| warn!("Failed to translate Echo original header: {}", err))
            .ok()
    }

    fn translate_original_datagram_to_esp(
        &self,
        dest: &mut [u8],
        nat64_prefix: Nat64Prefix,
    ) -> Result<IcmpTranslationAction, IpError> {
        // RFC 4884, Section 4 states that the sixth octet contains the datagram length.
        // All following octets (after the datagram) contain extensions.
        let data_len = self[5] as usize * 8;
        let (original_datagram, icmp_extensions) = if data_len == 0 {
            // No extensions.
            (&self[8..], &[] as &[u8])
        } else {
            (&self[8..8 + data_len * 8], &self[8 + data_len * 8..])
        };

        let original_packet = match IpPacket::from_data(original_datagram) {
            Ok(IpPacket::V4(packet)) => Ok(packet),
            Ok(IpPacket::V6(_)) => Err("ICMPv4 header contains IPv6 original data".into()),
            Err(err) => {
                warn!(
                    "Failed to parse original datagram in ICMPv4 packet: {}",
                    err
                );
                Err(err)
            }
        }?;

        let translated_length = if let Some(translated_echo_length) =
            Self::check_translate_echo(&original_packet, &mut dest[8..], nat64_prefix.clone())
        {
            // This is a deviation from RFC 7915 - allowing failed ping responses to be matched
            // with requests.
            translated_echo_length
        } else {
            // RFC 7915, Section 4.5.
            original_packet
                .write_translated(&mut dest[8..], nat64_prefix, true)
                .map_err(|err| {
                    warn!(
                        "Failed to translate ICMPv4 original datagram to IPv6: {}",
                        err
                    );
                    err
                })?
        };

        // RFC 4884, Section 5.1 states that at least 128 bytes of the original message should be
        // provided; and in Section 5.3 that IP+ICMPv6 packets should be limited to 1280 bytes.
        let translated_length_padded = if translated_length < 128 {
            128 / 8
        } else if translated_length % 8 != 0 {
            translated_length / 8 + 1
        } else {
            translated_length / 8
        };
        if !icmp_extensions.is_empty()
            && translated_length_padded + icmp_extensions.len()
                < Self::ICMPV6_ORIGINAL_MESSAGE_LIMIT
        {
            dest[4] = translated_length_padded as u8;
            let translated_length_padded = translated_length_padded * 8;
            dest[8 + translated_length..8 + translated_length_padded * 8].fill(0);
            let dest = &mut dest[8 + translated_length_padded..];
            dest[0..icmp_extensions.len()].copy_from_slice(icmp_extensions);
            Ok(IcmpTranslationAction::Forward(
                8 + translated_length_padded + icmp_extensions.len(),
            ))
        } else {
            // Drop ICMP extensions if they won't fit into an ICMPv6 packet.
            let translated_length = translated_length.min(Self::ICMPV6_ORIGINAL_MESSAGE_LIMIT);
            Ok(IcmpTranslationAction::Forward(8 + translated_length))
        }
    }

    pub fn translate_to_esp(
        &self,
        dest: &mut [u8],
        nat64_prefix: Nat64Prefix,
    ) -> Result<IcmpTranslationAction, IpError> {
        let data_len = self[..].len();
        // RFC 7915, Section 4.2.
        match self.icmp_type() {
            IcmpV4::EchoRequest => {
                dest[0] = 128;
                dest[1..4].fill(0);
                dest[4..data_len].copy_from_slice(&self[4..]);
                Ok(IcmpTranslationAction::Forward(data_len))
            }
            IcmpV4::EchoReply => {
                dest[0] = 129;
                dest[1..4].fill(0);
                dest[4..data_len].copy_from_slice(&self[4..]);
                Ok(IcmpTranslationAction::Forward(data_len))
            }
            IcmpV4::DestinationUnreachable(IcmpV4DestinationUnreachable(code)) => {
                dest[0] = 1;
                dest[2..8].fill(0);
                match code {
                    0 | 1 => dest[1] = 0,
                    2 => {
                        dest[0] = 4;
                        dest[1] = 1;
                        // TODO 0.5.0: set pointer value.
                    }
                    3 => dest[1] = 4,
                    4 => {
                        dest[0] = 2;
                        dest[1] = 0;
                        let mut mtu = [0u8; 2];
                        mtu.copy_from_slice(&self[6..8]);
                        // Assuming MTU for IPv4 and IPv6 next hop is large enough.
                        let mtu = u16::from_be_bytes(mtu) as u32;
                        let mtu = mtu.saturating_add(20);
                        dest[4..8].copy_from_slice(&mtu.to_be_bytes());
                    }
                    5 => dest[1] = 0,
                    6..=8 => dest[1] = 0,
                    9 | 10 => dest[1] = 1,
                    11 | 12 => dest[1] = 0,
                    13 => dest[1] = 1,
                    14 => dest[1] = 1,
                    _ => {
                        debug!("Dropping unsupported ICMPv6 request {}", self);
                        return Ok(IcmpTranslationAction::Drop);
                    }
                }

                self.translate_original_datagram_to_esp(dest, nat64_prefix)
            }
            IcmpV4::TimeExceeded(IcmpV4TimeExceeded(code)) => {
                dest[0] = 3;
                dest[1] = code;
                dest[2..8].fill(0);

                self.translate_original_datagram_to_esp(dest, nat64_prefix)
            }
            IcmpV4::ParameterProblem(IcmpV4ParameterProblem(code)) => {
                dest[0] = 4;
                match code {
                    0 => {
                        dest[1] = 0;
                        // TODO 0.5.0: set pointer value.

                        self.translate_original_datagram_to_esp(dest, nat64_prefix)
                    }
                    2 => {
                        dest[1] = 0;
                        // TODO 0.5.0: set pointer value.

                        self.translate_original_datagram_to_esp(dest, nat64_prefix)
                    }
                    _ => {
                        debug!("Dropping unsupported ICMPv4 request {}", self);
                        Ok(IcmpTranslationAction::Drop)
                    }
                }
            }
            IcmpV4::Unknown(_, _) => {
                debug!("Dropping unsupported ICMPv6 request {}", self);
                Ok(IcmpTranslationAction::Drop)
            }
        }
    }
}

impl Deref for IcmpV4Message<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl fmt::Display for IcmpV4Message<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ICMPv4 {} C={:#06X}: {}",
            self.icmp_type(),
            self.checksum(),
            fmt_slice_hex(self)
        )
    }
}

pub(super) struct IcmpV6Message<'a>(&'a [u8]);

impl IcmpV6Message<'_> {
    const ICMPV4_ORIGINAL_MESSAGE_LIMIT: usize = 576 - 8 - 20;

    pub fn from_data(data: &[u8]) -> Result<IcmpV6Message, IpError> {
        if data.len() >= 4 {
            Ok(IcmpV6Message(data))
        } else {
            Err("Not enough data in ICMPv6 header".into())
        }
    }

    fn icmp_type(&self) -> IcmpV6 {
        let icmp_type = self[0];
        let icmp_code = self[1];
        match icmp_type {
            1 => IcmpV6::DestinationUnreachable(IcmpV6DestinationUnreachable(icmp_code)),
            2 => IcmpV6::PacketTooBig,
            3 => IcmpV6::TimeExceeded(IcmpV6TimeExceeded(icmp_code)),
            4 => IcmpV6::ParameterProblem(IcmpV6ParameterProblem(icmp_code)),
            128 => IcmpV6::EchoRequest,
            129 => IcmpV6::EchoReply,
            icmp_type => IcmpV6::Unknown(icmp_type, icmp_code),
        }
    }

    fn checksum(&self) -> u16 {
        let mut checksum = [0u8; 2];
        checksum.copy_from_slice(&self[2..4]);
        u16::from_be_bytes(checksum)
    }

    fn check_translate_echo(original_packet: &Ipv6Packet, dest: &mut [u8]) -> Option<usize> {
        if original_packet.transport_protocol() != TransportProtocolType::IPV6_ICMP
            || dest.len() < 20 + 8
        {
            return None;
        }
        // Reserve space for IPv4 header.
        let out_buf = &mut dest[20..];
        let original_icmp =
            match IcmpV6Message::from_data(original_packet.transport_protocol_data().full_data()) {
                Ok(icmp) => icmp,
                Err(_) => return None,
            };
        let length = match original_icmp.icmp_type() {
            IcmpV6::EchoRequest => {
                out_buf[0] = 8;
                out_buf[1..4].fill(0);
                let copy_bytes = out_buf.len().min(original_icmp[..].len());
                out_buf[4..copy_bytes].copy_from_slice(&original_icmp[4..copy_bytes]);
                Some(copy_bytes)
            }
            IcmpV6::EchoReply => {
                out_buf[0] = 0;
                out_buf[1..4].fill(0);
                let copy_bytes = out_buf.len().min(original_icmp[..].len());
                out_buf[4..copy_bytes].copy_from_slice(&original_icmp[4..copy_bytes]);
                Some(copy_bytes)
            }
            _ => None,
        }?;
        original_packet
            .write_icmp_translated(dest, length)
            .map_err(|err| warn!("Failed to translate Echo original header: {}", err))
            .ok()
    }

    fn translate_original_datagram_to_vpn(
        &self,
        dest: &mut [u8],
    ) -> Result<IcmpTranslationAction, IpError> {
        // RFC 4884, Section 4 states that the fifth octet contains the datagram length.
        // All following octets (after the datagram) contain extensions.
        let data_len = self[4] as usize * 8;
        let (original_datagram, icmp_extensions) = if data_len == 0 {
            // No extensions.
            (&self[8..], &[] as &[u8])
        } else {
            (&self[8..8 + data_len * 8], &self[8 + data_len * 8..])
        };

        let original_packet = match IpPacket::from_data(original_datagram) {
            Ok(IpPacket::V4(_)) => Err("ICMPv6 header contains IPv4 original data".into()),
            Ok(IpPacket::V6(packet)) => Ok(packet),
            Err(err) => {
                warn!(
                    "Failed to parse original datagram in ICMPv6 packet: {}",
                    err
                );
                Err(err)
            }
        }?;

        let translated_length = if let Some(translated_echo_length) =
            Self::check_translate_echo(&original_packet, &mut dest[8..])
        {
            // This is a deviation from RFC 7915 - allowing failed ping responses to be matched
            // with requests.
            translated_echo_length
        } else {
            // RFC 7915, Section 5.5.
            original_packet
                .write_translated(&mut dest[8..], true)
                .map_err(|err| {
                    warn!(
                        "Failed to translate ICMPv6 original datagram to IPv4: {}",
                        err
                    );
                    err
                })?
        };

        // RFC 792 requires the first 20+8 bytes to be provided.
        // RFC 4884, Section 5.1 states that at least 128 bytes of the original message should be
        // provided; and in Section 5.3 that IP+ICMPv4 packets should be limited to 576 bytes.
        let translated_length_padded = if translated_length < 128 {
            128 / 8
        } else if translated_length % 8 != 0 {
            translated_length / 8 + 1
        } else {
            translated_length / 8
        };
        if !icmp_extensions.is_empty()
            && translated_length_padded + icmp_extensions.len()
                < Self::ICMPV4_ORIGINAL_MESSAGE_LIMIT
        {
            dest[4] = translated_length_padded as u8;
            let translated_length_padded = translated_length_padded * 8;
            dest[8 + translated_length..8 + translated_length_padded * 8].fill(0);
            let dest = &mut dest[8 + translated_length_padded..];
            dest[0..icmp_extensions.len()].copy_from_slice(icmp_extensions);
            Ok(IcmpTranslationAction::Forward(
                8 + translated_length_padded + icmp_extensions.len(),
            ))
        } else {
            // Drop ICMP extensions if they won't fit into an ICMPv4 packet.
            let translated_length = translated_length.min(Self::ICMPV4_ORIGINAL_MESSAGE_LIMIT);
            Ok(IcmpTranslationAction::Forward(8 + translated_length))
        }
    }

    pub fn translate_to_vpn(&self, dest: &mut [u8]) -> Result<IcmpTranslationAction, IpError> {
        let data_len = self[..].len();
        // RFC 7915, Section 5.2.
        match self.icmp_type() {
            IcmpV6::EchoRequest => {
                dest[0] = 8;
                dest[1..4].fill(0);
                dest[4..data_len].copy_from_slice(&self[4..]);
                Ok(IcmpTranslationAction::Forward(data_len))
            }
            IcmpV6::EchoReply => {
                dest[0] = 0;
                dest[1..4].fill(0);
                dest[4..data_len].copy_from_slice(&self[4..]);
                Ok(IcmpTranslationAction::Forward(data_len))
            }
            IcmpV6::DestinationUnreachable(IcmpV6DestinationUnreachable(code)) => {
                dest[0] = 3;
                match code {
                    0 => dest[1] = 1,
                    1 => dest[1] = 10,
                    2 => dest[1] = 1,
                    3 => dest[1] = 1,
                    4 => dest[1] = 3,
                    _ => {
                        debug!("Dropping unsupported ICMPv6 request {}", self);
                        return Ok(IcmpTranslationAction::Drop);
                    }
                }
                dest[2..8].fill(0);

                self.translate_original_datagram_to_vpn(dest)
            }
            IcmpV6::PacketTooBig => {
                dest[0] = 3;
                dest[1] = 4;
                dest[2..4].fill(0);
                let mut mtu = [0u8; 4];
                mtu.copy_from_slice(&self[4..8]);
                // Assuming MTU for IPv4 and IPv6 next hop is large enough.
                let mtu = u32::from_be_bytes(mtu);
                let mtu = mtu.min(u16::MAX as u32).saturating_sub(20) as u16;
                dest[6..8].copy_from_slice(&mtu.to_be_bytes());

                self.translate_original_datagram_to_vpn(dest)
            }
            IcmpV6::TimeExceeded(IcmpV6TimeExceeded(code)) => {
                dest[0] = 11;
                dest[1] = code;
                dest[2..8].fill(0);

                self.translate_original_datagram_to_vpn(dest)
            }
            IcmpV6::ParameterProblem(IcmpV6ParameterProblem(code)) => {
                match code {
                    0 => {
                        dest[0] = 12;
                        dest[1] = 0;
                        // TODO 0.5.0: set pointer value.

                        self.translate_original_datagram_to_vpn(dest)
                    }
                    1 => {
                        dest[0] = 3;
                        dest[1] = 2;
                        dest[2..8].fill(0);

                        self.translate_original_datagram_to_vpn(dest)
                    }
                    _ => {
                        debug!("Dropping unsupported ICMPv6 request {}", self);
                        Ok(IcmpTranslationAction::Drop)
                    }
                }
            }
            IcmpV6::Unknown(_, _) => {
                debug!("Dropping unsupported ICMPv6 request {}", self);
                Ok(IcmpTranslationAction::Drop)
            }
        }
    }
}

impl Deref for IcmpV6Message<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl fmt::Display for IcmpV6Message<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ICMPv6 {} C={:#06X}: {}",
            self.icmp_type(),
            self.checksum(),
            fmt_slice_hex(self)
        )
    }
}
