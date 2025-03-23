use std::{error, fmt};

use crate::logger::fmt_slice_hex;

pub(super) enum IcmpV4 {
    EchoReply,
    EchoRequest,
    DestinationUnreachable(IcmpV4DestinationUnreachable),
    TimeExceeded(IcmpV4TimeExceeded),
    ParameterProblem(IcmpV4ParameterProblem),
    Unknown(u8, u8),
}

pub(super) struct IcmpV4DestinationUnreachable(u8);

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
            other => write!(f, "Code {}", other),
        }
    }
}

pub(super) struct IcmpV4TimeExceeded(u8);

impl fmt::Display for IcmpV4TimeExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            0 => f.write_str("Time to live (TTL) expired in transit"),
            1 => f.write_str("Fragment reassembly time exceeded"),
            other => write!(f, "Code {}", other),
        }
    }
}

pub(super) struct IcmpV4ParameterProblem(u8);

impl fmt::Display for IcmpV4ParameterProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            0 => f.write_str("Pointer indicates the error"),
            1 => f.write_str("Missing a required option"),
            2 => f.write_str("Bad length"),
            other => write!(f, "Code {}", other),
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
            IcmpV4::Unknown(t, code) => write!(f, "Unknown type {} ({})", t, code),
        }
    }
}

pub(super) enum IcmpV6 {
    EchoRequest,
    EchoReply,
    DestinationUnreachable(IcmpV6DestinationUnreachable),
    PacketTooBig,
    TimeExceeded(IcmpV6TimeExceeded),
    ParameterProblem(IcmpV6ParameterProblem),
    Unknown(u8, u8),
}

pub(super) struct IcmpV6DestinationUnreachable(u8);

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
            other => write!(f, "Code {}", other),
        }
    }
}

pub(super) struct IcmpV6TimeExceeded(u8);

impl fmt::Display for IcmpV6TimeExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            0 => f.write_str("Hop limit exceeded in transit"),
            1 => f.write_str("Fragment reassembly time exceeded"),
            other => write!(f, "Code {}", other),
        }
    }
}

pub(super) struct IcmpV6ParameterProblem(u8);

impl fmt::Display for IcmpV6ParameterProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            0 => f.write_str("Erroneous header field encountered"),
            1 => f.write_str("Unrecognized Next Header type encountered"),
            2 => f.write_str("Unrecognized IPv6 option encountered"),
            other => write!(f, "Code {}", other),
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
            IcmpV6::Unknown(t, code) => write!(f, "Unknown type {} ({})", t, code),
        }
    }
}

pub(super) enum IcmpMessageType {
    V4(IcmpV4),
    V6(IcmpV6),
}

impl fmt::Display for IcmpMessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IcmpMessageType::V4(t) => t.fmt(f),
            IcmpMessageType::V6(t) => t.fmt(f),
        }
    }
}

pub(super) enum IcmpMessage<'a> {
    V4(&'a [u8]),
    V6(&'a [u8]),
}

impl IcmpMessage<'_> {
    pub fn from_icmpv4_data<'a>(data: &'a [u8]) -> Result<IcmpMessage<'a>, IcmpError> {
        if data.len() >= 8 {
            Ok(IcmpMessage::V4(data))
        } else {
            Err("Not enough data in ICMPv4 header".into())
        }
    }

    pub fn from_icmpv6_data<'a>(data: &'a [u8]) -> Result<IcmpMessage<'a>, IcmpError> {
        if data.len() >= 4 {
            Ok(IcmpMessage::V6(data))
        } else {
            Err("Not enough data in ICMPv6 header".into())
        }
    }

    pub fn icmp_type(&self) -> IcmpMessageType {
        match self {
            IcmpMessage::V4(data) => {
                let icmp_type = data[0];
                let icmp_code = data[1];
                let icmp_type = match icmp_type {
                    0 => IcmpV4::EchoReply,
                    3 => IcmpV4::DestinationUnreachable(IcmpV4DestinationUnreachable(icmp_code)),
                    8 => IcmpV4::EchoRequest,
                    11 => IcmpV4::TimeExceeded(IcmpV4TimeExceeded(icmp_code)),
                    12 => IcmpV4::ParameterProblem(IcmpV4ParameterProblem(icmp_code)),
                    icmp_type => IcmpV4::Unknown(icmp_type, icmp_code),
                };
                IcmpMessageType::V4(icmp_type)
            }
            IcmpMessage::V6(data) => {
                let icmp_type = data[0];
                let icmp_code = data[1];
                let icmp_type = match icmp_type {
                    1 => IcmpV6::DestinationUnreachable(IcmpV6DestinationUnreachable(icmp_code)),
                    2 => IcmpV6::PacketTooBig,
                    3 => IcmpV6::TimeExceeded(IcmpV6TimeExceeded(icmp_code)),
                    4 => IcmpV6::ParameterProblem(IcmpV6ParameterProblem(icmp_code)),
                    128 => IcmpV6::EchoRequest,
                    129 => IcmpV6::EchoReply,
                    icmp_type => IcmpV6::Unknown(icmp_type, icmp_code),
                };
                IcmpMessageType::V6(icmp_type)
            }
        }
    }

    pub fn checksum(&self) -> u16 {
        let data = match self {
            IcmpMessage::V4(data) => data,
            IcmpMessage::V6(data) => data,
        };
        let mut checksum = [0u8; 2];
        checksum.copy_from_slice(&data[2..4]);
        u16::from_be_bytes(checksum)
    }
}

impl fmt::Display for IcmpMessage<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IcmpMessage::V4(data) => {
                write!(
                    f,
                    "ICMPv4 {} C={:#06X}: {}",
                    self.icmp_type(),
                    self.checksum(),
                    fmt_slice_hex(data)
                )
            }
            IcmpMessage::V6(data) => {
                write!(
                    f,
                    "ICMPv6 {} C={:#06X}: {}",
                    self.icmp_type(),
                    self.checksum(),
                    fmt_slice_hex(data)
                )
            }
        }
    }
}

#[derive(Debug)]
pub enum IcmpError {
    Internal(&'static str),
}

impl fmt::Display for IcmpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Internal(msg) => f.write_str(msg),
        }
    }
}

impl error::Error for IcmpError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Internal(_msg) => None,
        }
    }
}

impl From<&'static str> for IcmpError {
    fn from(msg: &'static str) -> IcmpError {
        Self::Internal(msg)
    }
}
