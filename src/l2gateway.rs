use std::io::Read;
use std::io::{self};
use std::{error, fmt, net::Ipv6Addr};

use tokio::{runtime, sync::oneshot};

use crate::logger::fmt_slice_hex;
use crate::uplink::UplinkService as _;
use crate::{ip::Nat64Prefix, pcap, uplink};

pub struct Config {
    pub tunnel_domains: Vec<String>,
    pub nat64_prefix: Option<Ipv6Addr>,
    pub dns64_domains: Vec<String>,
}

pub struct Server {
    tunnel_domains: Vec<String>,
    dns64_domains: Vec<String>,
    nat64_prefix: Option<Nat64Prefix>,
}

impl Server {
    pub fn new(config: Config) -> Server {
        Server {
            tunnel_domains: config.tunnel_domains,
            dns64_domains: config.dns64_domains,
            nat64_prefix: config.nat64_prefix.map(Nat64Prefix::new),
        }
    }

    pub fn run(
        &mut self,
        rt: runtime::Runtime,
        uplink: uplink::UplinkServiceType,
        shutdown_receiver: oneshot::Receiver<()>,
        pcap_sender: Option<pcap::PcapSender>,
    ) -> Result<(), TproxyError> {
        // This only provides UDP or TCP headers.
        // Maybe extract IPv6 headers from recvmsg ancillary data?
        let eth_p_all = u16::from_be(libc::ETH_P_IPV6 as u16) as libc::c_int;
        let mut socket = socket2::Socket::new(
            socket2::Domain::PACKET,
            socket2::Type::RAW,
            Some(socket2::Protocol::from(eth_p_all)),
        )
        .expect("socket create");

        let mut buf = [0u8; 2000];
        loop {
            let bytes_read = socket.read(&mut buf).expect("read data");
            let data = &buf[..bytes_read];
            println!("! Got data {}", fmt_slice_hex(data));
        }
    }
}

#[derive(Debug)]
pub enum TproxyError {
    Internal(&'static str),
    Uplink(uplink::UplinkError),
    Io(io::Error),
}

impl fmt::Display for TproxyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Internal(msg) => f.write_str(msg),
            Self::Uplink(e) => write!(f, "Uplink/VPN error: {e}"),
            Self::Io(e) => write!(f, "IO error: {e}"),
        }
    }
}

impl error::Error for TproxyError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Internal(_msg) => None,
            Self::Uplink(err) => Some(err),
            Self::Io(err) => Some(err),
        }
    }
}

impl From<&'static str> for TproxyError {
    fn from(msg: &'static str) -> TproxyError {
        Self::Internal(msg)
    }
}

impl From<uplink::UplinkError> for TproxyError {
    fn from(err: uplink::UplinkError) -> TproxyError {
        Self::Uplink(err)
    }
}

impl From<io::Error> for TproxyError {
    fn from(err: io::Error) -> TproxyError {
        Self::Io(err)
    }
}
