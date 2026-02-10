use std::io::Read;
use std::io::{self, Error};
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::{error, fmt, net::Ipv6Addr};

use log::warn;
use socket2::SockAddr;
use tokio::io::ReadBuf;
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

    fn set_sockopts(socket: &socket2::Socket) -> std::io::Result<()> {
        let fd = socket.as_raw_fd();
        let enable: libc::c_int = 1;
        // Transparent mode (receive all network traffic).
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_IP,
                libc::IP_TRANSPARENT,
                std::ptr::addr_of!(enable).cast(),
                std::mem::size_of_val(&enable) as libc::socklen_t,
            )
        };
        if result != 0 {
            let err = Error::last_os_error();
            warn!("Failed to enable transparent mode on socket: {err}");
            return Err(err);
        }

        /*
        // Include all IP headers.
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_RAW,
                libc::IPV6_HDRINCL,
                std::ptr::addr_of!(enable).cast(),
                std::mem::size_of_val(&enable) as libc::socklen_t,
            )
        };
        if result != 0 {
            let err = Error::last_os_error();
            warn!("Failed to enable full headers on socket: {err}");
            return Err(err);
        }

        // Recieve additional packet information
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVPKTINFO,
                std::ptr::addr_of!(enable).cast(),
                std::mem::size_of_val(&enable) as libc::socklen_t,
            )
        };
        if result != 0 {
            let err = Error::last_os_error();
            warn!("Failed to enable full headers on socket: {err}");
            return Err(err);
        }
        */

        Ok(())
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
        /*
        let mut socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::RAW,
            Some(socket2::Protocol::UDP),
        )
        */
        // IPv4 extracts full headers.
        let mut socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::UDP),
        )
        .expect("socket create");
        Self::set_sockopts(&socket).expect("no error");
        /*socket
        .bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 53).into())
        .expect("socket bind");*/

        let mut buf = [0u8; 2000];
        loop {
            //let recv_buf = unsafe { &mut *(&mut buf as *mut [u8] as *mut [MaybeUninit<u8>]) };
            //let (bytes_read, _) = socket.recv_from(recv_buf).expect("read data");
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
