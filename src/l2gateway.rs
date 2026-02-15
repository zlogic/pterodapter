use std::io::Read;
use std::io::{self};
use std::os::fd::AsRawFd;
use std::{error, fmt, net::Ipv6Addr};

use log::warn;
use tokio::{runtime, sync::oneshot};

use crate::logger::fmt_slice_hex;
use crate::uplink::UplinkService as _;
use crate::{ip::Nat64Prefix, pcap, uplink};

pub struct Config {
    pub nat64_prefix: Ipv6Addr,
    pub dns64_domains: Vec<String>,
}

pub struct Server {
    dns64_domains: Vec<String>,
    nat64_prefix: Nat64Prefix,
}

impl Server {
    pub fn new(config: Config) -> Server {
        Server {
            dns64_domains: config.dns64_domains,
            nat64_prefix: Nat64Prefix::new(config.nat64_prefix),
        }
    }

    pub fn run(
        &mut self,
        rt: runtime::Runtime,
        uplink: uplink::UplinkServiceType,
        shutdown_receiver: oneshot::Receiver<()>,
        pcap_sender: Option<pcap::PcapSender>,
    ) -> Result<(), L2GatewayError> {
        let mut socket = match RawSocket::new(RawSocketProtocol::IPv6) {
            Ok(socket) => socket,
            Err(err) => {
                log::error!("Failed to open raw IPv6 socket: {err}");
                return Err(err.into());
            }
        };

        if let Err(err) = socket.set_nat64_filter(&self.nat64_prefix) {
            warn!("Failed to enable BPF filter, will rely on a less efficient packet filter: {err}")
        }

        let mut buf = [0u8; 2000];
        loop {
            let bytes_read = socket.read(&mut buf).expect("read data");
            let data = &buf[..bytes_read];
            println!("! Got data {}", fmt_slice_hex(data));
        }
    }
}

enum RawSocketProtocol {
    IPv6,
}

struct RawSocket {
    socket: socket2::Socket,
}

impl RawSocket {
    fn new(protocol: RawSocketProtocol) -> Result<RawSocket, io::Error> {
        let protocol = match protocol {
            RawSocketProtocol::IPv6 => libc::ETH_P_IPV6,
        };
        // TODO GATEWAY: switch to just libc, as socket2 doesn't work well with buffers,
        // and doesn't support async.
        let protocol = socket2::Protocol::from(u16::from_be(protocol as u16) as libc::c_int);
        let socket = socket2::Socket::new(
            socket2::Domain::PACKET,
            socket2::Type::RAW,
            Some(socket2::Protocol::from(protocol)),
        )?;

        let socket = RawSocket { socket };
        if let Err(err) =
            socket.setsockopt_bool(libc::SOL_PACKET, libc::PACKET_IGNORE_OUTGOING, true)
        {
            warn!(
                "Failed to enable PACKET_IGNORE_OUTGOING socket option, will rely on a less efficient packet filter: {err}"
            )
        }

        Ok(socket)
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.socket.read(buf)
    }

    fn setsockopt<T>(
        &self,
        level: libc::c_int,
        name: libc::c_int,
        value: &T,
    ) -> Result<(), io::Error>
    where
        T: Sized,
    {
        let fd = self.socket.as_raw_fd();
        match unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                std::ptr::from_ref(value).cast(),
                std::mem::size_of_val(value) as libc::socklen_t,
            )
        } {
            0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    fn setsockopt_bool(
        &self,
        level: libc::c_int,
        name: libc::c_int,
        value: bool,
    ) -> Result<(), io::Error> {
        let value = if value {
            1 as libc::c_int
        } else {
            0 as libc::c_int
        };
        self.setsockopt(level, name, &value)
    }

    fn set_nat64_filter(&self, prefix: &Nat64Prefix) -> Result<(), io::Error> {
        let mut filter_data = BpfFilter::new_nat64_filter(prefix);
        let filter = libc::sock_fprog {
            len: filter_data.ops_len as libc::c_ushort,
            filter: filter_data.program_data.as_mut_ptr().cast(),
        };
        self.setsockopt(libc::SOL_SOCKET, libc::SO_ATTACH_FILTER, &filter)
    }
}

#[repr(C)]
struct BpfFilterOp {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

impl BpfFilterOp {
    fn new(code: u16, jt: u8, jf: u8, k: u32) -> BpfFilterOp {
        BpfFilterOp { code, jt, jf, k }
    }

    fn as_slice(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(self).cast(),
                std::mem::size_of::<BpfFilterOp>(),
            )
        }
    }
}

struct BpfFilter {
    ops_len: usize,
    program_data: Vec<u8>,
}

impl BpfFilter {
    fn new_program(prog: &[BpfFilterOp]) -> BpfFilter {
        let mut program_data = vec![0u8; std::mem::size_of::<BpfFilterOp>() * prog.len()];
        // TODO GATEWAY: write bytes directly, BPF is a standard documented in RFC 9669.
        program_data
            .chunks_exact_mut(std::mem::size_of::<BpfFilterOp>())
            .zip(prog.iter())
            .for_each(|(data, op)| data.copy_from_slice(op.as_slice()));
        BpfFilter {
            ops_len: prog.len(),
            program_data,
        }
    }

    fn new_nat64_filter(prefix: &Nat64Prefix) -> BpfFilter {
        let prefix_part = |i: usize| -> u32 {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&prefix[i * 4..(i + 1) * 4]);
            u32::from_be_bytes(bytes)
        };
        // Output of 'sudo tcpdump -i wlo1 ip6 dst net 0064:ff9b::/96 -ddd'
        BpfFilter::new_program(&[
            BpfFilterOp::new(40, 0, 0, 12),
            BpfFilterOp::new(21, 0, 7, 34525),
            BpfFilterOp::new(32, 0, 0, 38),
            BpfFilterOp::new(21, 0, 5, prefix_part(0)),
            BpfFilterOp::new(32, 0, 0, 42),
            BpfFilterOp::new(21, 0, 3, prefix_part(1)),
            BpfFilterOp::new(32, 0, 0, 46),
            BpfFilterOp::new(21, 0, 1, prefix_part(2)),
            BpfFilterOp::new(6, 0, 0, 262144),
            BpfFilterOp::new(6, 0, 0, 0),
        ])
    }
}

#[derive(Debug)]
pub enum L2GatewayError {
    Internal(&'static str),
    Uplink(uplink::UplinkError),
    Io(io::Error),
}

impl fmt::Display for L2GatewayError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Internal(msg) => f.write_str(msg),
            Self::Uplink(e) => write!(f, "Uplink/VPN error: {e}"),
            Self::Io(e) => write!(f, "IO error: {e}"),
        }
    }
}

impl error::Error for L2GatewayError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Internal(_msg) => None,
            Self::Uplink(err) => Some(err),
            Self::Io(err) => Some(err),
        }
    }
}

impl From<&'static str> for L2GatewayError {
    fn from(msg: &'static str) -> L2GatewayError {
        Self::Internal(msg)
    }
}

impl From<uplink::UplinkError> for L2GatewayError {
    fn from(err: uplink::UplinkError) -> L2GatewayError {
        Self::Uplink(err)
    }
}

impl From<io::Error> for L2GatewayError {
    fn from(err: io::Error) -> L2GatewayError {
        Self::Io(err)
    }
}
