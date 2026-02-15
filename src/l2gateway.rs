use std::os::fd::AsRawFd;
use std::pin::pin;
use std::task::Poll;
use std::time::Duration;
use std::{error, fmt, net::Ipv6Addr};
use std::{future, io};

use log::{debug, info, warn};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
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
        let result = rt.block_on(self.run_process(shutdown_receiver, uplink));
        rt.shutdown_timeout(Duration::from_secs(60));
        result
    }

    async fn run_process(
        &mut self,
        shutdown_receiver: oneshot::Receiver<()>,
        uplink: uplink::UplinkServiceType,
    ) -> Result<(), L2GatewayError> {
        // TODO GATEWAY: use a fixed limit matching the Ethernet limit (1500), FortiVPN can reuse
        // space from Ethernet frames.
        let mut buf = [0u8; 2000];
        let socket = match RawSocket::new(RawSocketProtocol::IPv6).await {
            Ok(socket) => socket,
            Err(err) => {
                log::error!("Failed to open raw IPv6 socket: {err}");
                return Err(err.into());
            }
        };
        if let Err(err) = socket.set_nat64_filter(&self.nat64_prefix) {
            warn!("Failed to enable BPF filter, will rely on a less efficient packet filter: {err}")
        }

        info!("Started server");

        let mut shutdown_command = pin!(shutdown_receiver);
        let mut shutdown = false;
        loop {
            let uplink_is_connected = uplink.is_connected();
            if shutdown && !uplink_is_connected {
                debug!("Shutdown completed");
                return Ok(());
            }
            let (shutdown_requested, raw_packet) = {
                let mut raw_packet = None;
                let mut shutdown_requested = shutdown;
                future::poll_fn(|cx| {
                    if !shutdown_requested {
                        shutdown_requested = match shutdown_command.as_mut().poll(cx) {
                            Poll::Ready(_) => true,
                            Poll::Pending => false,
                        }
                    }
                    // shutdown_command.poll(cx)
                    if raw_packet.is_none() {
                        raw_packet = match socket.poll_recv(cx, &mut buf) {
                            Poll::Ready(result) => Some(result),
                            Poll::Pending => None,
                        };
                    }
                    if raw_packet.is_some() || shutdown_requested {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
                (shutdown_requested, raw_packet)
            };
            //let bytes_read = socket.read(&mut buf).await.expect("read data");
            if shutdown_requested {
                shutdown = true;
            }
            if let Some(raw_packet) = raw_packet {
                match raw_packet {
                    Ok(bytes_read) => {
                        let data = &buf[..bytes_read];
                        println!("! Got data {}", fmt_slice_hex(data));
                    }
                    Err(err) => {
                        warn!("Failed to read raw packet: {err}");
                    }
                }
            }
        }
    }
}

enum RawSocketProtocol {
    IPv6,
}

struct RawSocket {
    socket: AsyncFd<std::os::unix::io::RawFd>,
}

impl RawSocket {
    async fn new(protocol: RawSocketProtocol) -> Result<RawSocket, io::Error> {
        let protocol = match protocol {
            RawSocketProtocol::IPv6 => libc::ETH_P_IPV6,
        };
        let protocol = u16::from_be(protocol as u16) as libc::c_int;
        let socket = match unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, protocol) } {
            0 => return Err(io::Error::last_os_error()),
            fd => fd as std::os::unix::io::RawFd,
        };
        if unsafe { libc::fcntl(socket, libc::F_SETFL, libc::O_NONBLOCK) } != 0 {
            let err = io::Error::last_os_error();
            warn!("Failed to enable nonblocking operations: {err}");
            return Err(err);
        };
        let socket = AsyncFd::new(socket)?;
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

    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket
            .async_io(Interest::READABLE, |fd| {
                let result = unsafe { libc::recv(*fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
                if result >= 0 {
                    Ok(result as usize)
                } else {
                    Err(io::Error::last_os_error())
                }
            })
            .await
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        loop {
            let mut guard = std::task::ready!(self.socket.poll_read_ready(cx))?;
            match guard.try_io(|fd| {
                let result =
                    unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len(), 0) };
                if result >= 0 {
                    Ok(result as usize)
                } else {
                    Err(io::Error::last_os_error())
                }
            }) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
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
