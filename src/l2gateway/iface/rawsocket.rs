use std::{io, os::fd::AsRawFd, task::Poll};

use log::{debug, info, warn};
use tokio::io::unix::AsyncFd;

use crate::ip;

use crate::l2gateway::{L2GatewayError, MacAddr};

pub struct RawSocket {
    socket: AsyncFd<std::os::unix::io::RawFd>,
    mac: MacAddr,
    if_index: libc::c_int,
}

impl RawSocket {
    pub async fn new(
        listen_interface: &str,
        mtu: Option<usize>,
    ) -> Result<RawSocket, L2GatewayError> {
        let protocol = u16::from_be(libc::ETH_P_IPV6 as u16) as libc::c_int;
        let socket = match unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, protocol) } {
            0 => return Err(io::Error::last_os_error().into()),
            fd => fd as std::os::unix::io::RawFd,
        };
        let (mac, if_index) = RawSocket::iface_config(socket, listen_interface)?;
        if let Some(mtu) = mtu {
            match RawSocket::set_mtu(socket, listen_interface, mtu) {
                Ok(true) => {
                    info!("Updated MTU to {mtu}")
                }
                Ok(false) => {
                    debug!("MTU is already up to date")
                }
                Err(err) => {
                    warn!("Failed to update MTU: {err}")
                }
            }
        }
        let socket = AsyncFd::new(socket)?;
        let socket = RawSocket {
            socket,
            mac,
            if_index,
        };
        if let Err(err) =
            socket.setsockopt_bool(libc::SOL_PACKET, libc::PACKET_IGNORE_OUTGOING, true)
        {
            warn!(
                "Failed to enable PACKET_IGNORE_OUTGOING socket option, will rely on a less efficient packet filter: {err}"
            )
        }

        Ok(socket)
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

    fn ifr_name(name: &str) -> Result<[libc::c_char; libc::IFNAMSIZ], L2GatewayError> {
        match std::ffi::CString::new(name) {
            Ok(name) => {
                let name = name.as_bytes_with_nul();
                let mut ifr_name = [0; libc::IFNAMSIZ];
                if name.len() > ifr_name.len() {
                    return Err("Listen interace name is too long".into());
                }
                ifr_name
                    .iter_mut()
                    .zip(name)
                    .for_each(|(dst, src)| *dst = *src as libc::c_char);
                Ok(ifr_name)
            }
            Err(err) => {
                warn!("Failed to parse interface name {name}: {err}");
                Err("Failed to parse interface name".into())
            }
        }
    }

    fn iface_config(
        fd: std::os::unix::io::RawFd,
        name: &str,
    ) -> Result<(MacAddr, libc::c_int), L2GatewayError> {
        let ifr_name = Self::ifr_name(name)?;
        let mut ifreq = libc::ifreq {
            ifr_name,
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_hwaddr: libc::sockaddr {
                    sa_family: libc::AF_PACKET as u16,
                    sa_data: [0; 14],
                },
            },
        };
        let mac_addr = unsafe {
            match libc::ioctl(fd, libc::SIOCGIFHWADDR, std::ptr::from_mut(&mut ifreq)) {
                0 => {
                    let mut mac_addr = [0u8; 6];
                    mac_addr
                        .iter_mut()
                        .zip(&ifreq.ifr_ifru.ifru_hwaddr.sa_data[0..6])
                        .for_each(|(dst, src)| *dst = *src as u8);
                    MacAddr::from_data(&mac_addr)
                }
                _ => {
                    let err = io::Error::last_os_error();
                    warn!("Failed to get hardware address for {name}: {err}");
                    return Err(io::Error::last_os_error().into());
                }
            }
        };
        let mut ifreq = libc::ifreq {
            ifr_name,
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_ifindex: 0 },
        };
        let if_index = unsafe {
            match libc::ioctl(fd, libc::SIOCGIFINDEX, std::ptr::from_mut(&mut ifreq)) {
                0 => ifreq.ifr_ifru.ifru_ifindex,
                _ => {
                    let err = io::Error::last_os_error();
                    warn!("Failed to get interface index for {name}: {err}");
                    return Err(io::Error::last_os_error().into());
                }
            }
        };
        Ok((mac_addr, if_index))
    }

    fn set_mtu(
        fd: std::os::unix::io::RawFd,
        name: &str,
        mtu: usize,
    ) -> Result<bool, L2GatewayError> {
        let ifr_name = Self::ifr_name(name)?;
        let mut ifreq = libc::ifreq {
            ifr_name,
            ifr_ifru: libc::__c_anonymous_ifr_ifru { ifru_mtu: 0 },
        };
        let current_mtu = unsafe {
            match libc::ioctl(fd, libc::SIOCGIFMTU, std::ptr::from_mut(&mut ifreq)) {
                0 => ifreq.ifr_ifru.ifru_mtu,
                _ => {
                    let err = io::Error::last_os_error();
                    warn!("Failed to get MTU {name}: {err}");
                    return Err(io::Error::last_os_error().into());
                }
            }
        };
        if current_mtu >= mtu as i32 {
            return Ok(false);
        }
        let mut ifreq = libc::ifreq {
            ifr_name,
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_mtu: mtu as libc::c_int,
            },
        };
        unsafe {
            match libc::ioctl(fd, libc::SIOCSIFMTU, std::ptr::from_mut(&mut ifreq)) {
                0 => Ok(true),
                _ => {
                    let err = io::Error::last_os_error();
                    warn!("Failed to set MTU {name}: {err}");
                    Err(io::Error::last_os_error().into())
                }
            }
        }
    }
}

impl super::Interface for RawSocket {
    fn if_mac(&self) -> MacAddr {
        self.mac
    }

    fn set_nat64_filter(&self, prefix: &ip::Nat64Prefix) -> Result<(), io::Error> {
        // See https://docs.kernel.org/networking/filter.html for more information.
        let mut filter_data = BpfFilter::new_nat64_filter(&self.mac, prefix);
        let filter = libc::sock_fprog {
            len: filter_data.ops_len as libc::c_ushort,
            filter: filter_data.program_data.as_mut_ptr().cast(),
        };
        self.setsockopt(libc::SOL_SOCKET, libc::SO_ATTACH_FILTER, &filter)
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        loop {
            let mut guard = std::task::ready!(self.socket.poll_read_ready(cx))?;
            match guard.try_io(|fd| {
                let result = unsafe {
                    libc::recv(
                        fd.as_raw_fd(),
                        buf.as_mut_ptr() as *mut _,
                        buf.len(),
                        libc::MSG_DONTWAIT,
                    )
                };
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

    fn poll_send(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let mut sll_addr = [0u8; 8];
        sll_addr[0..6].copy_from_slice(self.mac.as_slice());
        let srcaddr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: libc::ETH_P_IPV6 as u16,
            sll_ifindex: self.if_index,
            sll_hatype: libc::ARPHRD_ETHER,
            sll_pkttype: 0,
            sll_halen: 6,
            sll_addr,
        };
        loop {
            let mut guard = std::task::ready!(self.socket.poll_write_ready(cx))?;
            match guard.try_io(|fd| {
                let result = unsafe {
                    libc::sendto(
                        fd.as_raw_fd(),
                        buf.as_ptr() as *const _,
                        buf.len(),
                        libc::MSG_DONTWAIT,
                        std::ptr::from_ref(&srcaddr).cast(),
                        std::mem::size_of_val(&srcaddr) as libc::socklen_t,
                    )
                };
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
}

#[repr(C)]
struct BpfFilterOp {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

impl BpfFilterOp {
    fn ldh(offset: u32) -> BpfFilterOp {
        BpfFilterOp {
            code: libc::BPF_LD as u16 | libc::BPF_H as u16 | libc::BPF_ABS as u16,
            jt: 0,
            jf: 0,
            k: offset,
        }
    }

    fn ldw(offset: u32) -> BpfFilterOp {
        BpfFilterOp {
            code: libc::BPF_LD as u16 | libc::BPF_W as u16 | libc::BPF_ABS as u16,
            jt: 0,
            jf: 0,
            k: offset,
        }
    }

    fn jeq(jt: u8, jf: u8, val: u32) -> BpfFilterOp {
        BpfFilterOp {
            code: libc::BPF_JMP as u16 | libc::BPF_JEQ as u16,
            jt,
            jf,
            k: val,
        }
    }

    fn ret(val: u32) -> BpfFilterOp {
        BpfFilterOp {
            code: libc::BPF_RET as u16,
            jt: 0,
            jf: 0,
            k: val,
        }
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
        let mut program_data = vec![0u8; std::mem::size_of_val(prog)];
        program_data
            .chunks_exact_mut(std::mem::size_of::<BpfFilterOp>())
            .zip(prog.iter())
            .for_each(|(data, op)| data.copy_from_slice(op.as_slice()));
        BpfFilter {
            ops_len: prog.len(),
            program_data,
        }
    }

    fn new_nat64_filter(if_mac: &MacAddr, prefix: &ip::Nat64Prefix) -> BpfFilter {
        // This is cBPF, not eBPF, RFC 9669 doesn't apply here.
        let prefix_part = |i: usize| -> u32 {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&prefix[i * 4..(i + 1) * 4]);
            u32::from_be_bytes(bytes)
        };
        let mut mac_part = [0u8; 4];
        mac_part.copy_from_slice(&if_mac.as_slice()[2..6]);
        let mac_end = u32::from_be_bytes(mac_part);
        let mut mac_part = [0u8; 4];
        mac_part[2..4].copy_from_slice(&if_mac.as_slice()[0..2]);
        let mac_start = u32::from_be_bytes(mac_part);
        // See https://www.kernel.org/doc/html/v6.0/bpf/instruction-set.html for more details on
        // legacy instructions.
        BpfFilter::new_program(&[
            BpfFilterOp::ldw(2),
            BpfFilterOp::jeq(0, 11, mac_end),
            BpfFilterOp::ldh(0),
            BpfFilterOp::jeq(0, 9, mac_start),
            BpfFilterOp::ldh(12),
            BpfFilterOp::jeq(0, 7, 0x86DD),
            BpfFilterOp::ldw(38),
            BpfFilterOp::jeq(0, 5, prefix_part(0)),
            BpfFilterOp::ldw(42),
            BpfFilterOp::jeq(0, 3, prefix_part(1)),
            BpfFilterOp::ldw(46),
            BpfFilterOp::jeq(0, 1, prefix_part(2)),
            // use first 262144 bytes, seems to be a magic number
            BpfFilterOp::ret(0x00040000),
            BpfFilterOp::ret(0),
        ])
    }
}
