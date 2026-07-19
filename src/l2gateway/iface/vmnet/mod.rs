use std::{error, fmt, task::Poll};

use log::{debug, trace, warn};
use rand::Rng as _;
use tokio::sync::mpsc;

use crate::{ip, l2gateway::MacAddr};

#[allow(dead_code, non_camel_case_types)]
mod sys;
#[link(kind = "framework", name = "vmnet")]
unsafe extern "C" {}

pub struct Vmnet {
    iface: Interface,
    packets_available: mpsc::Receiver<Option<u64>>,
    wait_for_packets: bool,
}

struct Interface {
    queue: sys::dispatch_queue_t,
    iface: sys::interface_ref,
    mac: MacAddr,
    terminated: bool,
}

impl Vmnet {
    pub async fn new(_listen_interface: &str, mtu: Option<usize>) -> Result<Self, InterfaceError> {
        let mut iface = Self::start_interface(mtu).await?;

        let (notify_packets, packets_available) = mpsc::channel(1);
        let callback = block2::RcBlock::new(
            move |status: sys::interface_event_t, params: sys::xpc_object_t| {
                let packets_available = if status == sys::VMNET_INTERFACE_PACKETS_AVAILABLE {
                    unsafe {
                        Some(sys::xpc_dictionary_get_uint64(
                            params,
                            sys::vmnet_estimated_packets_available_key,
                        ))
                    }
                } else {
                    None
                };
                if notify_packets.blocking_send(packets_available).is_err() {
                    trace!("Packets available channel closed for vmnet callback");
                }
            },
        );
        let raw_callback = block2::RcBlock::into_raw(callback).cast();
        let res = unsafe {
            sys::vmnet_interface_set_event_callback(
                iface.iface,
                sys::VMNET_INTERFACE_PACKETS_AVAILABLE,
                iface.queue,
                raw_callback,
            )
        };
        let res = VmnetResponse::from_code(res);
        if res.is_err() {
            warn!("Failed to enable notifications for new packets: {res}");
            return Err("Failed to enable notifications for new packets".into());
        }

        let mut test_buf = vec![0u8; super::super::MAX_PACKET_SIZE];
        if let Err(err) = iface.read(&mut test_buf) {
            warn!("Failed to read test packet from vmnet: {err}");
            if let Err(err) = iface.terminate().await {
                warn!("Failed to terminate interface: {err}");
            }
            return Err("Failed to read test packet from vmnet".into());
        };

        Ok(Vmnet {
            iface,
            packets_available,
            wait_for_packets: false,
        })
    }

    async fn start_interface(mtu: Option<usize>) -> Result<Interface, InterfaceError> {
        let interface_desc = unsafe {
            let mut dict = vec![
                (
                    sys::vmnet_operation_mode_key,
                    sys::xpc_uint64_create(sys::VMNET_HOST_MODE as u64),
                ),
                (
                    sys::vmnet_allocate_mac_address_key,
                    sys::xpc_bool_create(false),
                ),
                (
                    sys::vmnet_enable_checksum_offload_key,
                    sys::xpc_bool_create(false),
                ),
                (sys::vmnet_enable_tso_key, sys::xpc_bool_create(false)),
            ];
            if let Some(mtu) = mtu {
                dict.push((sys::vmnet_mtu_key, sys::xpc_uint64_create(mtu as u64)));
            }
            let keys = dict.iter().map(|(key, _)| *key).collect::<Vec<_>>();
            let values = dict.iter().map(|(_, value)| *value).collect::<Vec<_>>();
            sys::xpc_dictionary_create(keys.as_ptr(), values.as_ptr(), keys.len().min(values.len()))
        };
        let queue = unsafe { sys::dispatch_get_global_queue(0, 0) };

        let (tx, mut rx) = mpsc::channel(1);
        let block = block2::RcBlock::new(
            move |status: sys::vmnet_return_t, _params: sys::xpc_object_t| {
                let _ = tx.blocking_send(VmnetResponse::from_code(status));
            },
        );
        let raw_block = block2::RcBlock::into_raw(block).cast();

        let iface = unsafe { sys::vmnet_start_interface(interface_desc, queue, raw_block) };
        if iface.is_null() {
            unsafe {
                sys::xpc_release(interface_desc);
            }
            return Err("vmnet_start_interface returned null".into());
        }
        let res = rx.recv().await;
        unsafe {
            sys::xpc_release(interface_desc);
        }
        match res {
            Some(VmnetResponse::VMNET_SUCCESS) => Ok(()),
            Some(status) => {
                warn!("Failed vmnet_start_interface call, error code is {status}");
                Err("Failed vmnet_start_interface call")
            }
            None => Err("vmnet_start_interface result channel closed"),
        }?;

        let mac = Self::generate_mac();
        debug!("Generated MAC {mac}");
        Ok(Interface {
            queue,
            iface,
            mac,
            terminated: false,
        })
    }

    fn generate_mac() -> MacAddr {
        let mut mac = [0u8; 6];
        rand::rng().fill_bytes(&mut mac);
        // Based on Apple Container DefaultNetworkService.
        mac[0] = (mac[0] & 0x0c) | 0xf2;
        MacAddr::from_data(&mac)
    }
}

impl Interface {
    fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, InterfaceError> {
        let mut iov = sys::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut pktdesc = sys::vmpktdesc {
            vm_pkt_size: iov.iov_len,
            vm_pkt_iov: &mut iov,
            vm_pkt_iovcnt: 1,
            vm_flags: 0,
        };
        let mut pktcnt = 1;

        let status = unsafe { sys::vmnet_read(self.iface, &mut pktdesc, &mut pktcnt) };
        let status = VmnetResponse(status);
        if status.is_err() {
            warn!("Failed to read from vmnet: {status}");
            Err("Failed to read from vmnet".into())
        } else if pktcnt == 0 {
            Ok(None)
        } else {
            Ok(Some(pktdesc.vm_pkt_size))
        }
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, InterfaceError> {
        let mut iov = sys::iovec {
            iov_base: buf.as_ptr() as *mut _,
            iov_len: buf.len(),
        };
        let mut pktdesc = sys::vmpktdesc {
            vm_pkt_size: iov.iov_len,
            vm_pkt_iov: &mut iov,
            vm_pkt_iovcnt: 1,
            vm_flags: 0,
        };
        let mut pktcnt = 1;

        let status = unsafe { sys::vmnet_write(self.iface, &mut pktdesc, &mut pktcnt) };
        let status = VmnetResponse(status);
        if status.is_err() {
            warn!("Failed to write to vmnet: {status}");
            Err("Failed to write to vmnet".into())
        } else if pktcnt == 0 {
            Err("No packtets written".into())
        } else {
            Ok(pktdesc.vm_pkt_size)
        }
    }

    async fn terminate(&mut self) -> Result<(), InterfaceError> {
        if self.terminated {
            return Ok(());
        }
        let (tx, mut rx) = mpsc::channel(1);
        let block = block2::RcBlock::new(move |status: sys::vmnet_return_t| {
            let _ = tx.blocking_send(status);
        });
        let raw_block = block2::RcBlock::into_raw(block).cast();
        self.terminated = true;
        let status = unsafe { sys::vmnet_stop_interface(self.iface, self.queue, raw_block) };
        let status = VmnetResponse(status);
        if status.is_err() {
            warn!("Failed to stop vmnet interface: {status}");
            return Err("Failed to stop vmnet interface".into());
        }
        if let Some(status) = rx.recv().await {
            let status = VmnetResponse(status);
            if status.is_err() {
                warn!("Got error in vmnet_stop_interface callback: {status}");
                Err("Got error in vmnet_stop_interface callback".into())
            } else {
                Ok(())
            }
        } else {
            Err("Closed feedback channel of vmnet_stop_interface".into())
        }
    }
}

impl super::Interface for Vmnet {
    fn if_mac(&self) -> crate::l2gateway::MacAddr {
        self.iface.mac
    }

    fn dedicated_connection() -> bool {
        true
    }

    fn set_nat64_filter(&self, _prefix: &ip::Nat64Prefix) -> Result<(), std::io::Error> {
        // macOS doesn't support low-level filtering.
        Ok(())
    }

    fn poll_recv(
        &mut self,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<Result<usize, InterfaceError>> {
        if self.iface.terminated {
            return Poll::Pending;
        }
        loop {
            match self.packets_available.poll_recv(cx) {
                Poll::Ready(Some(packets_available)) => {
                    if let Some(packets_available) = packets_available
                        && packets_available > 0
                    {
                        self.wait_for_packets = false;
                    }
                    if self.wait_for_packets {
                        continue;
                    }
                }
                Poll::Ready(None) => {
                    debug!("Packets available channel closed");
                    return Poll::Pending;
                }
                Poll::Pending => {
                    if self.wait_for_packets {
                        return Poll::Pending;
                    }
                }
            }
            let bytes_read = match self.iface.read(buf) {
                Ok(Some(bytes_read)) => bytes_read,
                Ok(None) => {
                    self.wait_for_packets = true;
                    continue;
                }
                Err(err) => return Poll::Ready(Err(err)),
            };
            return Poll::Ready(Ok(bytes_read));
        }
    }

    fn poll_send(
        &mut self,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, InterfaceError>> {
        if !self.iface.terminated {
            // vmnet can only perform blocking writes.
            Poll::Ready(Ok(self.iface.write(buf)?))
        } else {
            Poll::Pending
        }
    }

    async fn terminate(&mut self) -> Result<(), super::InterfaceError> {
        self.iface.terminate().await
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct VmnetResponse(sys::vmnet_return_t);

impl VmnetResponse {
    const VMNET_SUCCESS: VmnetResponse = VmnetResponse(1000);
    const VMNET_FAILURE: VmnetResponse = VmnetResponse(1001);
    const VMNET_MEM_FAILURE: VmnetResponse = VmnetResponse(1002);
    const VMNET_INVALID_ARGUMENT: VmnetResponse = VmnetResponse(1003);
    const VMNET_SETUP_INCOMPLETE: VmnetResponse = VmnetResponse(1004);
    const VMNET_INVALID_ACCESS: VmnetResponse = VmnetResponse(1005);
    const VMNET_PACKET_TOO_BIG: VmnetResponse = VmnetResponse(1006);
    const VMNET_BUFFER_EXHAUSTED: VmnetResponse = VmnetResponse(1007);
    const VMNET_TOO_MANY_PACKETS: VmnetResponse = VmnetResponse(1008);
    const VMNET_SHARING_SERVICE_BUSY: VmnetResponse = VmnetResponse(1009);
    const VMNET_NOT_AUTHORIZED: VmnetResponse = VmnetResponse(1010);

    fn from_code(code: sys::vmnet_return_t) -> VmnetResponse {
        VmnetResponse(code)
    }

    fn is_err(&self) -> bool {
        *self != Self::VMNET_SUCCESS
    }
}

impl fmt::Display for VmnetResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::VMNET_SUCCESS => write!(f, "Success"),
            Self::VMNET_FAILURE => write!(f, "Failure"),
            Self::VMNET_MEM_FAILURE => write!(f, "Out of memory"),
            Self::VMNET_INVALID_ARGUMENT => write!(f, "Invalid argument"),
            Self::VMNET_SETUP_INCOMPLETE => write!(f, "Incomplete interface setup"),
            Self::VMNET_INVALID_ACCESS => write!(f, "Insufficient permissions"),
            Self::VMNET_PACKET_TOO_BIG => write!(f, "Packet size exceeding MTU"),
            Self::VMNET_BUFFER_EXHAUSTED => write!(f, "Buffers temporarily exhausted"),
            Self::VMNET_TOO_MANY_PACKETS => {
                write!(f, "Number of packets exceeding the system limit")
            }
            Self::VMNET_SHARING_SERVICE_BUSY => write!(f, "Sharing service busy"),
            Self::VMNET_NOT_AUTHORIZED => write!(f, "Not authorized"),
            _ => write!(f, "Unknown vmnet response {}", self.0),
        }
    }
}

#[derive(Debug)]
pub enum InterfaceError {
    Internal(&'static str),
}

impl fmt::Display for InterfaceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Internal(msg) => f.write_str(msg),
        }
    }
}

impl error::Error for InterfaceError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Internal(_msg) => None,
        }
    }
}

impl From<&'static str> for InterfaceError {
    fn from(msg: &'static str) -> InterfaceError {
        Self::Internal(msg)
    }
}
