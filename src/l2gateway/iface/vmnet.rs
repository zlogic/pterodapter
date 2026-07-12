use std::{error, ffi::CStr, fmt, task::Poll};

use log::{debug, trace, warn};
use tokio::sync::mpsc;

use crate::{
    ip,
    l2gateway::{L2GatewayError, MacAddr},
    sys,
};

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
    pub async fn new(_listen_interface: &str, mtu: Option<usize>) -> Result<Self, L2GatewayError> {
        let iface = Self::start_interface(mtu).await?;

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
        if res != sys::VMNET_SUCCESS {
            warn!("Failed to enable notifications for new packets: {res}");
            return Err("Failed to enable notifications for new packets".into());
        }

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
                    sys::xpc_bool_create(true),
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

        struct VmnetParams {
            mac: Option<String>,
        }
        let (tx, mut rx) = mpsc::channel(1);
        let block = block2::RcBlock::new(
            move |status: sys::vmnet_return_t, params: sys::xpc_object_t| {
                let res = if status == sys::VMNET_SUCCESS {
                    let mac = unsafe {
                        let ptr =
                            sys::xpc_dictionary_get_string(params, sys::vmnet_mac_address_key);
                        if ptr.is_null() {
                            None
                        } else {
                            CStr::from_ptr(ptr).to_str().ok().map(|str| str.to_owned())
                        }
                    };
                    Ok(VmnetParams { mac })
                } else {
                    warn!("Failed vmnet_start_interface call, error code is {status}");
                    Err("Failed vmnet_start_interface call")
                };
                let _ = tx.blocking_send(res);
            },
        );
        let raw_block = block2::RcBlock::into_raw(block).cast();

        let iface = unsafe { sys::vmnet_start_interface(interface_desc, queue, raw_block) };
        if iface.is_null() {
            return Err("vmnet_start_interface returned null".into());
        }
        let res = match rx.recv().await {
            Some(res) => res?,
            None => return Err("vmnet_start_interface result channel closed".into()),
        };
        if let Some(mac_addr) = res.mac {
            let mac = Self::parse_mac_from_string(&mac_addr)?;
            Ok(Interface {
                queue,
                iface,
                mac,
                terminated: false,
            })
        } else {
            Err("No MAC address assigned".into())
        }
    }

    fn parse_mac_from_string(mac: &str) -> Result<MacAddr, InterfaceError> {
        trace!("MAC address is {mac}");
        let mut mac_bytes = [0u8; 6];
        for (i, hex_part) in mac.split(':').enumerate() {
            if i > 6 {
                warn!("MAC address {mac} has too many parts");
                return Err("Failed to parse MAC address".into());
            }
            let hex_part = match u8::from_str_radix(hex_part, 16) {
                Ok(hex_part) => hex_part,
                Err(err) => {
                    warn!("Failed to parse hex segment {hex_part} in MAC address {mac}: {err}");
                    return Err("Failed to parse MAC address".into());
                }
            };
            mac_bytes[i] = hex_part;
        }
        Ok(MacAddr::from_data(&mac_bytes))
    }

    // TODO VMNET: implement shutdown code based on the vmnetrs project
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
        // TODO VMNET: use enum for status codes
        if status != sys::VMNET_SUCCESS {
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
        if status != sys::VMNET_SUCCESS {
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
        if status != sys::VMNET_SUCCESS {
            warn!("Failed to stop vmnet interface: {status}");
            return Err("Failed to stop vmnet interface".into());
        }
        if let Some(status) = rx.recv().await {
            if status != sys::VMNET_SUCCESS {
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
                        && packets_available > 0 {
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
