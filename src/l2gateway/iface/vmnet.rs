use std::{error, fmt, pin::pin, sync::Arc, task::Poll};

use log::{trace, warn};
use tokio::sync::Notify;
use vmnet::{
    mode::{Mode, Shared},
    parameters::Parameter,
};

use crate::{
    ip,
    l2gateway::{L2GatewayError, MacAddr},
};

pub struct Vmnet {
    iface: vmnet::Interface,
    packets_available: Arc<Notify>,
    wait_for_packets: bool,
    mac: MacAddr,
}

impl Vmnet {
    pub async fn new(_listen_interface: &str, mtu: Option<usize>) -> Result<Self, L2GatewayError> {
        let shared_mode = Shared {
            subnet_options: None,
            nat66_prefix: None,
            mtu: mtu.map(|mtu| mtu as u64),
        };

        let options = vmnet::Options {
            allocate_mac_address: Some(true),
            enable_checksum_offload: Some(false),
            enable_tso: Some(false),
            interface_id: None,
            enable_isolation: None,
        };

        let mut iface = match vmnet::Interface::new(Mode::Shared(shared_mode), options) {
            Ok(iface) => iface,
            Err(err) => {
                warn!("Failed to init vmnet interface: {err}");
                return Err("Failed to init vmnet interface".into());
            }
        };

        let params = iface.parameters();
        let mac = if let Some(Parameter::MACAddress(mac_addr)) =
            params.get(vmnet::parameters::ParameterKind::MACAddress)
        {
            Self::parse_mac_from_string(&mac_addr)?
        } else {
            return Err("No MAC address assigned".into());
        };

        let packets_available = Arc::new(Notify::new());
        packets_available.notify_one();
        let notify_packets = packets_available.clone();
        if let Err(err) =
            iface.set_event_callback(vmnet::Events::PACKETS_AVAILABLE, move |_events, _params| {
                notify_packets.notify_one();
            })
        {
            warn!("Failed to enable notifications for new packets: {err}");
            return Err("Failed to enable notifications for new packets".into());
        };

        Ok(Vmnet {
            iface,
            packets_available,
            wait_for_packets: false,
            mac,
        })
    }

    fn parse_mac_from_string(mac: &str) -> Result<MacAddr, L2GatewayError> {
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

    // TODO VMNET: implement shutdown code
}

impl super::Interface for Vmnet {
    fn if_mac(&self) -> crate::l2gateway::MacAddr {
        self.mac
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
        loop {
            if self.wait_for_packets {
                let res = pin!(self.packets_available.notified());
                match res.poll(cx) {
                    Poll::Ready(()) => {
                        self.wait_for_packets = false;
                        continue;
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            let bytes_read = match self.iface.read(buf) {
                Ok(bytes_read) => bytes_read,
                Err(vmnet::Error::VmnetReadNothing) => {
                    self.wait_for_packets = true;
                    continue;
                }
                Err(err) => return Poll::Ready(Err(err.into())),
            };
            return Poll::Ready(Ok(bytes_read));
        }
    }

    fn poll_send(
        &mut self,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, InterfaceError>> {
        // vmnet can only perform blocking writes.
        Poll::Ready(Ok(self.iface.write(buf)?))
    }
}

#[derive(Debug)]
pub enum InterfaceError {
    Internal(&'static str),
    Vmnet(vmnet::Error),
}

impl fmt::Display for InterfaceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Internal(msg) => f.write_str(msg),
            Self::Vmnet(e) => write!(f, "vmnet error: {e}"),
        }
    }
}

impl error::Error for InterfaceError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Internal(_msg) => None,
            Self::Vmnet(err) => Some(err),
        }
    }
}

impl From<&'static str> for InterfaceError {
    fn from(msg: &'static str) -> InterfaceError {
        Self::Internal(msg)
    }
}

impl From<vmnet::Error> for InterfaceError {
    fn from(err: vmnet::Error) -> InterfaceError {
        Self::Vmnet(err)
    }
}
