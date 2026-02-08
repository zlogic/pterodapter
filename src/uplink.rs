use std::net::IpAddr;
use std::{error, fmt};

use crate::{fortivpn, pcap};

pub enum Config {
    FortiVPN(fortivpn::Config),
}

pub trait UplinkService {
    fn is_connected(&self) -> bool;
    fn ip_configuration(&self) -> Option<(IpAddr, &[IpAddr])>;
    async fn wait_event(&mut self, buf: &mut [u8]) -> Result<(), UplinkError>;
    async fn read_packet<'a>(&mut self, buffer: &'a mut [u8]) -> Result<&'a [u8], UplinkError>;
    async fn process_events(&mut self, send_slices: &[&[u8]]) -> Result<(), UplinkError>;
    async fn terminate(&mut self) -> Result<(), UplinkError>;
}

pub enum UplinkServiceType {
    FortiVPN(fortivpn::service::FortiService),
}

impl UplinkServiceType {
    pub fn new(config: Config, pcap_sender: Option<pcap::PcapSender>) -> UplinkServiceType {
        match config {
            Config::FortiVPN(config) => UplinkServiceType::FortiVPN(
                fortivpn::service::FortiService::new(config, pcap_sender),
            ),
        }
    }

    pub fn reserved_header_bytes(&self) -> usize {
        // For FortiVPN, a packet might contain a PPP header that needs to be discarded.
        match self {
            UplinkServiceType::FortiVPN(_) => fortivpn::PPP_HEADER_SIZE,
        }
    }
}

impl UplinkService for UplinkServiceType {
    fn is_connected(&self) -> bool {
        match self {
            UplinkServiceType::FortiVPN(svc) => svc.is_connected(),
        }
    }

    fn ip_configuration(&self) -> Option<(IpAddr, &[IpAddr])> {
        match self {
            UplinkServiceType::FortiVPN(svc) => svc.ip_configuration(),
        }
    }

    async fn wait_event(&mut self, buf: &mut [u8]) -> Result<(), UplinkError> {
        match self {
            UplinkServiceType::FortiVPN(svc) => svc.wait_event(buf).await,
        }
    }

    async fn read_packet<'a>(&mut self, buffer: &'a mut [u8]) -> Result<&'a [u8], UplinkError> {
        match self {
            UplinkServiceType::FortiVPN(svc) => svc.read_packet(buffer).await,
        }
    }

    async fn process_events(&mut self, send_slices: &[&[u8]]) -> Result<(), UplinkError> {
        match self {
            UplinkServiceType::FortiVPN(svc) => svc.process_events(send_slices).await,
        }
    }

    async fn terminate(&mut self) -> Result<(), UplinkError> {
        match self {
            UplinkServiceType::FortiVPN(svc) => svc.terminate().await,
        }
    }
}

#[derive(Debug)]
pub enum UplinkError {
    Internal(&'static str),
    FortiVpn(fortivpn::FortiError),
    Join(tokio::task::JoinError),
}

impl fmt::Display for UplinkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Internal(msg) => f.write_str(msg),
            Self::FortiVpn(e) => write!(f, "FortiVPN client error: {e}"),
            Self::Join(e) => write!(f, "Tokio join error: {e}"),
        }
    }
}

impl error::Error for UplinkError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Internal(_msg) => None,
            Self::FortiVpn(err) => Some(err),
            Self::Join(err) => Some(err),
        }
    }
}

impl From<&'static str> for UplinkError {
    fn from(msg: &'static str) -> UplinkError {
        Self::Internal(msg)
    }
}

impl From<fortivpn::FortiError> for UplinkError {
    fn from(err: fortivpn::FortiError) -> UplinkError {
        Self::FortiVpn(err)
    }
}

impl From<tokio::task::JoinError> for UplinkError {
    fn from(err: tokio::task::JoinError) -> UplinkError {
        Self::Join(err)
    }
}
