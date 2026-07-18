use crate::ip;
use std::{io, task::Poll};

use super::MacAddr;

#[cfg(target_os = "linux")]
mod rawsocket;
#[cfg(target_os = "macos")]
mod vmnet;

#[cfg(target_os = "linux")]
pub(super) type L2Interface = rawsocket::RawSocket;
#[cfg(target_os = "macos")]
pub type L2Interface = vmnet::Vmnet;

#[cfg(target_os = "linux")]
pub(super) type InterfaceError = rawsocket::InterfaceError;
#[cfg(target_os = "macos")]
pub(super) type InterfaceError = vmnet::InterfaceError;

pub trait Interface {
    fn if_mac(&self) -> MacAddr;

    fn dedicated_connection() -> bool;

    fn set_nat64_filter(&self, prefix: &ip::Nat64Prefix) -> Result<(), io::Error>;

    fn poll_recv(
        &mut self,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, InterfaceError>>;

    fn poll_send(
        &mut self,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, InterfaceError>>;

    async fn terminate(&mut self) -> Result<(), InterfaceError>;
}
