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
pub(super) type L2Interface = vmnet::Vmnet;

// TODO VMNET: enforce contract via this trait, add a new method
pub(super) trait Interface {
    fn if_mac(&self) -> MacAddr;

    fn set_nat64_filter(&self, prefix: &ip::Nat64Prefix) -> Result<(), io::Error>;

    fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>>;

    fn poll_send(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>>;
}
