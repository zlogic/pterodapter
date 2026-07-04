use log::error;

use crate::{ip, l2gateway::L2GatewayError};

pub struct Vmnet {}

impl Vmnet {
    pub async fn new(listen_interface: &str, mtu: Option<usize>) -> Result<Self, L2GatewayError> {
        use vmnet::{Interface, Options, mode::Mode, mode::Shared};

        let shared_mode = Shared {
            subnet_options: None,
            ..Default::default()
        };

        let mut iface = match Interface::new(Mode::Shared(shared_mode), Options::default()) {
            Ok(iface) => (),
            Err(err) => {
                error!("Failed to init vmnet interface: {err}");
                ()
            }
        };
        std::process::exit(0);

        Ok(Vmnet {})
    }
}

impl super::Interface for Vmnet {
    fn if_mac(&self) -> crate::l2gateway::MacAddr {
        todo!()
    }

    fn set_nat64_filter(&self, prefix: &ip::Nat64Prefix) -> Result<(), std::io::Error> {
        todo!()
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        todo!()
    }

    fn poll_send(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        todo!()
    }
}
