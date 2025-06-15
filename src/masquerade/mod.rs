use std::net::{IpAddr, Ipv4Addr};

use crate::uplink;

pub struct Config {
    pub masquerade_ip: IpAddr,
}

pub struct MasqueradeClient {
    masquerade_ip: IpAddr,
    dns_addrs: Vec<IpAddr>,
    running: bool,
}

impl MasqueradeClient {
    pub fn new(config: Config) -> MasqueradeClient {
        // TODO MASQUERADE: get DNS servers from /etc/resolv.conf, ideally with a refresh timer.
        let dns_addrs = vec![
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 11)),
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 12)),
        ];
        MasqueradeClient {
            masquerade_ip: config.masquerade_ip,
            dns_addrs,
            running: true,
        }
    }
}

impl uplink::UplinkService for MasqueradeClient {
    fn is_connected(&self) -> bool {
        self.running
    }

    fn ip_configuration(&self) -> Option<(IpAddr, &[IpAddr])> {
        if self.running {
            Some((self.masquerade_ip, &self.dns_addrs))
        } else {
            None
        }
    }

    async fn wait_event(&mut self, buf: &mut [u8]) -> Result<(), uplink::UplinkError> {
        // TODO MASQUERADE: wait for TCP/UDP traffic from NAT, or for a timer event.
        std::future::pending().await
    }

    async fn read_packet<'a>(
        &mut self,
        buffer: &'a mut [u8],
    ) -> Result<&'a [u8], uplink::UplinkError> {
        // TODO MASQUERADE: wait for TCP/UDP traffic from NAT.
        std::future::pending().await
    }

    async fn process_events(&mut self, send_slices: &[&[u8]]) -> Result<(), uplink::UplinkError> {
        // TODO MASQUERADE: send traffic and handle state changes.
        Ok(())
    }

    async fn terminate(&mut self) -> Result<(), uplink::UplinkError> {
        self.running = false;
        Ok(())
    }
}
