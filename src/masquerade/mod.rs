use std::{
    error, fmt, io,
    net::{IpAddr, Ipv6Addr},
    str::FromStr as _,
};

use log::warn;
use tokio::{
    fs,
    io::{AsyncBufReadExt as _, BufReader},
};

use crate::{ip, uplink};

pub struct Config {
    pub masquerade_ip: IpAddr,
    pub dns_addrs: Vec<IpAddr>,
    pub nat64_prefix: Option<Ipv6Addr>,
    pub dns64_domains: Vec<String>,
}

pub struct MasqueradeClient {
    masquerade_ip: IpAddr,
    dns_addrs: Vec<IpAddr>,
    nat64_prefix: Option<ip::Nat64Prefix>,
    dns64_domains: ip::TunnelDomainsDns,
    dns_translator: Option<ip::Dns64Translator>,
    running: bool,
}

impl MasqueradeClient {
    pub fn new(config: Config) -> MasqueradeClient {
        let nat64_prefix = config.nat64_prefix.map(ip::Nat64Prefix::new);
        let dns_translator = nat64_prefix.clone().map(ip::Dns64Translator::new);
        let dns_addrs = if let Some(nat64_prefix) = &nat64_prefix {
            config
                .dns_addrs
                .iter()
                .filter_map(|dns_addr| {
                    if nat64_prefix.matches(dns_addr) {
                        None
                    } else {
                        Some(*dns_addr)
                    }
                })
                .collect::<Vec<_>>()
        } else {
            config.dns_addrs
        };
        MasqueradeClient {
            masquerade_ip: config.masquerade_ip,
            dns_addrs,
            nat64_prefix,
            dns64_domains: ip::TunnelDomainsDns::new(&config.dns64_domains),
            dns_translator,
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

pub async fn read_systen_dns_servers() -> Result<Vec<IpAddr>, MasqueradeError> {
    let file = fs::File::open("/etc/resolv.conf").await?;
    let mut lines = BufReader::new(file).lines();
    // Go parses this directly: https://go.dev/src/net/dnsclient_unix.go
    let mut dns_servers = vec![];
    while let Some(line) = lines.next_line().await? {
        if let Some("nameserver") = line.split_whitespace().next() {
            if let Some(dns_server) = line.strip_prefix("nameserver") {
                match IpAddr::from_str(dns_server.trim()) {
                    Ok(dns_server) => dns_servers.push(dns_server),
                    Err(err) => warn!("Failed to parse nameserver entry: {err}"),
                }
            }
        }
    }
    Ok(dns_servers)
}

#[derive(Debug)]
pub enum MasqueradeError {
    Internal(&'static str),
    Io(io::Error),
}

impl fmt::Display for MasqueradeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Internal(msg) => f.write_str(msg),
            Self::Io(e) => write!(f, "IO error: {e}"),
        }
    }
}

impl error::Error for MasqueradeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Internal(_msg) => None,
            Self::Io(err) => Some(err),
        }
    }
}

impl From<&'static str> for MasqueradeError {
    fn from(msg: &'static str) -> MasqueradeError {
        Self::Internal(msg)
    }
}

impl From<io::Error> for MasqueradeError {
    fn from(err: io::Error) -> MasqueradeError {
        Self::Io(err)
    }
}
