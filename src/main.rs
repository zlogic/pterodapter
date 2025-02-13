use std::{
    env, fmt, fs,
    net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    process,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use log::info;
use tokio::{signal, sync::mpsc};
use tokio_rustls::rustls;

mod fortivpn;
mod http;
mod logger;
mod ppp;

#[cfg(feature = "proxy")]
mod proxy;

#[cfg(feature = "ikev2")]
mod ikev2;

enum Action {
    #[cfg(feature = "proxy")]
    Proxy(ProxyConfig),
    #[cfg(feature = "ikev2")]
    IkeV2(Ikev2Config),
}

#[derive(Eq, PartialEq)]
enum ActionType {
    Proxy,
    IkeV2,
}

struct Args {
    log_level: log::LevelFilter,
    action: Action,
}

const USAGE_INSTRUCTIONS: &str = "Usage:\n\n\
> pterodapter [OPTIONS] proxy\n\
Options:\
\n      --log-level=<LOG_LEVEL>   Log level [default: info]\
\n      --listen-address=<IP>     Listen IP address [default: :::5328]\
\n      --destination=<HOSTPORT>  Destination FortiVPN address, e.g. sslvpn.example.com:443\
\n      --tunnel-domain=<SUFFIX>  (Optional) Forward only subdomains to VPN, other domains will use direct connection; can be specified multiple times\
\n      --pac-file=<PATH>         (Optional) Path to pac file (available at /proxy.pac)\
\n\n\
> pterodapter [OPTIONS] ikev2\n\
Options:\
\n      --log-level=<LOG_LEVEL>   Log level [default: info]\
\n      --listen-ip=<IP>          Listen IP address, multiple options can be provided [default: ::]\
\n      --ike-port=<PORT>         IKEv2 port [default: 500]\
\n      --nat-port=<PORT>         NAT port for IKEv2 and ESP [default: 4500]\
\n      --listen-ip=<IP>          Listen IP address, multiple options can be provided [default: ::]\
\n      --destination=<HOSTPORT>  Destination FortiVPN address, e.g. sslvpn.example.com:443\
\n      --tunnel-domain=<DOMAIN>  (Optional) Only forward domain to VPN through split routing; can be specified multiple times\
\n      --rnat-cidr=<IP4CIDR>     (Optional) Enable RNAT mode and use the specified IP/CIDR as the internal network, e.g. 192.168.40.0/24\
\n      --id-hostname=<FQDN>      Hostname for identification [default: pterodapter]\
\n      --cacert=<FILENAME>       Path to root CA certificate (in PKCS 8 PEM format)\
\n      --cert=<FILENAME>         Path to public certificate (in PKCS 8 PEM format)\
\n      --key=<FILENAME>          Path to private key (in PKCS 8 PEM format)\
\n\n\
> pretodapter help";

#[cfg(feature = "proxy")]
struct ProxyConfig {
    proxy: proxy::Config,
    fortivpn: fortivpn::Config,
}

#[cfg(feature = "ikev2")]
struct Ikev2Config {
    ikev2: ikev2::Config,
    fortivpn: fortivpn::Config,
}

impl Args {
    fn parse() -> Args {
        let action_type = match env::args().last().as_deref() {
            Some("proxy") => ActionType::Proxy,
            Some("ikev2") => ActionType::IkeV2,
            Some("help") => {
                println!("{}", USAGE_INSTRUCTIONS);
                process::exit(0);
            }
            _ => {
                eprintln!("No action specified");
                println!("{}", USAGE_INSTRUCTIONS);
                process::exit(2);
            }
        };

        let fail_with_error = |name: &str, value: &str, err: fmt::Arguments| -> ! {
            eprintln!(
                "Argument {} has an unsupported value {}: {}",
                name, value, err
            );
            println!("{}", USAGE_INSTRUCTIONS);
            process::exit(2);
        };

        let mut log_level = log::LevelFilter::Info;

        let mut listen_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5328);
        let mut pac_path: Option<String> = None;
        let mut tunnel_domains: Vec<String> = vec![];

        let mut destination_addr = None;
        let mut destination_hostport = None;

        let mut listen_ips = vec![];
        let mut ike_port = 500u16;
        let mut nat_port = 4500u16;
        let mut id_hostname: Option<String> = None;
        let mut root_ca = None;
        let mut private_key = None;
        let mut public_cert = None;
        let mut rnat_cidr = None;

        let tls_config =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .dangerous() // rustls_platform_verifier is claims this is not dangerous
                .with_custom_certificate_verifier(Arc::new(
                    rustls_platform_verifier::Verifier::new(),
                ))
                .with_no_client_auth();
        let tls_config = Arc::new(tls_config);

        for arg in env::args()
            .take(env::args().len().saturating_sub(1))
            .skip(1)
        {
            let (name, value) = if let Some(arg) = arg.split_once('=') {
                arg
            } else {
                eprintln!("Option flag {} has no value", arg);
                println!("{}", USAGE_INSTRUCTIONS);
                process::exit(2);
            };

            if name == "--log-level" {
                log_level = match value.to_uppercase().as_str() {
                    "TRACE" => log::LevelFilter::Trace,
                    "DEBUG" => log::LevelFilter::Debug,
                    "INFO" => log::LevelFilter::Info,
                    "WARN" => log::LevelFilter::Warn,
                    "ERROR" => log::LevelFilter::Error,
                    "OFF" => log::LevelFilter::Off,
                    _ => fail_with_error(name, value, format_args!("Unsupported log level")),
                };
            } else if action_type == ActionType::Proxy && name == "--listen-address" {
                match SocketAddr::from_str(value) {
                    Ok(addr) => listen_addr = addr,
                    Err(err) => fail_with_error(
                        name,
                        value,
                        format_args!("Failed to parse listen address: {}", err),
                    ),
                };
            } else if name == "--destination" {
                match value.to_socket_addrs() {
                    Ok(mut addr) => {
                        destination_addr = addr.next();
                        destination_hostport = Some(value.to_string());
                    }
                    Err(err) => fail_with_error(
                        name,
                        value,
                        format_args!("Failed to parse destination address: {}", err),
                    ),
                };
            } else if name == "--tunnel-domain" {
                tunnel_domains.push(value.into());
            } else if action_type == ActionType::Proxy && name == "--pac-file" {
                pac_path = Some(value.into());
            } else if action_type == ActionType::IkeV2 && name == "--listen-ip" {
                match IpAddr::from_str(value) {
                    Ok(ip) => {
                        listen_ips.push(ip);
                    }
                    Err(err) => fail_with_error(
                        name,
                        value,
                        format_args!("Failed to parse IP address: {}", err),
                    ),
                };
            } else if action_type == ActionType::IkeV2 && name == "--ike-port" {
                match u16::from_str(value) {
                    Ok(port) => ike_port = port,
                    Err(err) => fail_with_error(
                        name,
                        value,
                        format_args!("Failed to parse IKEv2 port: {}", err),
                    ),
                };
            } else if action_type == ActionType::IkeV2 && name == "--nat-port" {
                match u16::from_str(value) {
                    Ok(port) => nat_port = port,
                    Err(err) => fail_with_error(
                        name,
                        value,
                        format_args!("Failed to parse NAT port for IKEv2: {}", err),
                    ),
                };
            } else if action_type == ActionType::IkeV2 && name == "--rnat-cidr" {
                let (ip, prefix_len) = if let Some(value) = value.split_once("/") {
                    value
                } else {
                    eprintln!("Failed to parse RNAT CIDR {}", value);
                    println!("{}", USAGE_INSTRUCTIONS);
                    process::exit(2);
                };
                let ip = match IpAddr::from_str(ip) {
                    Ok(IpAddr::V4(ip)) => IpAddr::V4(ip),
                    Ok(IpAddr::V6(_)) => {
                        fail_with_error(name, value, format_args!("IPv4 CIDRs are not supported"))
                    }
                    Err(err) => fail_with_error(
                        name,
                        value,
                        format_args!("Failed to parse RNAT CIDR IP address: {}", err),
                    ),
                };
                let prefix_len = match u8::from_str(prefix_len) {
                    Ok(prefix) => prefix,
                    Err(err) => fail_with_error(
                        name,
                        value,
                        format_args!("Failed to parse RNAT CIDR prefix length: {}", err),
                    ),
                };
                if prefix_len > 32 {
                    fail_with_error(
                        name,
                        value,
                        format_args!("RNAT CIDR prefix length {} is invalid", prefix_len),
                    );
                }
                rnat_cidr = Some(ikev2::IpCidr::new(ip, prefix_len));
            } else if action_type == ActionType::IkeV2 && name == "--id-hostname" {
                id_hostname = Some(value.into());
            } else if action_type == ActionType::IkeV2 && name == "--cacert" {
                match fs::read_to_string(value) {
                    Ok(cert) => root_ca = Some(cert),
                    Err(err) => fail_with_error(
                        name,
                        value,
                        format_args!("Failed to read root CA cert: {}", err),
                    ),
                };
            } else if action_type == ActionType::IkeV2 && name == "--cert" {
                match fs::read_to_string(value) {
                    Ok(cert) => public_cert = Some(cert),
                    Err(err) => fail_with_error(
                        name,
                        value,
                        format_args!("Failed to read root CA cert: {}", err),
                    ),
                };
            } else if action_type == ActionType::IkeV2 && name == "--key" {
                match fs::read_to_string(value) {
                    Ok(cert) => private_key = Some(cert),
                    Err(err) => fail_with_error(
                        name,
                        value,
                        format_args!("Failed to read root CA cert: {}", err),
                    ),
                };
            } else {
                eprintln!("Unsupported argument {}", arg);
            }
        }

        let (destination_addr, destination_hostport) =
            match (destination_addr, destination_hostport) {
                (Some(destination_addr), Some(destination_hostport)) => {
                    (destination_addr, destination_hostport)
                }
                _ => {
                    eprintln!("No destination specified");
                    println!("{}", USAGE_INSTRUCTIONS);
                    process::exit(2);
                }
            };

        let mtu = match action_type {
            ActionType::Proxy => fortivpn::PPP_MTU,
            ActionType::IkeV2 => fortivpn::ESP_MTU,
        };
        let fortivpn_config = fortivpn::Config {
            destination_addr,
            destination_hostport,
            tls_config,
            mtu,
        };

        match action_type {
            ActionType::Proxy => {
                #[cfg(not(feature = "proxy"))]
                {
                    eprintln!("Compiled without proxy support");
                    println!("{}", USAGE_INSTRUCTIONS);
                    process::exit(2);
                }
                #[cfg(feature = "proxy")]
                {
                    let proxy_config = proxy::Config {
                        listen_addr,
                        pac_path,
                        tunnel_domains,
                    };
                    let action = Action::Proxy(ProxyConfig {
                        proxy: proxy_config,
                        fortivpn: fortivpn_config,
                    });
                    Args { log_level, action }
                }
            }
            ActionType::IkeV2 => {
                #[cfg(not(feature = "ikev2"))]
                {
                    eprintln!("Compiled without IKEv2 support");
                    println!("{}", USAGE_INSTRUCTIONS);
                    process::exit(2);
                }
                #[cfg(feature = "ikev2")]
                {
                    let server_cert = match (public_cert, private_key) {
                        (Some(public_cert), Some(private_key)) => Some((public_cert, private_key)),
                        _ => None,
                    };
                    if listen_ips.is_empty() {
                        listen_ips = vec![IpAddr::V6(Ipv6Addr::UNSPECIFIED)];
                    }

                    let ikev2_config = ikev2::Config {
                        hostname: id_hostname.clone(),
                        listen_ips: listen_ips.clone(),
                        port: ike_port,
                        nat_port,
                        root_ca,
                        server_cert,
                        tunnel_domains,
                        rnat_cidr,
                    };
                    let action = Action::IkeV2(Ikev2Config {
                        ikev2: ikev2_config,
                        fortivpn: fortivpn_config,
                    });
                    Args { log_level, action }
                }
            }
        }
    }
}

#[cfg(feature = "proxy")]
fn serve_proxy(config: ProxyConfig) -> Result<(), i32> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|err| {
            eprintln!("Failed to start runtime: {}", err);
            1
        })?;

    let (command_sender, command_receiver) = mpsc::channel(64);
    let server = proxy::Server::new(config.proxy, command_sender.clone()).map_err(|err| {
        eprintln!("Failed to start proxy server: {}", err);
        1
    })?;
    let server_handle = rt.spawn(async move {
        if let Err(err) = server.run().await {
            eprintln!("Server failed to run: {}", err);
        }
    });

    let client = proxy::network::Network::new(config.fortivpn).map_err(|err| {
        eprintln!("Failed to start virtual network interface: {}", err);
        1
    })?;

    let client_handle = rt.spawn(client.run(command_receiver));

    rt.block_on(async move {
        if let Err(err) = signal::ctrl_c().await {
            eprintln!("Failed to wait for CTRL+C signal: {}", err);
        }
        info!("Started shutdown");
        if command_sender
            .send(proxy::network::Command::Shutdown)
            .await
            .is_err()
        {
            eprintln!("Shutdown listener is closed");
            return;
        }
        if let Err(err) = client_handle.await {
            eprintln!("Network failed to run: {}", err);
        }
    });

    server_handle.abort();
    rt.shutdown_timeout(Duration::from_secs(60));

    info!("Stopped server");
    Ok(())
}

#[cfg(feature = "ikev2")]
fn serve_ikev2(config: Ikev2Config) -> Result<(), i32> {
    use tokio::sync::oneshot;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|err| {
            eprintln!("Failed to start runtime: {}", err);
            1
        })?;
    let server = match ikev2::Server::new(config.ikev2) {
        Ok(server) => server,
        Err(err) => {
            eprintln!("Failed to create server: {}", err);
            std::process::exit(1)
        }
    };

    let (shutdown_sender, shutdown_receiver) = oneshot::channel();

    let service_handle = rt.spawn(server.run(config.fortivpn, shutdown_receiver));

    rt.block_on(async move {
        if let Err(err) = signal::ctrl_c().await {
            eprintln!("Failed to wait for CTRL+C signal: {}", err);
        }
        info!("Started shutdown");
        if shutdown_sender.send(()).is_err() {
            eprintln!("Shutdown listener is closed");
            return;
        }
        if let Err(err) = service_handle.await {
            eprintln!("Failed to run server: {}", err);
        };
    });
    rt.shutdown_timeout(Duration::from_secs(60));

    info!("Stopped server");
    Ok(())
}

fn main() {
    println!(
        "Pterodapter version {}",
        option_env!("CARGO_PKG_VERSION").unwrap_or("unknown")
    );
    if rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        eprintln!("Crypto provider is aleady set, this should never happen");
        process::exit(1);
    }
    let args = Args::parse();

    if let Err(err) = logger::setup_logger(args.log_level) {
        eprintln!("Failed to set up logger, error is {}", err);
    }
    match args.action {
        #[cfg(feature = "proxy")]
        Action::Proxy(config) => {
            if let Err(exitcode) = serve_proxy(config) {
                process::exit(exitcode);
            }
        }
        #[cfg(feature = "ikev2")]
        Action::IkeV2(config) => {
            if let Err(exitcode) = serve_ikev2(config) {
                process::exit(exitcode);
            }
        }
    }
}
