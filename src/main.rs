use std::{
    env, fmt,
    net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    process,
    str::FromStr,
    sync::{atomic, Arc},
    time::Duration,
};

use log::{debug, info};
use tokio::{signal, sync::mpsc};
use tokio_rustls::rustls;

mod fortivpn;
mod http;
mod logger;
mod network;
mod ppp;
mod proxy;

enum Action {
    Proxy(Config),
}

struct Args {
    log_level: log::LevelFilter,
    action: Action,
}

const USAGE_INSTRUCTIONS: &str = "Usage: pterodapter [OPTIONS] proxy\n\n\
Options:\
\n      --log-level=<LOG_LEVEL>   Log level [default: info]\
\n      --listen-address=<IP>     Listen IP address [default: :::5328]\
\n      --destination=<HOSTPORT>  Destination FortiVPN address, e.g. sslvpn.example.com:443\
\n      --pac-file=<PATH>         (Optional) Path to pac file (available at /proxy.pac)\
\n      --tunnel-domain=<SUFFIX>  (Optional) Forward only subdomains to VPN, other domains will use direct connection; can be specified multiple times\
\n      --help                    Print help";

struct Config {
    proxy: proxy::Config,
    fortivpn: fortivpn::Config,
}

impl Args {
    fn parse() -> Args {
        let fail_with_error = |name: &str, value: &str, err: fmt::Arguments| {
            eprintln!(
                "Argument {} has an unsupported value {}: {}",
                name, value, err
            );
            println!("{}", USAGE_INSTRUCTIONS);
            process::exit(2);
        };

        let mut log_level = log::LevelFilter::Info;
        let mut listen_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5328);
        let mut destination_addr = None;
        let mut destination_hostport = None;
        let mut pac_path = None;
        let mut tunnel_domains = vec![];
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
            if arg == "--help" || arg == "help" {
                println!("{}", USAGE_INSTRUCTIONS);
                process::exit(0);
            }
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
                    _ => {
                        fail_with_error(name, value, format_args!("Unsupported log level"));
                        process::exit(2);
                    }
                };
            } else if name == "--listen-address" {
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
            } else if name == "--pac-file" {
                pac_path = Some(value.into());
            } else if name == "--tunnel-domain" {
                tunnel_domains.push(value.into());
            } else {
                eprintln!("Unsupported argument {}", arg);
            }
        }

        let action = if let Some(action) = env::args().last() {
            action
        } else {
            eprintln!("No action specified");
            println!("{}", USAGE_INSTRUCTIONS);
            process::exit(2);
        };

        match action.as_str() {
            "proxy" => {
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

                let proxy_config = proxy::Config {
                    listen_addr,
                    pac_path,
                    tunnel_domains,
                };
                let fortivpn_config = fortivpn::Config {
                    destination_addr,
                    destination_hostport,
                    tls_config,
                };

                let action = Action::Proxy(Config {
                    proxy: proxy_config,
                    fortivpn: fortivpn_config,
                });
                Args { log_level, action }
            }
            _ => {
                eprintln!("No action specified");
                println!("{}", USAGE_INSTRUCTIONS);
                process::exit(2);
            }
        }
    }
}

fn serve(config: Config) -> Result<(), i32> {
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

    let sslvpn_cookie = rt
        .block_on(fortivpn::get_oauth_cookie(&config.fortivpn))
        .map_err(|err| {
            eprintln!("Failed to get SSLVPN cookie: {}", err);
            1
        })?;

    let forti_client = rt
        .block_on(fortivpn::FortiVPNTunnel::new(
            &config.fortivpn,
            sslvpn_cookie,
        ))
        .map_err(|err| {
            eprintln!("Failed to connect to VPN service: {}", err);
            1
        })?;
    let cancel_flag = Arc::new(atomic::AtomicBool::new(false));
    let mut client = network::Network::new(forti_client, command_receiver, cancel_flag.clone())
        .map_err(|err| {
            eprintln!("Failed to start virtual network interface: {}", err);
            1
        })?;

    let cancel_handle = rt.spawn(async move {
        if let Err(err) = signal::ctrl_c().await {
            eprintln!("Failed to wait for CTRL+C signal: {}", err);
        }
        cancel_flag.store(true, atomic::Ordering::Relaxed);
    });
    rt.block_on(async move {
        if let Err(err) = client.run().await {
            eprintln!("Network failed to run: {}", err);
        }
        if let Err(err) = client.terminate().await {
            debug!("Failed to terminate client: {}", err);
        }
    });

    server_handle.abort();
    cancel_handle.abort();
    rt.shutdown_timeout(Duration::from_secs(60));

    info!("Stopped server");
    Ok(())
}

fn main() {
    println!(
        "Pterodapter version {}",
        option_env!("CARGO_PKG_VERSION").unwrap_or("unknown")
    );
    if rustls::crypto::ring::default_provider()
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
        Action::Proxy(config) => {
            if let Err(exitcode) = serve(config) {
                process::exit(exitcode);
            }
        }
    }
}
