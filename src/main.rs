use std::{
    env, fmt, fs,
    net::{IpAddr, Ipv6Addr, ToSocketAddrs},
    process,
    str::FromStr as _,
    sync::Arc,
};

use log::info;
use rustls_platform_verifier::BuilderVerifierExt as _;
use tokio::signal;
use tokio_rustls::rustls;

mod fortivpn;
mod http;
mod ikev2;
mod ip;
mod logger;
mod pcap;
mod ppp;
mod uplink;

struct Args {
    log_level: log::LevelFilter,
    config: Ikev2Config,
}

const USAGE_INSTRUCTIONS: &str = "Usage:\n\n\
> pterodapter [OPTIONS] ikev2\n\
Options:\
\n      --log-level=<LOG_LEVEL>         Log level [default: info]\
\n      --listen-ip=<IP>                Listen IP address, multiple options can be provided [default: ::]\
\n      --ike-port=<PORT>               IKEv2 port [default: 500]\
\n      --nat-port=<PORT>               NAT port for IKEv2 and ESP [default: 4500]\
\n      --listen-ip=<IP>                Listen IP address, multiple options can be provided [default: ::]\
\n      --fortivpn=<HOSTPORT>           Destination FortiVPN address, e.g. sslvpn.example.com:443\
\n      --tunnel-domain=<DOMAIN>        (Optional) Only forward domain to VPN through split routing; can be specified multiple times\
\n      --nat64-prefix=<IP6>            (Optional) Enable NAT64 mode and use the specified /96 IPv6 prefix to remap IPv4 addresses, e.g. 64:ff9b::\
\n      --dns64-tunnel-suffix=<DOMAIN>  (Optional) Forward specified domain and subdomains through NAT64; can be specified multiple times\
\n      --id-hostname=<FQDN>            Hostname for identification [default: pterodapter]\
\n      --cacert=<FILENAME>             Path to root CA certificate (in PKCS 8 PEM format)\
\n      --cert=<FILENAME>               Path to public certificate (in PKCS 8 PEM format)\
\n      --key=<FILENAME>                Path to private key (in PKCS 8 PEM format)\
\n      --pcap=<FILENAME>               (Optional) Enable packet capture into the specified tcpdump file\
\n\n\
> pretodapter help";

struct Ikev2Config {
    ikev2: ikev2::Config,
    uplink: uplink::Config,
    pcap: Option<String>,
}

impl Args {
    fn parse() -> Args {
        match env::args().next_back().as_deref() {
            Some("ikev2") => {}
            Some("help") => {
                println!("{USAGE_INSTRUCTIONS}");
                process::exit(0);
            }
            _ => {
                eprintln!("No action specified");
                println!("{USAGE_INSTRUCTIONS}");
                process::exit(2);
            }
        };

        let fail_with_error = |name: &str, value: &str, err: fmt::Arguments| -> ! {
            eprintln!("Argument {name} has an unsupported value {value}: {err}");
            println!("{USAGE_INSTRUCTIONS}");
            process::exit(2);
        };

        let mut log_level = log::LevelFilter::Info;

        let mut tunnel_domains: Vec<String> = vec![];

        let mut fortivpn_addr = None;
        let mut fortivpn_hostport = None;

        let mut listen_ips = vec![];
        let mut ike_port = 500u16;
        let mut nat_port = 4500u16;
        let mut id_hostname: Option<String> = None;
        let mut root_ca = None;
        let mut private_key = None;
        let mut public_cert = None;
        let mut nat64_prefix = None;
        let mut dns64_domains: Vec<String> = vec![];

        let mut pcap_file: Option<String> = None;

        let tls_config =
            match rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_platform_verifier()
            {
                Ok(builder) => builder.with_no_client_auth(),
                Err(err) => {
                    eprintln!("Failed to init platform verifier: {err}");
                    process::exit(2);
                }
            };
        let tls_config = Arc::new(tls_config);

        for arg in env::args()
            .take(env::args().len().saturating_sub(1))
            .skip(1)
        {
            let (name, value) = if let Some(arg) = arg.split_once('=') {
                arg
            } else {
                eprintln!("Option flag {arg} has no value");
                println!("{USAGE_INSTRUCTIONS}");
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
            } else if name == "--fortivpn" {
                match value.to_socket_addrs() {
                    Ok(mut addr) => {
                        fortivpn_addr = addr.next();
                        fortivpn_hostport = Some(value.to_string());
                    }
                    Err(err) => fail_with_error(
                        name,
                        value,
                        format_args!("Failed to parse destination address: {err}"),
                    ),
                };
            } else if name == "--tunnel-domain" {
                // Domains should be in DNS IDNA A-label format for Unicode strings.
                // All further processing assumes the domain is an ASCII UTF-8 string.
                if !value.is_ascii() {
                    fail_with_error(
                        name,
                        value,
                        format_args!("Domain is not a valid ASCII string"),
                    );
                }
                tunnel_domains.push(value.into());
            } else if name == "--dns64-tunnel-suffix" {
                // Domains should be in DNS IDNA A-label format for Unicode strings.
                // All further processing assumes the domain is an ASCII UTF-8 string.
                if !value.is_ascii() {
                    fail_with_error(
                        name,
                        value,
                        format_args!("Domain is not a valid ASCII string"),
                    );
                }
                dns64_domains.push(value.into());
            } else if name == "--listen-ip" {
                match IpAddr::from_str(value) {
                    Ok(ip) => {
                        listen_ips.push(ip);
                    }
                    Err(err) => fail_with_error(
                        name,
                        value,
                        format_args!("Failed to parse IP address: {err}"),
                    ),
                };
            } else if name == "--ike-port" {
                match u16::from_str(value) {
                    Ok(port) => ike_port = port,
                    Err(err) => fail_with_error(
                        name,
                        value,
                        format_args!("Failed to parse IKEv2 port: {err}"),
                    ),
                };
            } else if name == "--nat-port" {
                match u16::from_str(value) {
                    Ok(port) => nat_port = port,
                    Err(err) => fail_with_error(
                        name,
                        value,
                        format_args!("Failed to parse NAT port for IKEv2: {err}"),
                    ),
                };
            } else if name == "--nat64-prefix" {
                let ip = match IpAddr::from_str(value) {
                    Ok(IpAddr::V4(_)) => fail_with_error(
                        name,
                        value,
                        format_args!("NAT64 doesn't support IPv4 prefixes"),
                    ),
                    Ok(IpAddr::V6(ip)) => ip,
                    Err(err) => fail_with_error(
                        name,
                        value,
                        format_args!("Failed to parse NAT64 prefix: {err}"),
                    ),
                };
                nat64_prefix = Some(ip);
            } else if name == "--id-hostname" {
                id_hostname = Some(value.into());
            } else if name == "--cacert" {
                match fs::read_to_string(value) {
                    Ok(cert) => root_ca = Some(cert),
                    Err(err) => fail_with_error(
                        name,
                        value,
                        format_args!("Failed to read root CA cert: {err}"),
                    ),
                };
            } else if name == "--cert" {
                match fs::read_to_string(value) {
                    Ok(cert) => public_cert = Some(cert),
                    Err(err) => fail_with_error(
                        name,
                        value,
                        format_args!("Failed to read root CA cert: {err}"),
                    ),
                };
            } else if name == "--key" {
                match fs::read_to_string(value) {
                    Ok(cert) => private_key = Some(cert),
                    Err(err) => fail_with_error(
                        name,
                        value,
                        format_args!("Failed to read root CA cert: {err}"),
                    ),
                };
            } else if name == "--pcap" {
                pcap_file = Some(value.into());
            } else {
                eprintln!("Unsupported argument {arg}");
            }
        }

        let uplink_config = match (fortivpn_addr, fortivpn_hostport) {
            (Some(fortivpn_addr), Some(fortivpn_hostport)) => {
                uplink::Config::FortiVPN(fortivpn::Config {
                    destination_addr: fortivpn_addr,
                    destination_hostport: fortivpn_hostport,
                    tls_config,
                })
            }
            _ => {
                eprintln!("No destination specified");
                println!("{USAGE_INSTRUCTIONS}");
                process::exit(2);
            }
        };
        if nat64_prefix.is_none() && !dns64_domains.is_empty() {
            eprintln!("--dns64-tunnel-suffix should only be used when --nat64-prefix is specified");
            println!("{USAGE_INSTRUCTIONS}");
            process::exit(2);
        }

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
            nat64_prefix,
            dns64_domains,
        };
        let config = Ikev2Config {
            ikev2: ikev2_config,
            uplink: uplink_config,
            pcap: pcap_file,
        };
        Args { log_level, config }
    }
}

fn serve_ikev2(config: Ikev2Config) -> Result<(), i32> {
    use tokio::sync::oneshot;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|err| {
            eprintln!("Failed to start runtime: {err}");
            1
        })?;
    let mut server = match ikev2::Server::new(config.ikev2) {
        Ok(server) => server,
        Err(err) => {
            eprintln!("Failed to create server: {err}");
            std::process::exit(1)
        }
    };

    let (shutdown_sender, shutdown_receiver) = oneshot::channel();

    rt.spawn(async move {
        if let Err(err) = signal::ctrl_c().await {
            eprintln!("Failed to wait for CTRL+C signal: {err}");
        }
        info!("Started shutdown");
        if shutdown_sender.send(()).is_err() {
            eprintln!("Shutdown listener is closed");
        }
    });

    let pcap_sender = if let Some(pcap_file) = config.pcap {
        match rt.block_on(pcap::PcapWriter::new(pcap_file)) {
            Ok(pcap_writer) => {
                let pcap_sender = pcap_writer.create_sender();
                rt.spawn(pcap_writer.run());
                Some(pcap_sender)
            }
            Err(err) => {
                eprintln!("Failed to create PCAP writer: {err}");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    let uplink = uplink::UplinkServiceType::new(config.uplink, pcap_sender.clone());
    if let Err(err) = server.run(rt, uplink, shutdown_receiver, pcap_sender) {
        eprintln!("Failed to run server: {err}");
    };

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
        eprintln!("Failed to set up logger, error is {err}");
    }
    if let Err(exitcode) = serve_ikev2(args.config) {
        process::exit(exitcode);
    }
}
