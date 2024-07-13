use std::{
    env, fmt,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    process,
    str::FromStr,
    time::Duration,
};

use log::info;
use tokio::signal;

mod logger;
mod network;
mod socks;

enum Action {
    Proxy(socks::Config),
}

pub struct Args {
    log_level: log::LevelFilter,
    action: Action,
}

const USAGE_INSTRUCTIONS: &str = "Usage: pterodapter [OPTIONS] proxy\n\n\
Options:\
\n      --log-level=<LOG_LEVEL>   Log level [default: info]\
\n      --listen-address=<IP>     Listen IP address [default: :::5328]\
\n      --destination=<IP>        Destination FortiVPN address, e.g. sslvpn.example.com:443\
\n      --help                    Print help";

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
        let mut destination = None;

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
                match SocketAddr::from_str(value) {
                    Ok(addr) => destination = Some(addr),
                    Err(err) => fail_with_error(
                        name,
                        value,
                        format_args!("Failed to parse destination address: {}", err),
                    ),
                };
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
                if destination.is_none() {
                    eprintln!("No destination specified");
                    println!("{}", USAGE_INSTRUCTIONS);
                    process::exit(2);
                }

                let action = Action::Proxy(socks::Config { listen_addr });
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

pub fn serve(config: socks::Config) -> Result<(), i32> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|err| {
            eprintln!("Failed to start runtime: {}", err);
            1
        })?;

    let mut client = network::Network::new().map_err(|err| {
        eprintln!("Failed to start virtual network interface: {}", err);
        1
    })?;
    let command_bridge = client.create_command_sender();

    let server = socks::Server::new(config, command_bridge).map_err(|err| {
        eprintln!("Failed to start SOCKS5 server: {}", err);
        1
    })?;

    let client_handle = rt.spawn(async move {
        if let Err(err) = client.run().await {
            eprintln!("Network failed to run: {}", err);
        }
    });
    let server_handle = rt.spawn(async move {
        if let Err(err) = server.run().await {
            eprintln!("Server failed to run: {}", err);
        }
    });

    rt.block_on(async {
        if let Err(err) = signal::ctrl_c().await {
            eprintln!("Failed to wait for CTRL+C signal: {}", err);
        }
    });
    server_handle.abort();
    client_handle.abort();
    rt.shutdown_timeout(Duration::from_secs(60));

    info!("Stopped server");
    Ok(())
}

fn main() {
    println!(
        "Pterodapter version {}",
        option_env!("CARGO_PKG_VERSION").unwrap_or("unknown")
    );
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
