use std::{
    env, fmt,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    process,
    str::FromStr,
};

mod logger;
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
            match socks::run(config) {
                Ok(server) => server,
                Err(err) => {
                    println!("Failed to run server, error is {}", err);
                    std::process::exit(1)
                }
            };
        }
    }
}
