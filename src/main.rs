use std::{
    env, fmt, fs,
    net::{IpAddr, Ipv6Addr},
    process,
    str::FromStr,
};

mod ikev2;
mod logger;

enum Action {
    Serve(ikev2::Config),
}

pub struct Args {
    log_level: log::LevelFilter,
    action: Action,
}

const USAGE_INSTRUCTIONS: &str = "Usage: pterodapter [OPTIONS] serve\n\n\
Options:\
\n      --log-level=<LOG_LEVEL>          Log level [default: info]\
\n      --listen-ip=<IP>                 Listen IP address, multiple options can be provided [default: ::]\
\n      --id-hostname=<FQDN>             Hostname for identification [default: pterodapter]\
\n      --cacert=<FILENAME>              Path to root CA certificate (in PKCS 8 PEM format)\
\n      --cert=<FILENAME>                Path to public certificate (in PKCS 8 PEM format)\
\n      --key=<FILENAME>                 Path to private key (in PKCS 8 PEM format)\
\n      --help                           Print help";

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
        let mut listen_ips = vec![];
        let mut id_hostname = None;
        let mut root_ca = None;
        let mut private_key = None;
        let mut public_cert = None;

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
            } else if name == "--listen-ip" {
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
            } else if name == "--id-hostname" {
                id_hostname = Some(value.into());
            } else if name == "--cacert" {
                match fs::read_to_string(value) {
                    Ok(cert) => root_ca = Some(cert),
                    Err(err) => fail_with_error(
                        name,
                        value,
                        format_args!("Failed to read root CA cert: {}", err),
                    ),
                };
            } else if name == "--cert" {
                match fs::read_to_string(value) {
                    Ok(cert) => public_cert = Some(cert),
                    Err(err) => fail_with_error(
                        name,
                        value,
                        format_args!("Failed to read root CA cert: {}", err),
                    ),
                };
            } else if name == "--key" {
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

        let action = if let Some(action) = env::args().last() {
            action
        } else {
            eprintln!("No action specified");
            println!("{}", USAGE_INSTRUCTIONS);
            process::exit(2);
        };

        match action.as_str() {
            "serve" => {
                let server_cert = match (public_cert.clone(), private_key.clone()) {
                    (Some(public_cert), Some(private_key)) => Some((public_cert, private_key)),
                    _ => None,
                };
                if listen_ips.is_empty() {
                    listen_ips = vec![IpAddr::V6(Ipv6Addr::UNSPECIFIED)];
                }

                let action = Action::Serve(ikev2::Config {
                    hostname: id_hostname.clone(),
                    listen_ips: listen_ips.clone(),
                    root_ca: root_ca.clone(),
                    server_cert,
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
        Action::Serve(config) => {
            let server = match ikev2::Server::new(config) {
                Ok(server) => server,
                Err(err) => {
                    println!("Failed to create server, error is {}", err);
                    std::process::exit(1)
                }
            };
            if let Err(err) = server.run() {
                println!("Failed to run server, error is {}", err);
                std::process::exit(1);
            }
        }
    }
}
