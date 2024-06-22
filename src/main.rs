use std::net::{IpAddr, Ipv6Addr};

mod ikev2;
mod logger;

fn main() {
    if let Err(err) = logger::setup_logger() {
        eprintln!("Failed to set up logger, error is {}", err);
    }
    let listen_ips = vec![
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        //IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    ];
    let server = ikev2::Server::new(listen_ips);
    if let Err(err) = server.run() {
        println!("Failed to run server, error is {}", err);
        std::process::exit(1);
    }
}
