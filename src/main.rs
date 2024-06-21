use std::net::{IpAddr, Ipv4Addr};

mod ikev2;
mod logger;

fn main() {
    if let Err(err) = logger::setup_logger() {
        eprintln!("Failed to set up logger, error is {}", err);
    }
    //let listen_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    //let listen_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
    let listen_ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    //let listen_ip = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));

    let server = ikev2::Server::new(listen_ip);
    if let Err(err) = server.run() {
        println!("Failed to run server, error is {}", err);
        std::process::exit(1);
    }
}
