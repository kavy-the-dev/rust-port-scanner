mod scanner;

use std::env;
use std::net::IpAddr;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <IP>", args[0]);
        return;
    }

    let ip: IpAddr = args[1].parse().expect("Invalid IP address");
    scanner::scan_common_ports(ip);
}
