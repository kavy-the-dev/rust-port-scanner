use std::net::{TcpStream, SocketAddr, IpAddr};
use std::time::Duration;
use std::thread;
use std::io::{Write, Read};
use std::collections::HashMap;

pub fn scan_common_ports(ip: IpAddr) {
    let common_ports: [u16; 50] = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
        143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
        8443, 8888, 20, 554, 179, 389, 636, 1025, 1110, 2000,
        25565, 5432, 1521, 4444, 5000, 6000, 6666, 7000, 8000, 9000,
        9090, 49152, 49153, 49154, 49155, 49156, 49157, 37, 69, 161,
    ];

    let service_map = get_service_map();

    println!("{:<9} {:<7} {:<9} {}", "PORT", "STATE", "SERVICE", "VERSION");

    let mut handles = vec![];

    for &port in common_ports.iter() {
        let ip = ip.clone();
        let service_name = service_map.get(&port).unwrap_or(&"unknown").to_string();

        let handle = thread::spawn(move || {
            scan_port(ip, port, &service_name);
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.join();
    }
}

fn scan_port(ip: IpAddr, port: u16, service: &str) {
    let socket = SocketAddr::new(ip, port);
    if let Ok(mut stream) = TcpStream::connect_timeout(&socket, Duration::from_millis(300)) {
        stream.set_read_timeout(Some(Duration::from_millis(300))).ok();
        let _ = stream.write_all(b"\r\n");

        let mut buffer = [0u8; 1024];
        let version = match stream.read(&mut buffer) {
            Ok(size) if size > 0 => {
                let banner = String::from_utf8_lossy(&buffer[..size]).trim().to_string();
                if !banner.is_empty() {
                    banner.replace("\r", "").replace("\n", " ")
                } else {
                    "-".to_string()
                }
            }
            _ => "-".to_string(),
        };

        println!("{:<9} {:<7} {:<9} {}", format!("{}/tcp", port), "open", service, version);
    }
}

fn get_service_map() -> HashMap<u16, &'static str> {
    [
        (21, "ftp"), (22, "ssh"), (23, "telnet"), (25, "smtp"), (53, "dns"),
        (80, "http"), (110, "pop3"), (111, "rpcbind"), (135, "msrpc"), (139, "netbios-ssn"),
        (143, "imap"), (443, "https"), (445, "smb"), (993, "imaps"), (995, "pop3s"),
        (1723, "pptp"), (3306, "mysql"), (3389, "rdp"), (5900, "vnc"), (8080, "http-proxy"),
        (8443, "https-alt"), (8888, "http-alt"), (20, "ftp-data"), (554, "rtsp"),
        (179, "bgp"), (389, "ldap"), (636, "ldaps"), (1025, "nfs"), (1110, "pop3s-alt"),
        (2000, "cisco-sccp"), (25565, "minecraft"), (5432, "postgresql"), (1521, "oracle"),
        (4444, "metasploit"), (5000, "upnp"), (6000, "x11"), (6666, "irc"),
        (7000, "avaya"), (8000, "http-alt"), (9000, "samba"), (9090, "web-console"),
        (49152, "win-rpc"), (49153, "win-rpc"), (49154, "win-rpc"), (49155, "win-rpc"),
        (49156, "win-rpc"), (49157, "win-rpc"), (37, "time"), (69, "tftp"), (161, "snmp"),
    ]
    .iter()
    .cloned()
    .collect()
}
