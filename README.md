#  Rust TCP Port Scanner

A simple, fast, and multi-threaded **TCP port scanner** written in Rust. This tool scans the most common TCP ports on a target IP address and reports which ones are open, along with their associated services. Ideal for learning, debugging, and basic network analysis.

---

## Features

- Multi-threaded for fast scanning
- Scans 50+ of the most common TCP ports
- Maps known ports to services (e.g., 22 → SSH)
- Built using Rust's standard library (no external dependencies)
- Minimal CLI interface

## How It Works:
- It creates a list of common TCP ports (such as 21, 22, 80, 443, 3306, etc.).

- Each port is checked by attempting to connect using TcpStream::connect_timeout.

- If the connection is successful, the port is considered open.

- Services are inferred from a static map of well-known ports.

## Limitations
- This tool only scans TCP ports. UDP is not supported in this version.

- Only checks for port openness, no banner grabbing or vulnerability detection.

- Use responsibly and only on hosts/networks you own or have permission to scan.

## Resources
To learn more about common ports and services: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
