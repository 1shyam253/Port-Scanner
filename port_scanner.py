"""Port Scanner — a beginner-friendly Python cybersecurity project.

Scans a host for open TCP ports and reports which common services
are listening.

Only scan hosts you own or have explicit permission to scan.
Scanning a host without permission may be illegal or against
that network's rules.
"""

import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
}


def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """Return True if the TCP port is open on the host."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except (socket.gaierror, OSError):
        return False


def scan_host(host: str, ports, timeout: float = 1.0, workers: int = 50):
    """Scan ports in parallel and return a sorted list of open ports."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_port, host, p, timeout): p for p in ports}
        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                open_ports.append(port)
    return sorted(open_ports)


def parse_ports(value: str):
    """Parse '80,443,8080' or '1-1024' into a list of ports."""
    ports = set()
    for part in value.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    bad = [p for p in ports if p < 1 or p > 65535]
    if bad:
        raise ValueError(f"Port out of range (1-65535): {sorted(bad)}")
    return sorted(ports)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Scan a host for open TCP ports."
    )
    parser.add_argument("host", help="Hostname or IP address to scan")
    parser.add_argument(
        "--ports",
        default="common",
        help="Ports to scan: 'common', a list like '22,80,443', "
        "or a range like '1-1024' (default: common)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)",
    )
    args = parser.parse_args(argv)

    if args.ports == "common":
        ports = sorted(COMMON_PORTS)
    else:
        try:
            ports = parse_ports(args.ports)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2

    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"Error: could not resolve host '{args.host}'.", file=sys.stderr)
        return 2

    print("=" * 40)
    print("            PORT SCANNER")
    print("=" * 40)
    print(f"Host: {args.host} ({ip})")
    print(f"Ports: {len(ports)} port(s)")
    print()
    print("Only scan hosts you own or have permission to scan.")
    print()

    open_ports = scan_host(ip, ports, timeout=args.timeout)

    if open_ports:
        print("Open ports:")
        for port in open_ports:
            service = COMMON_PORTS.get(port, "Unknown")
            print(f"  {port:<6} OPEN   ({service})")
    else:
        print("No open ports found in the scanned range.")

    print(f"\nDone. {len(open_ports)} open port(s) found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
