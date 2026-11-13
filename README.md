# Port Scanner 🔍

A beginner-friendly Python cybersecurity project that scans a host
for open TCP ports and reports which common services are listening.

## Features

- Scans a single host (hostname or IP address)
- Scans common ports, a custom list, or a range
- Uses threads to scan ports in parallel, so it is fast
- Shows the service name for well-known ports (SSH, HTTP, HTTPS, …)
- Uses only the Python standard library — no third-party packages

## Requirements

- Python 3.8 or newer
- No third-party packages are required

## How to run

```bash
python port_scanner.py 127.0.0.1
```

On some systems, use `python3 port_scanner.py 127.0.0.1`.

### Examples

Scan the common ports on localhost:

```bash
python port_scanner.py 127.0.0.1
```

Scan specific ports:

```bash
python port_scanner.py 127.0.0.1 --ports 22,80,443,8080
```

Scan a range of ports:

```bash
python port_scanner.py 127.0.0.1 --ports 1-1024
```

Use a longer timeout for slow networks:

```bash
python port_scanner.py example.com --ports common --timeout 2
```

## Common ports scanned by default

| Port | Service |
| --- | --- |
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 25 | SMTP |
| 53 | DNS |
| 80 | HTTP |
| 110 | POP3 |
| 143 | IMAP |
| 443 | HTTPS |
| 3306 | MySQL |
| 5432 | PostgreSQL |
| 8080 | HTTP-Alt |

## Project structure

```text
port-scanner/
├── port_scanner.py
├── README.md
├── requirements.txt
└── .gitignore
```

## Learning outcomes

- Python sockets (`socket`)
- Running work in parallel with `ThreadPoolExecutor`
- Command-line arguments with `argparse`
- Basic networking and port-security concepts
- Organizing and documenting a GitHub project

## Important security note

**Only scan hosts you own or have explicit permission to scan.**
Scanning a host without permission may be illegal or against
that network's rules. This is a learning/demo tool for your own
computer and networks you are allowed to test.

## Author

SHANMUKHA SREE LALITHA VENKAT SHYAM PYNA ([@1shyam253](https://github.com/1shyam253))
