# Port scanner usage

This repository contains a simple concurrent TCP port scanner implemented in `port_scanner.py`.

Highlights:

- Command-line interface with `argparse` (target, ports, timeout, workers, output).
- Concurrent scanning using ThreadPoolExecutor for faster results.
- Hostname resolution and error handling.
- Optional service name resolution and ability to write results to a file.

Usage examples:

```bash
# Quick scan (default 20-85)
python3 port_scanner.py 127.0.0.1

# Scan common ports on example.com with a shorter timeout and more workers
python3 port_scanner.py example.com -p 1-1024 -t 0.3 -w 200

# Scan a few specific ports and save results
python3 port_scanner.py 10.0.0.5 -p 22,80,443 -o open_ports.txt
```

Security and ethics

Only scan systems you own or are authorized to test. Port scanning can trigger alerts and may be considered hostile if run against third-party infrastructure without permission.
