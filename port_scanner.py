#!/usr/bin/env python3
"""
Improved TCP port scanner:
- Uses argparse to configure target, port range, timeout, and concurrency.
- Uses ThreadPoolExecutor for parallel checks.
- Prints elapsed time and optional output to a file.
- Looks up common service names for open ports.
- Handles KeyboardInterrupt and socket errors gracefully.
"""
import socket
import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Tuple, Optional


def scan_port(host: str, port: int, timeout: float) -> Tuple[int, bool, Optional[str]]:
    """Attempt to connect to host:port. Return (port, is_open, service_name)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        result = s.connect_ex((host, port))
        if result == 0:
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = None
            return port, True, service
        else:
            return port, False, None
    except OSError:
        return port, False, None
    finally:
        try:
            s.close()
        except Exception:
            pass


def parse_args():
    p = argparse.ArgumentParser(description="Simple concurrent TCP port scanner")
    p.add_argument("target", help="Target hostname or IPv4 address (e.g. 127.0.0.1 or example.com)")
    p.add_argument(
        "-s",
        "--start",
        type=int,
        default=1,
        help="Start port (default: 1)",
    )
    p.add_argument(
        "-e",
        "--end",
        type=int,
        default=1024,
        help="End port (inclusive) (default: 1024)",
    )
    p.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=0.5,
        help="Socket timeout in seconds (default: 0.5)",
    )
    p.add_argument(
        "-w",
        "--workers",
        type=int,
        default=100,
        help="Number of concurrent worker threads (default: 100)",
    )
    p.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Optional output file to append results",
    )
    return p.parse_args()


def main():
    args = parse_args()

    # Validate ports
    start = max(1, args.start)
    end = min(65535, args.end)
    if start > end:
        raise SystemExit("Start port must be <= end port")

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror as exc:
        raise SystemExit(f"Could not resolve host {args.target}: {exc}")

    ports = range(start, end + 1)
    open_ports = []

    print(f"--- Initializing Automated Multi-Port Scan on {args.target} ({target_ip}) ---")
    print(f"Ports: {start}-{end}, timeout={args.timeout}s, workers={args.workers}")

    start_time = time.time()

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_to_port = {executor.submit(scan_port, target_ip, p, args.timeout): p for p in ports}

            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    port, is_open, service = future.result()
                except Exception as exc:
                    # unlikely, but safe fallback
                    print(f"[ERROR] Port {port}: scan failed: {exc}")
                    continue

                if is_open:
                    service_str = f" ({service})" if service else ""
                    msg = f"[ALERT]: Port {port} is OPEN{service_str}"
                    print(msg)
                    open_ports.append((port, service))
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Scan cancelled by user.")
    finally:
        elapsed = time.time() - start_time
        print(f"--- Scan Complete: evaluated {end - start + 1} ports in {elapsed:.2f}s ---")

    if args.output and open_ports:
        try:
            with open(args.output, "a", encoding="utf-8") as fh:
                for port, service in open_ports:
                    service_str = service or ""
                    fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {args.target} {port} {service_str}\n")
            print(f"Saved {len(open_ports)} open port(s) to {args.output}")
        except OSError as exc:
            print(f"[ERROR] Could not write to output file: {exc}")


if __name__ == "__main__":
    main()
