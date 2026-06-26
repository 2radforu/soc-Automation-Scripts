#!/usr/bin/env python3
"""
Simple concurrent TCP port scanner.

Improvements over the original:
 - Accepts target and port range from the command line (argparse).
 - Resolves the target host and handles lookup errors.
 - Uses ThreadPoolExecutor for concurrency to scan ports faster.
 - Proper error handling and clean socket closing.
 - Optional service name resolution and output to file.
 - Friendly progress and summary output.
 - Safety reminder: only scan hosts you are authorized to test.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import argparse
import sys
from typing import Iterable, List, Tuple


def parse_ports(port_spec: str) -> List[int]:
    """
    Parse port specification strings like:
      - "20-85"
      - "22,80,443"
      - "1-1024,8080,8443"
    Returns a sorted list of unique ports.
    """
    ports = set()
    for part in port_spec.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            start, end = part.split('-', 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def scan_port(addr: str, port: int, timeout: float) -> Tuple[int, bool, str]:
    """
    Try to connect to addr:port. Returns (port, is_open, service_name_or_empty).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((addr, port))
        if result == 0:
            # Try to get a well-known service name for nicer output
            try:
                service = socket.getservbyport(port)
            except Exception:
                service = ''
            return port, True, service
        else:
            return port, False, ''
    except Exception:
        return port, False, ''
    finally:
        try:
            sock.close()
        except Exception:
            pass


def resolve_host(hostname: str) -> str:
    """
    Resolve a hostname to an IPv4 address (raises on failure).
    """
    try:
        # getaddrinfo can return IPv4/IPv6; prefer IPv4 for simple socket.connect_ex usage
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
        if not infos:
            raise socket.gaierror(f"Could not resolve {hostname}")
        return infos[0][4][0]
    except socket.gaierror:
        # re-raise with useful message
        raise


def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser(description="Simple concurrent TCP port scanner")
    parser.add_argument("target", help="Target hostname or IP (e.g. 127.0.0.1)")
    parser.add_argument(
        "-p",
        "--ports",
        default="20-85",
        help="Ports to scan. Example: '20-85', '22,80,443', or '1-1024,8080'. Default: 20-85",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=0.5,
        help="Socket timeout in seconds (default: 0.5)",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=100,
        help="Number of concurrent worker threads (default: 100). Keep this reasonable.",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Write open ports to FILE (one per line). If omitted, prints to stdout.",
    )
    parser.add_argument(
        "--no-service",
        action="store_true",
        help="Do not attempt to resolve well-known service names for open ports.",
    )

    args = parser.parse_args(list(argv))
    try:
        ip = resolve_host(args.target)
    except Exception as e:
        print(f"ERROR: Failed to resolve target '{args.target}': {e}", file=sys.stderr)
        return 2

    ports = parse_ports(args.ports)
    if not ports:
        print("No valid ports to scan. Check the --ports argument.", file=sys.stderr)
        return 2

    print(f"--- Initializing Automated Multi-Port Scan ---")
    print(f"Target: {args.target} -> {ip}")
    print(f"Ports: {len(ports)} ports (example: {ports[0]} ... {ports[-1]})")
    print(f"Timeout: {args.timeout}s  Workers: {args.workers}")
    print("Note: Only scan systems you are authorized to test.\n")

    open_ports = []

    # Cap workers reasonably to avoid excessive thread creation
    max_workers = max(1, min(args.workers, len(ports), 1000))

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as exe:
            future_to_port = {exe.submit(scan_port, ip, p, args.timeout): p for p in ports}
            for future in as_completed(future_to_port):
                p = future_to_port[future]
                try:
                    port, is_open, service = future.result()
                except Exception as e:
                    # don't crash the whole scan for one failing thread
                    print(f"[WARN] Port {p} scan failed: {e}", file=sys.stderr)
                    continue

                if is_open:
                    if not args.no_service and service:
                        print(f"[ALERT]: Port {port} is OPEN (service: {service})")
                    else:
                        print(f"[ALERT]: Port {port} is OPEN")
                    open_ports.append(port)
    except KeyboardInterrupt:
        print("\nScan interrupted by user.", file=sys.stderr)
    except Exception as e:
        print(f"Unexpected error during scanning: {e}", file=sys.stderr)
        return 1

    open_ports.sort()
    print("\n--- Scan Complete! ---")
    if open_ports:
        print("Open ports:", ", ".join(str(p) for p in open_ports))
    else:
        print("No open ports found in the scanned range.")

    if args.output:
        try:
            with open(args.output, "w") as fh:
                for p in open_ports:
                    fh.write(f"{p}\n")
            print(f"Results written to {args.output}")
        except Exception as e:
            print(f"Failed to write output file: {e}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
