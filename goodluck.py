#!/usr/bin/env python3
"""Good-Luck port scanner. Fast, clean, no bloat."""

__version__ = "1.0.0"

import argparse
import json
import os
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# Logo
# ---------------------------------------------------------------------------

LOGO = r"""
  /$$$$$$                            /$$       /$$                           /$$                /$$$
 /$$__  $$                          | $$      | $$                          | $$               |_  $$
| $$  \__/  /$$$$$$   /$$$$$$   /$$$$$$$      | $$       /$$   /$$  /$$$$$$$| $$   /$$       /$$ \  $$
| $$ /$$$$ /$$__  $$ /$$__  $$ /$$__  $$      | $$      | $$  | $$ /$$_____/| $$  /$$/      |__/  | $$
| $$|_  $$| $$  \ $$| $$  \ $$| $$  | $$      | $$      | $$  | $$| $$      | $$$$$$/             | $$
| $$  \ $$| $$  | $$| $$  | $$| $$  | $$      | $$      | $$  | $$| $$      | $$_  $$        /$$  /$$/
|  $$$$$$/|  $$$$$$/|  $$$$$$/|  $$$$$$$      | $$$$$$$$|  $$$$$$/|  $$$$$$$| $$ \  $$      |__//$$$/
 \______/  \______/  \______/  \_______/      |________/ \______/  \_______/|__/  \__/         |___/

                                     By 44Viciius
"""

# ---------------------------------------------------------------------------
# Port parsing
# ---------------------------------------------------------------------------

def parse_ports(port_string):
    """Parse port specification like '22,80,443' or '1-1024' or '22,80,100-200'.

    Returns a sorted list of unique port numbers, all in 1..65535.
    """
    ports = set()
    for part in port_string.split(","):
        part = part.strip()
        if "-" in part:
            bounds = part.split("-", 1)
            if len(bounds) != 2:
                raise argparse.ArgumentTypeError(
                    "Invalid port range: {}".format(part)
                )
            try:
                lo, hi = int(bounds[0]), int(bounds[1])
            except ValueError:
                raise argparse.ArgumentTypeError(
                    "Non-numeric port in range: {}".format(part)
                )
            if lo > hi:
                raise argparse.ArgumentTypeError(
                    "Start port larger than end port: {}".format(part)
                )
            if lo < 1 or hi > 65535:
                raise argparse.ArgumentTypeError(
                    "Ports must be between 1 and 65535: {}".format(part)
                )
            ports.update(range(lo, hi + 1))
        else:
            try:
                p = int(part)
            except ValueError:
                raise argparse.ArgumentTypeError(
                    "Non-numeric port: {}".format(part)
                )
            if p < 1 or p > 65535:
                raise argparse.ArgumentTypeError(
                    "Port out of range: {}".format(p)
                )
            ports.add(p)
    return sorted(ports)


# ---------------------------------------------------------------------------
# Service name lookup
# ---------------------------------------------------------------------------

def get_service_name(port, proto="tcp"):
    """Return the IANA service name for a port, or empty string."""
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Scanning methods
# ---------------------------------------------------------------------------

def tcp_connect_scan(target, port, timeout):
    """Full TCP connect. Returns True if port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((target, port)) == 0
    except (socket.error, OSError):
        return False


def syn_scan(target, port, timeout):
    """Half-open SYN scan using scapy. Requires root."""
    from scapy.all import IP, TCP, RandShort, send, sr1

    src_port = RandShort()
    syn_pkt = IP(dst=target) / TCP(sport=src_port, dport=port, flags="S")
    response = sr1(syn_pkt, timeout=timeout, verbose=0)

    if response and response.haslayer(TCP):
        tcp_layer = response.getlayer(TCP)
        if tcp_layer.flags & 0x12 == 0x12:  # SYN-ACK
            send(
                IP(dst=target) / TCP(sport=src_port, dport=port, flags="R"),
                verbose=0,
            )
            return True
    return False


def udp_scan(target, port, timeout):
    """UDP scan. Returns 'open|filtered' if no response, 'open' if response,
    'closed' only on ICMP port-unreachable (handled as exception)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"\x00", (target, port))
        try:
            sock.recvfrom(1024)
            return "open"
        except socket.timeout:
            return "open|filtered"
        finally:
            sock.close()
    except (socket.error, OSError):
        return "closed"


# ---------------------------------------------------------------------------
# Banner / version grabbing
# ---------------------------------------------------------------------------

def banner_grab(target, port, timeout):
    """Try to grab a service banner. First try a raw socket read, then HTTP HEAD."""
    # Attempt 1: connect and wait for the service to send a banner
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target, port))
            s.settimeout(max(timeout, 2))
            data = s.recv(1024)
            if data:
                return _clean_banner(data.decode("utf-8", errors="replace"))
    except (socket.error, OSError):
        pass

    # Attempt 2: send HTTP HEAD with correct Host header
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target, port))
            request = "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n".format(
                target
            )
            s.sendall(request.encode())
            data = s.recv(1024)
            if data:
                return _clean_banner(data.decode("utf-8", errors="replace"))
    except (socket.error, OSError):
        pass

    return ""


def _clean_banner(banner):
    """Collapse whitespace, strip control chars."""
    return " ".join(banner.split())


def extract_version(banner):
    """Try to pull a version string from a banner."""
    if not banner:
        return ""
    # Common patterns: Server: Apache/2.4.52, SSH-2.0-OpenSSH_8.9p1, 220 ProFTPD 1.3.7
    for line in banner.replace("\\r\\n", "\n").split("\n"):
        line = line.strip()
        if line:
            # Return the first meaningful line, trimmed
            if len(line) > 80:
                return line[:80] + "..."
            return line
    return ""


# ---------------------------------------------------------------------------
# Single port scan
# ---------------------------------------------------------------------------

def scan_port(target, port, method, timeout):
    """Scan a single port. Returns a result dict."""
    result = {
        "port": port,
        "state": "closed",
        "service": get_service_name(port, "udp" if method == "udp" else "tcp"),
        "version": "",
    }

    if method == "syn":
        is_open = syn_scan(target, port, timeout)
        result["state"] = "open" if is_open else "closed"
    elif method == "connect":
        is_open = tcp_connect_scan(target, port, timeout)
        result["state"] = "open" if is_open else "closed"
    elif method == "udp":
        result["state"] = udp_scan(target, port, timeout)

    if result["state"] in ("open", "open|filtered"):
        banner = banner_grab(target, port, timeout)
        result["version"] = extract_version(banner)

    return result


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def print_table(results, scan_time):
    """Print nmap-style table of open ports."""
    open_results = [r for r in results if r["state"] != "closed"]
    if not open_results:
        print("\nNo open ports found.")
        return

    print("")
    print("PORT        STATE           SERVICE         VERSION")
    print("-" * 72)
    for r in sorted(open_results, key=lambda x: x["port"]):
        port_col = "{}/{}".format(r["port"], r.get("proto", "tcp"))
        print(
            "{:<12}{:<16}{:<16}{}".format(
                port_col,
                r["state"],
                r["service"] or "unknown",
                r["version"],
            )
        )
    print("")
    print("Scan completed in {:.2f}s, {} open port(s) found.".format(
        scan_time, len(open_results)
    ))


def write_json(results, filepath, target, method, scan_time):
    """Write scan results to a JSON file."""
    output = {
        "target": target,
        "method": method,
        "scan_time_seconds": round(scan_time, 2),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "results": results,
    }
    with open(filepath, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

def run_scan(target, ports, method, threads, timeout, quiet=False):
    """Run the scan using a thread pool. Returns list of result dicts."""
    results = []
    total = len(ports)
    done = 0

    proto = "udp" if method == "udp" else "tcp"

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {
            pool.submit(scan_port, target, port, method, timeout): port
            for port in ports
        }
        for future in as_completed(futures):
            result = future.result()
            result["proto"] = proto
            results.append(result)
            done += 1
            if not quiet:
                sys.stdout.write(
                    "\rScanning: {}/{} ports ({:.0f}%)".format(
                        done, total, done / total * 100
                    )
                )
                sys.stdout.flush()

    if not quiet:
        sys.stdout.write("\r" + " " * 40 + "\r")
        sys.stdout.flush()

    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="goodluck",
        description="Good-Luck port scanner v{}".format(__version__),
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument(
        "-p", "--ports",
        default="1-1024",
        help="Ports to scan: range (1-1024), list (22,80,443), or mixed (22,80,100-200)",
    )
    parser.add_argument(
        "-m", "--method",
        choices=["connect", "syn", "udp"],
        default="connect",
        help="Scan method (default: connect)",
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=100,
        help="Number of threads (default: 100)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Timeout per probe in seconds (default: 1.0)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Write results to a JSON file",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress progress output",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="Good-Luck {}".format(__version__),
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Parse and validate ports
    try:
        ports = parse_ports(args.ports)
    except argparse.ArgumentTypeError as e:
        parser.error(str(e))

    # SYN scan requires root
    if args.method == "syn":
        if os.geteuid() != 0:
            print("Error: SYN scan requires root privileges. Run with sudo.")
            sys.exit(1)
        # Conditional scapy import check
        try:
            import scapy  # noqa: F401
        except ImportError:
            print("Error: scapy is required for SYN scan. Install it: pip install scapy")
            sys.exit(1)

    if not args.quiet:
        print(LOGO)
        print("Target: {}".format(args.target))
        print("Ports: {} port(s)".format(len(ports)))
        print("Method: {}".format(args.method))
        print("Threads: {}".format(args.threads))
        print("")

    # Resolve hostname
    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print("Error: could not resolve hostname '{}'".format(args.target))
        sys.exit(1)

    start_time = time.time()
    results = run_scan(target_ip, ports, args.method, args.threads, args.timeout, args.quiet)
    scan_time = time.time() - start_time

    if not args.quiet:
        print_table(results, scan_time)

    if args.output:
        write_json(results, args.output, args.target, args.method, scan_time)
        if not args.quiet:
            print("Results saved to {}".format(args.output))


if __name__ == "__main__":
    main()
