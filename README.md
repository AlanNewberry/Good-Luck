# Good-Luck Port Scanner

A multithreaded port scanner written in Python. Supports TCP connect, SYN (half-open), and UDP scan methods with banner grabbing and service detection. Designed for authorized penetration testing and lab environments.

## Features

- **TCP connect scan** for full handshake verification (default)
- **SYN scan** for fast, stealthy detection (requires root)
- **UDP scan** with open|filtered state reporting
- **Banner grabbing** with native socket read and HTTP HEAD fallback
- **Service detection** via `socket.getservbyport()` and banner analysis
- **ThreadPoolExecutor** with configurable thread count
- **nmap-style table output** with PORT, STATE, SERVICE, VERSION columns
- **JSON export** with `-o` flag
- **Progress counter** during scanning
- **Flexible port syntax**: ranges (1-1024), lists (22,80,443), or mixed (22,80,100-200)

## Requirements

- Python 3.9+
- [Scapy](https://scapy.net/) (only required for SYN scan)

```bash
pip install -r requirements.txt
```

## Usage

```bash
python3 goodluck.py TARGET -p PORTS [-m connect|syn|udp] [-t THREADS] [--timeout SECS] [-o FILE] [-q] [--version]
```

### Arguments

| Argument | Description | Default |
|---|---|---|
| `TARGET` | IP address or hostname to scan | (required) |
| `-p, --ports` | Ports to scan (e.g. `1-1024`, `22,80,443`, `22,80,100-200`) | `1-1024` |
| `-m, --method` | Scan method: `connect`, `syn`, or `udp` | `connect` |
| `-t, --threads` | Number of concurrent threads | `100` |
| `--timeout` | Timeout per probe in seconds | `1.0` |
| `-o, --output` | Write results to a JSON file | (none) |
| `-q, --quiet` | Suppress logo and progress output | off |
| `--version` | Show version and exit | |

### Examples

```bash
# TCP connect scan on common ports
python3 goodluck.py 192.168.1.1 -p 1-1024

# SYN scan on specific ports (requires sudo)
sudo python3 goodluck.py 10.0.0.1 -p 22,80,443,8080 -m syn

# UDP scan with JSON output
python3 goodluck.py 10.0.0.1 -p 53,161,500 -m udp -o results.json

# Fast scan with more threads and shorter timeout
python3 goodluck.py target.local -p 1-65535 -t 500 --timeout 0.5 -q
```

## Limitations

- Not a replacement for Nmap. No OS fingerprinting, script engine, or advanced evasion.
- Banner grabbing is best-effort, based on initial service responses.
- UDP scanning can be slow and may report open|filtered for ports that are actually closed (protocol limitation).

## Legal

This tool is provided for authorized security testing and educational purposes only. Scanning networks or hosts without explicit permission is illegal. The author is not responsible for misuse.

## Credits

Developed by Alan Newberry (44Viciius).

## License

MIT License. See [LICENSE](LICENSE).
