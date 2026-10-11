# NetProbe

NetProbe is an IPv4 TCP port scanner, UDP application prober, and local network auditor built using only the Python standard library. Designed for network diagnostic and auditing workflows, NetProbe emphasizes deterministic execution, bounded concurrency, explicit state differentiation, and safety-conscious defaults.

---

## Safety and Authorized Testing Policy

> [!WARNING]
> **Strict Authorization Required**: Only scan systems and networks that you own or have explicit, documented permission to assess. Unauthorized scanning of computer networks may violate local, national, and international laws (such as the Computer Fraud and Abuse Act in the United States or equivalent cybercrime legislation).

NetProbe adheres to strict operational boundaries:
- **No Exploits or Evasion**: NetProbe does not perform evasion techniques, spoofing, packet crafting, or exploit delivery.
- **Bounded Concurrency**: Sockets operate under strict timeouts with bounded worker pools to prevent resource exhaustion.
- **Fail-Safe Argument Validation**: Command-line arguments and destination paths are validated before initiating network traffic.

---

## Features

- **TCP Connect Scanning**: Full three-way handshake scanning with explicit state classification (`OPEN`, `CLOSED`, `UNKNOWN`).
- **Target Resolution**: Supports IPv4 addresses and hostname resolution via standard-library resolver. Explicitly rejects IPv6 literals and IPv6-only hostnames with diagnostic messages.
- **Opt-in Service Fingerprinting (`-sV`, `--fingerprint`)**:
  - Passive greeting banner extraction: SSH (RFC 4253), FTP (RFC 959), SMTP/ESMTP (RFC 5321), POP3 (RFC 1939), IMAP (RFC 3501), and VNC/RFB (RFC 6143).
  - MySQL / MariaDB initial server handshake packet parsing (HandshakeV10 protocol).
  - Active HTTP/1.1 client probe extracting status line, `Server` header, and version metadata.
  - TLS transport negotiation extracting X.509 certificate metadata (subject, issuer, validity period, SAN, ALPN, TLS version, cipher suite).
- **UDP Scanning (`-u`, `--udp`)**:
  - Distinguishes between responsive services, ICMP port unreachable replies, and silent/dropped probes (`OPEN`, `CLOSED`, `OPEN_FILTERED`, `UNKNOWN`).
- **Application-Layer UDP Probes (`--udp-probe`)**:
  - **DNS** (`--udp-probe dns`): Generates bounded RFC 1035 A queries and validates responses, matching transaction IDs and parsing response sections.
  - **NTP** (`--udp-probe ntp`): Transmits 48-byte RFC 5905 client requests (Mode 3) and validates server responses, extracting stratum and leap indicator.
  - **SNMPv1** (`--udp-probe snmp`): Transmits bounded RFC 1157 ASN.1/BER `GetRequest` datagrams for `sysDescr.0` (`1.3.6.1.2.1.1.1.0`), verifying request ID and community echo.
- **Subnet Discovery (`--discover`, `--subnet`)**:
  - Discovers responsive IPv4 hosts across local subnets (/24 to /32, max 256 addresses) using multi-port TCP sweeping.
  - Optional reverse DNS lookup (`-R`, `--resolve-dns`) for discovered hosts.
- **Structured Export**:
  - Emits clean, parseable JSON to standard output (`--json`) or writes structured text tables and JSON documents to disk (`-o`, `--output`).
  - Pre-scan path validation ensures target directories exist and are writable before network probes begin.

---

## Requirements and Setup

### Prerequisites
- Python 3.11 or newer (tested on Python 3.11, 3.12, 3.13, and 3.14).
- Operating System: Windows, Linux, or macOS.
- **No Third-Party Runtime Dependencies**: NetProbe's core scanner, fingerprinting engine, UDP prober, and discovery modules use only the Python standard library.

### Setup (Virtual Environment)

1. Clone the repository and navigate to the project root:
   ```bash
   git clone https://github.com/banulakannangara/NetProbe.git
   cd NetProbe
   ```

2. Create and activate a virtual environment:
   ```powershell
   # Windows (PowerShell)
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
   ```bash
   # Linux / macOS (bash)
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. (Optional) Install development dependencies for running the automated test suite:
   ```powershell
   pip install -e ".[test]"
   # Or install pytest directly:
   pip install "pytest>=8.0.0"
   ```

---

## Usage Guide

NetProbe can be run directly as a Python module or through the entry point executable inside the virtual environment.

### 1. Showing Help and Version

```powershell
.\.venv\Scripts\python.exe -m netprobe.cli --help
.\.venv\Scripts\python.exe -m netprobe.cli --version
```

### 2. Basic TCP Connect Scan

Scan the default port range (1–1024) against an IPv4 target:

```powershell
.\.venv\Scripts\python.exe -m netprobe.cli 127.0.0.1
```

### 3. Selecting Ports and Ranges

Specify individual ports, comma-separated lists, and inclusive ranges:

```powershell
.\.venv\Scripts\python.exe -m netprobe.cli 127.0.0.1 -p 22,80,443,8000-8100
```

### 4. Scanning Hostname Targets

NetProbe resolves hostnames to their first IPv4 address via the system resolver:

```powershell
.\.venv\Scripts\python.exe -m netprobe.cli localhost -p 80,443
```

### 5. Opt-in Service Fingerprinting (`-sV`)

Identify running services, banner strings, HTTP headers, or TLS certificates on open TCP ports:

```powershell
.\.venv\Scripts\python.exe -m netprobe.cli 127.0.0.1 -p 21,22,80,443,3306 -sV
```

### 6. UDP Scanning (`-u`)

Scan UDP ports using generic zero-byte datagrams:

```powershell
.\.venv\Scripts\python.exe -m netprobe.cli 127.0.0.1 -u -p 53,123,161
```

### 7. Protocol-Specific UDP Probes (`--udp-probe`)

Send protocol-compliant queries and validate response structures (requires `-u`):

```powershell
# Probe DNS server on UDP port 53
.\.venv\Scripts\python.exe -m netprobe.cli 127.0.0.1 -u -p 53 --udp-probe dns

# Probe NTP time server on UDP port 123
.\.venv\Scripts\python.exe -m netprobe.cli 127.0.0.1 -u -p 123 --udp-probe ntp

# Probe SNMPv1 agent on UDP port 161 (reads sysDescr.0 using community 'public')
.\.venv\Scripts\python.exe -m netprobe.cli 127.0.0.1 -u -p 161 --udp-probe snmp
```

### 8. Subnet Discovery (`--discover`)

Sweep an IPv4 CIDR subnet (maximum 256 hosts, `/24` to `/32`) to find responsive devices:

```powershell
# Sweep using default probe ports (80, 443, 22, 445)
.\.venv\Scripts\python.exe -m netprobe.cli --discover 192.168.1.0/24

# Sweep using custom ports
.\.venv\Scripts\python.exe -m netprobe.cli --discover 192.168.1.0/24 --sweep-ports 22,80,443,8080
```

### 9. Subnet Discovery with Reverse DNS (`-R`)

Perform reverse DNS PTR lookups for discovered active hosts:

```powershell
.\.venv\Scripts\python.exe -m netprobe.cli --discover 192.168.1.0/24 -R
```

### 10. Structured JSON Output

Output structured JSON to stdout for scripting or ingestion:

```powershell
.\.venv\Scripts\python.exe -m netprobe.cli 127.0.0.1 -p 80,443 --json
```

### 11. File Export (`-o`, `--output`)

Save human-readable scan tables or JSON documents to a file:

```powershell
# Save formatted table to file (also displayed on stdout)
.\.venv\Scripts\python.exe -m netprobe.cli 127.0.0.1 -p 1-1024 -o scan_results.txt

# Save JSON document to file (stdout remains clean)
.\.venv\Scripts\python.exe -m netprobe.cli 127.0.0.1 -p 1-1024 --json -o scan_results.json
```

### 12. Adjusting Timeout and Concurrency

Control worker threads and socket timeouts:

```powershell
.\.venv\Scripts\python.exe -m netprobe.cli 127.0.0.1 -p 1-1000 -t 0.5 -w 200
```

---

## CLI Options Reference

| Flag | Argument | Description | Default | Bounds / Constraints |
|---|---|---|---|---|
| `target` | `[TARGET]` | Target IPv4 address or hostname to scan. | `None` | Positional argument. Required for single-target scanning. Mutually exclusive with `--discover`. |
| `-p`, `--ports` | `PORTS` | Target ports (comma-separated or hyphenated ranges). | `1-1024` | Valid port range is `1` to `65535`. |
| `-t`, `--timeout` | `TIMEOUT` | Socket connection / response timeout in seconds. | `1.0` | `0.05` to `60.0` seconds. |
| `-w`, `--workers` | `WORKERS` | Maximum concurrent worker thread pool size. | `100` | `1` to `500` worker threads. |
| `-a`, `--all` | — | Display all scanned ports in output table. | `False` | When scanning > 50 ports, closed ports are collapsed unless `--all` is set. |
| `-sV`, `--fingerprint` | — | Perform service fingerprinting on open TCP ports. | `False` | Probes HTTP, TLS, passive banners, and MySQL handshakes on confirmed `open` TCP ports. |
| `-u`, `--udp` | — | Perform UDP port scan instead of default TCP connect scan. | `False` | Mutually exclusive with `--discover`. |
| `--udp-probe` | `PROBE` | Protocol-specific UDP application probe (`dns`, `ntp`, `snmp`). | `None` | Requires `-u` / `--udp`. |
| `--json` | — | Emit scan results and metadata as formatted JSON. | `False` | Suppresses ASCII headers and non-JSON output. |
| `-o`, `--output` | `FILE` | Destination path for scan results. | `None` | Pre-validated before scan starts. |
| `--discover`, `--subnet` | `CIDR` | Discover active hosts across an IPv4 CIDR subnet. | `None` | Prefix length must be between `/24` and `/32` (max 256 addresses). Mutually exclusive with `target` and `-u`. |
| `--sweep-ports` | `PORTS` | Comma-separated TCP ports tested during discovery. | `80,443,22,445` | Valid port range `1` to `65535`. Requires `--discover`. |
| `-R`, `--resolve-dns` | — | Perform reverse DNS hostname lookup on discovered hosts. | `False` | Requires `--discover`. |
| `-v`, `--version` | — | Display NetProbe version number and exit. | — | — |
| `-h`, `--help` | — | Show help message and exit. | — | — |

---

## Understanding Scan Results and States

### TCP Port States

| State | Meaning | Technical Basis |
|---|---|---|
| `OPEN` | Service is accepting connections. | The TCP 3-way handshake completed successfully (`SYN-ACK` received). |
| `CLOSED` | Port is reachable but no service is listening. | The target actively reset the connection (`RST` received or `ECONNREFUSED`). |
| `UNKNOWN` | State could not be determined. | The connection timed out with no response (packet dropped or filtered by firewall) or local network error occurred. Timeouts are never reported as closed. |

### UDP Port States and Connectionless Caveats

UDP is a connectionless protocol without handshakes. Scan states reflect standard RFC 1122 / RFC 792 ICMP behaviors:

| State | Meaning | Technical Basis |
|---|---|---|
| `OPEN` | Service is running and responsive. | An actual UDP response payload was received from the target port. |
| `CLOSED` | Port is not listening. | An ICMP Port Unreachable message was received and surfaced by the OS socket (`ECONNREFUSED` / `WSAECONNREFUSED`). |
| `OPEN_FILTERED` | Inconclusive (listening or filtered). | No response was received before the socket timeout. Because UDP services are not required to respond to arbitrary payloads, a silent service and a packet dropped by a firewall appear identical. |
| `UNKNOWN` | Probing could not be completed. | A local network error or operating system socket exception occurred. |

### Subnet Discovery Reachability States

Subnet sweeping tests host reachability by sending TCP connect attempts across specified sweep ports:

| State | Meaning | Technical Basis |
|---|---|---|
| `TCP_RESPONSIVE` | Host network stack is online and active. | At least one sweep port returned an active TCP response (`SYN-ACK` indicating open, or `RST` indicating closed). |
| `NO_RESPONSE` | No response received on any tested port. | All tested ports timed out without replying. Inconclusive: the host may be offline, or host-based firewall rules may drop all probed ports. |
| `UNREACHABLE` | Host or network is unreachable. | The operating system returned an explicit routing or network unreachable error (`EHOSTUNREACH`, `ENETUNREACH`, `WSAEHOSTUNREACH`). |

---

## Security and Protocol Limitations

1. **Unverified TLS Metadata Extraction**:
   - TLS probing connects using Python's standard `ssl.CERT_NONE` mode to inspect self-signed, internal, or expired certificates without failing handshake negotiation.
   - The reported X.509 certificate fields (subject, issuer, validity period, SAN, cipher suite) reflect peer-presented attributes and **do not imply trust, certificate validity, or hostname verification**.

2. **SNMPv1 Security and Plaintext Community Strings**:
   - NetProbe's SNMP probe implements basic SNMPv1 (RFC 1157). SNMPv1 is an obsolete protocol that transmits community strings in cleartext across the network.
   - The probe defaults to the widely-used community string `"public"`.
   - The probe is strictly read-only and queries `sysDescr.0` (`1.3.6.1.2.1.1.1.0`). NetProbe does not perform `SET` requests, community brute-forcing, or credential guessing.

3. **Transaction Correlation vs. Authentication**:
   - The DNS, NTP, and SNMP probes generate pseudo-random transaction and request identifiers via Python's `secrets` module.
   - These identifiers correlate responses with outbound queries and guard against stale packets; they **do not provide cryptographic authentication**.

4. **Bounded Detection Probes vs. Protocol Clients**:
   - The DNS, NTP, and SNMP implementations in NetProbe are lightweight, bounded detection probes designed solely to verify service presence. They are not full-featured protocol clients and do not implement zone transfers, time synchronization algorithms, or SNMP MIB walking.

5. **Resolver Behavior and Timeouts**:
   - Hostname resolution (`socket.getaddrinfo`) and reverse DNS lookups (`socket.gethostbyaddr`) use the operating system's standard C library resolver.
   - Operating system resolver calls do not guarantee uniform per-call timeouts across different network environments.

6. **IPv6 Unsupported**:
   - NetProbe only supports IPv4 network auditing. IPv6 addresses, IPv6 CIDR subnets, and hostnames resolving exclusively to IPv6 addresses are explicitly rejected.

---

## Interruption, Exit Codes, and Output Behavior

### Graceful Termination (Ctrl+C)

NetProbe intercepts keyboard interrupts cleanly:
- Pressing `Ctrl+C` once signals running worker threads to halt further tasks and outputs a partial scan summary containing all ports completed prior to interruption.
- When `--json` is active, a valid partial JSON document is emitted.
- Pressing `Ctrl+C` a second time forces an immediate abort.

### Exit Codes

| Exit Code | Meaning |
|---|---|
| `0` | Scan or discovery completed successfully. |
| `1` | Configuration or validation error (e.g. invalid target, unresolvable hostname, invalid port, unwritable output file, invalid CIDR). |
| `2` | Command-line parsing error or unexpected runtime exception. |
| `130` | Interrupted by operator (`SIGINT` / `Ctrl+C`). |

### Output Destination Safety

Before initiating any network scanning, NetProbe checks the destination path passed to `-o` / `--output`:
- Ensures the path is not a directory.
- Verifies that the destination parent directory exists.
- Confirms the file can be opened for writing without prematurely truncating existing content.

---

## Development and Testing

NetProbe includes a comprehensive automated test suite utilizing Python standard library mocks and synthetic packet fixtures. Tests run locally and deterministically without generating real network traffic or requiring external internet access.

### Running Offline Validation Checks

```powershell
# 1. Run full automated test suite (348 tests)
.\.venv\Scripts\python.exe -m pytest -q

# 2. Verify bytecode compilation across all packages
.\.venv\Scripts\python.exe -m compileall -q netprobe tests

# 3. Test CLI help display
.\.venv\Scripts\python.exe -m netprobe.cli --help

# 4. Test version display
.\.venv\Scripts\netprobe.exe --version
```

---

## Known Scope Boundaries and Limitations

1. **IPv4 Only**: IPv6 targets and IPv6 subnet scanning are intentionally out of scope.
2. **TCP Connect Only**: NetProbe uses standard socket `connect()` calls. Raw SYN stealth scans, FIN scans, NULL scans, and Xmas scans are not implemented.
3. **No Exploitation or Vulnerability Scanning**: NetProbe reports open ports and detected services; it does not check CVE databases, test exploits, or assess vulnerability status.
4. **Subnet Scope Ceiling**: Subnet discovery is strictly capped at a maximum of 256 hosts (`/24` to `/32`) to prevent unintentional large-scale network scanning.
5. **Platform Loopback Timers**: On Windows operating systems, scanning closed ports on the loopback adapter (`127.0.0.1`) with extremely low timeouts (< 0.1s) may produce `UNKNOWN` if OS SYN retransmissions exceed the configured socket timeout.
