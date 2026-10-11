"""Core UDP scanning logic, data models, and probing engine for NetProbe Phase 4A/4B."""

import concurrent.futures
from dataclasses import dataclass
from enum import Enum
import errno
import socket
import time
from typing import Callable, Sequence

from netprobe.scanner import validate_ipv4
from netprobe.services import get_service_name
from netprobe.udp_probes import (
    SNMP_DEFAULT_COMMUNITY,
    UDPProtocolInfo,
    build_dns_query,
    build_ntp_request,
    build_snmp_get_request,
    validate_dns_response,
    validate_ntp_response,
    validate_snmp_response,
)

# Errno codes representing reliable ICMP Port Unreachable notifications across platforms
_PORT_UNREACHABLE_ERRNOS: frozenset[int] = frozenset(
    code
    for name in (
        "ECONNREFUSED",
        "ECONNRESET",
        "WSAECONNREFUSED",
        "WSAECONNRESET",
    )
    if (code := getattr(errno, name, None)) is not None
)

# Errno codes representing oversized datagram messages across platforms
_EMSGSIZE_ERRNOS: frozenset[int] = frozenset(
    code
    for name in (
        "EMSGSIZE",
        "WSAEMSGSIZE",
    )
    if (code := getattr(errno, name, None)) is not None
)

UDP_RECV_BUFFER_SIZE: int = 65535
SUPPORTED_UDP_PROBES: frozenset[str] = frozenset({"dns", "ntp", "snmp"})


class UDPPortState(str, Enum):
    """Possible outcomes for a scanned UDP port."""

    OPEN = "open"                     # Definite UDP application response received
    CLOSED = "closed"                 # Reliable ICMP port-unreachable received
    OPEN_FILTERED = "open_filtered"   # No response received before timeout (inconclusive / filtered)
    UNKNOWN = "unknown"               # Local or network error prevents classification


@dataclass(frozen=True)
class UDPScanResult:
    """Represents the scan result for a single UDP port.

    Attributes:
        port: The inspected UDP port number (1-65535).
        state: UDPPortState (OPEN, CLOSED, OPEN_FILTERED, or UNKNOWN).
        service: Likely service name from convention.
        reason: Diagnostic reason for the assigned state.
        response_bytes: Optional raw payload received from the target service.
        protocol_info: Optional validated protocol-specific metadata (DNS or NTP).
    """

    port: int
    state: UDPPortState
    service: str
    reason: str
    response_bytes: bytes | None = None
    protocol_info: UDPProtocolInfo | None = None


@dataclass(frozen=True)
class UDPScanSummary:
    """Aggregated statistics for a completed or interrupted UDP scan."""

    target: str
    total_ports: int
    open_count: int
    closed_count: int
    open_filtered_count: int
    unknown_count: int
    elapsed_seconds: float
    results: list[UDPScanResult]
    interrupted: bool = False
    resolved_target: str | None = None
    probe: str | None = None


class UDPScanInterruptedError(KeyboardInterrupt):
    """Raised when a UDP scan is interrupted by the operator, carrying partial results."""

    def __init__(self, summary: UDPScanSummary) -> None:
        super().__init__("UDP scan interrupted by operator")
        self.summary = summary


def probe_udp_port(
    target: str,
    port: int,
    timeout: float = 1.0,
    probe: str | None = None,
) -> UDPScanResult:
    """Perform a single UDP probe against a target port.

    Classification rules:
    - OPEN: A valid UDP response payload was received from the target.
    - CLOSED: A positive ICMP port-unreachable notification was received
      (ConnectionRefusedError, ConnectionResetError, or platform equivalent).
    - OPEN_FILTERED: No response arrived within the timeout budget.
      UDP is connectionless; non-response cannot prove whether the port is open
      (and the application remained silent) or filtered by an intermediate firewall.
    - UNKNOWN: Network unreachable, host unreachable, permission denied, or other
      unexpected OS/socket errors that prevent reliable determination.

    Args:
        target: Validated IPv4 target address.
        port: UDP port number (1-65535).
        timeout: Socket timeout in seconds.
        probe: Optional protocol probe ('dns' or 'ntp'). If None, sends a generic 0-byte datagram.

    Returns:
        UDPScanResult containing classification, protocol metadata, and diagnostics.
    """
    service = get_service_name(port)
    sock: socket.socket | None = None

    probe_norm = probe.strip().lower() if probe else None
    if probe_norm is not None and probe_norm not in SUPPORTED_UDP_PROBES:
        raise ValueError(f"Unsupported UDP probe '{probe}'. Supported probes: 'dns', 'ntp', 'snmp'.")

    # Build probe payload
    expected_tx_id: int | None = None
    expected_community: str | None = None
    if probe_norm == "dns":
        payload, expected_tx_id = build_dns_query()
    elif probe_norm == "ntp":
        payload = build_ntp_request()
    elif probe_norm == "snmp":
        expected_community = SNMP_DEFAULT_COMMUNITY
        payload, expected_tx_id = build_snmp_get_request(community=expected_community)
    else:
        payload = b""

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # On Windows (Winsock), enable ICMP Port Unreachable notification delivery
        # to connected UDP sockets via SIO_UDP_CONNRESET if supported.
        if hasattr(socket, "SIO_UDP_CONNRESET"):
            try:
                sock.ioctl(socket.SIO_UDP_CONNRESET, True)
            except Exception:
                pass

        sock.connect((target, port))
        sock.send(payload)

        # Wait for potential UDP response
        data = sock.recv(UDP_RECV_BUFFER_SIZE)

        # Evaluate application payload if protocol probe was selected
        protocol_info: UDPProtocolInfo | None = None
        if probe_norm == "dns":
            assert expected_tx_id is not None
            verified, details, meta = validate_dns_response(data, expected_tx_id)
            protocol_info = UDPProtocolInfo(
                protocol="dns",
                verified=verified,
                details=details,
                metadata=meta,
            )
            if verified:
                reason = f"Valid DNS response: {details}"
            elif meta.get("truncated"):
                reason = f"Received UDP response ({len(data)} bytes), but truncated DNS: {details}"
            else:
                reason = f"Received UDP response ({len(data)} bytes), but invalid DNS: {details}"

        elif probe_norm == "ntp":
            verified, details, meta = validate_ntp_response(data)
            protocol_info = UDPProtocolInfo(
                protocol="ntp",
                verified=verified,
                details=details,
                metadata=meta,
            )
            if verified:
                reason = f"Valid NTP response: {details}"
            else:
                reason = f"Received UDP response ({len(data)} bytes), but invalid NTP: {details}"

        elif probe_norm == "snmp":
            assert expected_tx_id is not None
            verified, details, meta = validate_snmp_response(
                data,
                expected_tx_id,
                expected_community=expected_community,
            )
            protocol_info = UDPProtocolInfo(
                protocol="snmp",
                verified=verified,
                details=details,
                metadata=meta,
            )
            if verified:
                reason = f"Valid SNMP response: {details}"
            else:
                reason = f"Received UDP response ({len(data)} bytes), but invalid SNMP: {details}"

        else:
            reason = f"Received UDP response ({len(data)} bytes)"

        return UDPScanResult(
            port=port,
            state=UDPPortState.OPEN,
            service=service,
            reason=reason,
            response_bytes=data,
            protocol_info=protocol_info,
        )

    except (socket.timeout, TimeoutError):
        if probe_norm == "dns":
            reason = "No DNS response received (open or filtered)"
        elif probe_norm == "ntp":
            reason = "No NTP response received (open or filtered)"
        elif probe_norm == "snmp":
            reason = "No SNMP response received (open or filtered)"
        else:
            reason = "No response received (open or filtered)"

        return UDPScanResult(
            port=port,
            state=UDPPortState.OPEN_FILTERED,
            service=service,
            reason=reason,
            protocol_info=None,
        )

    except (ConnectionRefusedError, ConnectionResetError) as exc:
        return UDPScanResult(
            port=port,
            state=UDPPortState.CLOSED,
            service=service,
            reason=f"ICMP port unreachable received ({exc.strerror or exc})",
            protocol_info=None,
        )

    except OSError as exc:
        err_code = exc.errno or getattr(exc, "winerror", None)
        if err_code in _PORT_UNREACHABLE_ERRNOS:
            return UDPScanResult(
                port=port,
                state=UDPPortState.CLOSED,
                service=service,
                reason=f"ICMP port unreachable received ({exc.strerror or exc})",
                protocol_info=None,
            )
        if err_code in _EMSGSIZE_ERRNOS:
            protocol_info: UDPProtocolInfo | None = None
            if probe_norm in SUPPORTED_UDP_PROBES:
                protocol_info = UDPProtocolInfo(
                    protocol=probe_norm,
                    verified=False,
                    details=f"Oversized {probe_norm.upper()} datagram received (unverified)",
                    metadata={"oversized": True},
                )
                reason = f"Received UDP response, but oversized {probe_norm.upper()}: exceeded buffer"
            else:
                reason = f"Received oversized UDP response ({exc.strerror or exc})"

            return UDPScanResult(
                port=port,
                state=UDPPortState.OPEN,
                service=service,
                reason=reason,
                response_bytes=None,
                protocol_info=protocol_info,
            )
        return UDPScanResult(
            port=port,
            state=UDPPortState.UNKNOWN,
            service=service,
            reason=f"Network or socket error ({exc.strerror or exc})",
            protocol_info=None,
        )

    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


class UDPScanner:
    """Thread-safe, bounded-concurrency UDP scanner for IPv4 targets."""

    MIN_TIMEOUT: float = 0.05
    MAX_TIMEOUT: float = 60.0
    MIN_WORKERS: int = 1
    MAX_WORKERS: int = 100
    DEFAULT_TIMEOUT: float = 1.0
    DEFAULT_WORKERS: int = 50

    def __init__(
        self,
        target: str,
        timeout: float = DEFAULT_TIMEOUT,
        max_workers: int = DEFAULT_WORKERS,
        display_target: str | None = None,
        probe: str | None = None,
    ) -> None:
        """Initialize UDPScanner.

        Args:
            target: Target IPv4 address.
            timeout: Socket timeout in seconds per probe.
            max_workers: Maximum concurrent worker threads (1-100).
            display_target: Optional original user-specified target hostname.
            probe: Optional protocol probe ('dns' or 'ntp').

        Raises:
            ValueError: If target, timeout, max_workers, or probe type are invalid.
        """
        self.target = validate_ipv4(target)
        self.display_target = display_target or self.target

        if not isinstance(timeout, (int, float)) or timeout < self.MIN_TIMEOUT or timeout > self.MAX_TIMEOUT:
            raise ValueError(
                f"Timeout must be between {self.MIN_TIMEOUT}s and {self.MAX_TIMEOUT}s (received {timeout})."
            )
        self.timeout = float(timeout)

        if not isinstance(max_workers, int) or max_workers < self.MIN_WORKERS or max_workers > self.MAX_WORKERS:
            raise ValueError(
                f"Workers must be an integer between {self.MIN_WORKERS} and {self.MAX_WORKERS} (received {max_workers})."
            )
        self.max_workers = max_workers

        if probe is not None:
            probe_norm = probe.strip().lower()
            if probe_norm not in SUPPORTED_UDP_PROBES:
                raise ValueError(
                    f"Unsupported UDP probe '{probe}'. Supported probes: 'dns', 'ntp', 'snmp'."
                )
            self.probe: str | None = probe_norm
        else:
            self.probe = None

    def scan(
        self,
        ports: Sequence[int],
        callback: Callable[[UDPScanResult], None] | None = None,
    ) -> UDPScanSummary:
        """Scan a sequence of UDP ports using bounded thread concurrency.

        Args:
            ports: Sequence of port integers.
            callback: Optional callback invoked with each UDPScanResult as completed.

        Returns:
            UDPScanSummary containing counts and ordered results.

        Raises:
            UDPScanInterruptedError: If interrupted by operator, carrying partial results.
            ValueError: If no ports are provided.
        """
        if not ports:
            raise ValueError("No ports provided to scan.")

        unique_ports = sorted(set(ports))
        results: list[UDPScanResult] = []
        start_time = time.perf_counter()

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers)
        try:
            if self.probe is not None:
                future_to_port = {
                    executor.submit(probe_udp_port, self.target, port, self.timeout, probe=self.probe): port
                    for port in unique_ports
                }
            else:
                future_to_port = {
                    executor.submit(probe_udp_port, self.target, port, self.timeout): port
                    for port in unique_ports
                }

            for future in concurrent.futures.as_completed(future_to_port):
                try:
                    result = future.result()
                except Exception as exc:
                    port = future_to_port[future]
                    result = UDPScanResult(
                        port=port,
                        state=UDPPortState.UNKNOWN,
                        service=get_service_name(port),
                        reason=f"Scan error ({exc})",
                    )
                results.append(result)
                if callback:
                    callback(result)

        except KeyboardInterrupt:
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass

            try:
                elapsed = time.perf_counter() - start_time
                results.sort(key=lambda r: r.port)
                open_cnt = sum(1 for r in results if r.state == UDPPortState.OPEN)
                closed_cnt = sum(1 for r in results if r.state == UDPPortState.CLOSED)
                of_cnt = sum(1 for r in results if r.state == UDPPortState.OPEN_FILTERED)
                unk_cnt = sum(1 for r in results if r.state == UDPPortState.UNKNOWN)

                partial_summary = UDPScanSummary(
                    target=self.display_target,
                    total_ports=len(unique_ports),
                    open_count=open_cnt,
                    closed_count=closed_cnt,
                    open_filtered_count=of_cnt,
                    unknown_count=unk_cnt,
                    elapsed_seconds=elapsed,
                    results=results,
                    interrupted=True,
                    resolved_target=self.target,
                    probe=self.probe,
                )
            except KeyboardInterrupt:
                results.sort(key=lambda r: r.port)
                partial_summary = UDPScanSummary(
                    target=self.display_target,
                    total_ports=len(unique_ports),
                    open_count=sum(1 for r in results if r.state == UDPPortState.OPEN),
                    closed_count=sum(1 for r in results if r.state == UDPPortState.CLOSED),
                    open_filtered_count=sum(1 for r in results if r.state == UDPPortState.OPEN_FILTERED),
                    unknown_count=sum(1 for r in results if r.state == UDPPortState.UNKNOWN),
                    elapsed_seconds=time.perf_counter() - start_time,
                    results=results,
                    interrupted=True,
                    resolved_target=self.target,
                    probe=self.probe,
                )

            raise UDPScanInterruptedError(partial_summary)

        finally:
            try:
                executor.shutdown(wait=False)
            except Exception:
                pass

        elapsed = time.perf_counter() - start_time
        results.sort(key=lambda r: r.port)
        return UDPScanSummary(
            target=self.display_target,
            total_ports=len(unique_ports),
            open_count=sum(1 for r in results if r.state == UDPPortState.OPEN),
            closed_count=sum(1 for r in results if r.state == UDPPortState.CLOSED),
            open_filtered_count=sum(1 for r in results if r.state == UDPPortState.OPEN_FILTERED),
            unknown_count=sum(1 for r in results if r.state == UDPPortState.UNKNOWN),
            elapsed_seconds=elapsed,
            results=results,
            interrupted=False,
            resolved_target=self.target,
            probe=self.probe,
        )
