"""Core networking, parsing, and TCP scanning logic for NetProbe."""

import concurrent.futures
from dataclasses import dataclass
from enum import Enum
import ipaddress
import socket
import time
from typing import Callable, Iterable, Sequence

from netprobe.fingerprint.models import ServiceInfo
from netprobe.services import get_service_name


class PortState(str, Enum):
    """Possible outcomes for a scanned TCP port."""

    OPEN = "open"
    CLOSED = "closed"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ScanResult:
    """Represents the scan result for a single TCP port.

    Attributes:
        port: The inspected TCP port number.
        state: PortState (OPEN, CLOSED, or UNKNOWN).
        service: Likely service name from convention (does not guarantee service identity).
        reason: Diagnostic reason for the assigned state.
        service_info: Optional verified application-layer metadata from fingerprinting.
    """

    port: int
    state: PortState
    service: str
    reason: str
    service_info: ServiceInfo | None = None


@dataclass(frozen=True)
class ScanSummary:
    """Aggregated statistics for a completed or interrupted scan."""

    target: str
    total_ports: int
    open_count: int
    closed_count: int
    unknown_count: int
    elapsed_seconds: float
    results: list[ScanResult]
    interrupted: bool = False
    resolved_target: str | None = None


class ScanInterruptedError(KeyboardInterrupt):
    """Raised when a scan is interrupted by the operator, preserving completed results."""

    def __init__(self, summary: ScanSummary) -> None:
        super().__init__("Scan interrupted by operator")
        self.summary = summary


def validate_ipv4(target: str) -> str:
    """Validate that the target is a valid single IPv4 address.

    Args:
        target: Target IP string to validate.

    Returns:
        Normalized IPv4 address string.

    Raises:
        ValueError: If target is not a valid IPv4 address or is a hostname/IPv6.
    """
    cleaned = (target or "").strip()
    if not cleaned:
        raise ValueError("Target IPv4 address cannot be empty.")

    try:
        ip = ipaddress.ip_address(cleaned)
    except ValueError as exc:
        raise ValueError(
            f"Invalid IPv4 address '{cleaned}'. NetProbe Phase 1 requires a single IPv4 address "
            "(hostnames and CIDR ranges are not permitted)."
        ) from exc

    if not isinstance(ip, ipaddress.IPv4Address):
        raise ValueError(
            f"Target '{cleaned}' is an IPv6 address. NetProbe Phase 1 only supports IPv4 targets."
        )

    return str(ip)


def resolve_target(target: str) -> tuple[str, str]:
    """Resolve a target hostname or IPv4 literal to a canonical IPv4 address.

    Requirements:
    1. A valid IPv4 address literal is used directly without invoking DNS resolution.
    2. IPv6 literals (e.g. '::1') are rejected with a clear message.
    3. Hostnames resolve to an IPv4 address using standard-library getaddrinfo.
    4. If a hostname resolves to multiple addresses (including IPv6), IPv4 is selected
       deterministically (the first IPv4 address returned by getaddrinfo).
    5. If a hostname resolves only to IPv6, it is rejected explaining IPv6 is unsupported.
    6. Resolver errors (gaierror/herror) raise ValueError with diagnostic context.

    Args:
        target: Target hostname or IPv4 literal.

    Returns:
        tuple[str, str]: (original_target, resolved_ipv4)

    Raises:
        ValueError: If target is empty, malformed, resolves only to IPv6, or fails DNS resolution.
    """
    cleaned = (target or "").strip()
    if not cleaned:
        raise ValueError("Target address cannot be empty.")

    # 1. Fast path: check if target is an IP literal
    try:
        ip = ipaddress.ip_address(cleaned)
    except ValueError:
        ip = None

    if ip is not None:
        if isinstance(ip, ipaddress.IPv4Address):
            return cleaned, str(ip)
        raise ValueError(
            f"Target '{cleaned}' is an IPv6 address. NetProbe only supports IPv4 scanning."
        )


    # 2. Hostname resolution path via socket.getaddrinfo
    try:
        # Query both AF_UNSPEC to detect if host exists and whether it has IPv4 vs IPv6-only
        addr_infos = socket.getaddrinfo(cleaned, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Failed to resolve target '{cleaned}': {exc.strerror or exc}") from exc
    except socket.herror as exc:
        raise ValueError(f"Host error resolving target '{cleaned}': {exc.strerror or exc}") from exc
    except OSError as exc:
        raise ValueError(f"System error resolving target '{cleaned}': {exc}") from exc

    if not addr_infos:
        raise ValueError(f"No address records found for target '{cleaned}'.")

    # Filter for first IPv4 address deterministically
    first_ipv4: str | None = None
    has_ipv6: bool = False

    for family, _socktype, _proto, _canonname, sockaddr in addr_infos:
        if family == socket.AF_INET and sockaddr:
            ip_str = sockaddr[0]
            if first_ipv4 is None:
                first_ipv4 = ip_str
        elif family == socket.AF_INET6:
            has_ipv6 = True

    if first_ipv4 is not None:
        return cleaned, first_ipv4

    if has_ipv6:
        raise ValueError(
            f"Target '{cleaned}' resolved only to IPv6 address(es). NetProbe only supports IPv4 scanning."
        )

    raise ValueError(f"Failed to resolve target '{cleaned}' to a valid IPv4 address.")



def parse_ports(ports_spec: str) -> list[int]:
    """Parse and validate a port specification string.

    Supports individual ports, comma-separated ports, and ranges (e.g. '22,80,443,8000-8100').
    Port numbers must be between 1 and 65535.
    Returns a sorted, deduplicated list of port integers.

    Args:
        ports_spec: Port specification string.

    Returns:
        Sorted list of unique port integers.

    Raises:
        ValueError: If the specification is empty, malformed, or contains invalid port numbers.
    """
    if not ports_spec or not ports_spec.strip():
        raise ValueError("Port specification cannot be empty.")

    cleaned_spec = ports_spec.strip()

    # Reject malformed empty tokens caused by leading, trailing, or consecutive commas
    raw_tokens = cleaned_spec.split(",")
    for raw_token in raw_tokens:
        if not raw_token.strip():
            raise ValueError(
                f"Malformed port specification '{ports_spec}': contains empty token or consecutive commas."
            )

    # Safety check: avoid processing unreasonable token counts
    if len(raw_tokens) > 65535:
        raise ValueError("Port specification exceeds maximum allowed elements (65535).")

    parsed_ports: set[int] = set()

    for raw_token in raw_tokens:
        token = raw_token.strip()
        if "-" in token:
            parts = token.split("-")
            if len(parts) != 2:
                raise ValueError(
                    f"Invalid range format '{token}'. Expected 'start-end' (e.g. '8000-8100')."
                )
            start_str, end_str = parts[0].strip(), parts[1].strip()

            if not start_str or not end_str:
                raise ValueError(
                    f"Port range '{token}' is missing boundary values."
                )

            if len(start_str) > 5 or len(end_str) > 5:
                raise ValueError(
                    f"Port range boundaries in '{token}' cannot exceed 5 digits."
                )

            if not start_str.isdigit() or not end_str.isdigit():
                raise ValueError(
                    f"Port range boundaries in '{token}' must be positive integers."
                )

            start = int(start_str)
            end = int(end_str)

            if start > end:
                raise ValueError(
                    f"Invalid range '{token}': start port {start} is greater than end port {end}."
                )

            if start < 1 or end > 65535:
                raise ValueError(
                    f"Port range '{token}' falls outside the valid TCP range (1-65535)."
                )

            # Add all ports in range
            parsed_ports.update(range(start, end + 1))
        else:
            if len(token) > 5:
                raise ValueError(
                    f"Invalid port '{token}'. TCP port numbers cannot exceed 5 digits."
                )

            if not token.isdigit():
                raise ValueError(
                    f"Invalid port '{token}'. Ports must be integer values between 1 and 65535."
                )

            port = int(token)
            if port < 1 or port > 65535:
                raise ValueError(
                    f"Port {port} is out of range. TCP ports must be between 1 and 65535."
                )

            parsed_ports.add(port)

    if not parsed_ports:
        raise ValueError("No valid ports parsed from specification.")

    return sorted(parsed_ports)


def scan_single_port(target: str, port: int, timeout: float = 1.0) -> ScanResult:
    """Perform a TCP connect scan against a single port.

    Distinguishes OPEN (SYN/ACK), CLOSED (RST), and UNKNOWN (timeout/filtered/unreachable/error).
    Guarantees proper socket cleanup even if socket creation or configuration fails.

    Args:
        target: Validated IPv4 target address.
        port: TCP port to scan (1-65535).
        timeout: Socket timeout in seconds.

    Returns:
        ScanResult detailing state, service mapping, and reason.
    """
    service = get_service_name(port)
    sock: socket.socket | None = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        return ScanResult(
            port=port,
            state=PortState.OPEN,
            service=service,
            reason="Connection established",
        )
    except ConnectionRefusedError:
        return ScanResult(
            port=port,
            state=PortState.CLOSED,
            service=service,
            reason="Connection refused (RST)",
        )
    except (socket.timeout, TimeoutError):
        return ScanResult(
            port=port,
            state=PortState.UNKNOWN,
            service=service,
            reason="Timed out (filtered / dropped / no response)",
        )
    except OSError as exc:
        # Handles host unreachable, network unreachable, and socket descriptor exhaustion (EMFILE/ENFILE)
        return ScanResult(
            port=port,
            state=PortState.UNKNOWN,
            service=service,
            reason=f"Network error ({exc.strerror or exc})",
        )
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


class TCPScanner:
    """Thread-safe, bounded-concurrency TCP connect scanner for IPv4 targets."""

    MIN_TIMEOUT: float = 0.05
    MAX_TIMEOUT: float = 60.0
    MIN_WORKERS: int = 1
    MAX_WORKERS: int = 500

    def __init__(
        self,
        target: str,
        timeout: float = 1.0,
        max_workers: int = 100,
        display_target: str | None = None,
    ) -> None:
        """Initialize the scanner.

        Args:
            target: Target IPv4 address.
            timeout: Connection timeout in seconds.
            max_workers: Bounded number of concurrent worker threads.
            display_target: Optional original user-specified target (e.g. hostname).

        Raises:
            ValueError: If target, timeout, or max_workers are invalid.
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

    def scan(
        self,
        ports: Sequence[int],
        callback: Callable[[ScanResult], None] | None = None,
    ) -> ScanSummary:
        """Scan a collection of TCP ports using bounded thread concurrency.

        Args:
            ports: Sequence of port integers.
            callback: Optional callback invoked with each ScanResult as it completes.

        Returns:
            ScanSummary with aggregated counts and sorted results.

        Raises:
            ScanInterruptedError: If interrupted by operator (Ctrl+C), carrying partial results.
            ValueError: If no ports are provided.

        Note on Cancellation:
            When cancelled via KeyboardInterrupt, executor.shutdown(wait=False, cancel_futures=True)
            is executed immediately. Queued futures that have not started are cancelled. Active socket
            operations in running threads may continue until their finite connection timeouts expire;
            they are not abruptly terminated to avoid resource corruption. Results completed prior to
            the interrupt are preserved in ScanInterruptedError.summary.
        """
        if not ports:
            raise ValueError("No ports provided to scan.")

        # Ensure ports are valid and sorted
        unique_ports = sorted(set(ports))
        results: list[ScanResult] = []
        start_time = time.perf_counter()

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers)
        try:
            future_to_port = {
                executor.submit(scan_single_port, self.target, port, self.timeout): port
                for port in unique_ports
            }

            for future in concurrent.futures.as_completed(future_to_port):
                try:
                    result = future.result()
                except Exception as exc:
                    port = future_to_port[future]
                    result = ScanResult(
                        port=port,
                        state=PortState.UNKNOWN,
                        service=get_service_name(port),
                        reason=f"Scan error ({exc})",
                    )
                results.append(result)
                if callback:
                    callback(result)
        except KeyboardInterrupt:
            # Immediate cancellation of queued futures without context-manager blocking wait
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass

            try:
                elapsed = time.perf_counter() - start_time
                results.sort(key=lambda r: r.port)
                open_cnt = sum(1 for r in results if r.state == PortState.OPEN)
                closed_cnt = sum(1 for r in results if r.state == PortState.CLOSED)
                unknown_cnt = sum(1 for r in results if r.state == PortState.UNKNOWN)
                partial_summary = ScanSummary(
                    target=self.display_target,
                    total_ports=len(unique_ports),
                    open_count=open_cnt,
                    closed_count=closed_cnt,
                    unknown_count=unknown_cnt,
                    elapsed_seconds=elapsed,
                    results=results,
                    interrupted=True,
                    resolved_target=self.target,
                )
            except KeyboardInterrupt:
                # If a second interrupt arrives during summary aggregation, build best-effort summary
                partial_summary = ScanSummary(
                    target=self.display_target,
                    total_ports=len(unique_ports),
                    open_count=sum(1 for r in results if r.state == PortState.OPEN),
                    closed_count=sum(1 for r in results if r.state == PortState.CLOSED),
                    unknown_count=sum(1 for r in results if r.state == PortState.UNKNOWN),
                    elapsed_seconds=time.perf_counter() - start_time,
                    results=sorted(results, key=lambda r: r.port),
                    interrupted=True,
                    resolved_target=self.target,
                )

            raise ScanInterruptedError(partial_summary)
        except Exception:
            executor.shutdown(wait=False, cancel_futures=True)
            raise
        else:
            # Clean shutdown on normal completion
            executor.shutdown(wait=True)

        elapsed = time.perf_counter() - start_time
        # Sort results deterministically by port number
        results.sort(key=lambda r: r.port)

        open_cnt = sum(1 for r in results if r.state == PortState.OPEN)
        closed_cnt = sum(1 for r in results if r.state == PortState.CLOSED)
        unknown_cnt = sum(1 for r in results if r.state == PortState.UNKNOWN)

        return ScanSummary(
            target=self.display_target,
            total_ports=len(results),
            open_count=open_cnt,
            closed_count=closed_cnt,
            unknown_count=unknown_cnt,
            elapsed_seconds=elapsed,
            results=results,
            interrupted=False,
            resolved_target=self.target,
        )
