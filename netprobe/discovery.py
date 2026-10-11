"""Data models, validation, and scanning engine for NetProbe Phase 3 device discovery."""

import concurrent.futures
from dataclasses import dataclass
from enum import Enum
import errno
import ipaddress
import socket
import time
from typing import Sequence

from netprobe.scanner import PortState

# Common errno codes representing explicit network or host unreachability
_UNREACHABLE_ERRNOS: frozenset[int] = frozenset(
    code
    for name in (
        "EHOSTUNREACH",
        "ENETUNREACH",
        "EHOSTDOWN",
        "ENETDOWN",
        "WSAEHOSTUNREACH",
        "WSAENETUNREACH",
        "WSAEHOSTDOWN",
        "WSAENETDOWN",
    )
    if (code := getattr(errno, name, None)) is not None
)

DEFAULT_SWEEP_PORTS: tuple[int, ...] = (80, 443, 22, 445)


class HostReachability(str, Enum):
    """Classification of host responsiveness based on TCP probes."""

    TCP_RESPONSIVE = "tcp_responsive"  # Active TCP stack replied (SYN-ACK or RST)
    NO_RESPONSE = "no_response"        # All probes timed out / filtered (inconclusive)
    UNREACHABLE = "unreachable"        # Network or host unreachable error


@dataclass(frozen=True)
class DiscoveredHost:
    """Immutable reachability assessment for a single IP address."""

    ip: str
    status: HostReachability
    responsive_port: int | None
    responsive_state: PortState | None
    tested_ports: tuple[int, ...]
    hostname: str | None = None
    reason: str = ""


@dataclass(frozen=True)
class DiscoverySummary:
    """Aggregated statistics for a completed or interrupted subnet discovery."""

    network: str
    total_candidates: int
    responsive_count: int
    no_response_count: int
    unreachable_count: int
    elapsed_seconds: float
    hosts: tuple[DiscoveredHost, ...]
    interrupted: bool = False
    sweep_ports: tuple[int, ...] = DEFAULT_SWEEP_PORTS


class DiscoveryInterruptedError(KeyboardInterrupt):
    """Raised when subnet discovery is interrupted by the operator, carrying partial results."""

    def __init__(self, summary: DiscoverySummary) -> None:
        super().__init__("Discovery scan interrupted by operator")
        self.summary = summary


def parse_cidr(value: str) -> ipaddress.IPv4Network:
    """Parse and validate an IPv4 CIDR string into an IPv4Network.

    Requirements:
    - Must be valid IPv4 CIDR notation with explicit '/' prefix.
    - Rejects IPv6, non-CIDR strings, and malformed IP/prefix values.
    - Limits maximum network size to 256 addresses (prefix length >= 24, e.g. /24 through /32).
    - Normalizes host addresses with prefixes (e.g. '192.168.1.50/24') to the containing
      network ('192.168.1.0/24') using strict=False.
    - Correctly accepts /31 (2 addresses) and /32 (1 address).

    Args:
        value: IPv4 CIDR notation string (e.g. '192.168.1.0/24').

    Returns:
        ipaddress.IPv4Network instance.

    Raises:
        ValueError: If value is empty, not IPv4, missing a prefix, invalid syntax,
            or specifies a network larger than 256 addresses.
    """
    cleaned = (value or "").strip()
    if not cleaned:
        raise ValueError("CIDR specification cannot be empty.")

    if "/" not in cleaned:
        raise ValueError(
            f"Invalid CIDR notation '{cleaned}': missing prefix length (expected format: 'IP/prefix', e.g. '192.168.1.0/24')."
        )

    # Validate syntax and construct network
    try:
        network = ipaddress.ip_network(cleaned, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR specification '{cleaned}': {exc}") from exc

    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError(
            f"Network '{cleaned}' is an IPv6 network. NetProbe only supports IPv4 networks."
        )

    # Enforce safe network size ceiling: max 256 addresses (/24 through /32)
    # In IPv4, num_addresses = 2 ** (32 - prefixlen).
    # /24 has 256 addresses. /23 has 512 addresses.
    if network.num_addresses > 256:
        raise ValueError(
            f"Network '{cleaned}' contains {network.num_addresses} addresses, which exceeds "
            f"the maximum allowed subnet size of 256 addresses (/24)."
        )

    return network


def parse_sweep_ports(value: str) -> tuple[int, ...]:
    """Parse a comma-separated list of TCP discovery ports.

    Requirements:
    - Accepts integers between 1 and 65535.
    - Preserves input ordering while removing duplicates (keeps first occurrence).
    - Rejects empty input, empty tokens, non-integers, and out-of-range ports.

    Args:
        value: Comma-separated port specification (e.g. '80,443,22,80').

    Returns:
        tuple[int, ...] of unique port numbers in original order.

    Raises:
        ValueError: If value is empty, contains empty tokens, or has invalid ports.
    """
    if not value or not value.strip():
        raise ValueError("Sweep port specification cannot be empty.")

    cleaned = value.strip()
    tokens = cleaned.split(",")

    seen: set[int] = set()
    result: list[int] = []

    for raw_token in tokens:
        token = raw_token.strip()
        if not token:
            raise ValueError(
                f"Malformed sweep port specification '{value}': contains empty token or consecutive commas."
            )

        if not token.isdigit():
            raise ValueError(
                f"Invalid sweep port '{token}': must be an integer between 1 and 65535."
            )

        port = int(token)
        if port < 1 or port > 65535:
            raise ValueError(
                f"Sweep port {port} is out of range. TCP ports must be between 1 and 65535."
            )

        if port not in seen:
            seen.add(port)
            result.append(port)

    return tuple(result)


def probe_single_tcp_port(
    ip: str, port: int, timeout: float
) -> tuple[PortState | str, str]:
    """Probe a single TCP port on a target IP address.

    Args:
        ip: Target IPv4 address.
        port: TCP port to test.
        timeout: Socket connection timeout in seconds.

    Returns:
        tuple: (outcome, reason)
        Outcome is one of:
        - PortState.OPEN: connection established (SYN-ACK)
        - PortState.CLOSED: connection refused (RST)
        - 'TIMEOUT': socket connection timed out
        - 'UNREACHABLE': host/network unreachable (OS error with unreachable errno)

    Raises:
        OSError: Unexpected local socket error not attributable to reachability or timeout.
    """
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        return PortState.OPEN, "Connection established"
    except ConnectionRefusedError:
        return PortState.CLOSED, "Connection refused (RST)"
    except (socket.timeout, TimeoutError):
        return "TIMEOUT", "Timed out"
    except OSError as exc:
        err_code = exc.errno or getattr(exc, "winerror", None)
        if err_code in _UNREACHABLE_ERRNOS:
            return "UNREACHABLE", f"Unreachable ({exc.strerror or exc})"
        # Re-raise unexpected local socket errors (e.g. EMFILE, EPERM, ENOMEM, etc.)
        raise
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def probe_candidate_host(
    ip: str, sweep_ports: Sequence[int], timeout: float
) -> DiscoveredHost:
    """Probe a candidate host across an ordered sequence of discovery ports with fast-exit.

    Probes ports sequentially:
    1. Stops immediately on the first convincing response:
       - PortState.OPEN -> TCP_RESPONSIVE (responsive_state=OPEN)
       - PortState.CLOSED -> TCP_RESPONSIVE (responsive_state=CLOSED)
    2. If no port responds:
       - If at least one port timed out -> NO_RESPONSE (inconclusive)
       - If all ports produced unreachable errors -> UNREACHABLE

    Args:
        ip: Target IPv4 address.
        sweep_ports: Ordered sequence of port numbers.
        timeout: Socket timeout per port in seconds.

    Returns:
        DiscoveredHost with tested ports, final reachability status, and responsive details.

    Raises:
        OSError: If an unexpected local socket error occurs.
    """
    tested_ports: list[int] = []
    has_timeout = False
    all_unreachable = True
    last_unreachable_reason = ""

    for port in sweep_ports:
        tested_ports.append(port)
        outcome, reason = probe_single_tcp_port(ip, port, timeout)

        if outcome == PortState.OPEN:
            return DiscoveredHost(
                ip=ip,
                status=HostReachability.TCP_RESPONSIVE,
                responsive_port=port,
                responsive_state=PortState.OPEN,
                tested_ports=tuple(tested_ports),
                reason=f"Connection established on port {port}",
            )
        if outcome == PortState.CLOSED:
            return DiscoveredHost(
                ip=ip,
                status=HostReachability.TCP_RESPONSIVE,
                responsive_port=port,
                responsive_state=PortState.CLOSED,
                tested_ports=tuple(tested_ports),
                reason=f"Connection refused (RST) on port {port}",
            )

        if outcome == "TIMEOUT":
            has_timeout = True
            all_unreachable = False
        elif outcome == "UNREACHABLE":
            last_unreachable_reason = reason
        else:
            all_unreachable = False

    # Classification when no port established or refused connection:
    # Rule: If at least one probe timed out, classify as NO_RESPONSE (inconclusive).
    # Rule: If all probes produced unreachable errors, classify as UNREACHABLE.
    if has_timeout or not all_unreachable:
        return DiscoveredHost(
            ip=ip,
            status=HostReachability.NO_RESPONSE,
            responsive_port=None,
            responsive_state=None,
            tested_ports=tuple(tested_ports),
            reason="Timed out on tested discovery ports (inconclusive)",
        )

    return DiscoveredHost(
        ip=ip,
        status=HostReachability.UNREACHABLE,
        responsive_port=None,
        responsive_state=None,
        tested_ports=tuple(tested_ports),
        reason=last_unreachable_reason or "Network or host unreachable",
    )


def resolve_reverse_dns(ip: str) -> str | None:
    """Perform reverse DNS lookup for an IPv4 address.

    Args:
        ip: IPv4 address string.

    Returns:
        Canonical hostname string if reverse DNS resolution succeeds, or None if resolution
        fails or produces an empty name.

    Note:
        Standard library `socket.gethostbyaddr` relies on the underlying OS resolver.
        Common resolver errors (herror, gaierror, timeout, OSError) return None safely
        without raising exceptions or altering host reachability status.
    """
    try:
        hostname, _aliases, _ipaddrs = socket.gethostbyaddr(ip)
        cleaned = (hostname or "").strip()
        return cleaned if cleaned else None
    except (socket.herror, socket.gaierror, socket.timeout, TimeoutError, OSError):
        return None


class SubnetScanner:
    """Thread-safe, bounded-concurrency TCP discovery scanner for IPv4 subnets."""

    MIN_TIMEOUT: float = 0.05
    MAX_TIMEOUT: float = 60.0
    MIN_WORKERS: int = 1
    MAX_WORKERS: int = 100
    DEFAULT_TIMEOUT: float = 0.5
    DEFAULT_WORKERS: int = 50

    def __init__(
        self,
        network: str | ipaddress.IPv4Network,
        sweep_ports: str | Sequence[int] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_workers: int = DEFAULT_WORKERS,
        resolve_hostnames: bool = False,
    ) -> None:
        """Initialize SubnetScanner.

        Args:
            network: IPv4Network instance or CIDR notation string (e.g. '192.168.1.0/24').
            sweep_ports: Port specification string ('80,443') or sequence of port integers.
            timeout: Socket timeout in seconds per connection attempt.
            max_workers: Maximum number of concurrent host worker threads (1-100).
            resolve_hostnames: If True, perform reverse DNS lookup for discovered hosts. Default False.

        Raises:
            ValueError: If network exceeds 256 addresses, or if timeout/workers/ports/resolve_hostnames are invalid.
        """
        if isinstance(network, ipaddress.IPv4Network):
            if network.num_addresses > 256:
                raise ValueError(
                    f"Network '{network}' contains {network.num_addresses} addresses, which exceeds "
                    f"the maximum allowed subnet size of 256 addresses (/24)."
                )
            self.network = network
        elif isinstance(network, str):
            self.network = parse_cidr(network)
        else:
            raise ValueError(f"Invalid network type '{type(network).__name__}': expected str or IPv4Network.")

        if sweep_ports is None:
            self.sweep_ports: tuple[int, ...] = DEFAULT_SWEEP_PORTS
        elif isinstance(sweep_ports, str):
            self.sweep_ports = parse_sweep_ports(sweep_ports)
        else:
            ports_list: list[int] = []
            seen: set[int] = set()
            for p in sweep_ports:
                if not isinstance(p, int) or p < 1 or p > 65535:
                    raise ValueError(f"Invalid sweep port '{p}': must be an integer between 1 and 65535.")
                if p not in seen:
                    seen.add(p)
                    ports_list.append(p)
            if not ports_list:
                raise ValueError("Sweep ports cannot be empty.")
            self.sweep_ports = tuple(ports_list)

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

        if not isinstance(resolve_hostnames, bool):
            raise ValueError(
                f"resolve_hostnames must be a boolean (received {type(resolve_hostnames).__name__})."
            )
        self.resolve_hostnames = resolve_hostnames

    def _resolve_hostnames_for_hosts(
        self, hosts: list[DiscoveredHost]
    ) -> list[DiscoveredHost]:
        """Perform reverse DNS lookups on completed host results in parallel.

        Args:
            hosts: List of DiscoveredHost instances.

        Returns:
            List of DiscoveredHost instances with hostname populated where resolution succeeded.

        Note on Cancellation:
            When cancelled via KeyboardInterrupt, executor.shutdown(wait=False, cancel_futures=True)
            cancels queued lookup futures. However, in-flight socket.gethostbyaddr() OS resolver
            system calls in running worker threads cannot be forcibly killed by Python threads.
            These active lookups will run until their underlying OS resolver timeout expires, which
            may briefly delay Python interpreter exit. Completed DNS lookups are harvested and
            retained in the resulting DiscoveredHost instances upon interruption.
        """
        if not self.resolve_hostnames or not hosts:
            return hosts

        # Bounded concurrency for DNS resolution
        dns_pool_size = max(1, min(len(hosts), self.max_workers))
        resolved_hosts_map: dict[str, str | None] = {}

        dns_executor = concurrent.futures.ThreadPoolExecutor(max_workers=dns_pool_size)
        try:
            future_to_ip = {
                dns_executor.submit(resolve_reverse_dns, h.ip): h.ip
                for h in hosts
            }
            for fut in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[fut]
                try:
                    resolved_hosts_map[ip] = fut.result()
                except Exception:
                    resolved_hosts_map[ip] = None
        except KeyboardInterrupt:
            # Immediate non-blocking cancellation of unstarted lookups
            try:
                dns_executor.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass

            # Harvest completed DNS futures that finished before or during interruption
            for fut, ip in future_to_ip.items():
                if ip not in resolved_hosts_map and fut.done() and not fut.cancelled():
                    try:
                        if fut.exception() is None:
                            resolved_hosts_map[ip] = fut.result()
                    except Exception:
                        pass

            # Reconstruct DiscoveredHost instances preserving partial DNS lookups
            partial_hosts: list[DiscoveredHost] = []
            for h in hosts:
                hostname = resolved_hosts_map.get(h.ip)
                if hostname is not None:
                    partial_hosts.append(
                        DiscoveredHost(
                            ip=h.ip,
                            status=h.status,
                            responsive_port=h.responsive_port,
                            responsive_state=h.responsive_state,
                            tested_ports=h.tested_ports,
                            hostname=hostname,
                            reason=h.reason,
                        )
                    )
                else:
                    partial_hosts.append(h)

            hosts[:] = partial_hosts
            raise
        except Exception:
            dns_executor.shutdown(wait=False, cancel_futures=True)
            # Resolver failures should not fail the scan; fall back to unpopulated
            return hosts
        else:
            dns_executor.shutdown(wait=True)

        # Reconstruct immutable DiscoveredHost instances preserving original fields
        updated_hosts: list[DiscoveredHost] = []
        for h in hosts:
            hostname = resolved_hosts_map.get(h.ip)
            if hostname is not None:
                updated_hosts.append(
                    DiscoveredHost(
                        ip=h.ip,
                        status=h.status,
                        responsive_port=h.responsive_port,
                        responsive_state=h.responsive_state,
                        tested_ports=h.tested_ports,
                        hostname=hostname,
                        reason=h.reason,
                    )
                )
            else:
                updated_hosts.append(h)

        return updated_hosts

    def scan(self) -> DiscoverySummary:
        """Perform concurrent discovery sweep across candidate hosts in the subnet.

        Enumerates hosts using IPv4Network.hosts(), preserving correct candidate semantics
        for /31 and /32 networks.

        Uses bounded concurrency at the host level: each worker thread probes one host's ports.
        Optionally resolves hostnames via reverse DNS when resolve_hostnames is True.

        Returns:
            DiscoverySummary with deterministic IP-sorted hosts and aggregated counts.

        Raises:
            DiscoveryInterruptedError: If interrupted by operator (Ctrl+C), carrying completed results.
            Exception: If an unexpected error occurs during worker execution.
        """
        candidate_ips = [str(ip) for ip in self.network.hosts()]
        total_candidates = len(candidate_ips)

        if total_candidates == 0:
            return DiscoverySummary(
                network=str(self.network),
                total_candidates=0,
                responsive_count=0,
                no_response_count=0,
                unreachable_count=0,
                elapsed_seconds=0.0,
                hosts=(),
                interrupted=False,
                sweep_ports=self.sweep_ports,
            )

        start_time = time.monotonic()
        completed_hosts: list[DiscoveredHost] = []

        pool_size = max(1, min(total_candidates, self.max_workers))
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=pool_size)

        try:
            future_to_ip = {
                executor.submit(probe_candidate_host, ip, self.sweep_ports, self.timeout): ip
                for ip in candidate_ips
            }

            for future in concurrent.futures.as_completed(future_to_ip):
                host_result = future.result()
                completed_hosts.append(host_result)

        except KeyboardInterrupt:
            # Immediate shutdown of queued tasks; running socket operations finish within finite timeout
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass

            # Harvest completed futures that were finished but not yet gathered from as_completed
            collected_ips = {h.ip for h in completed_hosts}
            for fut, target_ip in future_to_ip.items():
                if target_ip not in collected_ips and fut.done() and not fut.cancelled():
                    try:
                        # Only collect if no exception occurred during probe
                        fut_exc = fut.exception()
                        if fut_exc is None:
                            host_res = fut.result()
                            completed_hosts.append(host_res)
                            collected_ips.add(host_res.ip)
                    except Exception:
                        # Do not allow worker exception during cleanup to replace the interruption
                        pass

            try:
                elapsed = max(0.0, time.monotonic() - start_time)
                # Sort deterministically by IPv4 address
                completed_hosts.sort(key=lambda h: ipaddress.IPv4Address(h.ip))

                resp_cnt = sum(1 for h in completed_hosts if h.status == HostReachability.TCP_RESPONSIVE)
                no_resp_cnt = sum(1 for h in completed_hosts if h.status == HostReachability.NO_RESPONSE)
                unreach_cnt = sum(1 for h in completed_hosts if h.status == HostReachability.UNREACHABLE)

                partial_summary = DiscoverySummary(
                    network=str(self.network),
                    total_candidates=total_candidates,
                    responsive_count=resp_cnt,
                    no_response_count=no_resp_cnt,
                    unreachable_count=unreach_cnt,
                    elapsed_seconds=elapsed,
                    hosts=tuple(completed_hosts),
                    interrupted=True,
                    sweep_ports=self.sweep_ports,
                )
            except KeyboardInterrupt:
                # If a second interrupt arrives during summary aggregation, build best-effort summary
                partial_summary = DiscoverySummary(
                    network=str(self.network),
                    total_candidates=total_candidates,
                    responsive_count=sum(1 for h in completed_hosts if h.status == HostReachability.TCP_RESPONSIVE),
                    no_response_count=sum(1 for h in completed_hosts if h.status == HostReachability.NO_RESPONSE),
                    unreachable_count=sum(1 for h in completed_hosts if h.status == HostReachability.UNREACHABLE),
                    elapsed_seconds=max(0.0, time.monotonic() - start_time),
                    hosts=tuple(sorted(completed_hosts, key=lambda h: ipaddress.IPv4Address(h.ip))),
                    interrupted=True,
                    sweep_ports=self.sweep_ports,
                )

            raise DiscoveryInterruptedError(partial_summary)

        except Exception:
            executor.shutdown(wait=False, cancel_futures=True)
            raise

        else:
            executor.shutdown(wait=True)

        # If resolve_hostnames is enabled, resolve reverse DNS for completed hosts
        if self.resolve_hostnames and completed_hosts:
            try:
                completed_hosts = self._resolve_hostnames_for_hosts(completed_hosts)
            except KeyboardInterrupt:
                elapsed = max(0.0, time.monotonic() - start_time)
                completed_hosts.sort(key=lambda h: ipaddress.IPv4Address(h.ip))
                resp_cnt = sum(1 for h in completed_hosts if h.status == HostReachability.TCP_RESPONSIVE)
                no_resp_cnt = sum(1 for h in completed_hosts if h.status == HostReachability.NO_RESPONSE)
                unreach_cnt = sum(1 for h in completed_hosts if h.status == HostReachability.UNREACHABLE)

                partial_summary = DiscoverySummary(
                    network=str(self.network),
                    total_candidates=total_candidates,
                    responsive_count=resp_cnt,
                    no_response_count=no_resp_cnt,
                    unreachable_count=unreach_cnt,
                    elapsed_seconds=elapsed,
                    hosts=tuple(completed_hosts),
                    interrupted=True,
                    sweep_ports=self.sweep_ports,
                )
                raise DiscoveryInterruptedError(partial_summary)

        elapsed = max(0.0, time.monotonic() - start_time)
        # Sort deterministically by IPv4 address integer representation
        completed_hosts.sort(key=lambda h: ipaddress.IPv4Address(h.ip))

        resp_cnt = sum(1 for h in completed_hosts if h.status == HostReachability.TCP_RESPONSIVE)
        no_resp_cnt = sum(1 for h in completed_hosts if h.status == HostReachability.NO_RESPONSE)
        unreach_cnt = sum(1 for h in completed_hosts if h.status == HostReachability.UNREACHABLE)

        return DiscoverySummary(
            network=str(self.network),
            total_candidates=total_candidates,
            responsive_count=resp_cnt,
            no_response_count=no_resp_cnt,
            unreachable_count=unreach_cnt,
            elapsed_seconds=elapsed,
            hosts=tuple(completed_hosts),
            interrupted=False,
            sweep_ports=self.sweep_ports,
        )
