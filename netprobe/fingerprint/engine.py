"""Fingerprint engine orchestrator for NetProbe Phase 2.1."""

import concurrent.futures
import time
from typing import Callable, Sequence

from netprobe.fingerprint.models import IdentificationMethod, ServiceInfo
from netprobe.fingerprint.probes import probe_http, probe_passive_banner, probe_tls
from netprobe.scanner import PortState, ScanInterruptedError, ScanResult, ScanSummary
from netprobe.services import get_service_name


# Port sets for fast-path probe prioritization
COMMON_HTTP_PORTS: frozenset[int] = frozenset({80, 8080, 8000, 8888, 9000, 5000})
COMMON_HTTPS_PORTS: frozenset[int] = frozenset({443, 8443, 9443})


class FingerprintEngine:
    """Orchestrates protocol fingerprinting on confirmed OPEN TCP ports."""

    DEFAULT_OVERALL_TIMEOUT: float = 2.0
    DEFAULT_MAX_WORKERS: int = 50

    def __init__(
        self,
        overall_timeout: float = DEFAULT_OVERALL_TIMEOUT,
        max_workers: int = DEFAULT_MAX_WORKERS,
    ) -> None:
        """Initialize FingerprintEngine.

        Args:
            overall_timeout: Hard deadline per port in seconds.
            max_workers: Bounded concurrency pool size.
        """
        self.overall_timeout = max(0.1, float(overall_timeout))
        self.max_workers = max(1, int(max_workers))

    def fingerprint_port(self, target: str, port: int) -> ServiceInfo:
        """Perform sequential probes on an open port within the overall deadline.

        Probing order is port-aware to reduce latency:
        - Common HTTP ports (80, 8080, ...): HTTP probe -> TLS probe -> Passive banner
        - Common HTTPS ports (443, 8443, ...): TLS probe -> HTTP probe -> Passive banner
        - Other ports (22, 21, 25, non-standard): Passive banner -> HTTP probe -> TLS probe
        - Final fallback: Conventional unverified port mapping

        All probes share and strictly decrement against self.overall_timeout.
        If a prioritized probe returns None, the engine safely falls through
        to remaining probes.

        Args:
            target: Target IPv4 address.
            port: Open TCP port number.

        Returns:
            ServiceInfo with verified identification or conventional fallback.
        """
        start_time = time.perf_counter()
        deadline = start_time + self.overall_timeout

        def _try_passive() -> ServiceInfo | None:
            rem = deadline - time.perf_counter()
            if rem > 0.05:
                return probe_passive_banner(target, port, timeout=min(0.5, rem))
            return None

        def _try_http() -> ServiceInfo | None:
            rem = deadline - time.perf_counter()
            if rem > 0.05:
                return probe_http(target, port, timeout=min(0.75, rem))
            return None

        def _try_tls() -> ServiceInfo | None:
            rem = deadline - time.perf_counter()
            if rem > 0.05:
                return probe_tls(target, port, timeout=min(1.0, rem))
            return None

        # Determine probe execution sequence based on port heuristics
        if port in COMMON_HTTP_PORTS:
            probe_sequence = (_try_http, _try_tls, _try_passive)
        elif port in COMMON_HTTPS_PORTS:
            probe_sequence = (_try_tls, _try_http, _try_passive)
        else:
            probe_sequence = (_try_passive, _try_http, _try_tls)

        for probe_fn in probe_sequence:
            info = probe_fn()
            if info is not None:
                return info

        # Conventional fallback when no probe matched
        fallback_name = get_service_name(port)
        return ServiceInfo(
            name=fallback_name,
            method=IdentificationMethod.CONVENTIONAL,
            details="Unverified (port convention)",
        )

    def fingerprint_results(
        self,
        target: str,
        results: Sequence[ScanResult],
        callback: Callable[[ScanResult], None] | None = None,
        initial_elapsed: float = 0.0,
    ) -> list[ScanResult]:
        """Fingerprint confirmed OPEN ports from scan results.

        Non-OPEN ports (CLOSED, UNKNOWN) are preserved unchanged.
        Supports cancellation without leaking threads or discarding results.

        Args:
            target: Target IPv4 address.
            results: Results list from TCPScanner.
            callback: Optional callback invoked as each open port is fingerprinted.
            initial_elapsed: Elapsed duration from prior scan phase to preserve.

        Returns:
            Updated list of ScanResults with ServiceInfo attached to OPEN ports.

        Raises:
            ScanInterruptedError: If interrupted by operator, carrying preserved results
                and accumulated elapsed time.
        """
        open_results = [r for r in results if r.state == PortState.OPEN]
        if not open_results:
            return list(results)

        fp_start = time.perf_counter()
        port_to_orig = {r.port: r for r in results}
        updated: dict[int, ScanResult] = {r.port: r for r in results}

        workers = max(1, min(len(open_results), self.max_workers))
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers)

        try:
            future_to_port = {
                executor.submit(self.fingerprint_port, target, r.port): r.port
                for r in open_results
            }

            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                orig_res = port_to_orig[port]

                try:
                    service_info = future.result()
                except Exception:
                    service_info = ServiceInfo(
                        name=orig_res.service,
                        method=IdentificationMethod.CONVENTIONAL,
                        details="Fingerprint error",
                    )

                # Use verified protocol name if identified, else retain original convention
                service_name = (
                    service_info.name
                    if service_info.method != IdentificationMethod.CONVENTIONAL
                    else orig_res.service
                )

                new_res = ScanResult(
                    port=port,
                    state=orig_res.state,
                    service=service_name,
                    reason=orig_res.reason,
                    service_info=service_info,
                )
                updated[port] = new_res
                if callback:
                    callback(new_res)
        except KeyboardInterrupt:
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass

            partial_list = [updated[r.port] for r in results]
            open_cnt = sum(1 for r in partial_list if r.state == PortState.OPEN)
            closed_cnt = sum(1 for r in partial_list if r.state == PortState.CLOSED)
            unknown_cnt = sum(1 for r in partial_list if r.state == PortState.UNKNOWN)

            total_elapsed = initial_elapsed + (time.perf_counter() - fp_start)
            partial_summary = ScanSummary(
                target=target,
                total_ports=len(results),
                open_count=open_cnt,
                closed_count=closed_cnt,
                unknown_count=unknown_cnt,
                elapsed_seconds=total_elapsed,
                results=partial_list,
                interrupted=True,
            )
            raise ScanInterruptedError(partial_summary)
        except Exception:
            executor.shutdown(wait=False, cancel_futures=True)
            raise
        else:
            executor.shutdown(wait=True)

        return [updated[r.port] for r in results]
