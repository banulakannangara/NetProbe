"""Command-Line Interface (CLI) for NetProbe."""

import argparse
import sys
import time

from netprobe import __version__
from netprobe.discovery import (
    DEFAULT_SWEEP_PORTS,
    DiscoveryInterruptedError,
    DiscoverySummary,
    HostReachability,
    SubnetScanner,
    parse_cidr,
    parse_sweep_ports,
)
from netprobe.fingerprint import FingerprintEngine
from netprobe.scanner import (
    PortState,
    ScanInterruptedError,
    ScanSummary,
    TCPScanner,
    parse_ports,
    validate_ipv4,
)
from netprobe.udp import (
    UDPPortState,
    UDPScanInterruptedError,
    UDPScanSummary,
    UDPScanner,
)


def create_parser() -> argparse.ArgumentParser:
    """Construct and configure the argument parser for NetProbe CLI."""
    parser = argparse.ArgumentParser(
        prog="netprobe",
        description=(
            f"NetProbe v{__version__} - Professional IPv4 TCP Port Scanner & Network Auditor.\n"
            "SAFETY NOTICE: Only scan systems that you own or have explicit written authorization to assess."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Target IPv4 address or hostname to scan (e.g., 127.0.0.1).",
    )
    parser.add_argument(
        "-p",
        "--ports",
        default="1-1024",
        help=(
            "Port specification (individual ports, comma-separated, or ranges). "
            "Example: '22,80,443,8000-8100'. Default: '1-1024'."
        ),
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.0,
        help=f"Socket connection timeout in seconds ({TCPScanner.MIN_TIMEOUT} to {TCPScanner.MAX_TIMEOUT}). Default: 1.0.",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=100,
        help=f"Concurrency worker pool size ({TCPScanner.MIN_WORKERS} to {TCPScanner.MAX_WORKERS}). Default: 100.",
    )
    parser.add_argument(
        "-a",
        "--all",
        dest="show_all",
        action="store_true",
        help="Display all scanned ports in the table (including closed ports). By default, only open/unknown ports are listed when scanning > 50 ports.",
    )
    parser.add_argument(
        "-sV",
        "--fingerprint",
        action="store_true",
        help="Perform service fingerprinting on open ports (banner grabbing and HTTP probing).",
    )
    parser.add_argument(
        "-u",
        "--udp",
        action="store_true",
        dest="udp",
        help="Perform UDP port scan instead of default TCP connect scan.",
    )
    parser.add_argument(
        "--udp-probe",
        dest="udp_probe",
        metavar="PROBE",
        default=None,
        help="Perform protocol-specific UDP probe ('dns', 'ntp', or 'snmp') instead of generic 0-byte probe. Requires -u/--udp.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit scan results and metadata as structured JSON.",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        default=None,
        help="Write scan output to the specified file path.",
    )

    # Subnet Discovery argument group
    discovery_group = parser.add_argument_group(
        "Subnet Discovery Options",
        "Options for sweeping and discovering active IPv4 hosts across a local subnet (/24 to /32).",
    )
    discovery_group.add_argument(
        "--discover",
        "--subnet",
        dest="discover",
        metavar="CIDR",
        default=None,
        help="Discover active hosts across an IPv4 CIDR subnet (e.g., '192.168.1.0/24'). Max 256 addresses.",
    )
    discovery_group.add_argument(
        "--sweep-ports",
        dest="sweep_ports",
        metavar="PORTS",
        default="80,443,22,445",
        help="Comma-separated TCP ports to test for host responsiveness. Default: '80,443,22,445'.",
    )
    discovery_group.add_argument(
        "-R",
        "--resolve-dns",
        dest="resolve_dns",
        action="store_true",
        help="Perform reverse DNS hostname lookup on discovered hosts.",
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"NetProbe {__version__}",
    )

    return parser


def format_results_table(
    summary: ScanSummary,
    show_all: bool = False,
    fingerprint: bool = False,
) -> str:
    """Format scan results into a human-readable text table.

    Args:
        summary: ScanSummary containing results.
        show_all: Whether to include closed ports when total > 50.
        fingerprint: Whether to display fingerprinting method and details columns.

    Returns:
        Formatted tabular string.
    """
    # Determine which results to display
    display_results = summary.results
    auto_filtered = False

    if not show_all and len(summary.results) > 50:
        display_results = [r for r in summary.results if r.state != PortState.CLOSED]
        auto_filtered = True

    lines: list[str] = []
    width = 90 if fingerprint else 75
    lines.append("-" * width)
    if fingerprint:
        lines.append(f"{'PORT':<10} {'STATE':<10} {'SERVICE':<14} {'METHOD':<14} {'DETAILS'}")
    else:
        lines.append(f"{'PORT':<10} {'STATE':<10} {'SERVICE':<18} {'REASON'}")
    lines.append("-" * width)

    if not display_results:
        lines.append("No open or responsive ports identified.")
    else:
        for res in display_results:
            port_str = f"{res.port}/tcp"
            state_str = res.state.value.upper()
            if fingerprint:
                if res.service_info is not None:
                    service_str = res.service_info.name
                    method_str = res.service_info.method.value.upper()
                    details_str = res.service_info.details or res.reason
                else:
                    service_str = res.service
                    method_str = "CONVENTIONAL"
                    details_str = res.reason
                lines.append(f"{port_str:<10} {state_str:<10} {service_str:<14} {method_str:<14} {details_str}")
            else:
                service_str = res.service
                lines.append(f"{port_str:<10} {state_str:<10} {service_str:<18} {res.reason}")

    lines.append("-" * width)
    if auto_filtered:
        lines.append(
            f"[*] Note: {summary.closed_count} closed ports hidden to keep output concise. Use --all to list all ports."
        )

    return "\n".join(lines)


def format_summary_block(summary: ScanSummary) -> str:
    """Format the concluding scan summary text block."""
    lines = [
        "Scan Summary:",
        f"  Target:          {summary.target}",
        f"  Total Ports:     {summary.total_ports}",
        f"  Open Ports:      {summary.open_count}",
        f"  Closed Ports:    {summary.closed_count}",
        f"  Unknown/Timeout: {summary.unknown_count}",
        f"  Elapsed Time:    {summary.elapsed_seconds:.2f} seconds",
    ]
    return "\n".join(lines)


def format_partial_summary_block(partial: ScanSummary) -> str:
    """Format the partial scan summary text block after operator interrupt."""
    lines = [
        "Partial Scan Summary:",
        f"  Target:          {partial.target}",
        f"  Total Ports:     {partial.total_ports}",
        f"  Completed:       {len(partial.results)}",
        f"  Open Ports:      {partial.open_count}",
        f"  Closed Ports:    {partial.closed_count}",
        f"  Unknown/Timeout: {partial.unknown_count}",
        f"  Elapsed Time:    {partial.elapsed_seconds:.2f} seconds",
    ]
    return "\n".join(lines)


def format_discovery_table(
    summary: DiscoverySummary,
    show_all: bool = False,
) -> str:
    """Format subnet discovery results into a readable table."""
    # Check if any host has a hostname
    has_hostnames = any(h.hostname for h in summary.hosts)

    lines: list[str] = []
    width = 90 if has_hostnames else 75
    lines.append("-" * width)

    if has_hostnames:
        lines.append(f"{'IP ADDRESS':<16} {'STATUS':<16} {'PORT':<10} {'STATE':<10} {'HOSTNAME'}")
    else:
        lines.append(f"{'IP ADDRESS':<16} {'STATUS':<16} {'PORT':<10} {'STATE':<10} {'DETAILS'}")
    lines.append("-" * width)

    # Filter: by default, show responsive hosts or all hosts if count <= 50
    display_hosts = summary.hosts
    auto_filtered = False
    if not show_all and len(summary.hosts) > 50:
        display_hosts = tuple(h for h in summary.hosts if h.status == HostReachability.TCP_RESPONSIVE)
        auto_filtered = True

    if not display_hosts:
        lines.append("No responsive hosts identified.")
    else:
        for host in display_hosts:
            ip_str = host.ip
            status_str = host.status.value.upper()
            port_str = f"{host.responsive_port}/tcp" if host.responsive_port is not None else "-"
            state_str = host.responsive_state.value.upper() if host.responsive_state is not None else "-"
            if has_hostnames:
                detail_str = host.hostname or "-"
            else:
                detail_str = host.reason or "-"
            lines.append(f"{ip_str:<16} {status_str:<16} {port_str:<10} {state_str:<10} {detail_str}")

    lines.append("-" * width)
    if auto_filtered:
        non_responsive = len(summary.hosts) - len(display_hosts)
        lines.append(
            f"[*] Note: {non_responsive} non-responsive/unreachable hosts hidden. Use --all to list all hosts."
        )

    return "\n".join(lines)


def format_discovery_summary_block(summary: DiscoverySummary) -> str:
    """Format concluding discovery summary text block."""
    lines = [
        "Discovery Summary:",
        f"  Network:         {summary.network}",
        f"  Total Hosts:     {summary.total_candidates}",
        f"  Responsive:      {summary.responsive_count}",
        f"  No Response:     {summary.no_response_count}",
        f"  Unreachable:     {summary.unreachable_count}",
        f"  Sweep Ports:     {','.join(map(str, summary.sweep_ports))}",
        f"  Elapsed Time:    {summary.elapsed_seconds:.2f} seconds",
    ]
    return "\n".join(lines)


def format_partial_discovery_summary_block(partial: DiscoverySummary) -> str:
    """Format partial discovery summary text block after operator interrupt."""
    lines = [
        "Partial Discovery Summary (Interrupted):",
        f"  Network:         {partial.network}",
        f"  Total Hosts:     {partial.total_candidates}",
        f"  Completed:       {len(partial.hosts)}",
        f"  Responsive:      {partial.responsive_count}",
        f"  No Response:     {partial.no_response_count}",
        f"  Unreachable:     {partial.unreachable_count}",
        f"  Sweep Ports:     {','.join(map(str, partial.sweep_ports))}",
        f"  Elapsed Time:    {partial.elapsed_seconds:.2f} seconds",
    ]
    return "\n".join(lines)


def _write_file_safely(path: str, content: str) -> None:
    """Write text content to file, logging an error to stderr if it fails."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
    except Exception as exc:
        sys.stderr.write(f"[ERROR] Failed to write output file '{path}': {exc}\n")


def _emit_output(
    summary: ScanSummary,
    json_mode: bool,
    output_file: str | None,
    show_all: bool,
    fingerprint: bool,
    is_partial: bool = False,
) -> None:
    """Emit formatted scan results to stdout and/or file according to configuration."""
    from netprobe.export import scan_summary_to_json

    if json_mode:
        json_doc = scan_summary_to_json(summary)
        if output_file:
            _write_file_safely(output_file, json_doc)
        else:
            sys.stdout.write(json_doc + "\n")
    else:
        # Table output mode
        parts: list[str] = []
        if is_partial and not summary.results:
            parts.append("No ports completed before interruption.\n")
        else:
            parts.append(format_results_table(summary, show_all=show_all, fingerprint=fingerprint) + "\n")

        if is_partial:
            parts.append(format_partial_summary_block(summary) + "\n")
        else:
            parts.append(format_summary_block(summary) + "\n")

        full_text = "\n".join(parts) + "\n"
        sys.stdout.write(full_text)
        if output_file:
            _write_file_safely(output_file, full_text)


def _emit_discovery_output(
    summary: DiscoverySummary,
    json_mode: bool,
    output_file: str | None,
    show_all: bool,
    is_partial: bool = False,
) -> None:
    """Emit formatted discovery results to stdout and/or file."""
    from netprobe.export import discovery_summary_to_json

    if json_mode:
        json_doc = discovery_summary_to_json(summary)
        if output_file:
            _write_file_safely(output_file, json_doc)
        else:
            sys.stdout.write(json_doc + "\n")
    else:
        parts: list[str] = []
        if is_partial and not summary.hosts:
            parts.append("No hosts completed before interruption.\n")
        else:
            parts.append(format_discovery_table(summary, show_all=show_all) + "\n")

        if is_partial:
            parts.append(format_partial_discovery_summary_block(summary) + "\n")
        else:
            parts.append(format_discovery_summary_block(summary) + "\n")

        full_text = "\n".join(parts) + "\n"
        sys.stdout.write(full_text)
        if output_file:
            _write_file_safely(output_file, full_text)


def _run_discovery(args: argparse.Namespace) -> int:
    """Execute subnet discovery workflow."""
    # 1. Validate CIDR
    try:
        network = parse_cidr(args.discover)
    except ValueError as err:
        sys.stderr.write(f"[ERROR] Invalid subnet CIDR: {err}\n")
        return 1

    # 2. Validate Sweep Ports
    try:
        sweep_ports = parse_sweep_ports(args.sweep_ports)
    except ValueError as err:
        sys.stderr.write(f"[ERROR] Invalid sweep ports: {err}\n")
        return 1

    # 3. Validate Output Destination if specified
    if args.output:
        from netprobe.export import validate_output_path

        try:
            validate_output_path(args.output)
        except Exception as err:
            sys.stderr.write(f"[ERROR] Output file validation failed: {err}\n")
            return 1

    # 4. Instantiate SubnetScanner
    try:
        scanner = SubnetScanner(
            network=network,
            sweep_ports=sweep_ports,
            timeout=args.timeout,
            max_workers=args.workers,
            resolve_hostnames=args.resolve_dns,
        )
    except ValueError as err:
        sys.stderr.write(f"[ERROR] Configuration error: {err}\n")
        return 1

    # Banner header (unless --json)
    if not args.json:
        start_timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        sys.stdout.write(f"\nNetProbe v{__version__} - Subnet Discovery\n")
        sys.stdout.write(f"Initiated at: {start_timestamp}\n")
        sys.stdout.write(f"Subnet:       {network}\n")
        sys.stdout.write(
            f"Sweep Ports:  {len(sweep_ports)} port(s) ({','.join(map(str, sweep_ports))}) "
            f"[timeout: {scanner.timeout}s, workers: {scanner.max_workers}]\n"
        )
        if args.resolve_dns:
            sys.stdout.write("Reverse DNS:  Enabled\n")
        sys.stdout.write("Notice:       TCP probes classify reachability only; closed/filtered ports do not imply host is offline.\n\n")

    # Run discovery sweep
    try:
        summary = scanner.scan()
    except DiscoveryInterruptedError as exc:
        try:
            sys.stderr.write("\n[WARN] Discovery scan interrupted by operator (Ctrl+C).\n\n")
            _emit_discovery_output(
                summary=exc.summary,
                json_mode=args.json,
                output_file=args.output,
                show_all=args.show_all,
                is_partial=True,
            )
        except KeyboardInterrupt:
            sys.stderr.write("\n[WARN] Discovery scan forcefully aborted by operator.\n")
        return 130
    except KeyboardInterrupt:
        sys.stderr.write("\n[WARN] Discovery scan interrupted by operator (Ctrl+C). Exiting cleanly.\n")
        return 130
    except Exception as exc:
        sys.stderr.write(f"\n[ERROR] Unexpected error during discovery: {exc}\n")
        return 2

    _emit_discovery_output(
        summary=summary,
        json_mode=args.json,
        output_file=args.output,
        show_all=args.show_all,
        is_partial=False,
    )
    return 0


def format_udp_results_table(
    summary: UDPScanSummary,
    show_all: bool = False,
) -> str:
    """Format UDP scan results into a human-readable text table."""
    display_results = summary.results
    auto_filtered = False

    if not show_all and len(summary.results) > 50:
        display_results = [r for r in summary.results if r.state != UDPPortState.CLOSED]
        auto_filtered = True

    lines: list[str] = []
    width = 80
    lines.append("-" * width)
    lines.append(f"{'PORT':<10} {'STATE':<16} {'SERVICE':<18} {'REASON'}")
    lines.append("-" * width)

    if not display_results:
        lines.append("No open or open/filtered UDP ports identified.")
    else:
        for res in display_results:
            port_str = f"{res.port}/udp"
            state_str = res.state.value.upper()
            service_str = res.service
            lines.append(f"{port_str:<10} {state_str:<16} {service_str:<18} {res.reason}")

    lines.append("-" * width)
    if auto_filtered:
        lines.append(
            f"[*] Note: {summary.closed_count} closed ports hidden to keep output concise. Use --all to list all ports."
        )

    return "\n".join(lines)


def format_udp_summary_block(summary: UDPScanSummary) -> str:
    """Format the concluding UDP scan summary text block."""
    lines = [
        "UDP Scan Summary:",
        f"  Target:          {summary.target}",
        f"  Total Ports:     {summary.total_ports}",
        f"  Open:            {summary.open_count}",
        f"  Closed:          {summary.closed_count}",
        f"  Open|Filtered:   {summary.open_filtered_count}",
        f"  Unknown/Error:   {summary.unknown_count}",
        f"  Elapsed Time:    {summary.elapsed_seconds:.2f} seconds",
    ]
    return "\n".join(lines)


def format_partial_udp_summary_block(partial: UDPScanSummary) -> str:
    """Format partial UDP scan summary text block after operator interrupt."""
    lines = [
        "Partial UDP Scan Summary (Interrupted):",
        f"  Target:          {partial.target}",
        f"  Total Ports:     {partial.total_ports}",
        f"  Completed:       {len(partial.results)}",
        f"  Open:            {partial.open_count}",
        f"  Closed:          {partial.closed_count}",
        f"  Open|Filtered:   {partial.open_filtered_count}",
        f"  Unknown/Error:   {partial.unknown_count}",
        f"  Elapsed Time:    {partial.elapsed_seconds:.2f} seconds",
    ]
    return "\n".join(lines)


def _emit_udp_output(
    summary: UDPScanSummary,
    json_mode: bool,
    output_file: str | None,
    show_all: bool,
    is_partial: bool = False,
) -> None:
    """Emit formatted UDP scan results to stdout and/or file."""
    from netprobe.export import udp_scan_summary_to_json

    if json_mode:
        json_doc = udp_scan_summary_to_json(summary)
        if output_file:
            _write_file_safely(output_file, json_doc)
        else:
            sys.stdout.write(json_doc + "\n")
    else:
        parts: list[str] = []
        if is_partial and not summary.results:
            parts.append("No ports completed before interruption.\n")
        else:
            parts.append(format_udp_results_table(summary, show_all=show_all) + "\n")

        if is_partial:
            parts.append(format_partial_udp_summary_block(summary) + "\n")
        else:
            parts.append(format_udp_summary_block(summary) + "\n")

        full_text = "\n".join(parts) + "\n"
        sys.stdout.write(full_text)
        if output_file:
            _write_file_safely(output_file, full_text)


def _run_udp(args: argparse.Namespace) -> int:
    """Execute UDP port scan workflow."""
    from netprobe.scanner import parse_ports, resolve_target

    # 0. Validate UDP probe if specified
    probe_name: str | None = None
    if getattr(args, "udp_probe", None):
        probe_clean = args.udp_probe.strip().lower()
        if probe_clean not in ("dns", "ntp", "snmp"):
            sys.stderr.write(
                f"[ERROR] Invalid UDP probe '{args.udp_probe}'. Supported probes: 'dns', 'ntp', 'snmp'.\n"
            )
            return 1
        probe_name = probe_clean

    # 1. Validate / Resolve Target
    try:
        orig_target, resolved_ip = resolve_target(args.target)
    except ValueError as err:
        sys.stderr.write(f"[ERROR] Target validation failed: {err}\n")
        return 1

    # 2. Parse Ports
    try:
        ports = parse_ports(args.ports)
    except ValueError as err:
        sys.stderr.write(f"[ERROR] Port parsing failed: {err}\n")
        return 1

    # 3. Validate Output Destination if specified
    if args.output:
        from netprobe.export import validate_output_path

        try:
            validate_output_path(args.output)
        except Exception as err:
            sys.stderr.write(f"[ERROR] Output file validation failed: {err}\n")
            return 1

    # 4. Instantiate UDPScanner
    try:
        scanner = UDPScanner(
            target=resolved_ip,
            timeout=args.timeout,
            max_workers=args.workers,
            display_target=orig_target,
            probe=probe_name,
        )
    except ValueError as err:
        sys.stderr.write(f"[ERROR] Configuration error: {err}\n")
        return 1

    # Print scan header only when not in JSON mode
    if not args.json:
        start_timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        target_display = (
            f"{orig_target} ({resolved_ip})"
            if orig_target != resolved_ip
            else resolved_ip
        )
        sys.stdout.write(f"\nNetProbe v{__version__} - UDP Network Auditor\n")
        sys.stdout.write(f"Initiated at: {start_timestamp}\n")
        sys.stdout.write(f"Target:       {target_display}\n")
        sys.stdout.write(
            f"Ports:        {len(ports)} UDP port(s) specified (timeout: {scanner.timeout}s, workers: {scanner.max_workers})\n"
        )
        if probe_name:
            sys.stdout.write(f"UDP Probe:    {probe_name.upper()} Application Payload\n")
        sys.stdout.write("Notice:       UDP is connectionless; non-responding ports are classified OPEN_FILTERED.\n\n")

    # Run UDP scan
    try:
        summary = scanner.scan(ports)
    except UDPScanInterruptedError as exc:
        try:
            sys.stderr.write("\n[WARN] UDP scan interrupted by operator (Ctrl+C).\n\n")
            _emit_udp_output(
                summary=exc.summary,
                json_mode=args.json,
                output_file=args.output,
                show_all=args.show_all,
                is_partial=True,
            )
        except KeyboardInterrupt:
            sys.stderr.write("\n[WARN] UDP scan forcefully aborted by operator.\n")
        return 130
    except KeyboardInterrupt:
        sys.stderr.write("\n[WARN] UDP scan interrupted by operator (Ctrl+C). Exiting cleanly.\n")
        return 130
    except Exception as exc:
        sys.stderr.write(f"\n[ERROR] Unexpected error during UDP scan: {exc}\n")
        return 2

    # Output completed scan results
    _emit_udp_output(
        summary=summary,
        json_mode=args.json,
        output_file=args.output,
        show_all=args.show_all,
        is_partial=False,
    )

    return 0


def main(argv: list[str] | None = None) -> int:
    """Entry point for NetProbe CLI."""
    parser = create_parser()

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code

    # Mode validation: Single Target vs Subnet Discovery
    if args.discover:
        if args.target:
            sys.stderr.write(
                "[ERROR] Cannot specify both a target host and --discover mode. Use one or the other.\n"
            )
            return 1
        if args.udp or getattr(args, "udp_probe", None):
            sys.stderr.write(
                "[ERROR] UDP scanning is not supported in subnet discovery mode.\n"
            )
            return 1
        return _run_discovery(args)

    # Validate that --udp-probe is only used when UDP mode is active
    if getattr(args, "udp_probe", None) and not args.udp:
        sys.stderr.write(
            "[ERROR] --udp-probe requires -u/--udp mode. Specify both options together.\n"
        )
        return 1

    if not args.target:
        sys.stderr.write("[ERROR] Target host is required when not in --discover mode.\n")
        parser.print_usage(sys.stderr)
        return 2

    # Dispatch to UDP mode if requested
    if args.udp:
        return _run_udp(args)

    # 1. Validate / Resolve Target
    from netprobe.scanner import resolve_target

    try:
        orig_target, resolved_ip = resolve_target(args.target)
    except ValueError as err:
        sys.stderr.write(f"[ERROR] Target validation failed: {err}\n")
        return 1

    # 2. Parse Ports
    try:
        ports = parse_ports(args.ports)
    except ValueError as err:
        sys.stderr.write(f"[ERROR] Port parsing failed: {err}\n")
        return 1

    # 3. Validate Output Destination if specified
    if args.output:
        from netprobe.export import validate_output_path

        try:
            validate_output_path(args.output)
        except Exception as err:
            sys.stderr.write(f"[ERROR] Output file validation failed: {err}\n")
            return 1

    # 4. Instantiate Scanner
    try:
        scanner = TCPScanner(
            target=resolved_ip,
            timeout=args.timeout,
            max_workers=args.workers,
            display_target=orig_target,
        )
    except ValueError as err:
        sys.stderr.write(f"[ERROR] Configuration error: {err}\n")
        return 1

    # Print scan header only when not in JSON mode
    if not args.json:
        start_timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        target_display = (
            f"{orig_target} ({resolved_ip})"
            if orig_target != resolved_ip
            else resolved_ip
        )
        sys.stdout.write(f"\nNetProbe v{__version__} - TCP Network Auditor\n")
        sys.stdout.write(f"Initiated at: {start_timestamp}\n")
        sys.stdout.write(f"Target:       {target_display}\n")
        sys.stdout.write(
            f"Ports:        {len(ports)} port(s) specified (timeout: {scanner.timeout}s, workers: {scanner.max_workers})\n"
        )
        sys.stdout.write("Notice:       Port service labels reflect common conventions, not verified application signatures.\n\n")

    # Run scan
    try:
        summary = scanner.scan(ports)
    except ScanInterruptedError as exc:
        try:
            sys.stderr.write("\n[WARN] Scan interrupted by operator (Ctrl+C).\n\n")
            _emit_output(
                summary=exc.summary,
                json_mode=args.json,
                output_file=args.output,
                show_all=args.show_all,
                fingerprint=args.fingerprint,
                is_partial=True,
            )
        except KeyboardInterrupt:
            sys.stderr.write("\n[WARN] Scan forcefully aborted by operator.\n")
        return 130
    except KeyboardInterrupt:
        sys.stderr.write("\n[WARN] Scan interrupted by operator (Ctrl+C). Exiting cleanly.\n")
        return 130
    except Exception as exc:
        sys.stderr.write(f"\n[ERROR] Unexpected error during scan: {exc}\n")
        return 2

    # Run fingerprinting on OPEN ports if requested
    if args.fingerprint and summary.open_count > 0:
        try:
            fp_start = time.perf_counter()
            engine = FingerprintEngine(max_workers=min(summary.open_count, args.workers))
            fingerprinted_results = engine.fingerprint_results(
                resolved_ip,
                summary.results,
                initial_elapsed=summary.elapsed_seconds,
            )
            total_elapsed = summary.elapsed_seconds + (time.perf_counter() - fp_start)
            summary = ScanSummary(
                target=summary.target,
                total_ports=summary.total_ports,
                open_count=summary.open_count,
                closed_count=summary.closed_count,
                unknown_count=summary.unknown_count,
                elapsed_seconds=total_elapsed,
                results=fingerprinted_results,
                interrupted=summary.interrupted,
                resolved_target=summary.resolved_target or resolved_ip,
            )

        except ScanInterruptedError as exc:
            try:
                sys.stderr.write("\n[WARN] Fingerprinting interrupted by operator (Ctrl+C).\n\n")
                _emit_output(
                    summary=exc.summary,
                    json_mode=args.json,
                    output_file=args.output,
                    show_all=args.show_all,
                    fingerprint=True,
                    is_partial=True,
                )
            except KeyboardInterrupt:
                sys.stderr.write("\n[WARN] Scan forcefully aborted by operator.\n")
            return 130
        except KeyboardInterrupt:
            sys.stderr.write("\n[WARN] Scan interrupted by operator (Ctrl+C). Exiting cleanly.\n")
            return 130
        except Exception as exc:
            sys.stderr.write(f"\n[ERROR] Unexpected error during fingerprinting: {exc}\n")
            return 2

    # Output completed scan results
    _emit_output(
        summary=summary,
        json_mode=args.json,
        output_file=args.output,
        show_all=args.show_all,
        fingerprint=args.fingerprint,
        is_partial=False,
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())

