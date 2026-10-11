"""Comprehensive automated test suite for NetProbe."""

import io
import socket
import time
from unittest.mock import MagicMock, patch

import pytest

from netprobe.cli import create_parser, format_results_table, main
from netprobe.scanner import (
    PortState,
    ScanInterruptedError,
    ScanResult,
    ScanSummary,
    TCPScanner,
    parse_ports,
    resolve_target,
    scan_single_port,
    validate_ipv4,
)

from netprobe.services import COMMON_SERVICES, get_service_name


class TestIPv4Validation:
    """Test IPv4 target address validation."""

    def test_valid_ipv4_addresses(self) -> None:
        assert validate_ipv4("127.0.0.1") == "127.0.0.1"
        assert validate_ipv4("192.168.1.100") == "192.168.1.100"
        assert validate_ipv4("10.0.0.1") == "10.0.0.1"
        assert validate_ipv4("  172.16.0.1  ") == "172.16.0.1"
        assert validate_ipv4("0.0.0.0") == "0.0.0.0"
        assert validate_ipv4("255.255.255.255") == "255.255.255.255"

    def test_reject_empty_or_whitespace(self) -> None:
        with pytest.raises(ValueError, match="cannot be empty"):
            validate_ipv4("")
        with pytest.raises(ValueError, match="cannot be empty"):
            validate_ipv4("   ")

    def test_reject_hostnames(self) -> None:
        with pytest.raises(ValueError, match="Invalid IPv4 address 'localhost'"):
            validate_ipv4("localhost")
        with pytest.raises(ValueError, match="Invalid IPv4 address 'example.com'"):
            validate_ipv4("example.com")

    def test_reject_ipv6(self) -> None:
        with pytest.raises(ValueError, match="IPv6"):
            validate_ipv4("::1")
        with pytest.raises(ValueError, match="IPv6"):
            validate_ipv4("2001:db8::1")

    def test_reject_invalid_octets(self) -> None:
        with pytest.raises(ValueError, match="Invalid IPv4 address"):
            validate_ipv4("256.0.0.1")
        with pytest.raises(ValueError, match="Invalid IPv4 address"):
            validate_ipv4("192.168.1")
        with pytest.raises(ValueError, match="Invalid IPv4 address"):
            validate_ipv4("192.168.1.1.1")


class TestTargetResolution:
    """Test resolve_target hostname resolution and validation."""

    def test_valid_ipv4_literal_bypasses_dns(self) -> None:
        with patch("socket.getaddrinfo") as mock_gai:
            orig, resolved = resolve_target("127.0.0.1")
            assert orig == "127.0.0.1"
            assert resolved == "127.0.0.1"
            mock_gai.assert_not_called()

        with patch("socket.getaddrinfo") as mock_gai:
            orig, resolved = resolve_target("  192.168.1.50  ")
            assert orig == "192.168.1.50"
            assert resolved == "192.168.1.50"
            mock_gai.assert_not_called()

    def test_hostname_resolves_to_ipv4(self) -> None:
        mock_addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        ]
        with patch("socket.getaddrinfo", return_value=mock_addrinfo) as mock_gai:
            orig, resolved = resolve_target("example.com")
            assert orig == "example.com"
            assert resolved == "93.184.216.34"
            mock_gai.assert_called_once_with("example.com", None, socket.AF_UNSPEC, socket.SOCK_STREAM)

    def test_multiple_ipv4_results_selects_first(self) -> None:
        mock_addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.0.0.1", 0)),
        ]
        with patch("socket.getaddrinfo", return_value=mock_addrinfo):
            orig, resolved = resolve_target("one.one.one.one")
            assert orig == "one.one.one.one"
            assert resolved == "1.1.1.1"

    def test_hostname_with_ipv4_and_ipv6_selects_ipv4(self) -> None:
        mock_addrinfo = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700:4700::1111", 0, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 0)),
        ]
        with patch("socket.getaddrinfo", return_value=mock_addrinfo):
            orig, resolved = resolve_target("dualstack.example.com")
            assert orig == "dualstack.example.com"
            assert resolved == "1.1.1.1"

    def test_ipv6_literal_rejected(self) -> None:
        with pytest.raises(ValueError, match="IPv6 address. NetProbe only supports IPv4"):
            resolve_target("::1")

        with pytest.raises(ValueError, match="IPv6 address. NetProbe only supports IPv4"):
            resolve_target("2001:db8::1")

    def test_ipv6_only_resolution_rejected(self) -> None:
        mock_addrinfo = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 0, 0, 0)),
        ]
        with patch("socket.getaddrinfo", return_value=mock_addrinfo):
            with pytest.raises(ValueError, match="resolved only to IPv6 address"):
                resolve_target("ipv6.example.com")

    def test_resolver_gaierror_reports_useful_message(self) -> None:
        with patch("socket.getaddrinfo", side_effect=socket.gaierror(11001, "getaddrinfo failed")):
            with pytest.raises(ValueError, match="Failed to resolve target 'nonexistent.domain'"):
                resolve_target("nonexistent.domain")

    def test_empty_target_rejected(self) -> None:
        with pytest.raises(ValueError, match="cannot be empty"):
            resolve_target("")
        with pytest.raises(ValueError, match="cannot be empty"):
            resolve_target("   ")



class TestPortParsing:
    """Test port list, range, and format parsing."""

    def test_single_port(self) -> None:
        assert parse_ports("80") == [80]
        assert parse_ports("443") == [443]

    def test_comma_separated_ports(self) -> None:
        assert parse_ports("22,80,443") == [22, 80, 443]

    def test_port_ranges(self) -> None:
        assert parse_ports("8000-8003") == [8000, 8001, 8002, 8003]

    def test_single_port_range(self) -> None:
        assert parse_ports("80-80") == [80]

    def test_mixed_specification(self) -> None:
        spec = "22, 80, 443, 8000-8002"
        expected = [22, 80, 443, 8000, 8001, 8002]
        assert parse_ports(spec) == expected

    def test_deduplication_and_sorting(self) -> None:
        spec = "8080, 80, 8080, 22, 80-82"
        expected = [22, 80, 81, 82, 8080]
        assert parse_ports(spec) == expected

    def test_boundary_ports(self) -> None:
        assert parse_ports("1") == [1]
        assert parse_ports("65535") == [65535]
        assert parse_ports("1, 65535") == [1, 65535]

    def test_reject_empty_specification(self) -> None:
        with pytest.raises(ValueError, match="cannot be empty"):
            parse_ports("")
        with pytest.raises(ValueError, match="cannot be empty"):
            parse_ports("   ")

    def test_reject_empty_tokens_and_consecutive_separators(self) -> None:
        with pytest.raises(ValueError, match="empty token or consecutive commas"):
            parse_ports(",,,")
        with pytest.raises(ValueError, match="empty token or consecutive commas"):
            parse_ports("80,,443")
        with pytest.raises(ValueError, match="empty token or consecutive commas"):
            parse_ports(",80")
        with pytest.raises(ValueError, match="empty token or consecutive commas"):
            parse_ports("80,")
        with pytest.raises(ValueError, match="empty token or consecutive commas"):
            parse_ports("80, ,443")

    def test_reject_excessive_digit_lengths(self) -> None:
        with pytest.raises(ValueError, match="cannot exceed 5 digits"):
            parse_ports("100000")
        with pytest.raises(ValueError, match="cannot exceed 5 digits"):
            parse_ports("1" * 5000)
        with pytest.raises(ValueError, match="cannot exceed 5 digits"):
            parse_ports("100000-100010")
        with pytest.raises(ValueError, match="cannot exceed 5 digits"):
            parse_ports("80-800000")

    def test_overlapping_and_adjacent_ranges(self) -> None:
        assert parse_ports("80-85, 82-87") == list(range(80, 88))
        assert parse_ports("100-102, 102-105") == list(range(100, 106))

    def test_reject_missing_range_boundaries(self) -> None:
        with pytest.raises(ValueError, match="missing boundary values"):
            parse_ports("-80")
        with pytest.raises(ValueError, match="missing boundary values"):
            parse_ports("80-")

    def test_reject_invalid_port_numbers(self) -> None:
        with pytest.raises(ValueError, match="out of range"):
            parse_ports("0")
        with pytest.raises(ValueError, match="cannot exceed 5 digits"):
            parse_ports("655360")
        with pytest.raises(ValueError, match="out of range"):
            parse_ports("65536")
        with pytest.raises(ValueError, match="out of range"):
            parse_ports("70000")

    def test_reject_non_numeric_tokens(self) -> None:
        with pytest.raises(ValueError, match="must be integer"):
            parse_ports("http")
        with pytest.raises(ValueError, match="must be integer"):
            parse_ports("22, ssh, 443")

    def test_reject_invalid_ranges(self) -> None:
        with pytest.raises(ValueError, match="greater than end"):
            parse_ports("8000-7000")
        with pytest.raises(ValueError, match="Expected 'start-end'"):
            parse_ports("80-90-100")
        with pytest.raises(ValueError, match="boundaries in '80-abc' must be positive integers"):
            parse_ports("80-abc")
        with pytest.raises(ValueError, match="falls outside the valid TCP range"):
            parse_ports("0-10")
        with pytest.raises(ValueError, match="falls outside the valid TCP range"):
            parse_ports("65530-65540")


class TestServiceMappings:
    """Test TCP port-to-service name resolution."""

    def test_common_services(self) -> None:
        assert get_service_name(22) == "ssh"
        assert get_service_name(80) == "http"
        assert get_service_name(443) == "https"
        assert get_service_name(3306) == "mysql"
        assert get_service_name(5432) == "postgresql"

    def test_unmapped_port_fallback(self) -> None:
        assert get_service_name(64123) == "unknown"
        assert get_service_name(64123, default="unassigned") == "unassigned"

    def test_mapping_coverage_non_empty(self) -> None:
        assert len(COMMON_SERVICES) >= 20
        assert all(1 <= port <= 65535 for port in COMMON_SERVICES.keys())


class TestSinglePortScanner:
    """Test single port TCP connect scan outcomes and socket handling."""

    def test_open_port_local_socket(self) -> None:
        """Verify OPEN state using a real local listening socket."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        assigned_port = server.getsockname()[1]

        try:
            res = scan_single_port("127.0.0.1", assigned_port, timeout=0.5)
            assert res.state == PortState.OPEN
            assert res.port == assigned_port
            assert res.reason == "Connection established"
        finally:
            server.close()

    def test_closed_port_outcome(self) -> None:
        """Verify CLOSED state when ConnectionRefusedError (RST) is received."""
        with patch("socket.socket") as mock_socket_class:
            mock_sock = MagicMock()
            mock_sock.connect.side_effect = ConnectionRefusedError("Connection refused")
            mock_socket_class.return_value = mock_sock

            res = scan_single_port("127.0.0.1", 9999, timeout=0.5)
            assert res.state == PortState.CLOSED
            assert res.port == 9999
            assert "refused" in res.reason.lower()
            mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_timeout_filtered_outcome(self, mock_socket_class: MagicMock) -> None:
        """Verify UNKNOWN state when connection times out."""
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = TimeoutError("Timed out")
        mock_socket_class.return_value = mock_sock

        res = scan_single_port("127.0.0.1", 80, timeout=1.0)
        assert res.state == PortState.UNKNOWN
        assert "Timed out" in res.reason
        mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_network_unreachable_outcome(self, mock_socket_class: MagicMock) -> None:
        """Verify UNKNOWN state on network-level OSError."""
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(10065, "No route to host")
        mock_socket_class.return_value = mock_sock

        res = scan_single_port("127.0.0.1", 443, timeout=1.0)
        assert res.state == PortState.UNKNOWN
        assert "Network error" in res.reason
        mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_socket_cleanup_guarantee(self, mock_socket_class: MagicMock) -> None:
        """Verify socket is always closed regardless of exceptions."""
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError()
        mock_socket_class.return_value = mock_sock

        scan_single_port("127.0.0.1", 9999, timeout=0.5)
        mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_socket_creation_failure_handled(self, mock_socket_class: MagicMock) -> None:
        """Verify socket creation failure (e.g. EMFILE) is classified as UNKNOWN."""
        mock_socket_class.side_effect = OSError(24, "Too many open files")
        res = scan_single_port("127.0.0.1", 80, timeout=1.0)
        assert res.state == PortState.UNKNOWN
        assert res.port == 80
        assert "Too many open files" in res.reason


class TestTCPScannerExecution:
    """Test TCPScanner concurrency, configuration, and summaries."""

    def test_configuration_validation(self) -> None:
        with pytest.raises(ValueError, match="Invalid IPv4"):
            TCPScanner(target="invalid_ip")

        with pytest.raises(ValueError, match="Timeout must be between"):
            TCPScanner(target="127.0.0.1", timeout=0.01)

        with pytest.raises(ValueError, match="Timeout must be between"):
            TCPScanner(target="127.0.0.1", timeout=100.0)

        with pytest.raises(ValueError, match="Workers must be an integer between"):
            TCPScanner(target="127.0.0.1", max_workers=0)

        with pytest.raises(ValueError, match="Workers must be an integer between"):
            TCPScanner(target="127.0.0.1", max_workers=1000)

    def test_empty_ports_list_rejected(self) -> None:
        scanner = TCPScanner(target="127.0.0.1", timeout=0.5, max_workers=10)
        with pytest.raises(ValueError, match="No ports provided"):
            scanner.scan([])

    def test_concurrent_scan_with_callback(self) -> None:
        """Verify concurrent scanning and callback execution deterministically."""
        def fake_scan(target: str, port: int, timeout: float) -> ScanResult:
            if port == 80:
                return ScanResult(port=80, state=PortState.OPEN, service="http", reason="Connection established")
            elif port == 81:
                return ScanResult(port=81, state=PortState.CLOSED, service="unknown", reason="Connection refused (RST)")
            else:
                return ScanResult(port=port, state=PortState.UNKNOWN, service="unknown", reason="Timed out")

        callback_results: list[ScanResult] = []

        with patch("netprobe.scanner.scan_single_port", side_effect=fake_scan):
            scanner = TCPScanner(target="127.0.0.1", timeout=0.5, max_workers=2)
            summary = scanner.scan(
                ports=[81, 80, 82],
                callback=callback_results.append,
            )

            assert summary.target == "127.0.0.1"
            assert summary.total_ports == 3
            assert summary.open_count == 1
            assert summary.closed_count == 1
            assert summary.unknown_count == 1
            assert summary.elapsed_seconds >= 0.0

            # Results must be sorted by port
            assert summary.results == sorted(summary.results, key=lambda r: r.port)
            assert [r.port for r in summary.results] == [80, 81, 82]
            assert len(callback_results) == 3

    def test_socket_creation_failure_continues_scanning(self) -> None:
        """Verify scan continues processing other ports when one socket creation fails."""
        def fake_scan(target: str, port: int, timeout: float) -> ScanResult:
            if port == 80:
                return ScanResult(port=80, state=PortState.UNKNOWN, service="http", reason="Network error (Too many open files)")
            return ScanResult(port=port, state=PortState.OPEN, service="other", reason="Connection established")

        with patch("netprobe.scanner.scan_single_port", side_effect=fake_scan):
            scanner = TCPScanner(target="127.0.0.1", timeout=0.5, max_workers=2)
            summary = scanner.scan([80, 443])
            assert summary.total_ports == 2
            assert summary.unknown_count == 1
            assert summary.open_count == 1

    def test_cancellation_preserves_partial_results(self) -> None:
        """Verify cancellation preserves results from ports that have already completed."""
        call_count = 0

        def interrupt_on_second_port(target: str, port: int, timeout: float) -> ScanResult:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return ScanResult(port=80, state=PortState.OPEN, service="http", reason="Connection established")
            raise KeyboardInterrupt()

        with patch("netprobe.scanner.scan_single_port", side_effect=interrupt_on_second_port):
            scanner = TCPScanner(target="127.0.0.1", timeout=0.5, max_workers=1)
            with pytest.raises(ScanInterruptedError) as exc_info:
                scanner.scan([80, 443, 8080])

            err = exc_info.value
            assert isinstance(err, KeyboardInterrupt)
            assert err.summary.interrupted is True
            assert err.summary.total_ports == 3
            assert err.summary.open_count == 1
            assert len(err.summary.results) == 1
            assert err.summary.results[0].port == 80

    def test_repeated_interrupt_during_cancellation(self) -> None:
        """Verify repeated interrupt during cancellation still yields ScanInterruptedError."""
        def interrupt_scanner(target: str, port: int, timeout: float) -> ScanResult:
            if port == 80:
                return ScanResult(port=80, state=PortState.OPEN, service="http", reason="Connection established")
            raise KeyboardInterrupt()

        original_perf = time.perf_counter
        call_count = 0

        def flaky_perf_counter() -> float:
            nonlocal call_count
            call_count += 1
            # Raise KeyboardInterrupt when calculating elapsed time inside except KeyboardInterrupt block
            if call_count == 3:
                raise KeyboardInterrupt()
            return original_perf()

        with patch("netprobe.scanner.scan_single_port", side_effect=interrupt_scanner):
            with patch("time.perf_counter", side_effect=flaky_perf_counter):
                scanner = TCPScanner(target="127.0.0.1", timeout=0.5, max_workers=1)
                with pytest.raises(ScanInterruptedError) as exc_info:
                    scanner.scan([80, 443])

                err = exc_info.value
                assert err.summary.interrupted is True
                assert err.summary.open_count == 1
                assert len(err.summary.results) == 1
                assert err.summary.results[0].port == 80

    @patch("netprobe.scanner.scan_single_port")
    def test_keyboard_interrupt_handling(self, mock_scan: MagicMock) -> None:
        mock_scan.side_effect = KeyboardInterrupt()
        scanner = TCPScanner(target="127.0.0.1", timeout=0.5, max_workers=2)

        with pytest.raises(KeyboardInterrupt):
            scanner.scan([80, 443])


class TestCLI:
    """Test CLI parsing, output presentation, and error handling."""

    def test_parser_defaults(self) -> None:
        parser = create_parser()
        args = parser.parse_args(["127.0.0.1"])
        assert args.target == "127.0.0.1"
        assert args.ports == "1-1024"
        assert args.timeout == 1.0
        assert args.workers == 100
        assert not args.show_all

    def test_parser_custom_args(self) -> None:
        parser = create_parser()
        args = parser.parse_args([
            "192.168.1.1",
            "--ports", "22,80,443",
            "--timeout", "0.5",
            "--workers", "50",
            "--all",
        ])
        assert args.target == "192.168.1.1"
        assert args.ports == "22,80,443"
        assert args.timeout == 0.5
        assert args.workers == 50
        assert args.show_all is True

    def test_main_invalid_target(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["not_an_ip"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Target validation failed" in captured.err

    def test_main_invalid_ports(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["127.0.0.1", "--ports", "abc"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Port parsing failed" in captured.err

    def test_main_invalid_timeout(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["127.0.0.1", "--timeout", "0.001"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Configuration error" in captured.err

    def test_main_successful_scan(self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
        mock_summary = ScanSummary(
            target="127.0.0.1",
            total_ports=2,
            open_count=1,
            closed_count=1,
            unknown_count=0,
            elapsed_seconds=0.15,
            results=[
                ScanResult(port=22, state=PortState.CLOSED, service="ssh", reason="Connection refused (RST)"),
                ScanResult(port=80, state=PortState.OPEN, service="http", reason="Connection established"),
            ],
        )

        with patch.object(TCPScanner, "scan", return_value=mock_summary):
            exit_code = main(["127.0.0.1", "--ports", "22,80"])
            assert exit_code == 0
            captured = capsys.readouterr()
            assert "NetProbe v" in captured.out
            assert "22/tcp" in captured.out
            assert "80/tcp" in captured.out
            assert "Open Ports:      1" in captured.out
            assert "Closed Ports:    1" in captured.out

    def test_main_interrupted_scan(self, capsys: pytest.CaptureFixture[str]) -> None:
        with patch.object(TCPScanner, "scan", side_effect=KeyboardInterrupt()):
            exit_code = main(["127.0.0.1", "--ports", "80"])
            assert exit_code == 130
            captured = capsys.readouterr()
            assert "Scan interrupted by operator" in captured.err

    def test_main_interrupted_scan_shows_partial_results(self, capsys: pytest.CaptureFixture[str]) -> None:
        partial_summary = ScanSummary(
            target="127.0.0.1",
            total_ports=3,
            open_count=1,
            closed_count=0,
            unknown_count=0,
            elapsed_seconds=0.1,
            results=[
                ScanResult(port=80, state=PortState.OPEN, service="http", reason="Connection established")
            ],
            interrupted=True,
        )
        with patch.object(TCPScanner, "scan", side_effect=ScanInterruptedError(partial_summary)):
            exit_code = main(["127.0.0.1", "--ports", "80,443,8080"])
            assert exit_code == 130
            captured = capsys.readouterr()
            assert "Scan interrupted by operator" in captured.err
            assert "80/tcp" in captured.out
            assert "Partial Scan Summary:" in captured.out
            assert "Completed:       1" in captured.out

    def test_main_interrupted_scan_no_completed_results(self, capsys: pytest.CaptureFixture[str]) -> None:
        empty_partial = ScanSummary(
            target="127.0.0.1",
            total_ports=2,
            open_count=0,
            closed_count=0,
            unknown_count=0,
            elapsed_seconds=0.01,
            results=[],
            interrupted=True,
        )
        with patch.object(TCPScanner, "scan", side_effect=ScanInterruptedError(empty_partial)):
            exit_code = main(["127.0.0.1", "--ports", "80,443"])
            assert exit_code == 130
            captured = capsys.readouterr()
            assert "No ports completed before interruption" in captured.out

    def test_main_repeated_interrupt_during_rendering(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Verify second interrupt during table rendering exits with 130 and warning without traceback."""
        partial = ScanSummary(
            target="127.0.0.1",
            total_ports=2,
            open_count=1,
            closed_count=0,
            unknown_count=0,
            elapsed_seconds=0.05,
            results=[
                ScanResult(port=80, state=PortState.OPEN, service="http", reason="Connection established")
            ],
            interrupted=True,
        )
        with patch.object(TCPScanner, "scan", side_effect=ScanInterruptedError(partial)):
            with patch("netprobe.cli.format_results_table", side_effect=KeyboardInterrupt()):
                exit_code = main(["127.0.0.1", "--ports", "80,443"])
                assert exit_code == 130
                captured = capsys.readouterr()
                assert "forcefully aborted" in captured.err

    def test_main_help_and_version(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code_help = main(["--help"])
        assert exit_code_help == 0
        captured_help = capsys.readouterr()
        assert "usage: netprobe" in captured_help.out

        exit_code_ver = main(["--version"])
        assert exit_code_ver == 0
        captured_ver = capsys.readouterr()
        assert "NetProbe" in captured_ver.out

    def test_main_runtime_scan_exception(self, capsys: pytest.CaptureFixture[str]) -> None:
        with patch.object(TCPScanner, "scan", side_effect=RuntimeError("Socket descriptor failure")):
            exit_code = main(["127.0.0.1", "--ports", "80"])
            assert exit_code == 2
            captured = capsys.readouterr()
            assert "Unexpected error during scan" in captured.err

    def test_format_results_table_empty(self) -> None:
        summary = ScanSummary(
            target="127.0.0.1",
            total_ports=0,
            open_count=0,
            closed_count=0,
            unknown_count=0,
            elapsed_seconds=0.01,
            results=[],
        )
        table = format_results_table(summary)
        assert "No open or responsive ports identified." in table

    def test_parse_ports_whitespace_and_excessive_tokens(self) -> None:
        assert parse_ports("  22 ,  80 , 443 - 445  ") == [22, 80, 443, 444, 445]

        # Excessive token rejection
        excessive = ",".join(str(i) for i in range(1, 65538))
        with pytest.raises(ValueError, match="exceeds maximum allowed elements"):
            parse_ports(excessive)

    def test_format_results_table_filtering(self) -> None:
        # Create 60 dummy results: 1 open, 59 closed
        results = [
            ScanResult(port=80, state=PortState.OPEN, service="http", reason="Connection established")
        ] + [
            ScanResult(port=p, state=PortState.CLOSED, service="unknown", reason="Connection refused (RST)")
            for p in range(100, 159)
        ]
        summary = ScanSummary(
            target="127.0.0.1",
            total_ports=60,
            open_count=1,
            closed_count=59,
            unknown_count=0,
            elapsed_seconds=1.0,
            results=results,
        )

        table_default = format_results_table(summary, show_all=False)
        assert "80/tcp" in table_default
        assert "closed ports hidden" in table_default
        assert "100/tcp" not in table_default

        table_all = format_results_table(summary, show_all=True)
        assert "80/tcp" in table_all
        assert "100/tcp" in table_all
        assert "closed ports hidden" not in table_all
