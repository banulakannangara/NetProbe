"""Unit and integration tests for NetProbe Phase 4A UDP scanning foundation."""

import errno
import json
from pathlib import Path
import socket
import struct
from unittest.mock import MagicMock, patch

import pytest

from netprobe.cli import create_parser, main
from netprobe.export import (
    scan_summary_to_dict,
    udp_scan_result_to_dict,
    udp_scan_summary_to_dict,
    udp_scan_summary_to_json,
)
from netprobe.scanner import PortState, ScanResult, ScanSummary
from netprobe.udp import (
    UDPPortState,
    UDPScanInterruptedError,
    UDPScanResult,
    UDPScanSummary,
    UDPScanner,
    probe_udp_port,
)
from netprobe.udp_probes import (
    UDPProtocolInfo,
    build_dns_query,
    build_ntp_request,
    build_snmp_get_request,
    encode_dns_name,
    validate_dns_response,
    validate_ntp_response,
    validate_snmp_response,
    _encode_ber_integer,
    _encode_ber_length,
    _read_ber_integer,
    _read_ber_oid,
    _read_ber_tlv,
)


class TestUDPModels:
    """Tests for UDPPortState enum and immutable dataclass models."""

    def test_udp_port_state_enum_values(self) -> None:
        assert UDPPortState.OPEN == "open"
        assert UDPPortState.CLOSED == "closed"
        assert UDPPortState.OPEN_FILTERED == "open_filtered"
        assert UDPPortState.UNKNOWN == "unknown"

        # Verify string subclassing
        assert isinstance(UDPPortState.OPEN, str)
        assert isinstance(UDPPortState.CLOSED, str)
        assert isinstance(UDPPortState.OPEN_FILTERED, str)
        assert isinstance(UDPPortState.UNKNOWN, str)

    def test_udp_scan_result_immutability_and_defaults(self) -> None:
        res = UDPScanResult(
            port=53,
            state=UDPPortState.OPEN,
            service="dns",
            reason="Received UDP response",
        )
        assert res.port == 53
        assert res.state == UDPPortState.OPEN
        assert res.service == "dns"
        assert res.reason == "Received UDP response"
        assert res.response_bytes is None

        # Verify frozen immutability
        with pytest.raises(Exception):
            res.port = 80  # type: ignore

    def test_udp_scan_result_positional_compatibility_with_scan_result(self) -> None:
        # Both take (port, state, service, reason) positionally
        udp_res = UDPScanResult(123, UDPPortState.OPEN, "ntp", "Response")
        tcp_res = ScanResult(123, PortState.OPEN, "ntp", "Response")

        assert udp_res.port == tcp_res.port
        assert udp_res.service == tcp_res.service
        assert udp_res.reason == tcp_res.reason

    def test_udp_scan_summary_immutability(self) -> None:
        summary = UDPScanSummary(
            target="127.0.0.1",
            total_ports=2,
            open_count=1,
            closed_count=0,
            open_filtered_count=1,
            unknown_count=0,
            elapsed_seconds=0.12,
            results=[
                UDPScanResult(53, UDPPortState.OPEN, "dns", "Response"),
                UDPScanResult(123, UDPPortState.OPEN_FILTERED, "ntp", "Timeout"),
            ],
            interrupted=False,
            resolved_target="127.0.0.1",
        )
        assert summary.open_filtered_count == 1
        assert summary.open_count == 1
        assert summary.total_ports == 2
        assert summary.interrupted is False

        with pytest.raises(Exception):
            summary.open_count = 5  # type: ignore

    def test_udp_scan_interrupted_error_inheritance(self) -> None:
        summary = UDPScanSummary(
            target="127.0.0.1",
            total_ports=1,
            open_count=0,
            closed_count=0,
            open_filtered_count=1,
            unknown_count=0,
            elapsed_seconds=0.05,
            results=[],
            interrupted=True,
        )
        err = UDPScanInterruptedError(summary)
        assert isinstance(err, KeyboardInterrupt)
        assert err.summary == summary


class TestUDPProbingAndClassification:
    """Tests for single-port UDP probing and state classification rules."""

    def test_probe_open_on_valid_udp_response(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"\x00\x01\x81\x80\x00\x01"

        with patch("socket.socket", return_value=mock_sock):
            result = probe_udp_port("127.0.0.1", 53, timeout=1.0)
            assert result.port == 53
            assert result.state == UDPPortState.OPEN
            assert result.service == "dns"
            assert "Received UDP response (6 bytes)" in result.reason
            assert result.response_bytes == b"\x00\x01\x81\x80\x00\x01"
            mock_sock.close.assert_called_once()

    def test_probe_timeout_classified_open_filtered(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = socket.timeout("timed out")

        with patch("socket.socket", return_value=mock_sock):
            result = probe_udp_port("127.0.0.1", 123, timeout=1.0)
            assert result.port == 123
            # Crucial requirement: timeout must produce OPEN_FILTERED, NOT CLOSED!
            assert result.state == UDPPortState.OPEN_FILTERED
            assert result.state != UDPPortState.CLOSED
            assert "No response received (open or filtered)" in result.reason
            mock_sock.close.assert_called_once()

    def test_probe_timeouterror_classified_open_filtered(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = TimeoutError("operation timed out")

        with patch("socket.socket", return_value=mock_sock):
            result = probe_udp_port("127.0.0.1", 161, timeout=1.0)
            assert result.state == UDPPortState.OPEN_FILTERED
            mock_sock.close.assert_called_once()

    def test_probe_connection_refused_classified_closed(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused")

        with patch("socket.socket", return_value=mock_sock):
            result = probe_udp_port("127.0.0.1", 9999, timeout=1.0)
            assert result.state == UDPPortState.CLOSED
            assert "ICMP port unreachable" in result.reason
            mock_sock.close.assert_called_once()

    def test_probe_connection_reset_classified_closed(self) -> None:
        # WSAECONNRESET on Windows arrives as ConnectionResetError
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = ConnectionResetError(10054, "An existing connection was forcibly closed")

        with patch("socket.socket", return_value=mock_sock):
            result = probe_udp_port("127.0.0.1", 9999, timeout=1.0)
            assert result.state == UDPPortState.CLOSED
            assert "ICMP port unreachable" in result.reason
            mock_sock.close.assert_called_once()

    def test_probe_econnrefused_errno_classified_closed(self) -> None:
        mock_sock = MagicMock()
        err = OSError()
        err.errno = errno.ECONNREFUSED
        mock_sock.recv.side_effect = err

        with patch("socket.socket", return_value=mock_sock):
            result = probe_udp_port("127.0.0.1", 9999, timeout=1.0)
            assert result.state == UDPPortState.CLOSED
            mock_sock.close.assert_called_once()

    def test_probe_generic_oserror_classified_unknown_not_closed(self) -> None:
        mock_sock = MagicMock()
        # Permission denied or host unreachable must NOT be classified closed
        err = OSError(errno.EACCES, "Permission denied")
        mock_sock.recv.side_effect = err

        with patch("socket.socket", return_value=mock_sock):
            result = probe_udp_port("127.0.0.1", 53, timeout=1.0)
            assert result.state == UDPPortState.UNKNOWN
            assert result.state != UDPPortState.CLOSED
            assert "Network or socket error" in result.reason
            mock_sock.close.assert_called_once()

    def test_probe_socket_cleanup_guarantee_on_exception(self) -> None:
        mock_sock = MagicMock()
        mock_sock.send.side_effect = RuntimeError("Fatal socket fault")

        with patch("socket.socket", return_value=mock_sock):
            with pytest.raises(RuntimeError):
                probe_udp_port("127.0.0.1", 53, timeout=1.0)
            mock_sock.close.assert_called_once()


class TestUDPScannerExecution:
    """Tests for bounded multi-threaded UDPScanner."""

    def test_scanner_constructor_validations(self) -> None:
        # Invalid target
        with pytest.raises(ValueError, match="Invalid IPv4 address"):
            UDPScanner("invalid_target")

        # Invalid timeout
        with pytest.raises(ValueError, match="Timeout must be between"):
            UDPScanner("127.0.0.1", timeout=0.01)

        with pytest.raises(ValueError, match="Timeout must be between"):
            UDPScanner("127.0.0.1", timeout=100.0)

        # Invalid workers
        with pytest.raises(ValueError, match="Workers must be an integer between 1 and 100"):
            UDPScanner("127.0.0.1", max_workers=0)

        with pytest.raises(ValueError, match="Workers must be an integer between 1 and 100"):
            UDPScanner("127.0.0.1", max_workers=101)

    def test_scanner_empty_ports_rejected(self) -> None:
        scanner = UDPScanner("127.0.0.1")
        with pytest.raises(ValueError, match="No ports provided"):
            scanner.scan([])

    def test_scanner_deterministic_port_ordering(self) -> None:
        scanner = UDPScanner("127.0.0.1", max_workers=2)

        def mock_probe(target: str, port: int, timeout: float) -> UDPScanResult:
            if port == 53:
                return UDPScanResult(53, UDPPortState.OPEN, "dns", "Resp")
            elif port == 67:
                return UDPScanResult(67, UDPPortState.OPEN_FILTERED, "dhcp", "Timeout")
            else:
                return UDPScanResult(123, UDPPortState.CLOSED, "ntp", "Refused")

        with patch("netprobe.udp.probe_udp_port", side_effect=mock_probe):
            # Pass out of order
            summary = scanner.scan([123, 53, 67])
            assert [r.port for r in summary.results] == [53, 67, 123]
            assert summary.open_count == 1
            assert summary.open_filtered_count == 1
            assert summary.closed_count == 1
            assert summary.total_ports == 3
            assert summary.interrupted is False

    def test_scanner_callback_invoked_for_each_result(self) -> None:
        scanner = UDPScanner("127.0.0.1", max_workers=2)
        called_ports: list[int] = []

        def mock_probe(target: str, port: int, timeout: float) -> UDPScanResult:
            return UDPScanResult(port, UDPPortState.OPEN_FILTERED, "svc", "Timeout")

        with patch("netprobe.udp.probe_udp_port", side_effect=mock_probe):
            scanner.scan([53, 123], callback=lambda r: called_ports.append(r.port))
            assert sorted(called_ports) == [53, 123]

    def test_scanner_unexpected_worker_exception_becomes_unknown(self) -> None:
        scanner = UDPScanner("127.0.0.1", max_workers=1)

        with patch("netprobe.udp.probe_udp_port", side_effect=ValueError("Unexpected worker crash")):
            summary = scanner.scan([53])
            assert len(summary.results) == 1
            assert summary.results[0].state == UDPPortState.UNKNOWN
            assert "Scan error" in summary.results[0].reason
            assert summary.unknown_count == 1

    def test_scanner_keyboard_interrupt_raises_interrupted_error_with_partial_results(self) -> None:
        scanner = UDPScanner("127.0.0.1", max_workers=1)

        def mock_probe(target: str, port: int, timeout: float) -> UDPScanResult:
            if port == 53:
                return UDPScanResult(53, UDPPortState.OPEN, "dns", "Resp")
            raise KeyboardInterrupt()

        with patch("netprobe.udp.probe_udp_port", side_effect=mock_probe):
            with pytest.raises(UDPScanInterruptedError) as exc_info:
                scanner.scan([53, 123])

            partial = exc_info.value.summary
            assert partial.interrupted is True
            assert partial.total_ports == 2
            assert len(partial.results) >= 1
            assert partial.results[0].port == 53
            assert partial.results[0].state == UDPPortState.OPEN


class TestUDPSerialization:
    """Tests for UDP serialization and export helpers."""

    def test_udp_scan_result_and_summary_to_dict(self) -> None:
        res = UDPScanResult(53, UDPPortState.OPEN, "dns", "Response received")
        res_dict = udp_scan_result_to_dict(res)
        assert res_dict == {
            "port": 53,
            "state": "open",
            "service": "dns",
            "reason": "Response received",
        }

        summary = UDPScanSummary(
            target="example.com",
            total_ports=2,
            open_count=1,
            closed_count=0,
            open_filtered_count=1,
            unknown_count=0,
            elapsed_seconds=0.12345,
            results=[
                res,
                UDPScanResult(123, UDPPortState.OPEN_FILTERED, "ntp", "Timeout"),
            ],
            interrupted=False,
            resolved_target="192.168.1.1",
        )
        d = udp_scan_summary_to_dict(summary)
        assert d["mode"] == "udp"
        assert d["target"] == "example.com"
        assert d["resolved_target"] == "192.168.1.1"
        assert d["open_count"] == 1
        assert d["closed_count"] == 0
        assert d["open_filtered_count"] == 1
        assert d["unknown_count"] == 0
        assert d["elapsed_seconds"] == 0.1235
        assert d["interrupted"] is False
        assert len(d["results"]) == 2

    def test_udp_scan_summary_to_json(self) -> None:
        summary = UDPScanSummary(
            target="127.0.0.1",
            total_ports=1,
            open_count=0,
            closed_count=1,
            open_filtered_count=0,
            unknown_count=0,
            elapsed_seconds=0.05,
            results=[UDPScanResult(9999, UDPPortState.CLOSED, "unknown", "ICMP port unreachable")],
            interrupted=False,
        )
        json_doc = udp_scan_summary_to_json(summary)
        loaded = json.loads(json_doc)
        assert loaded["mode"] == "udp"
        assert loaded["results"][0]["state"] == "closed"

    def test_tcp_scan_summary_schema_backward_compatibility(self) -> None:
        # Verify that existing TCP scan serialization remains 100% backward-compatible
        tcp_summary = ScanSummary(
            target="127.0.0.1",
            total_ports=1,
            open_count=1,
            closed_count=0,
            unknown_count=0,
            elapsed_seconds=0.1,
            results=[ScanResult(80, PortState.OPEN, "http", "Established")],
            interrupted=False,
        )
        d = scan_summary_to_dict(tcp_summary)
        # TCP schema should NOT have "mode": "udp"
        assert "mode" not in d
        assert d["target"] == "127.0.0.1"
        assert "open_count" in d


class TestUDPCLI:
    """Deterministic tests for CLI --udp option, execution, and outputs."""

    def test_parser_udp_flag_defaults(self) -> None:
        parser = create_parser()
        args_default = parser.parse_args(["127.0.0.1"])
        assert args_default.udp is False

        args_udp = parser.parse_args(["127.0.0.1", "--udp"])
        assert args_udp.udp is True

        args_short = parser.parse_args(["127.0.0.1", "-u"])
        assert args_short.udp is True

    def test_udp_missing_target_returns_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["--udp"])
        assert exit_code == 2
        captured = capsys.readouterr()
        assert "Target host is required" in captured.err

    def test_udp_conflicting_with_discover_rejected(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["--discover", "192.168.1.0/24", "--udp"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "UDP scanning is not supported in subnet discovery mode" in captured.err

    def test_udp_invalid_target_returns_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["invalid_host_name_!!!", "--udp"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Target validation failed" in captured.err

    def test_udp_invalid_ports_returns_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["127.0.0.1", "--udp", "-p", "invalid"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Port parsing failed" in captured.err

    def test_udp_invalid_output_path_rejected_before_scanning(
        self, capsys: pytest.CaptureFixture[str], tmp_path: Path
    ) -> None:
        bad_path = str(tmp_path / "nonexistent_dir" / "out.txt")
        exit_code = main(["127.0.0.1", "--udp", "-p", "53", "-o", bad_path])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Output file validation failed" in captured.err

    def test_successful_udp_table_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        dummy_summary = UDPScanSummary(
            target="127.0.0.1",
            total_ports=2,
            open_count=1,
            closed_count=0,
            open_filtered_count=1,
            unknown_count=0,
            elapsed_seconds=0.25,
            results=[
                UDPScanResult(53, UDPPortState.OPEN, "dns", "Received UDP response (12 bytes)"),
                UDPScanResult(123, UDPPortState.OPEN_FILTERED, "ntp", "No response received (open or filtered)"),
            ],
            interrupted=False,
        )

        with patch.object(UDPScanner, "scan", return_value=dummy_summary):
            exit_code = main(["127.0.0.1", "--udp", "-p", "53,123"])
            assert exit_code == 0
            captured = capsys.readouterr()
            assert "UDP Network Auditor" in captured.out
            assert "53/udp" in captured.out
            assert "OPEN" in captured.out
            assert "123/udp" in captured.out
            assert "OPEN_FILTERED" in captured.out
            assert "UDP Scan Summary:" in captured.out
            assert "Open|Filtered:   1" in captured.out

    def test_udp_auto_filtering_over_50_closed_ports(self, capsys: pytest.CaptureFixture[str]) -> None:
        results = [
            UDPScanResult(53, UDPPortState.OPEN, "dns", "Received response"),
        ] + [
            UDPScanResult(p, UDPPortState.CLOSED, "unknown", "ICMP port unreachable")
            for p in range(100, 160)
        ]
        summary = UDPScanSummary(
            target="127.0.0.1",
            total_ports=61,
            open_count=1,
            closed_count=60,
            open_filtered_count=0,
            unknown_count=0,
            elapsed_seconds=0.4,
            results=results,
            interrupted=False,
        )

        with patch.object(UDPScanner, "scan", return_value=summary):
            # 1. Default hides closed ports
            exit_code = main(["127.0.0.1", "--udp", "-p", "53,100-159"])
            assert exit_code == 0
            captured = capsys.readouterr()
            assert "53/udp" in captured.out
            assert "100/udp" not in captured.out
            assert "60 closed ports hidden" in captured.out

            # 2. Run with --all shows all ports
            exit_code_all = main(["127.0.0.1", "--udp", "-p", "53,100-159", "--all"])
            assert exit_code_all == 0
            captured_all = capsys.readouterr()
            assert "53/udp" in captured_all.out
            assert "100/udp" in captured_all.out
            assert "closed ports hidden" not in captured_all.out

    def test_successful_udp_json_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        dummy_summary = UDPScanSummary(
            target="127.0.0.1",
            total_ports=1,
            open_count=0,
            closed_count=0,
            open_filtered_count=1,
            unknown_count=0,
            elapsed_seconds=0.1,
            results=[UDPScanResult(53, UDPPortState.OPEN_FILTERED, "dns", "No response")],
            interrupted=False,
        )

        with patch.object(UDPScanner, "scan", return_value=dummy_summary):
            exit_code = main(["127.0.0.1", "--udp", "-p", "53", "--json"])
            assert exit_code == 0
            captured = capsys.readouterr()
            doc = json.loads(captured.out)
            assert doc["mode"] == "udp"
            assert doc["target"] == "127.0.0.1"
            assert doc["open_filtered_count"] == 1
            assert doc["results"][0]["port"] == 53
            assert doc["results"][0]["state"] == "open_filtered"

    def test_udp_json_file_export_suppresses_stdout(
        self, capsys: pytest.CaptureFixture[str], tmp_path: Path
    ) -> None:
        dummy_summary = UDPScanSummary(
            target="127.0.0.1",
            total_ports=1,
            open_count=1,
            closed_count=0,
            open_filtered_count=0,
            unknown_count=0,
            elapsed_seconds=0.08,
            results=[UDPScanResult(123, UDPPortState.OPEN, "ntp", "Resp")],
            interrupted=False,
        )

        out_json = tmp_path / "udp_out.json"
        with patch.object(UDPScanner, "scan", return_value=dummy_summary):
            exit_code = main(["127.0.0.1", "--udp", "-p", "123", "--json", "-o", str(out_json)])
            assert exit_code == 0
            captured = capsys.readouterr()
            assert captured.out == ""
            assert out_json.exists()
            data = json.loads(out_json.read_text(encoding="utf-8"))
            assert data["mode"] == "udp"
            assert data["open_count"] == 1

    def test_interrupted_udp_scan_returns_exit_code_130_with_partial_results(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        partial_summary = UDPScanSummary(
            target="127.0.0.1",
            total_ports=2,
            open_count=1,
            closed_count=0,
            open_filtered_count=0,
            unknown_count=0,
            elapsed_seconds=0.05,
            results=[UDPScanResult(53, UDPPortState.OPEN, "dns", "Resp")],
            interrupted=True,
        )

        with patch.object(UDPScanner, "scan", side_effect=UDPScanInterruptedError(partial_summary)):
            exit_code = main(["127.0.0.1", "--udp", "-p", "53,123"])
            assert exit_code == 130
            captured = capsys.readouterr()
            assert "UDP scan interrupted by operator" in captured.err
            assert "Partial UDP Scan Summary (Interrupted):" in captured.out
            assert "53/udp" in captured.out

    def test_interrupted_udp_scan_json_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        partial_summary = UDPScanSummary(
            target="127.0.0.1",
            total_ports=2,
            open_count=1,
            closed_count=0,
            open_filtered_count=0,
            unknown_count=0,
            elapsed_seconds=0.05,
            results=[UDPScanResult(53, UDPPortState.OPEN, "dns", "Resp")],
            interrupted=True,
        )

        with patch.object(UDPScanner, "scan", side_effect=UDPScanInterruptedError(partial_summary)):
            exit_code = main(["127.0.0.1", "--udp", "-p", "53,123", "--json"])
            assert exit_code == 130
            captured = capsys.readouterr()
            assert "UDP scan interrupted by operator" in captured.err
            doc = json.loads(captured.out)
            assert doc["mode"] == "udp"
            assert doc["interrupted"] is True
            assert doc["open_count"] == 1
            assert len(doc["results"]) == 1

    def test_regression_tcp_default_unchanged(self, capsys: pytest.CaptureFixture[str]) -> None:
        dummy_tcp_summary = ScanSummary(
            target="127.0.0.1",
            total_ports=1,
            open_count=1,
            closed_count=0,
            unknown_count=0,
            elapsed_seconds=0.05,
            results=[ScanResult(80, PortState.OPEN, "http", "Established")],
            interrupted=False,
        )

        with patch("netprobe.scanner.TCPScanner.scan", return_value=dummy_tcp_summary):
            # Normal invocation without --udp remains TCP
            exit_code = main(["127.0.0.1", "-p", "80"])
            assert exit_code == 0
            captured = capsys.readouterr()
            assert "TCP Network Auditor" in captured.out
            assert "80/tcp" in captured.out
            assert "Scan Summary:" in captured.out


class TestDNSProbe:
    """Deterministic tests for DNS query construction and response validation."""

    def test_encode_dns_name_valid(self) -> None:
        encoded = encode_dns_name("example.com")
        assert encoded == b"\x07example\x03com\x00"

        root_encoded = encode_dns_name("")
        assert root_encoded == b"\x00"

    def test_encode_dns_name_invalid_limits(self) -> None:
        # Label > 63 bytes
        long_label = "a" * 64 + ".com"
        with pytest.raises(ValueError, match="exceeds maximum length of 63"):
            encode_dns_name(long_label)

        # Name > 253 characters
        long_name = ".".join(["abc" for _ in range(70)])
        with pytest.raises(ValueError, match="exceeds maximum allowed length"):
            encode_dns_name(long_name)

        # Consecutive dots
        with pytest.raises(ValueError, match="consecutive dots or empty label"):
            encode_dns_name("example..com")

        # Invalid characters
        with pytest.raises(ValueError, match="contains invalid characters"):
            encode_dns_name("example$.com")

    def test_build_dns_query_structure(self) -> None:
        query, tx_id = build_dns_query("example.com", tx_id=0x1234)
        assert tx_id == 0x1234
        # Header (12 bytes) + \x07example\x03com\x00 (13 bytes) + QTYPE(2) + QCLASS(2) = 29 bytes
        assert len(query) == 29

        rx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", query[:12])
        assert rx_id == 0x1234
        assert flags == 0x0100  # RD = 1
        assert qdcount == 1
        assert ancount == 0
        assert nscount == 0
        assert arcount == 0

        # Verify question trailer
        qtype, qclass = struct.unpack("!HH", query[-4:])
        assert qtype == 1  # A
        assert qclass == 1  # IN

    def test_build_dns_query_invalid_tx_id(self) -> None:
        with pytest.raises(ValueError, match="Transaction ID must be an integer between 0 and 65535"):
            build_dns_query("example.com", tx_id=-1)

        with pytest.raises(ValueError, match="Transaction ID must be an integer between 0 and 65535"):
            build_dns_query("example.com", tx_id=70000)

    def test_validate_dns_response_valid_noerror(self) -> None:
        tx_id = 0xABCD
        # Flags: QR=1 (0x8000), RD=1 (0x0100), RA=1 (0x0080) -> 0x8180
        flags = 0x8180
        qdcount = 1
        ancount = 1
        nscount = 0
        arcount = 0
        header = struct.pack("!HHHHHH", tx_id, flags, qdcount, ancount, nscount, arcount)
        question = encode_dns_name("example.com") + struct.pack("!HH", 1, 1)
        # Name pointer to offset 12: 0xC00C
        # TYPE=1 (A), CLASS=1 (IN), TTL=300, RDLENGTH=4, RDATA=4 bytes
        answer = b"\xC0\x0C" + struct.pack("!HHIH4s", 1, 1, 300, 4, socket.inet_aton("1.2.3.4"))
        packet = header + question + answer

        verified, details, meta = validate_dns_response(packet, tx_id)
        assert verified is True
        assert "RCODE=NOERROR" in details
        assert "AN=1" in details
        assert meta["rcode"] == 0
        assert meta["ancount"] == 1

    def test_validate_dns_response_valid_error_rcode_is_verified(self) -> None:
        tx_id = 0x5555
        # Flags: QR=1, RCODE=3 (NXDOMAIN) -> 0x8183
        flags = 0x8183
        header = struct.pack("!HHHHHH", tx_id, flags, 1, 0, 0, 0)
        question = encode_dns_name("nonexistent.example") + struct.pack("!HH", 1, 1)
        packet = header + question

        verified, details, meta = validate_dns_response(packet, tx_id)
        # Valid DNS error response from live server is positive application proof
        assert verified is True
        assert "RCODE=NXDOMAIN" in details
        assert meta["rcode"] == 3
        assert meta["rcode_name"] == "NXDOMAIN"

    def test_validate_dns_response_mismatched_tx_id(self) -> None:
        tx_id = 0x1111
        header = struct.pack("!HHHHHH", 0x9999, 0x8180, 1, 0, 0, 0)
        question = encode_dns_name("example.com") + struct.pack("!HH", 1, 1)
        packet = header + question

        verified, details, _ = validate_dns_response(packet, tx_id)
        assert verified is False
        assert "Transaction ID mismatch" in details

    def test_validate_dns_response_qr_bit_not_set(self) -> None:
        tx_id = 0x2222
        # QR bit = 0 (Query packet, not response)
        flags = 0x0100
        header = struct.pack("!HHHHHH", tx_id, flags, 1, 0, 0, 0)
        packet = header + encode_dns_name("example.com") + struct.pack("!HH", 1, 1)

        verified, details, _ = validate_dns_response(packet, tx_id)
        assert verified is False
        assert "QR bit is 0" in details

    def test_validate_dns_response_too_short(self) -> None:
        verified, details, _ = validate_dns_response(b"\x00\x01\x02", 0x1234)
        assert verified is False
        assert "too short" in details

    def test_validate_dns_response_truncated_flag(self) -> None:
        tx_id = 0x3333
        # QR=1, TC=1 (0x8200)
        flags = 0x8200
        header = struct.pack("!HHHHHH", tx_id, flags, 1, 0, 0, 0)
        packet = header + encode_dns_name("example.com") + struct.pack("!HH", 1, 1)

        verified, details, meta = validate_dns_response(packet, tx_id)
        # TC bit means the response was truncated by the server and cannot be verified as complete
        assert verified is False
        assert meta["truncated"] is True
        assert "TC bit set" in details

    def test_validate_dns_response_missing_answer_rrs_rejected(self) -> None:
        tx_id = 0x4444
        # Declares 2 answers, but packet only contains 29 bytes of header + question
        header = struct.pack("!HHHHHH", tx_id, 0x8180, 1, 2, 0, 0)
        question = encode_dns_name("example.com") + struct.pack("!HH", 1, 1)
        packet = header + question

        verified, details, meta = validate_dns_response(packet, tx_id)
        assert verified is False
        assert "Answer record" in details

    def test_validate_dns_response_incomplete_rr_fixed_fields(self) -> None:
        tx_id = 0x4445
        header = struct.pack("!HHHHHH", tx_id, 0x8180, 1, 1, 0, 0)
        question = encode_dns_name("example.com") + struct.pack("!HH", 1, 1)
        # Owner name pointer (\xC0\x0C) followed by only 4 bytes instead of 10-byte fixed header
        truncated_rr = b"\xC0\x0C\x00\x01\x00\x01"
        packet = header + question + truncated_rr

        verified, details, _ = validate_dns_response(packet, tx_id)
        assert verified is False
        assert "Incomplete fixed fields" in details

    def test_validate_dns_response_incomplete_rdata(self) -> None:
        tx_id = 0x4446
        header = struct.pack("!HHHHHH", tx_id, 0x8180, 1, 1, 0, 0)
        question = encode_dns_name("example.com") + struct.pack("!HH", 1, 1)
        # 10 bytes fixed fields with declared rdlength=4, but only 2 bytes of RDATA provided
        rr = struct.pack("!HHIH", 1, 1, 300, 4) + b"\x01\x02"
        packet = header + question + b"\xC0\x0C" + rr

        verified, details, _ = validate_dns_response(packet, tx_id)
        assert verified is False
        assert "Truncated RDATA" in details

    def test_validate_dns_response_valid_compressed_owner_names(self) -> None:
        tx_id = 0x4447
        header = struct.pack("!HHHHHH", tx_id, 0x8180, 1, 2, 0, 0)
        question = encode_dns_name("example.com") + struct.pack("!HH", 1, 1)  # 29 bytes
        # Two valid answers using compression pointers to question name at offset 12
        ans1 = b"\xC0\x0C" + struct.pack("!HHIH4s", 1, 1, 300, 4, socket.inet_aton("1.2.3.4"))
        ans2 = b"\xC0\x0C" + struct.pack("!HHIH4s", 1, 1, 300, 4, socket.inet_aton("5.6.7.8"))
        packet = header + question + ans1 + ans2

        verified, details, meta = validate_dns_response(packet, tx_id)
        assert verified is True
        assert meta["ancount"] == 2
        assert "AN=2" in details

    def test_validate_dns_response_pointer_out_of_bounds(self) -> None:
        tx_id = 0x4448
        header = struct.pack("!HHHHHH", tx_id, 0x8180, 1, 1, 0, 0)
        question = encode_dns_name("example.com") + struct.pack("!HH", 1, 1)
        # Pointer 0xC0FF points to offset 255 which is out of bounds
        ans = b"\xC0\xFF" + struct.pack("!HHIH4s", 1, 1, 300, 4, socket.inet_aton("1.2.3.4"))
        packet = header + question + ans

        verified, details, _ = validate_dns_response(packet, tx_id)
        assert verified is False
        assert "Malformed owner name" in details

    def test_validate_dns_response_pointer_loop(self) -> None:
        tx_id = 0x4449
        header = struct.pack("!HHHHHH", tx_id, 0x8180, 1, 1, 0, 0)
        question = encode_dns_name("example.com") + struct.pack("!HH", 1, 1)  # ends at offset 29
        # Offset 29 pointer points to 29 (itself)
        ans = b"\xC0\x1D" + struct.pack("!HHIH4s", 1, 1, 300, 4, socket.inet_aton("1.2.3.4"))
        packet = header + question + ans

        verified, details, _ = validate_dns_response(packet, tx_id)
        assert verified is False
        assert "Malformed owner name" in details

    def test_validate_dns_response_inconsistent_section_counts(self) -> None:
        tx_id = 0x4450
        # Declares 1 answer and 1 authority, but packet omits the authority record
        header = struct.pack("!HHHHHH", tx_id, 0x8180, 1, 1, 1, 0)
        question = encode_dns_name("example.com") + struct.pack("!HH", 1, 1)
        ans = b"\xC0\x0C" + struct.pack("!HHIH4s", 1, 1, 300, 4, socket.inet_aton("1.2.3.4"))
        packet = header + question + ans

        verified, details, _ = validate_dns_response(packet, tx_id)
        assert verified is False
        assert "Authority record" in details


class TestNTPProbe:
    """Deterministic tests for NTP client request construction and response validation."""

    def test_build_ntp_request_structure(self) -> None:
        req = build_ntp_request(version=4)
        assert len(req) == 48
        # First byte: LI=0 (0), VN=4 (4<<3=32), Mode=3 (3) -> 35 (0x23)
        assert req[0] == 0x23
        assert req[1:] == b"\x00" * 47

        req3 = build_ntp_request(version=3)
        assert len(req3) == 48
        assert req3[0] == 0x1B  # (3<<3)|3 = 27 = 0x1B

    def test_build_ntp_request_invalid_version(self) -> None:
        with pytest.raises(ValueError, match="Unsupported NTP version"):
            build_ntp_request(version=2)

    def test_validate_ntp_response_valid_server(self) -> None:
        # First byte: LI=0, VN=4, Mode=4 (server) -> (4<<3)|4 = 36 (0x24)
        first_byte = 0x24
        stratum = 2
        poll = 6
        precision = -20
        header = bytes([first_byte, stratum, poll]) + struct.pack("!b", precision)
        packet = header + (b"\x00" * 44)  # Total 48 bytes

        verified, details, meta = validate_ntp_response(packet)
        assert verified is True
        assert "NTP v4 server response" in details
        assert "stratum 2" in details
        assert meta["vn"] == 4
        assert meta["mode"] == 4
        assert meta["stratum"] == 2

    def test_validate_ntp_response_valid_broadcast_mode(self) -> None:
        # Mode=5 (broadcast)
        first_byte = (0 << 6) | (4 << 3) | 5
        packet = bytes([first_byte, 1, 4, 0]) + (b"\x00" * 44)

        verified, details, meta = validate_ntp_response(packet)
        assert verified is True
        assert "broadcast response" in details
        assert meta["mode"] == 5

    def test_validate_ntp_response_too_short(self) -> None:
        verified, details, _ = validate_ntp_response(b"\x24\x02\x04")
        assert verified is False
        assert "too short" in details

    def test_validate_ntp_response_invalid_mode(self) -> None:
        # Mode=3 (client request, not a server response!)
        first_byte = (0 << 6) | (4 << 3) | 3
        packet = bytes([first_byte, 2, 4, 0]) + (b"\x00" * 44)

        verified, details, _ = validate_ntp_response(packet)
        assert verified is False
        assert "Invalid NTP mode" in details

    def test_validate_ntp_response_invalid_version(self) -> None:
        # VN=5 (invalid)
        first_byte = (0 << 6) | (5 << 3) | 4
        packet = bytes([first_byte, 2, 4, 0]) + (b"\x00" * 44)

        verified, details, _ = validate_ntp_response(packet)
        assert verified is False
        assert "Invalid NTP version" in details

    def test_validate_ntp_response_stratum_0_kiss_of_death(self) -> None:
        # LI=0, VN=4, Mode=4 (server) -> 0x24
        # Stratum=0 (Kiss-o'-Death), Poll=4, Precision=-20
        # Reference ID at bytes 12-16 = "RATE"
        header = bytes([0x24, 0, 4, 0xEC]) + (b"\x00" * 8) + b"RATE" + (b"\x00" * 32)
        verified, details, meta = validate_ntp_response(header)
        assert verified is True
        assert meta["stratum"] == 0
        assert meta["kiss_of_death"] is True
        assert meta["kiss_code"] == "RATE"
        assert meta["synchronized"] is False
        assert "Kiss-o'-Death" in details
        assert "RATE" in details

    def test_validate_ntp_response_leap_indicator_3_unsynchronized(self) -> None:
        # LI=3, VN=4, Mode=4 -> (3<<6)|(4<<3)|4 = 0xE4
        # Stratum=2, Poll=6, Precision=-20
        header = bytes([0xE4, 2, 6, 0xEC]) + (b"\x00" * 44)
        verified, details, meta = validate_ntp_response(header)
        assert verified is True
        assert meta["li"] == 3
        assert meta["leap_indicator"] == 3
        assert meta["synchronized"] is False
        assert meta["kiss_of_death"] is False
        assert "unsynchronized" in details
        assert "LI=3" in details


class TestSNMPProbe:
    """Deterministic tests for SNMP request construction and BER response validation."""

    def test_build_snmp_get_request_structure(self) -> None:
        req, req_id = build_snmp_get_request(community="public", req_id=0x12345678)
        assert req_id == 0x12345678
        assert req[0] == 0x30
        outer = _read_ber_tlv(req, 0)
        assert outer is not None
        tag, c_off, c_len, next_off = outer
        assert tag == 0x30
        assert next_off == len(req)

        # Version (INTEGER 0 for v1)
        ver_res = _read_ber_integer(req, c_off)
        assert ver_res is not None
        assert ver_res[0] == 0

        # Community string ("public")
        comm_tlv = _read_ber_tlv(req, ver_res[1])
        assert comm_tlv is not None
        assert comm_tlv[0] == 0x04  # OCTET STRING
        assert req[comm_tlv[1] : comm_tlv[1] + comm_tlv[2]] == b"public"

        # PDU tag (0xA0 GetRequest)
        pdu_tlv = _read_ber_tlv(req, comm_tlv[3])
        assert pdu_tlv is not None
        assert pdu_tlv[0] == 0xA0  # GetRequest-PDU

    def test_build_snmp_get_request_invalid_inputs(self) -> None:
        with pytest.raises(ValueError, match="Request ID must be an integer"):
            build_snmp_get_request(req_id=-1)
        with pytest.raises(ValueError, match="Request ID must be an integer"):
            build_snmp_get_request(req_id=0)
        with pytest.raises(ValueError, match="Community string cannot be empty"):
            build_snmp_get_request(community="")
        with pytest.raises(ValueError, match="Invalid OID"):
            build_snmp_get_request(oid="1")

    def test_ber_length_short_and_long_form(self) -> None:
        # Short form
        assert _read_ber_tlv(b"\x02\x05hello", 0) == (0x02, 2, 5, 7)
        # Long form 1 octet (130 bytes)
        long_1 = b"\x04\x81\x82" + (b"A" * 130)
        res_1 = _read_ber_tlv(long_1, 0)
        assert res_1 == (0x04, 3, 130, 133)
        # Long form 2 octets (300 bytes)
        long_2 = b"\x04\x82\x01\x2C" + (b"B" * 300)
        res_2 = _read_ber_tlv(long_2, 0)
        assert res_2 == (0x04, 4, 300, 304)

        # Indefinite length (0x80) rejected
        assert _read_ber_tlv(b"\x30\x80\x00\x00", 0) is None
        # Truncated length
        assert _read_ber_tlv(b"\x30\x82\x01", 0) is None
        # Oversized length octets (> 2 octets)
        assert _read_ber_tlv(b"\x30\x83\x01\x00\x00", 0) is None
        # Length exceeding packet bytes
        assert _read_ber_tlv(b"\x04\x0Aabc", 0) is None

    def test_ber_integer_decoding(self) -> None:
        # Valid zero
        assert _read_ber_integer(b"\x02\x01\x00", 0) == (0, 3)
        # Valid positive integers
        assert _read_ber_integer(b"\x02\x01\x01", 0) == (1, 3)
        assert _read_ber_integer(b"\x02\x01\x7F", 0) == (127, 3)
        # 128 requires leading 0x00 sign-protection octet because 0x80 has MSB 1
        assert _read_ber_integer(b"\x02\x02\x00\x80", 0) == (128, 4)
        assert _read_ber_integer(b"\x02\x02\x01\x00", 0) == (256, 4)
        # Valid negative integers
        assert _read_ber_integer(b"\x02\x01\xFF", 0) == (-1, 3)
        assert _read_ber_integer(b"\x02\x01\x80", 0) == (-128, 3)
        # -129 requires leading 0xFF sign-protection octet because 0x7F has MSB 0
        assert _read_ber_integer(b"\x02\x02\xFF\x7F", 0) == (-129, 4)

        # Redundant leading 0x00 for non-negative values rejected (non-minimal)
        assert _read_ber_integer(b"\x02\x02\x00\x00", 0) is None
        assert _read_ber_integer(b"\x02\x02\x00\x05", 0) is None
        assert _read_ber_integer(b"\x02\x02\x00\x7F", 0) is None
        assert _read_ber_integer(b"\x02\x03\x00\x00\x80", 0) is None

        # Redundant leading 0xFF for negative values rejected (non-minimal)
        assert _read_ber_integer(b"\x02\x02\xFF\xFF", 0) is None
        assert _read_ber_integer(b"\x02\x02\xFF\x80", 0) is None
        assert _read_ber_integer(b"\x02\x03\xFF\xFF\x7F", 0) is None

        # Malformed tag or length
        assert _read_ber_integer(b"\x04\x01\x00", 0) is None
        assert _read_ber_integer(b"\x02\x00", 0) is None
        # Oversized integer (> 8 bytes)
        assert _read_ber_integer(b"\x02\x09" + (b"\x01" * 9), 0) is None
        # Truncated content
        assert _read_ber_integer(b"\x02\x02\x01", 0) is None

    def test_ber_oid_decoding(self) -> None:
        # sysDescr.0 raw: \x2b\x06\x01\x02\x01\x01\x01\x00 -> 1.3.6.1.2.1.1.1.0
        oid_tlv = b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"
        res = _read_ber_oid(oid_tlv, 0)
        assert res is not None
        assert res[1] == "1.3.6.1.2.1.1.1.0"

        # Arc 0 with combined value < 40 (e.g. 0.25 -> 25)
        res_arc0 = _read_ber_oid(b"\x06\x01\x19", 0)
        assert res_arc0 is not None
        assert res_arc0[1] == "0.25"

        # Arc 1 with combined value between 40 and 79 (e.g. 1.2 -> 42)
        res_arc1 = _read_ber_oid(b"\x06\x01\x2A", 0)
        assert res_arc1 is not None
        assert res_arc1[1] == "1.2"

        # Multibyte first combined subidentifier (Arc 2 with combined value >= 80)
        # 2.100 -> combined = 80 + 100 = 180 -> base-128 VLQ: \x81\x34
        res_arc2 = _read_ber_oid(b"\x06\x02\x81\x34", 0)
        assert res_arc2 is not None
        assert res_arc2[1] == "2.100"

        # Multibyte subsequent subidentifier
        # 1.3.6.1000 -> 1000 = (7 << 7) | 104 -> \x87\x68
        res_sub = _read_ber_oid(b"\x06\x04\x2B\x06\x87\x68", 0)
        assert res_sub is not None
        assert res_sub[1] == "1.3.6.1000"

        # Incomplete VLQ multibyte encoding / unterminated continuation byte
        assert _read_ber_oid(b"\x06\x02\x2b\x86", 0) is None
        assert _read_ber_oid(b"\x06\x01\x81", 0) is None

        # Overflowing subidentifier exceeding 32-bit limit
        assert _read_ber_oid(b"\x06\x06\x2B\x88\x80\x80\x80\x80", 0) is None

        # Empty OID contents
        assert _read_ber_oid(b"\x06\x00", 0) is None

    @staticmethod
    def _build_mock_snmp_response(
        req_id: int,
        error_status: int = 0,
        error_index: int = 0,
        version: int = 0,
        community: bytes = b"public",
        pdu_tag: int = 0xA2,
        oid_bytes: bytes = b"\x2b\x06\x01\x02\x01\x01\x01\x00",
        val_tag: int = 0x04,
        val_bytes: bytes = b"Linux Server 6.1 NetProbe",
    ) -> bytes:
        # VarBind
        oid_tlv = b"\x06" + _encode_ber_length(len(oid_bytes)) + oid_bytes
        val_tlv = bytes([val_tag]) + _encode_ber_length(len(val_bytes)) + val_bytes
        vb_content = oid_tlv + val_tlv
        vb = b"\x30" + _encode_ber_length(len(vb_content)) + vb_content
        vblist = b"\x30" + _encode_ber_length(len(vb)) + vb

        # PDU
        req_id_tlv = _encode_ber_integer(req_id)
        err_stat_tlv = _encode_ber_integer(error_status)
        err_idx_tlv = _encode_ber_integer(error_index)
        pdu_content = req_id_tlv + err_stat_tlv + err_idx_tlv + vblist
        pdu = bytes([pdu_tag]) + _encode_ber_length(len(pdu_content)) + pdu_content

        # Outer message
        ver_tlv = _encode_ber_integer(version)
        comm_tlv = b"\x04" + _encode_ber_length(len(community)) + community
        msg_content = ver_tlv + comm_tlv + pdu
        return b"\x30" + _encode_ber_length(len(msg_content)) + msg_content

    def test_validate_snmp_response_valid_sysdescr(self) -> None:
        req_id = 0x55AA1122
        resp = self._build_mock_snmp_response(req_id, val_bytes=b"Cisco IOS Software 15.0")
        verified, details, meta = validate_snmp_response(resp, req_id)
        assert verified is True
        assert meta["version"] == "v1"
        assert meta["request_id"] == req_id
        assert meta["error_status"] == 0
        assert meta["sys_descr_oid"] is True
        assert meta["sys_descr"] == "Cisco IOS Software 15.0"
        assert "noError" in details
        assert "Cisco IOS Software 15.0" in details
        # Verify community string is never stored in metadata or details
        assert "public" not in str(meta)
        assert "public" not in details

    def test_validate_snmp_response_sysdescr_truncation(self) -> None:
        req_id = 0x1234
        long_descr = b"A" * 200
        resp = self._build_mock_snmp_response(req_id, val_bytes=long_descr)
        verified, details, meta = validate_snmp_response(resp, req_id)
        assert verified is True
        assert meta["sys_descr"] is not None
        assert len(meta["sys_descr"]) == 123  # 120 chars + "..."
        assert meta["sys_descr"].endswith("...")

    def test_validate_snmp_response_mismatched_request_id(self) -> None:
        resp = self._build_mock_snmp_response(req_id=100)
        verified, details, meta = validate_snmp_response(resp, expected_req_id=200)
        assert verified is False
        assert "request ID mismatch" in details
        assert meta["request_id"] == 100

    def test_validate_snmp_response_wrong_version(self) -> None:
        # Version 1 (SNMPv2c)
        resp = self._build_mock_snmp_response(req_id=100, version=1)
        verified, details, meta = validate_snmp_response(resp, expected_req_id=100)
        assert verified is False
        assert "Unsupported SNMP version" in details

    def test_validate_snmp_response_wrong_pdu_type(self) -> None:
        # PDU tag 0xA0 (GetRequest instead of GetResponse)
        resp = self._build_mock_snmp_response(req_id=100, pdu_tag=0xA0)
        verified, details, _ = validate_snmp_response(resp, expected_req_id=100)
        assert verified is False
        assert "GetRequest PDU" in details

    def test_validate_snmp_response_snmp_error_status_verified(self) -> None:
        req_id = 999
        # error-status = 2 (noSuchName), error-index = 1
        resp = self._build_mock_snmp_response(req_id, error_status=2, error_index=1)
        verified, details, meta = validate_snmp_response(resp, req_id)
        # Agent responded with a valid SNMP protocol error packet!
        assert verified is True
        assert meta["error_status"] == 2
        assert meta["error_status_name"] == "noSuchName"
        assert meta["error_index"] == 1
        assert "noSuchName" in details

    def test_validate_snmp_response_trailing_garbage_rejected(self) -> None:
        req_id = 123
        valid_resp = self._build_mock_snmp_response(req_id)
        garbage_resp = valid_resp + b"\xDE\xAD\xBE\xEF"
        verified, details, _ = validate_snmp_response(garbage_resp, req_id)
        assert verified is False
        assert "Trailing garbage bytes" in details

    def test_validate_snmp_response_truncated_packet_rejected(self) -> None:
        verified, details, _ = validate_snmp_response(b"\x30\x05\x02\x01\x00", 123)
        assert verified is False
        assert "too short" in details

    def test_validate_snmp_response_community_match_and_mismatch(self) -> None:
        req_id = 0x55AA
        # Response with default "public" community
        resp_public = self._build_mock_snmp_response(req_id, community=b"public")
        verified, details, meta = validate_snmp_response(resp_public, req_id, expected_community="public")
        assert verified is True

        # Backward compatibility: expected_community not specified still succeeds
        verified_no_arg, _, _ = validate_snmp_response(resp_public, req_id)
        assert verified_no_arg is True

        # Response with mismatched community
        resp_private = self._build_mock_snmp_response(req_id, community=b"private_mgmt")
        verified_bad, details_bad, meta_bad = validate_snmp_response(
            resp_private, req_id, expected_community="public"
        )
        assert verified_bad is False
        assert "community string mismatch" in details_bad
        # Sensitive strings never leaked in error text or metadata
        assert "private_mgmt" not in details_bad
        assert "private_mgmt" not in str(meta_bad)
        assert "public" not in str(meta_bad)

    def test_validate_snmp_response_non_minimal_integer_rejected(self) -> None:
        req_id = 0x1234
        # Response where error-status has redundant 0x00 octet: \x02\x02\x00\x00 instead of \x02\x01\x00
        bad_err_tlv = b"\x02\x02\x00\x00"
        pdu_content = (
            _encode_ber_integer(req_id)
            + bad_err_tlv
            + b"\x02\x01\x00"
            + (b"\x30\x0C\x30\x0A\x06\x08\x2B\x06\x01\x02\x01\x01\x01\x00")
        )
        pdu = b"\xA2" + _encode_ber_length(len(pdu_content)) + pdu_content
        msg_content = b"\x02\x01\x00\x04\x06public" + pdu
        resp = b"\x30" + _encode_ber_length(len(msg_content)) + msg_content

        verified, details, _ = validate_snmp_response(resp, req_id, expected_community="public")
        assert verified is False
        assert "Malformed SNMP error status field" in details

    @staticmethod
    def _build_multi_varbind_mock_response(
        req_id: int,
        varbinds: list[tuple[bytes, int, bytes]],
        community: bytes = b"public",
        error_status: int = 0,
        error_index: int = 0,
    ) -> bytes:
        encoded_vbs = []
        for oid_raw, val_tag, val_raw in varbinds:
            oid_tlv = b"\x06" + _encode_ber_length(len(oid_raw)) + oid_raw
            val_tlv = bytes([val_tag]) + _encode_ber_length(len(val_raw)) + val_raw
            vb_content = oid_tlv + val_tlv
            encoded_vbs.append(b"\x30" + _encode_ber_length(len(vb_content)) + vb_content)
        vblist_content = b"".join(encoded_vbs)
        vblist = b"\x30" + _encode_ber_length(len(vblist_content)) + vblist_content

        req_id_tlv = _encode_ber_integer(req_id)
        err_stat_tlv = _encode_ber_integer(error_status)
        err_idx_tlv = _encode_ber_integer(error_index)
        pdu_content = req_id_tlv + err_stat_tlv + err_idx_tlv + vblist
        pdu = b"\xA2" + _encode_ber_length(len(pdu_content)) + pdu_content

        ver_tlv = _encode_ber_integer(0)
        comm_tlv = b"\x04" + _encode_ber_length(len(community)) + community
        msg_content = ver_tlv + comm_tlv + pdu
        return b"\x30" + _encode_ber_length(len(msg_content)) + msg_content

    def test_validate_snmp_response_multiple_varbinds(self) -> None:
        req_id = 0x8899AABB
        # VarBind 1: sysDescr.0 (1.3.6.1.2.1.1.1.0) -> OCTET STRING "MikroTik RouterOS 7.12"
        # VarBind 2: sysObjectID.0 (1.3.6.1.2.1.1.2.0) -> OID 1.3.6.1.4.1.2777
        varbinds = [
            (
                b"\x2b\x06\x01\x02\x01\x01\x01\x00",
                0x04,
                b"MikroTik RouterOS 7.12",
            ),
            (
                b"\x2b\x06\x01\x02\x01\x01\x02\x00",
                0x06,
                b"\x2b\x06\x01\x04\x01\x95\x69",
            ),
        ]
        resp = self._build_multi_varbind_mock_response(req_id, varbinds)
        verified, details, meta = validate_snmp_response(resp, req_id)
        assert verified is True
        assert meta["varbind_count"] == 2
        assert meta["sys_descr_oid"] is True
        assert meta["sys_descr"] == "MikroTik RouterOS 7.12"
        assert "noError" in details
        assert "MikroTik RouterOS 7.12" in details

    def test_validate_snmp_response_truncated_varbind_entry(self) -> None:
        req_id = 0x4321
        # Declare VarBind SEQUENCE length 30, but provide only 10 bytes of content
        truncated_vb = b"\x30\x1E\x06\x08\x2B\x06\x01\x02\x01\x01\x01\x00"
        vblist = b"\x30" + _encode_ber_length(len(truncated_vb)) + truncated_vb

        pdu_content = (
            _encode_ber_integer(req_id)
            + _encode_ber_integer(0)
            + _encode_ber_integer(0)
            + vblist
        )
        pdu = b"\xA2" + _encode_ber_length(len(pdu_content)) + pdu_content
        msg_content = _encode_ber_integer(0) + b"\x04\x06public" + pdu
        resp = b"\x30" + _encode_ber_length(len(msg_content)) + msg_content

        verified, details, _ = validate_snmp_response(resp, req_id)
        assert verified is False
        assert "Malformed VarBind #1" in details

    def test_validate_snmp_response_varbind_trailing_bytes(self) -> None:
        req_id = 0x4322
        # VarBind sequence content has valid OID and value, followed by trailing unparsed bytes
        oid_tlv = b"\x06\x08\x2B\x06\x01\x02\x01\x01\x01\x00"
        val_tlv = b"\x04\x04test"
        garbage = b"\xAA\xBB\xCC"
        bad_vb_content = oid_tlv + val_tlv + garbage
        bad_vb = b"\x30" + _encode_ber_length(len(bad_vb_content)) + bad_vb_content
        vblist = b"\x30" + _encode_ber_length(len(bad_vb)) + bad_vb

        pdu_content = (
            _encode_ber_integer(req_id)
            + _encode_ber_integer(0)
            + _encode_ber_integer(0)
            + vblist
        )
        pdu = b"\xA2" + _encode_ber_length(len(pdu_content)) + pdu_content
        msg_content = _encode_ber_integer(0) + b"\x04\x06public" + pdu
        resp = b"\x30" + _encode_ber_length(len(msg_content)) + msg_content

        verified, details, _ = validate_snmp_response(resp, req_id)
        assert verified is False
        assert "Trailing bytes inside VarBind #1" in details

    def test_validate_snmp_response_inconsistent_varbindlist_boundary(self) -> None:
        req_id = 0x4323
        valid_vb = (
            b"\x30\x10\x06\x08\x2B\x06\x01\x02\x01\x01\x01\x00\x04\x04test"
        )
        vblist = b"\x30" + _encode_ber_length(len(valid_vb)) + valid_vb
        # Inject trailing bytes after VarBindList inside PDU
        pdu_content = (
            _encode_ber_integer(req_id)
            + _encode_ber_integer(0)
            + _encode_ber_integer(0)
            + vblist
            + b"\xFF\xFF"
        )
        pdu = b"\xA2" + _encode_ber_length(len(pdu_content)) + pdu_content
        msg_content = _encode_ber_integer(0) + b"\x04\x06public" + pdu
        resp = b"\x30" + _encode_ber_length(len(msg_content)) + msg_content

        verified, details, _ = validate_snmp_response(resp, req_id)
        assert verified is False
        assert "Inconsistent VarBindList boundary" in details

    def test_validate_snmp_response_distinguishes_error_from_malformed(self) -> None:
        req_id = 0x7777
        # 1. Valid SNMP error response (e.g. tooBig = 1) -> verified is True
        resp_err = self._build_mock_snmp_response(req_id, error_status=1)
        v_err, d_err, m_err = validate_snmp_response(resp_err, req_id)
        assert v_err is True
        assert m_err["error_status"] == 1
        assert "tooBig" in d_err

        # 2. Corrupted/unrelated packet -> verified is False
        corrupt = b"\x30\x20\x02\x01\x00\x04\x06public\xFF\xFFcorrupted_payload"
        v_bad, d_bad, _ = validate_snmp_response(corrupt, req_id)
        assert v_bad is False
        assert "Malformed" in d_bad or "Invalid" in d_bad

    def test_snmp_community_never_leaked_in_json_or_diagnostics(self) -> None:
        secret_comm = "super_secret_comm_xyz_123"
        req_id = 0x9999
        resp = self._build_mock_snmp_response(
            req_id, community=secret_comm.encode("ascii")
        )

        # 1. Successful validation: community match
        v_ok, d_ok, m_ok = validate_snmp_response(
            resp, req_id, expected_community=secret_comm
        )
        assert v_ok is True
        assert secret_comm not in d_ok
        assert secret_comm not in str(m_ok)

        # 2. Mismatch validation
        v_fail, d_fail, m_fail = validate_snmp_response(
            resp, req_id, expected_community="different_comm_abc"
        )
        assert v_fail is False
        assert secret_comm not in d_fail
        assert "different_comm_abc" not in d_fail
        assert secret_comm not in str(m_fail)
        assert "different_comm_abc" not in str(m_fail)

        # 3. Serialized JSON output
        result = UDPScanResult(
            port=161,
            state=UDPPortState.OPEN,
            service="snmp",
            reason=f"Valid SNMP response: {d_ok}",
            protocol_info=UDPProtocolInfo(
                protocol="snmp",
                verified=v_ok,
                details=d_ok,
                metadata=m_ok,
            ),
        )
        summary = UDPScanSummary(
            target="127.0.0.1",
            total_ports=1,
            open_count=1,
            closed_count=0,
            open_filtered_count=0,
            unknown_count=0,
            elapsed_seconds=0.05,
            results=[result],
            probe="snmp",
        )
        json_doc = udp_scan_summary_to_json(summary)
        summary_dict = udp_scan_summary_to_dict(summary)
        assert secret_comm not in json_doc
        assert secret_comm not in str(summary_dict)


class TestProtocolProbingAndClassification:
    """Tests for protocol probe execution within probe_udp_port."""

    def test_probe_udp_port_dns_success(self) -> None:
        mock_sock = MagicMock()
        # When send is called, extract tx_id from the query payload
        saved_tx_id = [0]

        def mock_send(payload: bytes) -> int:
            saved_tx_id[0] = struct.unpack("!H", payload[:2])[0]
            return len(payload)

        mock_sock.send.side_effect = mock_send

        def mock_recv(bufsize: int) -> bytes:
            tx_id = saved_tx_id[0]
            header = struct.pack("!HHHHHH", tx_id, 0x8180, 1, 1, 0, 0)
            question = encode_dns_name("example.com") + struct.pack("!HH", 1, 1)
            answer = b"\xC0\x0C" + struct.pack("!HHIH4s", 1, 1, 300, 4, socket.inet_aton("93.184.216.34"))
            return header + question + answer

        mock_sock.recv.side_effect = mock_recv

        with patch("socket.socket", return_value=mock_sock):
            result = probe_udp_port("127.0.0.1", 53, timeout=1.0, probe="dns")
            assert result.state == UDPPortState.OPEN
            assert "Valid DNS response" in result.reason
            assert result.protocol_info is not None
            assert result.protocol_info.protocol == "dns"
            assert result.protocol_info.verified is True

    def test_probe_udp_port_dns_unverified_payload_remains_open(self) -> None:
        mock_sock = MagicMock()
        # Returns bytes, but not valid DNS
        mock_sock.recv.return_value = b"random_unrelated_garbage_data"

        with patch("socket.socket", return_value=mock_sock):
            result = probe_udp_port("127.0.0.1", 53, timeout=1.0, probe="dns")
            # Must still be OPEN since bytes arrived, but protocol verification must be False
            assert result.state == UDPPortState.OPEN
            assert "invalid DNS" in result.reason
            assert result.protocol_info is not None
            assert result.protocol_info.protocol == "dns"
            assert result.protocol_info.verified is False

    def test_probe_udp_port_dns_truncated_payload_is_open_unverified(self) -> None:
        mock_sock = MagicMock()
        saved_tx_id = [0]

        def mock_send(payload: bytes) -> int:
            saved_tx_id[0] = struct.unpack("!H", payload[:2])[0]
            return len(payload)

        mock_sock.send.side_effect = mock_send

        def mock_recv(bufsize: int) -> bytes:
            tx_id = saved_tx_id[0]
            # Truncated DNS response: TC=1 (0x8200)
            header = struct.pack("!HHHHHH", tx_id, 0x8200, 1, 0, 0, 0)
            question = encode_dns_name("example.com") + struct.pack("!HH", 1, 1)
            return header + question

        mock_sock.recv.side_effect = mock_recv

        with patch("socket.socket", return_value=mock_sock):
            result = probe_udp_port("127.0.0.1", 53, timeout=1.0, probe="dns")
            assert result.state == UDPPortState.OPEN
            assert "truncated DNS" in result.reason
            assert result.protocol_info is not None
            assert result.protocol_info.protocol == "dns"
            assert result.protocol_info.verified is False
            assert result.protocol_info.metadata["truncated"] is True

    def test_probe_udp_port_dns_timeout_is_open_filtered(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = socket.timeout("timed out")

        with patch("socket.socket", return_value=mock_sock):
            result = probe_udp_port("127.0.0.1", 53, timeout=1.0, probe="dns")
            assert result.state == UDPPortState.OPEN_FILTERED
            assert "No DNS response received" in result.reason
            assert result.protocol_info is None

    def test_probe_udp_port_ntp_success(self) -> None:
        mock_sock = MagicMock()
        # 48 bytes NTP server response
        resp = bytes([0x24, 2, 6, 0]) + (b"\x00" * 44)
        mock_sock.recv.return_value = resp

        with patch("socket.socket", return_value=mock_sock):
            result = probe_udp_port("127.0.0.1", 123, timeout=1.0, probe="ntp")
            assert result.state == UDPPortState.OPEN
            assert "Valid NTP response" in result.reason
            assert result.protocol_info is not None
            assert result.protocol_info.protocol == "ntp"
            assert result.protocol_info.verified is True

    def test_probe_udp_port_ntp_timeout_is_open_filtered(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = socket.timeout("timed out")

        with patch("socket.socket", return_value=mock_sock):
            result = probe_udp_port("127.0.0.1", 123, timeout=1.0, probe="ntp")
            assert result.state == UDPPortState.OPEN_FILTERED
            assert "No NTP response received" in result.reason
            assert result.protocol_info is None

    def test_probe_udp_port_snmp_success(self) -> None:
        mock_sock = MagicMock()
        saved_req_id = [0]

        def mock_send(payload: bytes) -> int:
            outer = _read_ber_tlv(payload, 0)
            assert outer is not None
            ver = _read_ber_integer(payload, outer[1])
            assert ver is not None
            comm_tlv = _read_ber_tlv(payload, ver[1])
            assert comm_tlv is not None
            pdu_tlv = _read_ber_tlv(payload, comm_tlv[3])
            assert pdu_tlv is not None
            req = _read_ber_integer(payload, pdu_tlv[1])
            assert req is not None
            saved_req_id[0] = req[0]
            return len(payload)

        mock_sock.send.side_effect = mock_send

        def mock_recv(bufsize: int) -> bytes:
            req_id = saved_req_id[0]
            return TestSNMPProbe._build_mock_snmp_response(req_id, val_bytes=b"NetProbe Agent")

        mock_sock.recv.side_effect = mock_recv

        with patch("socket.socket", return_value=mock_sock):
            result = probe_udp_port("127.0.0.1", 161, timeout=1.0, probe="snmp")
            assert result.state == UDPPortState.OPEN
            assert "Valid SNMP response" in result.reason
            assert result.protocol_info is not None
            assert result.protocol_info.protocol == "snmp"
            assert result.protocol_info.verified is True
            assert result.protocol_info.metadata["sys_descr"] == "NetProbe Agent"

    def test_probe_udp_port_snmp_unverified_payload(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"random_unrelated_payload_bytes"

        with patch("socket.socket", return_value=mock_sock):
            result = probe_udp_port("127.0.0.1", 161, timeout=1.0, probe="snmp")
            assert result.state == UDPPortState.OPEN
            assert "invalid SNMP" in result.reason
            assert result.protocol_info is not None
            assert result.protocol_info.protocol == "snmp"
            assert result.protocol_info.verified is False

    def test_probe_udp_port_snmp_community_mismatch_is_open_unverified(self) -> None:
        expected_tx_id = 0x1234
        # Agent responds with a different community string "custom_private"
        response_data = TestSNMPProbe._build_mock_snmp_response(
            expected_tx_id, community=b"custom_private"
        )

        mock_sock = MagicMock()
        mock_sock.recv.return_value = response_data

        with patch("netprobe.udp.build_snmp_get_request", return_value=(b"query", expected_tx_id)), \
             patch("socket.socket", return_value=mock_sock):
            result = probe_udp_port("127.0.0.1", 161, timeout=1.0, probe="snmp")

        assert result.port == 161
        assert result.state == UDPPortState.OPEN
        assert result.protocol_info is not None
        assert result.protocol_info.protocol == "snmp"
        assert result.protocol_info.verified is False
        assert "community string mismatch" in result.protocol_info.details
        assert "custom_private" not in result.reason
        assert "custom_private" not in str(result.protocol_info.metadata)
        assert "public" not in str(result.protocol_info.metadata)

    def test_probe_udp_port_snmp_timeout_is_open_filtered(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = socket.timeout("timed out")

        with patch("socket.socket", return_value=mock_sock):
            result = probe_udp_port("127.0.0.1", 161, timeout=1.0, probe="snmp")
            assert result.state == UDPPortState.OPEN_FILTERED
            assert "No SNMP response received (open or filtered)" in result.reason
            assert result.protocol_info is None

    def test_probe_udp_port_snmp_port_unreachable_is_closed(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = ConnectionRefusedError("Connection refused")

        with patch("socket.socket", return_value=mock_sock):
            result = probe_udp_port("127.0.0.1", 161, timeout=1.0, probe="snmp")
            assert result.state == UDPPortState.CLOSED
            assert "port unreachable" in result.reason

    def test_probe_udp_port_snmp_unexpected_error_is_unknown(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = OSError(errno.EACCES, "Permission denied")

        with patch("socket.socket", return_value=mock_sock):
            result = probe_udp_port("127.0.0.1", 161, timeout=1.0, probe="snmp")
            assert result.state == UDPPortState.UNKNOWN
            assert "Network or socket error" in result.reason

    def test_probe_udp_port_recv_buffer_size_65535(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"OK"
        with patch("socket.socket", return_value=mock_sock):
            probe_udp_port("127.0.0.1", 53)
            mock_sock.recv.assert_called_once_with(65535)

    def test_probe_udp_port_wsaemsgsize_generic_is_open(self) -> None:
        mock_sock = MagicMock()
        err = OSError(getattr(errno, "WSAEMSGSIZE", 10040), "Message too large")
        err.winerror = 10040
        mock_sock.recv.side_effect = err

        with patch("socket.socket", return_value=mock_sock):
            result = probe_udp_port("127.0.0.1", 12345)
            assert result.state == UDPPortState.OPEN
            assert result.response_bytes is None
            assert result.protocol_info is None
            assert "oversized" in result.reason.lower()

    def test_probe_udp_port_wsaemsgsize_dns_is_open_unverified(self) -> None:
        mock_sock = MagicMock()
        err = OSError(getattr(errno, "WSAEMSGSIZE", 10040), "Message too large")
        err.winerror = 10040
        mock_sock.recv.side_effect = err

        with patch("socket.socket", return_value=mock_sock):
            result = probe_udp_port("127.0.0.1", 53, probe="dns")
            assert result.state == UDPPortState.OPEN
            assert result.response_bytes is None
            assert result.protocol_info is not None
            assert result.protocol_info.protocol == "dns"
            assert result.protocol_info.verified is False
            assert result.protocol_info.metadata.get("oversized") is True
            assert "oversized DNS" in result.reason

    def test_probe_udp_port_wsaemsgsize_snmp_is_open_unverified(self) -> None:
        mock_sock = MagicMock()
        err = OSError(getattr(errno, "WSAEMSGSIZE", 10040), "Message too large")
        err.winerror = 10040
        mock_sock.recv.side_effect = err

        with patch("socket.socket", return_value=mock_sock):
            result = probe_udp_port("127.0.0.1", 161, probe="snmp")
            assert result.state == UDPPortState.OPEN
            assert result.response_bytes is None
            assert result.protocol_info is not None
            assert result.protocol_info.protocol == "snmp"
            assert result.protocol_info.verified is False
            assert result.protocol_info.metadata.get("oversized") is True
            assert "oversized SNMP" in result.reason

    def test_probe_udp_port_unsupported_probe_rejected(self) -> None:
        with pytest.raises(ValueError, match="Unsupported UDP probe"):
            probe_udp_port("127.0.0.1", 69, probe="tftp")

    def test_scanner_with_probe_passes_to_summary(self) -> None:
        scanner = UDPScanner("127.0.0.1", probe="dns")
        assert scanner.probe == "dns"

        with patch.object(
            scanner,
            "scan",
            return_value=UDPScanSummary(
                target="127.0.0.1",
                total_ports=1,
                open_count=1,
                closed_count=0,
                open_filtered_count=0,
                unknown_count=0,
                elapsed_seconds=0.01,
                results=[],
                probe="dns",
            ),
        ):
            summary = scanner.scan([53])
            assert summary.probe == "dns"

    def test_scanner_with_snmp_probe_passes_to_summary(self) -> None:
        scanner = UDPScanner("127.0.0.1", probe="snmp")
        assert scanner.probe == "snmp"


class TestProtocolProbeCLIAndExport:
    """Deterministic tests for CLI options and JSON export with UDP protocol probes."""

    def test_cli_udp_probe_without_udp_flag_rejected(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["127.0.0.1", "--udp-probe", "dns"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "--udp-probe requires -u/--udp mode" in captured.err

    def test_cli_udp_probe_with_discover_rejected(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["--discover", "192.168.1.0/24", "--udp", "--udp-probe", "dns"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "UDP scanning is not supported in subnet discovery mode" in captured.err

    def test_cli_invalid_udp_probe_name_rejected(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["127.0.0.1", "--udp", "--udp-probe", "unsupported_proto"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Invalid UDP probe" in captured.err

    def test_cli_successful_dns_probe_output_and_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        proto_info = UDPProtocolInfo(
            protocol="dns",
            verified=True,
            details="DNS response (RCODE=NOERROR, QD=1, AN=1)",
            metadata={"rcode": 0, "ancount": 1},
        )
        dummy_result = UDPScanResult(
            port=53,
            state=UDPPortState.OPEN,
            service="dns",
            reason="Valid DNS response: DNS response (RCODE=NOERROR, QD=1, AN=1)",
            response_bytes=b"\x00",
            protocol_info=proto_info,
        )
        dummy_summary = UDPScanSummary(
            target="127.0.0.1",
            total_ports=1,
            open_count=1,
            closed_count=0,
            open_filtered_count=0,
            unknown_count=0,
            elapsed_seconds=0.1,
            results=[dummy_result],
            probe="dns",
        )

        with patch.object(UDPScanner, "scan", return_value=dummy_summary):
            # 1. Table output includes probe header
            exit_code = main(["127.0.0.1", "--udp", "--udp-probe", "dns", "-p", "53"])
            assert exit_code == 0
            captured = capsys.readouterr()
            assert "UDP Probe:    DNS Application Payload" in captured.out
            assert "53/udp" in captured.out
            assert "OPEN" in captured.out

            # 2. JSON mode includes probe and protocol_info
            capsys.readouterr()
            exit_code_json = main(["127.0.0.1", "--udp", "--udp-probe", "dns", "-p", "53", "--json"])
            assert exit_code_json == 0
            captured_json = capsys.readouterr()
            doc = json.loads(captured_json.out)
            assert doc["mode"] == "udp"
            assert doc["probe"] == "dns"
            assert doc["results"][0]["protocol_info"]["protocol"] == "dns"
            assert doc["results"][0]["protocol_info"]["verified"] is True

    def test_cli_udp_probe_json_file_export(
        self, capsys: pytest.CaptureFixture[str], tmp_path: Path
    ) -> None:
        proto_info = UDPProtocolInfo(
            protocol="ntp",
            verified=True,
            details="NTP v4 server response (stratum 2)",
            metadata={"vn": 4, "stratum": 2},
        )
        dummy_summary = UDPScanSummary(
            target="127.0.0.1",
            total_ports=1,
            open_count=1,
            closed_count=0,
            open_filtered_count=0,
            unknown_count=0,
            elapsed_seconds=0.05,
            results=[
                UDPScanResult(
                    123,
                    UDPPortState.OPEN,
                    "ntp",
                    "Valid NTP response",
                    protocol_info=proto_info,
                )
            ],
            probe="ntp",
        )

        out_file = tmp_path / "ntp.json"
        with patch.object(UDPScanner, "scan", return_value=dummy_summary):
            exit_code = main(
                ["127.0.0.1", "-u", "--udp-probe", "ntp", "-p", "123", "--json", "-o", str(out_file)]
            )
            assert exit_code == 0
            captured = capsys.readouterr()
            assert captured.out == ""
            assert out_file.exists()
            doc = json.loads(out_file.read_text(encoding="utf-8"))
            assert doc["probe"] == "ntp"
            assert doc["results"][0]["protocol_info"]["protocol"] == "ntp"

    def test_cli_successful_snmp_probe_output_and_json_no_community_leak(
        self, capsys: pytest.CaptureFixture[str], tmp_path: Path
    ) -> None:
        community = "super_secret_community_string"
        proto_info = UDPProtocolInfo(
            protocol="snmp",
            verified=True,
            details="SNMPv1 response (sysDescr='Linux router 5.15')",
            metadata={
                "version": 0,
                "pdu_type": 0xA2,
                "error_status": 0,
                "error_index": 0,
                "sys_descr_returned": True,
                "sys_descr": "Linux router 5.15",
            },
        )
        dummy_result = UDPScanResult(
            port=161,
            state=UDPPortState.OPEN,
            service="snmp",
            reason="Valid SNMP response: SNMPv1 response (sysDescr='Linux router 5.15')",
            response_bytes=b"\x30\x20\x02\x01\x00...",
            protocol_info=proto_info,
        )
        dummy_summary = UDPScanSummary(
            target="192.168.1.1",
            total_ports=1,
            open_count=1,
            closed_count=0,
            open_filtered_count=0,
            unknown_count=0,
            elapsed_seconds=0.1,
            results=[dummy_result],
            probe="snmp",
        )

        with patch.object(UDPScanner, "scan", return_value=dummy_summary):
            # 1. Table output includes probe header and formatted result
            exit_code = main(["192.168.1.1", "--udp", "--udp-probe", "snmp", "-p", "161"])
            assert exit_code == 0
            captured = capsys.readouterr()
            assert "UDP Probe:    SNMP Application Payload" in captured.out
            assert "161/udp" in captured.out
            assert "OPEN" in captured.out
            assert community not in captured.out
            assert community not in captured.err

            # 2. JSON output to stdout
            exit_code_json = main(["192.168.1.1", "-u", "--udp-probe", "snmp", "-p", "161", "--json"])
            assert exit_code_json == 0
            captured_json = capsys.readouterr()
            assert community not in captured_json.out
            doc = json.loads(captured_json.out)
            assert doc["mode"] == "udp"
            assert doc["probe"] == "snmp"
            result_json = doc["results"][0]
            assert result_json["port"] == 161
            assert result_json["protocol_info"]["protocol"] == "snmp"
            assert result_json["protocol_info"]["verified"] is True
            assert result_json["protocol_info"]["metadata"]["sys_descr"] == "Linux router 5.15"
            assert community not in json.dumps(doc)

            # 3. JSON file export
            out_file = tmp_path / "snmp_export.json"
            exit_code_file = main(
                ["192.168.1.1", "-u", "--udp-probe", "snmp", "-p", "161", "--json", "-o", str(out_file)]
            )
            assert exit_code_file == 0
            file_content = out_file.read_text(encoding="utf-8")
            assert community not in file_content
            file_doc = json.loads(file_content)
            assert file_doc["probe"] == "snmp"
            assert file_doc["results"][0]["protocol_info"]["metadata"]["version"] == 0

    def test_cli_snmp_probe_without_udp_flag_rejected(self, capsys: pytest.CaptureFixture[str]) -> None:
        exit_code = main(["127.0.0.1", "--udp-probe", "snmp"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "--udp-probe requires -u/--udp mode" in captured.err


