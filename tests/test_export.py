"""Unit tests for Phase 2.7 JSON serialization and file export."""

import importlib
import json
from pathlib import Path
import socket
import tomllib
from unittest.mock import MagicMock, patch

import pytest

import netprobe

from netprobe.cli import create_parser, main
from netprobe.export import (
    certificate_info_to_dict,
    scan_result_to_dict,
    scan_summary_to_dict,
    scan_summary_to_json,
    service_info_to_dict,
    validate_output_path,
)
from netprobe.fingerprint.models import CertificateInfo, IdentificationMethod, ServiceInfo
from netprobe.scanner import (
    PortState,
    ScanInterruptedError,
    ScanResult,
    ScanSummary,
    TCPScanner,
)


class TestPhase27Serialization:
    """Tests for export.py dictionary and JSON serialization."""

    def test_serialize_normal_scan_summary(self):
        summary = ScanSummary(
            target="127.0.0.1",
            total_ports=2,
            open_count=1,
            closed_count=1,
            unknown_count=0,
            elapsed_seconds=0.123456,
            results=[
                ScanResult(port=22, state=PortState.CLOSED, service="ssh", reason="Connection refused (RST)"),
                ScanResult(port=80, state=PortState.OPEN, service="http", reason="Connection established"),
            ],
            interrupted=False,
        )

        d = scan_summary_to_dict(summary)
        assert d["target"] == "127.0.0.1"
        assert d["total_ports"] == 2
        assert d["open_count"] == 1
        assert d["closed_count"] == 1
        assert d["unknown_count"] == 0
        assert d["elapsed_seconds"] == 0.1235
        assert d["interrupted"] is False
        assert len(d["results"]) == 2

        res0 = d["results"][0]
        assert res0["port"] == 22
        assert res0["state"] == "closed"
        assert res0["service"] == "ssh"
        assert res0["reason"] == "Connection refused (RST)"
        assert res0["service_info"] is None

        # Verify JSON dumping and loading
        json_str = scan_summary_to_json(summary)
        loaded = json.loads(json_str)
        assert loaded == d

    def test_serialize_enums_as_stable_strings(self):
        assert PortState.OPEN.value == "open"
        assert IdentificationMethod.HTTP.value == "http"

        result = ScanResult(
            port=443,
            state=PortState.OPEN,
            service="https",
            reason="Connection established",
            service_info=ServiceInfo(
                name="https",
                method=IdentificationMethod.TLS,
                details="TLS handshake successful",
            ),
        )
        d = scan_result_to_dict(result)
        assert d["state"] == "open"
        assert isinstance(d["state"], str)
        assert d["service_info"]["method"] == "tls"
        assert isinstance(d["service_info"]["method"], str)

    def test_serialize_nested_service_and_certificate_info(self):
        cert = CertificateInfo(
            subject="CN=example.com",
            issuer="CN=Example CA",
            not_before="2025-01-01 00:00:00 GMT",
            not_after="2026-01-01 00:00:00 GMT",
            verified=False,
            alpn_protocol="http/1.1",
            tls_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            san=("example.com", "127.0.0.1", "sub.example.com"),
        )
        svc = ServiceInfo(
            name="https",
            method=IdentificationMethod.TLS,
            product="nginx",
            version="1.24.0",
            details="HTTP/1.1 200 OK",
            confidence_note="High confidence",
            raw_response="HTTP/1.1 200 OK\r\nServer: nginx\r\n",
            tls_info=cert,
        )

        svc_dict = service_info_to_dict(svc)
        assert svc_dict["name"] == "https"
        assert svc_dict["product"] == "nginx"
        assert svc_dict["version"] == "1.24.0"
        assert svc_dict["confidence_note"] == "High confidence"
        assert svc_dict["raw_response"] == "HTTP/1.1 200 OK\r\nServer: nginx\r\n"

        tls_dict = svc_dict["tls_info"]
        assert tls_dict is not None
        assert tls_dict["subject"] == "CN=example.com"
        assert tls_dict["issuer"] == "CN=Example CA"
        assert tls_dict["tls_version"] == "TLSv1.3"
        assert tls_dict["cipher_suite"] == "TLS_AES_256_GCM_SHA384"
        assert tls_dict["san"] == ["example.com", "127.0.0.1", "sub.example.com"]
        assert isinstance(tls_dict["san"], list)

    def test_preserve_san_entries_as_json_array(self):
        cert = CertificateInfo(san=("alt1.com", "alt2.com", "10.0.0.1"))
        d = certificate_info_to_dict(cert)
        assert d["san"] == ["alt1.com", "alt2.com", "10.0.0.1"]
        assert isinstance(d["san"], list)

        # Empty SAN tuple serializes as empty list
        empty_cert = CertificateInfo(san=())
        empty_d = certificate_info_to_dict(empty_cert)
        assert empty_d["san"] == []

    def test_handling_absent_service_info_and_absent_tls(self):
        res = ScanResult(
            port=80,
            state=PortState.OPEN,
            service="http",
            reason="Connection established",
            service_info=None,
        )
        d = scan_result_to_dict(res)
        assert d["service_info"] is None

        svc_no_tls = ServiceInfo(
            name="http",
            method=IdentificationMethod.HTTP,
            tls_info=None,
        )
        s_dict = service_info_to_dict(svc_no_tls)
        assert s_dict["tls_info"] is None


class TestPhase27CLIExport:
    """Tests for CLI options --json and -o/--output."""

    def test_parser_options(self):
        parser = create_parser()
        args = parser.parse_args(["127.0.0.1", "--json", "-o", "scan.json"])
        assert args.json is True
        assert args.output == "scan.json"

    def test_json_stdout_is_valid_json_with_no_extra_text(self, capsys: pytest.CaptureFixture[str]):
        mock_summary = ScanSummary(
            target="127.0.0.1",
            total_ports=1,
            open_count=1,
            closed_count=0,
            unknown_count=0,
            elapsed_seconds=0.05,
            results=[
                ScanResult(port=80, state=PortState.OPEN, service="http", reason="Connection established"),
            ],
            interrupted=False,
        )

        with patch.object(TCPScanner, "scan", return_value=mock_summary):
            exit_code = main(["127.0.0.1", "-p", "80", "--json"])
            assert exit_code == 0
            captured = capsys.readouterr()

            # Stdout must be strictly parseable JSON without ASCII header
            assert not captured.out.startswith("\nNetProbe v")
            data = json.loads(captured.out)
            assert data["target"] == "127.0.0.1"
            assert data["open_count"] == 1
            assert data["results"][0]["port"] == 80
            assert data["results"][0]["state"] == "open"

    def test_output_file_alone_writes_default_table(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
        out_file = tmp_path / "scan_table.txt"
        mock_summary = ScanSummary(
            target="127.0.0.1",
            total_ports=1,
            open_count=1,
            closed_count=0,
            unknown_count=0,
            elapsed_seconds=0.05,
            results=[
                ScanResult(port=80, state=PortState.OPEN, service="http", reason="Connection established"),
            ],
        )

        with patch.object(TCPScanner, "scan", return_value=mock_summary):
            exit_code = main(["127.0.0.1", "-p", "80", "-o", str(out_file)])
            assert exit_code == 0
            captured = capsys.readouterr()

            # Stdout still shows ASCII banner and table
            assert "NetProbe v" in captured.out
            assert "80/tcp" in captured.out
            assert "Scan Summary:" in captured.out

            # File contains table and summary
            content = out_file.read_text(encoding="utf-8")
            assert "80/tcp" in content
            assert "Scan Summary:" in content
            assert "Target:          127.0.0.1" in content

    def test_json_and_output_file_writes_json_to_file(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
        out_file = tmp_path / "scan.json"
        mock_summary = ScanSummary(
            target="127.0.0.1",
            total_ports=1,
            open_count=1,
            closed_count=0,
            unknown_count=0,
            elapsed_seconds=0.05,
            results=[
                ScanResult(port=80, state=PortState.OPEN, service="http", reason="Connection established"),
            ],
        )

        with patch.object(TCPScanner, "scan", return_value=mock_summary):
            exit_code = main(["127.0.0.1", "-p", "80", "--json", "-o", str(out_file)])
            assert exit_code == 0
            captured = capsys.readouterr()

            # When --json and -o are both specified, stdout must emit NO non-JSON text (empty stdout is expected)
            assert captured.out == ""

            # File contains strictly valid JSON
            content = out_file.read_text(encoding="utf-8")
            data = json.loads(content)
            assert data["target"] == "127.0.0.1"
            assert data["results"][0]["port"] == 80
            assert data["interrupted"] is False

    def test_interrupted_json_output_with_output_file(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
        out_file = tmp_path / "partial_scan.json"
        partial_summary = ScanSummary(
            target="127.0.0.1",
            total_ports=3,
            open_count=1,
            closed_count=1,
            unknown_count=0,
            elapsed_seconds=0.12,
            results=[
                ScanResult(port=22, state=PortState.CLOSED, service="ssh", reason="Connection refused (RST)"),
                ScanResult(port=80, state=PortState.OPEN, service="http", reason="Connection established"),
            ],
            interrupted=True,
        )

        with patch.object(TCPScanner, "scan", side_effect=ScanInterruptedError(partial_summary)):
            exit_code = main(["127.0.0.1", "-p", "22,80,443", "--json", "-o", str(out_file)])
            assert exit_code == 130
            captured = capsys.readouterr()

            # Stderr receives warning
            assert "Scan interrupted by operator" in captured.err

            # Stdout emits no non-JSON text (empty stdout)
            assert captured.out == ""

            # Output file contains valid JSON with interrupted: true and preserved completed results
            content = out_file.read_text(encoding="utf-8")
            data = json.loads(content)
            assert data["interrupted"] is True
            assert data["target"] == "127.0.0.1"
            assert data["total_ports"] == 3
            assert len(data["results"]) == 2
            assert data["results"][0]["port"] == 22
            assert data["results"][1]["port"] == 80


    def test_fingerprinting_metadata_present_in_json(self, capsys: pytest.CaptureFixture[str]):
        mock_summary = ScanSummary(
            target="127.0.0.1",
            total_ports=1,
            open_count=1,
            closed_count=0,
            unknown_count=0,
            elapsed_seconds=0.1,
            results=[
                ScanResult(port=80, state=PortState.OPEN, service="http", reason="Connection established"),
            ],
        )
        mock_fp_result = ScanResult(
            port=80,
            state=PortState.OPEN,
            service="http",
            reason="Connection established",
            service_info=ServiceInfo(
                name="http",
                method=IdentificationMethod.HTTP,
                product="Apache",
                version="2.4.52",
                details="HTTP/1.1 200 OK",
            ),
        )

        with patch.object(TCPScanner, "scan", return_value=mock_summary), \
             patch("netprobe.cli.FingerprintEngine.fingerprint_results", return_value=[mock_fp_result]):
            exit_code = main(["127.0.0.1", "-p", "80", "-sV", "--json"])
            assert exit_code == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            res = data["results"][0]
            assert res["service_info"] is not None
            assert res["service_info"]["name"] == "http"
            assert res["service_info"]["product"] == "Apache"
            assert res["service_info"]["version"] == "2.4.52"
            assert res["service_info"]["method"] == "http"

    def test_interrupted_json_output_preserves_results_and_sets_interrupted(self, capsys: pytest.CaptureFixture[str]):
        partial_summary = ScanSummary(
            target="127.0.0.1",
            total_ports=2,
            open_count=1,
            closed_count=0,
            unknown_count=0,
            elapsed_seconds=0.08,
            results=[
                ScanResult(port=80, state=PortState.OPEN, service="http", reason="Connection established"),
            ],
            interrupted=True,
        )

        with patch.object(TCPScanner, "scan", side_effect=ScanInterruptedError(partial_summary)):
            exit_code = main(["127.0.0.1", "-p", "80,443", "--json"])
            assert exit_code == 130
            captured = capsys.readouterr()

            # Stderr receives warning
            assert "Scan interrupted by operator" in captured.err

            # Stdout receives valid JSON with interrupted: true
            data = json.loads(captured.out)
            assert data["interrupted"] is True
            assert data["target"] == "127.0.0.1"
            assert data["total_ports"] == 2
            assert len(data["results"]) == 1
            assert data["results"][0]["port"] == 80

    def test_validate_output_path_failures(self, tmp_path: Path):
        # Empty path
        with pytest.raises(ValueError, match="cannot be empty"):
            validate_output_path("")

        # Existing directory
        with pytest.raises(IsADirectoryError, match="is an existing directory"):
            validate_output_path(str(tmp_path))

        # Non-existent parent directory
        non_existent_dir = tmp_path / "non_existent_sub" / "output.txt"
        with pytest.raises(FileNotFoundError, match="does not exist"):
            validate_output_path(str(non_existent_dir))

    def test_main_rejects_invalid_output_path_before_scanning(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
        invalid_path = str(tmp_path / "missing_dir" / "scan.json")
        with patch.object(TCPScanner, "scan") as mock_scan:
            exit_code = main(["127.0.0.1", "-o", invalid_path])
            assert exit_code == 1
            captured = capsys.readouterr()
            assert "Output file validation failed" in captured.err
            mock_scan.assert_not_called()

    def test_existing_cli_behavior_preserved_without_new_flags(self, capsys: pytest.CaptureFixture[str]):
        mock_summary = ScanSummary(
            target="127.0.0.1",
            total_ports=1,
            open_count=1,
            closed_count=0,
            unknown_count=0,
            elapsed_seconds=0.05,
            results=[
                ScanResult(port=80, state=PortState.OPEN, service="http", reason="Connection established"),
            ],
        )

        with patch.object(TCPScanner, "scan", return_value=mock_summary):
            exit_code = main(["127.0.0.1", "-p", "80"])
            assert exit_code == 0
            captured = capsys.readouterr()
            assert "NetProbe v" in captured.out
            assert "80/tcp" in captured.out
            assert "Scan Summary:" in captured.out

    def test_hostname_scan_table_output_shows_both_names(self, capsys: pytest.CaptureFixture[str]):
        mock_summary = ScanSummary(
            target="localhost",
            total_ports=1,
            open_count=1,
            closed_count=0,
            unknown_count=0,
            elapsed_seconds=0.05,
            results=[
                ScanResult(port=80, state=PortState.OPEN, service="http", reason="Connection established"),
            ],
            resolved_target="127.0.0.1",
        )

        mock_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
        with patch("socket.getaddrinfo", return_value=mock_addrinfo), \
             patch.object(TCPScanner, "scan", return_value=mock_summary):
            exit_code = main(["localhost", "-p", "80"])
            assert exit_code == 0
            captured = capsys.readouterr()
            assert "Target:       localhost (127.0.0.1)" in captured.out
            assert "Scan Summary:" in captured.out
            assert "Target:          localhost" in captured.out

    def test_hostname_scan_json_output_preserves_both_targets(self, capsys: pytest.CaptureFixture[str]):
        mock_summary = ScanSummary(
            target="example.com",
            total_ports=1,
            open_count=1,
            closed_count=0,
            unknown_count=0,
            elapsed_seconds=0.05,
            results=[
                ScanResult(port=80, state=PortState.OPEN, service="http", reason="Connection established"),
            ],
            resolved_target="93.184.216.34",
        )

        mock_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
        with patch("socket.getaddrinfo", return_value=mock_addrinfo), \
             patch.object(TCPScanner, "scan", return_value=mock_summary):
            exit_code = main(["example.com", "-p", "80", "--json"])
            assert exit_code == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["target"] == "example.com"
            assert data["resolved_target"] == "93.184.216.34"

    def test_hostname_scan_json_file_export_preserves_both_targets(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
        out_file = tmp_path / "host_scan.json"
        mock_summary = ScanSummary(
            target="example.com",
            total_ports=1,
            open_count=1,
            closed_count=0,
            unknown_count=0,
            elapsed_seconds=0.05,
            results=[
                ScanResult(port=80, state=PortState.OPEN, service="http", reason="Connection established"),
            ],
            resolved_target="93.184.216.34",
        )

        mock_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
        with patch("socket.getaddrinfo", return_value=mock_addrinfo), \
             patch.object(TCPScanner, "scan", return_value=mock_summary):
            exit_code = main(["example.com", "-p", "80", "--json", "-o", str(out_file)])
            assert exit_code == 0
            captured = capsys.readouterr()
            assert captured.out == ""
            data = json.loads(out_file.read_text(encoding="utf-8"))
            assert data["target"] == "example.com"
            assert data["resolved_target"] == "93.184.216.34"


class TestProjectMetadata:
    """Regression tests for project metadata consistency."""

    def test_pyproject_version_matches_package_version(self) -> None:
        """Ensure pyproject.toml project.version matches netprobe.__version__."""
        pyproject_path = Path(__file__).resolve().parent.parent / "pyproject.toml"
        assert pyproject_path.exists(), f"pyproject.toml not found at {pyproject_path}"
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)
        toml_version = data["project"]["version"]
        assert toml_version == netprobe.__version__
        assert toml_version == "0.2.0"


class TestPackagePublicAPI:
    """Tests for package-level public exports and import safety."""

    def test_discovery_and_export_symbols_exported(self) -> None:
        """Verify discovery and serialization symbols are exported at package root."""
        import netprobe.discovery as disc
        import netprobe.export as exp

        expected_exports = [
            ("SubnetScanner", disc.SubnetScanner),
            ("DiscoverySummary", disc.DiscoverySummary),
            ("DiscoveredHost", disc.DiscoveredHost),
            ("HostReachability", disc.HostReachability),
            ("DiscoveryInterruptedError", disc.DiscoveryInterruptedError),
            ("parse_cidr", disc.parse_cidr),
            ("parse_sweep_ports", disc.parse_sweep_ports),
            ("DEFAULT_SWEEP_PORTS", disc.DEFAULT_SWEEP_PORTS),
            ("udp_scan_summary_to_dict", exp.udp_scan_summary_to_dict),
            ("udp_scan_summary_to_json", exp.udp_scan_summary_to_json),
            ("discovery_summary_to_dict", exp.discovery_summary_to_dict),
            ("discovery_summary_to_json", exp.discovery_summary_to_json),
            ("validate_output_path", exp.validate_output_path),
        ]

        for name, expected_obj in expected_exports:
            assert hasattr(netprobe, name), f"netprobe missing export: {name}"
            assert getattr(netprobe, name) is expected_obj
            assert name in netprobe.__all__, f"{name} missing from __all__"

    def test_package_import_has_no_network_side_effects(self) -> None:
        """Ensure importing/reloading netprobe initiates zero socket activity."""
        with patch("socket.socket") as mock_socket:
            importlib.reload(netprobe)
            assert mock_socket.call_count == 0

    def test_package_version_remains_consistent(self) -> None:
        """Ensure package version is 0.2.0."""
        assert netprobe.__version__ == "0.2.0"

