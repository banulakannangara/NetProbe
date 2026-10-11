"""Focused tests for NetProbe Milestone 2.1: Initial Service Fingerprinting."""

import concurrent.futures
import socket
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from netprobe.cli import format_results_table, main
from netprobe.fingerprint.engine import FingerprintEngine
from netprobe.fingerprint.models import CertificateInfo, IdentificationMethod, ServiceInfo
from netprobe.fingerprint.probes import (
    MAX_BANNER_BYTES,
    MAX_HTTP_BYTES,
    parse_banner,
    parse_certificate_der,
    parse_http_response,
    parse_mysql_handshake,
    probe_http,
    probe_passive_banner,
    probe_tls,
)
from netprobe.scanner import (
    PortState,
    ScanInterruptedError,
    ScanResult,
    ScanSummary,
)


# ============================================================================
# 1. Data Model & ScanResult Backward Compatibility Tests
# ============================================================================


class TestFingerprintModels:
    """Validate data models, immutability, and ScanResult backward compatibility."""

    def test_service_info_immutability(self):
        """Ensure ServiceInfo is frozen and fields cannot be mutated."""
        info = ServiceInfo(
            name="ssh",
            method=IdentificationMethod.BANNER,
            product="OpenSSH",
            version="9.6p1",
            details="protocol 2.0 (OpenSSH_9.6p1)",
            confidence_note="Server greeting banner",
        )
        assert info.name == "ssh"
        assert info.method == IdentificationMethod.BANNER
        assert info.product == "OpenSSH"
        assert info.version == "9.6p1"
        with pytest.raises(AttributeError):
            info.name = "http"  # type: ignore[misc]

    def test_scan_result_backward_compatibility_positional(self):
        """ScanResult must support legacy 4-argument positional construction."""
        # Port, State, Service, Reason (Phase 1 constructor)
        res = ScanResult(80, PortState.OPEN, "http", "Connection established")
        assert res.port == 80
        assert res.state == PortState.OPEN
        assert res.service == "http"
        assert res.reason == "Connection established"
        assert res.service_info is None

    def test_scan_result_with_service_info(self):
        """ScanResult supports optional 5th parameter service_info."""
        info = ServiceInfo(
            name="http",
            method=IdentificationMethod.HTTP,
            details="HTTP/1.1 200 OK",
        )
        res = ScanResult(80, PortState.OPEN, "http", "Connection established", info)
        assert res.service_info is info
        assert res.service_info.method == IdentificationMethod.HTTP

    def test_conventional_vs_verified_methods(self):
        """IdentificationMethod must clearly separate conventional guesses from active probes."""
        assert IdentificationMethod.CONVENTIONAL.value == "conventional"
        assert IdentificationMethod.BANNER.value == "banner"
        assert IdentificationMethod.HTTP.value == "http"
        assert IdentificationMethod.UNKNOWN.value == "unknown"


# ============================================================================
# 2. Passive Banner Parsing Tests
# ============================================================================


class TestPassiveBannerParsing:
    """Validate passive greeting banner parser against RFCs and edge cases."""

    def test_parse_ssh_standard_banner(self):
        banner = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4\r\n"
        info = parse_banner(banner)
        assert info is not None
        assert info.name == "ssh"
        assert info.method == IdentificationMethod.BANNER
        assert info.product == "OpenSSH"
        assert info.version == "9.6p1"
        assert "protocol 2.0" in (info.details or "")
        assert info.confidence_note == "Server greeting banner"

    def test_parse_ssh_dropbear_banner(self):
        banner = "SSH-2.0-dropbear_2020.81\r\n"
        info = parse_banner(banner)
        assert info is not None
        assert info.name == "ssh"
        assert info.product == "dropbear"
        assert info.version == "2020.81"

    def test_parse_ftp_vsftpd_banner(self):
        banner = "220 (vsFTPd 3.0.5)\r\n"
        info = parse_banner(banner)
        assert info is not None
        assert info.name == "ftp"
        assert info.method == IdentificationMethod.BANNER
        assert info.product == "vsFTPd"
        assert "220" in (info.details or "")

    def test_parse_ftp_generic_banner(self):
        banner = "220 Service ready for new user.\r\n"
        info = parse_banner(banner)
        assert info is not None
        assert info.name == "ftp"
        assert info.method == IdentificationMethod.BANNER
        assert info.product is None

    def test_parse_smtp_banner_with_esmtp(self):
        banner = "220 mail.example.com ESMTP Postfix (Ubuntu)\r\n"
        info = parse_banner(banner)
        assert info is not None
        assert info.name == "smtp"
        assert info.method == IdentificationMethod.BANNER
        assert info.product == "Postfix"

    def test_parse_smtp_banner_generic(self):
        banner = "220 mx.example.org SMTP Service ready\r\n"
        info = parse_banner(banner)
        assert info is not None
        assert info.name == "smtp"
        assert info.method == IdentificationMethod.BANNER

    def test_parse_rejects_arbitrary_text(self):
        """Random words, echo lines, or protocol greetings not matching supported RFCs."""
        assert parse_banner("HELLO WORLD\r\n") is None
        assert parse_banner("Welcome to my custom server\n") is None
        assert parse_banner("REDIS +PONG\r\n") is None
        assert parse_banner("TELNET IAC\r\n") is None

    def test_parse_empty_and_whitespace(self):
        assert parse_banner("") is None
        assert parse_banner("   \r\n\t  ") is None


# ============================================================================
# 3. HTTP Response Parsing Tests
# ============================================================================


class TestHTTPResponseParsing:
    """Validate HTTP response parsing, status line handling, and Server header safety."""

    def test_http_200_ok_with_server_header(self):
        raw = (
            "HTTP/1.1 200 OK\r\n"
            "Date: Sun, 11 Oct 2026 12:00:00 GMT\r\n"
            "Server: nginx/1.24.0 (Ubuntu)\r\n"
            "Content-Length: 0\r\n\r\n"
        )
        info = parse_http_response(raw)
        assert info is not None
        assert info.name == "http"
        assert info.method == IdentificationMethod.HTTP
        assert info.product == "nginx"
        assert info.version == "1.24.0"
        assert "HTTP/1.1 200 OK" in (info.details or "")
        assert "Server: nginx/1.24.0 (Ubuntu)" in (info.details or "")
        # Must clearly identify Server header as self-reported / unverified
        assert "Self-reported by Server header (unverified)" in (info.confidence_note or "")

    def test_http_non_2xx_responses_confirm_http(self):
        """400, 403, 404, 500 responses still confirm HTTP service."""
        for code, reason in [("400", "Bad Request"), ("404", "Not Found"), ("500", "Internal Server Error")]:
            raw = f"HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\n\r\n"
            info = parse_http_response(raw)
            assert info is not None
            assert info.name == "http"
            assert info.method == IdentificationMethod.HTTP
            assert f"HTTP/1.1 {code} {reason}" in (info.details or "")
            assert "Syntactically valid HTTP status line" in (info.confidence_note or "")

    def test_http_response_without_server_header(self):
        raw = "HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n"
        info = parse_http_response(raw)
        assert info is not None
        assert info.name == "http"
        assert info.product is None
        assert info.version is None
        assert info.details == "HTTP/1.0 200 OK"

    def test_http_rejects_binary_or_malformed(self):
        assert parse_http_response("") is None
        assert parse_http_response("NOT HTTP AT ALL\r\n\r\n") is None
        assert parse_http_response("\x00\x01\x02\x03\x04") is None
        assert parse_http_response("HTTP/9.9 999 Invalid\r\n") is None

    def test_http_rejects_textual_http2_status_lines(self):
        """HTTP/2 is a binary framing protocol; textual 'HTTP/2 ...' must be rejected."""
        assert parse_http_response("HTTP/2 200 OK\r\nServer: nginx\r\n\r\n") is None
        assert parse_http_response("HTTP/2.0 200 OK\r\n\r\n") is None
        assert parse_http_response("HTTP/2 404 Not Found\r\n\r\n") is None

    def test_http_accepts_valid_http1_status_codes(self):
        """Status codes from 100 through 599 with HTTP/1.0 and HTTP/1.1 are valid."""
        for code in ["100", "200", "301", "404", "500", "599"]:
            for ver in ["1.0", "1.1"]:
                res = parse_http_response(f"HTTP/{ver} {code} Reason\r\n\r\n")
                assert res is not None
                assert res.name == "http"


# ============================================================================
# 4. Network Probe Function Tests (Local Socket & Mock Tests)
# ============================================================================


class TestNetworkProbes:
    """Test actual socket-level interaction for banner and HTTP probes."""

    def test_probe_passive_banner_ssh_loopback(self):
        """Establish a local loopback server that sends an SSH banner."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def serve():
            try:
                conn, _ = server.accept()
                conn.sendall(b"SSH-2.0-OpenSSH_9.6p1 NetProbeTest\r\n")
                conn.close()
            except Exception:
                pass
            finally:
                server.close()

        th = threading.Thread(target=serve, daemon=True)
        th.start()

        info = probe_passive_banner("127.0.0.1", port, timeout=1.0)
        th.join(timeout=1.0)

        assert info is not None
        assert info.name == "ssh"
        assert info.method == IdentificationMethod.BANNER
        assert info.product == "OpenSSH"

    def test_probe_passive_banner_silent_port_times_out(self):
        """A server that accepts connections but sends nothing must return None after timeout."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def serve():
            try:
                conn, _ = server.accept()
                time.sleep(0.3)
                conn.close()
            except Exception:
                pass
            finally:
                server.close()

        th = threading.Thread(target=serve, daemon=True)
        th.start()

        # Probe with small timeout
        info = probe_passive_banner("127.0.0.1", port, timeout=0.1)
        th.join(timeout=1.0)

        assert info is None

    def test_probe_passive_banner_connection_refused(self):
        """A closed port must return None without raising an exception."""
        # Pick an unused port by binding and immediately closing
        temp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        temp.bind(("127.0.0.1", 0))
        port = temp.getsockname()[1]
        temp.close()

        info = probe_passive_banner("127.0.0.1", port, timeout=0.2)
        assert info is None

    def test_probe_http_loopback(self):
        """Establish a local loopback server responding to HEAD with HTTP 200."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def serve():
            try:
                conn, _ = server.accept()
                req = conn.recv(1024)
                assert b"HEAD / HTTP/1.1" in req
                assert b"User-Agent: NetProbe" in req
                response = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Server: Apache/2.4.52 (Ubuntu)\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                conn.sendall(response)
                conn.close()
            except Exception:
                pass
            finally:
                server.close()

        th = threading.Thread(target=serve, daemon=True)
        th.start()

        info = probe_http("127.0.0.1", port, timeout=1.0)
        th.join(timeout=1.0)

        assert info is not None
        assert info.name == "http"
        assert info.method == IdentificationMethod.HTTP
        assert info.product == "Apache"
        assert info.version == "2.4.52"

    def test_probe_http_binary_garbage_response(self):
        """Server responding with binary noise must not crash probe."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def serve():
            try:
                conn, _ = server.accept()
                conn.recv(1024)
                conn.sendall(b"\xff\xfe\x00\x00\xaa\xbb\xcc\xdd\xee")
                conn.close()
            except Exception:
                pass
            finally:
                server.close()

        th = threading.Thread(target=serve, daemon=True)
        th.start()

        info = probe_http("127.0.0.1", port, timeout=1.0)
        th.join(timeout=1.0)

        assert info is None

    def test_misleading_port_identification(self):
        """SSH running on port 8080 or HTTP running on port 2222 must be correctly identified."""
        # 1. SSH on port 8080
        with patch("netprobe.fingerprint.probes.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"

            info = probe_passive_banner("127.0.0.1", 8080, timeout=0.5)
            assert info is not None
            assert info.name == "ssh"
            assert info.method == IdentificationMethod.BANNER

        # 2. HTTP on port 2222
        with patch("netprobe.fingerprint.probes.socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: Caddy\r\n\r\n"

            info = probe_http("127.0.0.1", 2222, timeout=0.5)
            assert info is not None
            assert info.name == "http"
            assert info.product == "Caddy"


# ============================================================================
# 5. FingerprintEngine Tests
# ============================================================================


class TestFingerprintEngine:
    """Validate engine sequencing, deadline adherence, and fallback behavior."""

    def test_fingerprint_port_prefers_banner_over_http(self):
        engine = FingerprintEngine(overall_timeout=1.0)

        with patch("netprobe.fingerprint.engine.probe_passive_banner") as mock_banner, \
             patch("netprobe.fingerprint.engine.probe_http") as mock_http:
            mock_banner.return_value = ServiceInfo(
                name="ssh",
                method=IdentificationMethod.BANNER,
                product="OpenSSH",
            )

            info = engine.fingerprint_port("127.0.0.1", 22)
            assert info.name == "ssh"
            assert info.method == IdentificationMethod.BANNER
            # HTTP probe should not be called if banner matches
            mock_http.assert_not_called()

    def test_fingerprint_port_falls_back_to_http(self):
        engine = FingerprintEngine(overall_timeout=1.0)

        with patch("netprobe.fingerprint.engine.probe_passive_banner") as mock_banner, \
             patch("netprobe.fingerprint.engine.probe_http") as mock_http:
            mock_banner.return_value = None  # Silent banner
            mock_http.return_value = ServiceInfo(
                name="http",
                method=IdentificationMethod.HTTP,
                details="HTTP/1.1 200 OK",
            )

            info = engine.fingerprint_port("127.0.0.1", 8080)
            assert info.name == "http"
            assert info.method == IdentificationMethod.HTTP

    def test_fingerprint_port_fallback_to_conventional(self):
        engine = FingerprintEngine(overall_timeout=1.0)

        with patch("netprobe.fingerprint.engine.probe_passive_banner", return_value=None), \
             patch("netprobe.fingerprint.engine.probe_http", return_value=None):
            info = engine.fingerprint_port("127.0.0.1", 3306)
            assert info.name == "mysql"
            assert info.method == IdentificationMethod.CONVENTIONAL
            assert "Unverified" in (info.details or "")

    def test_engine_only_fingerprints_open_ports(self):
        engine = FingerprintEngine()
        results = [
            ScanResult(22, PortState.OPEN, "ssh", "open"),
            ScanResult(23, PortState.CLOSED, "telnet", "Connection refused"),
            ScanResult(80, PortState.UNKNOWN, "http", "Timeout"),
        ]

        with patch.object(engine, "fingerprint_port") as mock_fp:
            mock_fp.return_value = ServiceInfo(
                name="ssh",
                method=IdentificationMethod.BANNER,
                product="OpenSSH",
            )
            updated = engine.fingerprint_results("127.0.0.1", results)

            assert len(updated) == 3
            # Only port 22 should have been fingerprinted
            mock_fp.assert_called_once_with("127.0.0.1", 22)
            assert updated[0].service_info is not None
            assert updated[1].service_info is None
            assert updated[2].service_info is None

    def test_engine_interruption_preserves_results(self):
        """Simulate Ctrl+C during fingerprinting; verify ScanInterruptedError preserves data and elapsed time."""
        engine = FingerprintEngine(max_workers=2)
        results = [
            ScanResult(22, PortState.OPEN, "ssh", "open"),
            ScanResult(80, PortState.OPEN, "http", "open"),
        ]

        # Patch ThreadPoolExecutor to simulate KeyboardInterrupt
        with patch("concurrent.futures.as_completed", side_effect=KeyboardInterrupt):
            with pytest.raises(ScanInterruptedError) as exc_info:
                engine.fingerprint_results("127.0.0.1", results, initial_elapsed=1.25)

            interrupted_summary = exc_info.value.summary
            assert interrupted_summary.interrupted is True
            assert len(interrupted_summary.results) == 2
            assert interrupted_summary.open_count == 2
            # Total elapsed time must be >= initial_elapsed
            assert interrupted_summary.elapsed_seconds >= 1.25

    def test_socket_budget_exhaustion_in_passive_banner(self):
        """When budget is exhausted after connect, banner probe must not call recv."""
        with patch("netprobe.fingerprint.probes.socket.socket") as mock_sock_cls, \
             patch("time.perf_counter") as mock_time:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            # Simulate time: start=10.0, after connect=10.55 (budget 0.5s expired)
            mock_time.side_effect = [10.0, 10.55]

            info = probe_passive_banner("127.0.0.1", 22, timeout=0.5)
            assert info is None
            mock_sock.connect.assert_called_once()
            # recv must not be called when remaining <= 0.01
            mock_sock.recv.assert_not_called()

    def test_socket_budget_exhaustion_in_http_probe(self):
        """When budget is exhausted after connect, HTTP probe must not call sendall or recv."""
        with patch("netprobe.fingerprint.probes.socket.socket") as mock_sock_cls, \
             patch("time.perf_counter") as mock_time:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            # Simulate time: start=10.0, after connect=10.8 (budget 0.75s expired)
            mock_time.side_effect = [10.0, 10.8]

            info = probe_http("127.0.0.1", 80, timeout=0.75)
            assert info is None
            mock_sock.connect.assert_called_once()
            mock_sock.sendall.assert_not_called()
            mock_sock.recv.assert_not_called()

    def test_zero_or_negative_budget_aborts_immediately(self):
        """Zero or negative timeout must abort before opening a socket."""
        with patch("netprobe.fingerprint.probes.socket.socket") as mock_sock_cls:
            assert probe_passive_banner("127.0.0.1", 22, timeout=0.0) is None
            assert probe_http("127.0.0.1", 80, timeout=-0.1) is None
            mock_sock_cls.assert_not_called()


# ============================================================================
# 6. CLI Integration Tests
# ============================================================================


class TestCLIIntegration:
    """Validate CLI behavior with --fingerprint / -sV and backward compatibility."""

    def test_format_results_table_default_unchanged(self):
        """When fingerprint=False, output format must match Phase 1 table."""
        summary = ScanSummary(
            target="192.168.1.1",
            total_ports=2,
            open_count=1,
            closed_count=1,
            unknown_count=0,
            elapsed_seconds=0.1,
            results=[
                ScanResult(80, PortState.OPEN, "http", "Connection established"),
                ScanResult(443, PortState.CLOSED, "https", "Connection refused"),
            ],
            interrupted=False,
        )
        table = format_results_table(summary, show_all=True, fingerprint=False)
        assert "REASON" in table
        assert "METHOD" not in table
        assert "DETAILS" not in table
        assert "Connection established" in table

    def test_format_results_table_fingerprint_enabled(self):
        """When fingerprint=True, table includes METHOD and DETAILS columns."""
        info = ServiceInfo(
            name="http",
            method=IdentificationMethod.HTTP,
            details="HTTP/1.1 200 OK (Server: nginx)",
        )
        summary = ScanSummary(
            target="192.168.1.1",
            total_ports=1,
            open_count=1,
            closed_count=0,
            unknown_count=0,
            elapsed_seconds=0.1,
            results=[
                ScanResult(80, PortState.OPEN, "http", "Connection established", info),
            ],
            interrupted=False,
        )
        table = format_results_table(summary, show_all=True, fingerprint=True)
        assert "METHOD" in table
        assert "DETAILS" in table
        assert "HTTP" in table
        assert "Server: nginx" in table

    def test_cli_help_includes_fingerprint_option(self, capsys):
        """netprobe --help must list --fingerprint and -sV."""
        exit_code = main(["--help"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "--fingerprint" in captured.out
        assert "-sV" in captured.out

    def test_cli_successful_scan_with_fingerprint(self, monkeypatch, capsys):
        """Run CLI main() with --fingerprint on an open port."""
        def fake_scan(self, ports):
            return ScanSummary(
                target="127.0.0.1",
                total_ports=1,
                open_count=1,
                closed_count=0,
                unknown_count=0,
                elapsed_seconds=0.05,
                results=[
                    ScanResult(22, PortState.OPEN, "ssh", "Connection established"),
                ],
                interrupted=False,
            )

        def fake_fingerprint_results(self, target, results, callback=None, initial_elapsed=0.0):
            info = ServiceInfo(
                name="ssh",
                method=IdentificationMethod.BANNER,
                product="OpenSSH",
                version="9.6p1",
                details="protocol 2.0 (OpenSSH_9.6p1)",
            )
            return [
                ScanResult(22, PortState.OPEN, "ssh", "Connection established", info),
            ]

        monkeypatch.setattr("netprobe.scanner.TCPScanner.scan", fake_scan)
        monkeypatch.setattr("netprobe.fingerprint.engine.FingerprintEngine.fingerprint_results", fake_fingerprint_results)

        exit_code = main(["127.0.0.1", "-p", "22", "--fingerprint"])
        assert exit_code == 0

        captured = capsys.readouterr()
        assert "METHOD" in captured.out
        assert "BANNER" in captured.out
        assert "OpenSSH_9.6p1" in captured.out

    def test_cli_table_formatting_with_tls_info(self):
        """When fingerprint=True and service has tls_info, details reflect TLS metadata."""
        cert = CertificateInfo(
            subject="CN=secure.example.com",
            issuer="CN=Example CA",
            not_before="Jan 01 00:00:00 2026 GMT",
            not_after="Dec 31 23:59:59 2026 GMT",
            verified=False,
            alpn_protocol="http/1.1",
            tls_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
        )
        info = ServiceInfo(
            name="https",
            method=IdentificationMethod.TLS,
            details="TLSv1.3 (TLS_AES_256_GCM_SHA384); HTTP/1.1 200 OK; CN: CN=secure.example.com",
            confidence_note="HTTP confirmed over TLS (Certificate unverified / CERT_NONE)",
            tls_info=cert,
        )
        summary = ScanSummary(
            target="127.0.0.1",
            total_ports=1,
            open_count=1,
            closed_count=0,
            unknown_count=0,
            elapsed_seconds=0.1,
            results=[
                ScanResult(443, PortState.OPEN, "https", "Connection established", info),
            ],
            interrupted=False,
        )
        table = format_results_table(summary, show_all=True, fingerprint=True)
        assert "443/tcp" in table
        assert "https" in table
        assert "TLS" in table
        assert "TLSv1.3" in table
        assert "secure.example.com" in table


# ============================================================================
# 7. Phase 2.2 TLS & HTTPS Probing Tests
# ============================================================================


class TestTLSProbing:
    """Validate TLS handshake, certificate parsing, ALPN, and engine sequencing."""

    def test_certificate_info_defaults(self):
        cert = CertificateInfo()
        assert cert.verified is False
        assert cert.subject is None
        assert cert.tls_version is None

    def test_parse_certificate_der_empty_or_malformed(self):
        from netprobe.fingerprint.probes import parse_certificate_der
        assert parse_certificate_der(b"") is None
        # Malformed bytes fall back to unverified CertificateInfo without crashing
        res = parse_certificate_der(b"not-a-der-cert")
        assert res is not None
        assert res.verified is False

    def test_parse_certificate_der_decoder_unavailable(self):
        """When ssl._ssl._test_decode_cert is unavailable, parse_certificate_der falls back safely."""
        from netprobe.fingerprint.probes import parse_certificate_der
        import ssl

        # Simulate standard library runtime where internal decoder is absent
        with patch.object(ssl, "_ssl", create=True) as mock_ssl_internal:
            # Delete _test_decode_cert attribute if present on mock
            if hasattr(mock_ssl_internal, "_test_decode_cert"):
                delattr(mock_ssl_internal, "_test_decode_cert")

            with patch("ssl.DER_cert_to_PEM_cert", return_value="-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----"):
                res = parse_certificate_der(b"fake-der-bytes")

            assert res is not None
            assert res.verified is False
            # Metadata must not be fabricated
            assert res.subject is None
            assert res.issuer is None
            assert res.not_before is None
            assert res.not_after is None

    def test_parse_certificate_der_decoder_raises_exception(self):
        """When internal decoder raises an exception, parser degrades safely without crashing."""
        from netprobe.fingerprint.probes import parse_certificate_der
        import ssl

        mock_internal = MagicMock()
        mock_internal._test_decode_cert.side_effect = ValueError("Corrupt certificate ASN.1 structure")

        with patch.object(ssl, "_ssl", mock_internal):
            with patch("ssl.DER_cert_to_PEM_cert", return_value="-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----"):
                res = parse_certificate_der(b"fake-der-bytes")

            assert res is not None
            assert res.verified is False
            assert res.subject is None
            assert res.issuer is None
            assert res.not_before is None
            assert res.not_after is None

    def test_probe_tls_loopback_self_signed(self):
        """Test real TLS handshake against local loopback with self-signed certificate."""
        import os
        import subprocess
        import tempfile

        # Generate a temporary self-signed cert for loopback testing
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, "key.pem")
            cert_path = os.path.join(tmpdir, "cert.pem")
            cmd = [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path, "-out", cert_path, "-days", "1",
                "-nodes", "-subj", "/CN=netprobe.test"
            ]
            try:
                subprocess.run(cmd, capture_output=True, check=True)
            except (subprocess.SubprocessError, FileNotFoundError):
                pytest.skip("OpenSSL CLI not available for loopback test cert generation")

            import ssl
            server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ctx.load_cert_chain(cert_path, key_path)
            server_ctx.set_alpn_protocols(["http/1.1"])

            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            port = server.getsockname()[1]

            def serve():
                try:
                    conn, _ = server.accept()
                    with server_ctx.wrap_socket(conn, server_side=True) as s_conn:
                        req = s_conn.recv(1024)
                        if b"HEAD" in req:
                            s_conn.sendall(b"HTTP/1.1 200 OK\r\nServer: NetProbe-TLS\r\nContent-Length: 0\r\n\r\n")
                except Exception:
                    pass
                finally:
                    server.close()

            th = threading.Thread(target=serve, daemon=True)
            th.start()

            from netprobe.fingerprint.probes import probe_tls
            info = probe_tls("127.0.0.1", port, timeout=2.0)
            th.join(timeout=2.0)

            assert info is not None
            assert info.name == "https"
            assert info.method == IdentificationMethod.TLS
            assert info.tls_info is not None
            assert info.tls_info.verified is False  # Explicitly unverified / CERT_NONE
            assert info.tls_info.alpn_protocol == "http/1.1"
            assert "NetProbe-TLS" in (info.details or "")
            assert "netprobe.test" in (info.details or "")

    def test_probe_tls_generic_non_http(self):
        """Test TLS service that handshakes successfully but does not speak HTTP."""
        import os
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, "key.pem")
            cert_path = os.path.join(tmpdir, "cert.pem")
            cmd = [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path, "-out", cert_path, "-days", "1",
                "-nodes", "-subj", "/CN=generic-tls.local"
            ]
            try:
                subprocess.run(cmd, capture_output=True, check=True)
            except (subprocess.SubprocessError, FileNotFoundError):
                pytest.skip("OpenSSL CLI not available for loopback test cert generation")

            import ssl
            server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ctx.load_cert_chain(cert_path, key_path)

            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            port = server.getsockname()[1]

            def serve():
                try:
                    conn, _ = server.accept()
                    with server_ctx.wrap_socket(conn, server_side=True) as s_conn:
                        # Close connection without sending HTTP response
                        s_conn.recv(1024)
                except Exception:
                    pass
                finally:
                    server.close()

            th = threading.Thread(target=serve, daemon=True)
            th.start()

            from netprobe.fingerprint.probes import probe_tls
            info = probe_tls("127.0.0.1", port, timeout=2.0)
            th.join(timeout=2.0)

            assert info is not None
            assert info.name == "tls"
            assert info.method == IdentificationMethod.TLS
            assert info.tls_info is not None
            assert "generic-tls.local" in (info.details or "")

    def test_probe_tls_handshake_failure_on_plain_http_port(self):
        """A plain HTTP server that receives a TLS ClientHello fails the handshake and returns None."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def serve():
            try:
                conn, _ = server.accept()
                # Server does not understand TLS ClientHello and closes or sends plain text
                conn.recv(1024)
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                conn.close()
            except Exception:
                pass
            finally:
                server.close()

        th = threading.Thread(target=serve, daemon=True)
        th.start()

        from netprobe.fingerprint.probes import probe_tls
        info = probe_tls("127.0.0.1", port, timeout=1.0)
        th.join(timeout=1.0)

        # probe_tls must return None on handshake failure
        assert info is None

    def test_probe_tls_connection_refused(self):
        """Closed port must return None without raising uncaught exceptions."""
        temp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        temp.bind(("127.0.0.1", 0))
        port = temp.getsockname()[1]
        temp.close()

        from netprobe.fingerprint.probes import probe_tls
        info = probe_tls("127.0.0.1", port, timeout=0.2)
        assert info is None

    def test_probe_tls_budget_exhaustion(self):
        """When budget is exhausted after connect, probe_tls aborts before wrapping socket."""
        with patch("netprobe.fingerprint.probes.socket.socket") as mock_sock_cls, \
             patch("time.perf_counter") as mock_time:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            # Start: 10.0, after connect: 11.05 (timeout 1.0s exhausted)
            mock_time.side_effect = [10.0, 11.05]

            from netprobe.fingerprint.probes import probe_tls
            info = probe_tls("127.0.0.1", 443, timeout=1.0)
            assert info is None
            mock_sock.connect.assert_called_once()

    def test_engine_probe_sequencing_tls_fallback(self):
        """Engine attempts passive banner -> HTTP -> TLS -> Conventional."""
        engine = FingerprintEngine(overall_timeout=2.0)

        with patch("netprobe.fingerprint.engine.probe_passive_banner", return_value=None), \
             patch("netprobe.fingerprint.engine.probe_http", return_value=None), \
             patch("netprobe.fingerprint.engine.probe_tls") as mock_tls:

            mock_tls.return_value = ServiceInfo(
                name="https",
                method=IdentificationMethod.TLS,
                details="TLSv1.3",
            )

            info = engine.fingerprint_port("127.0.0.1", 8443)
            assert info.name == "https"
            assert info.method == IdentificationMethod.TLS
            mock_tls.assert_called_once_with("127.0.0.1", 8443, timeout=1.0)


# ============================================================================
# 8. Phase 2.3 Conditional GET Fallback & Status-Line Resilience Tests
# ============================================================================


class TestHTTPGetFallback:
    """Validate conditional GET fallback, budget enforcement, and status resilience."""

    def test_valid_head_response_never_sends_get(self):
        """When HEAD succeeds with a valid status line, GET is never sent."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        requests_received: list[bytes] = []

        def serve():
            try:
                conn, _ = server.accept()
                req = conn.recv(1024)
                requests_received.append(req)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                conn.close()
            except Exception:
                pass
            finally:
                server.close()

        th = threading.Thread(target=serve, daemon=True)
        th.start()

        info = probe_http("127.0.0.1", port, timeout=1.0)
        th.join(timeout=1.0)

        assert info is not None
        assert info.name == "http"
        assert len(requests_received) == 1
        assert b"HEAD / HTTP/1.1" in requests_received[0]
        assert b"GET / HTTP/1.1" not in requests_received[0]

    def test_head_receives_valid_405_and_does_not_send_get(self):
        """A valid HTTP 405 Method Not Allowed response to HEAD confirms HTTP and does not send GET."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        requests_received: list[bytes] = []

        def serve():
            try:
                conn, _ = server.accept()
                req = conn.recv(1024)
                requests_received.append(req)
                conn.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nAllow: GET, POST\r\n\r\n")
                conn.close()
            except Exception:
                pass
            finally:
                server.close()

        th = threading.Thread(target=serve, daemon=True)
        th.start()

        info = probe_http("127.0.0.1", port, timeout=1.0)
        th.join(timeout=1.0)

        assert info is not None
        assert info.name == "http"
        assert "405 Method Not Allowed" in (info.details or "")
        assert len(requests_received) == 1
        assert b"HEAD / HTTP/1.1" in requests_received[0]

    def test_head_empty_response_triggers_get_fallback_when_budget_remains(self):
        """When HEAD produces an empty response (or closes), probe_http falls back to GET."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(2)
        port = server.getsockname()[1]
        requests_received: list[bytes] = []

        def serve():
            try:
                # 1st connection (HEAD): accept and close immediately without response
                conn1, _ = server.accept()
                req1 = conn1.recv(1024)
                requests_received.append(req1)
                conn1.close()

                # 2nd connection (GET fallback): respond with 200 OK
                conn2, _ = server.accept()
                req2 = conn2.recv(1024)
                requests_received.append(req2)
                conn2.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO")
                conn2.close()
            except Exception:
                pass
            finally:
                server.close()

        th = threading.Thread(target=serve, daemon=True)
        th.start()

        info = probe_http("127.0.0.1", port, timeout=1.5)
        th.join(timeout=1.5)

        assert info is not None
        assert info.name == "http"
        assert len(requests_received) == 2
        assert b"HEAD / HTTP/1.1" in requests_received[0]
        assert b"GET / HTTP/1.1" in requests_received[1]
        assert b"Range: bytes=0-512" in requests_received[1]

    def test_fallback_get_response_recognized_as_http(self):
        """A valid response to fallback GET is recognized and extracts metadata properly."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(2)
        port = server.getsockname()[1]

        def serve():
            try:
                conn1, _ = server.accept()
                conn1.recv(1024)
                conn1.close()  # Drop HEAD

                conn2, _ = server.accept()
                conn2.recv(1024)
                conn2.sendall(b"HTTP/1.1 206 Partial Content\r\nServer: Caddy\r\nContent-Range: bytes 0-512/1000\r\n\r\nDATA")
                conn2.close()
            except Exception:
                pass
            finally:
                server.close()

        th = threading.Thread(target=serve, daemon=True)
        th.start()

        info = probe_http("127.0.0.1", port, timeout=1.5)
        th.join(timeout=1.5)

        assert info is not None
        assert info.name == "http"
        assert info.product == "Caddy"
        assert "206 Partial Content" in (info.details or "")

    def test_insufficient_remaining_budget_prevents_get_fallback(self):
        """If remaining budget after failed HEAD is <= 0.05s, GET fallback must not be dispatched."""
        with patch("netprobe.fingerprint.probes.socket.socket") as mock_sock_cls, \
             patch("time.perf_counter") as mock_time:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.recv.return_value = b""  # Empty HEAD response

            # Start at 10.0, connect at 10.1, after HEAD recv at 10.72 (remaining = 0.75 - 0.72 = 0.03 <= 0.05)
            mock_time.side_effect = [10.0, 10.1, 10.2, 10.72]

            info = probe_http("127.0.0.1", 80, timeout=0.75)
            assert info is None
            # Only 1 socket was created and connected (for HEAD); no second socket for GET
            assert mock_sock.connect.call_count == 1

    def test_get_fallback_request_contains_range_header(self):
        """GET fallback request must include Range: bytes=0-512 and Connection: close."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(2)
        port = server.getsockname()[1]
        get_request_bytes = b""

        def serve():
            nonlocal get_request_bytes
            try:
                conn1, _ = server.accept()
                conn1.recv(1024)
                conn1.close()  # Drop HEAD

                conn2, _ = server.accept()
                get_request_bytes = conn2.recv(1024)
                conn2.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
                conn2.close()
            except Exception:
                pass
            finally:
                server.close()

        th = threading.Thread(target=serve, daemon=True)
        th.start()

        probe_http("127.0.0.1", port, timeout=1.5)
        th.join(timeout=1.5)

        assert b"GET / HTTP/1.1\r\n" in get_request_bytes
        assert b"Range: bytes=0-512\r\n" in get_request_bytes
        assert b"Connection: close\r\n" in get_request_bytes

    def test_get_fallback_response_capped_at_max_bytes(self):
        """Verify that probe_http passes max_bytes=2048 to recv during GET fallback."""
        with patch("netprobe.fingerprint.probes.socket.socket") as mock_sock_cls:
            mock_sock1 = MagicMock()
            mock_sock2 = MagicMock()
            mock_sock_cls.side_effect = [mock_sock1, mock_sock2]

            # HEAD returns nothing
            mock_sock1.recv.return_value = b""
            # GET returns 200 OK
            mock_sock2.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"

            info = probe_http("127.0.0.1", 80, timeout=1.0, max_bytes=2048)
            assert info is not None
            mock_sock2.recv.assert_called_once_with(2048)

    def test_https_get_fallback_within_existing_tls_session(self):
        """In probe_tls, if HEAD yields no HTTP status line, GET fallback is sent in the same TLS session."""
        import os
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, "key.pem")
            cert_path = os.path.join(tmpdir, "cert.pem")
            cmd = [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path, "-out", cert_path, "-days", "1",
                "-nodes", "-subj", "/CN=https-fallback.local"
            ]
            try:
                subprocess.run(cmd, capture_output=True, check=True)
            except (subprocess.SubprocessError, FileNotFoundError):
                pytest.skip("OpenSSL CLI not available for loopback test cert generation")

            import ssl
            server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ctx.load_cert_chain(cert_path, key_path)

            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            port = server.getsockname()[1]
            tls_requests: list[bytes] = []

            def serve():
                try:
                    conn, _ = server.accept()
                    with server_ctx.wrap_socket(conn, server_side=True) as s_conn:
                        # 1st request inside TLS (HEAD): send non-HTTP line so HEAD doesn't validate
                        req1 = s_conn.recv(1024)
                        tls_requests.append(req1)
                        s_conn.sendall(b"NON-HTTP-RESPONSE\r\n")

                        # 2nd request inside TLS (fallback GET): respond with valid HTTP status line
                        req2 = s_conn.recv(1024)
                        tls_requests.append(req2)
                        s_conn.sendall(b"HTTP/1.1 200 OK\r\nServer: TLS-App\r\n\r\n")
                except Exception:
                    pass
                finally:
                    server.close()

            th = threading.Thread(target=serve, daemon=True)
            th.start()

            info = probe_tls("127.0.0.1", port, timeout=2.5)
            th.join(timeout=2.5)

            assert info is not None
            assert info.name == "https"
            assert info.method == IdentificationMethod.TLS
            assert len(tls_requests) == 2
            assert b"HEAD / HTTP/1.1" in tls_requests[0]
            assert b"GET / HTTP/1.1" in tls_requests[1]
            assert b"Range: bytes=0-512" in tls_requests[1]
            assert "TLS-App" in (info.details or "")

    def test_status_line_resilience_and_rejections(self):
        """Status line parser correctly accepts LF/CRLF and rejects truncated tokens."""
        # CRLF and LF both valid
        assert parse_http_response("HTTP/1.1 200 OK\r\n\r\n") is not None
        assert parse_http_response("HTTP/1.1 200 OK\n\n") is not None
        assert parse_http_response("HTTP/1.0 404 Not Found\n") is not None

        # Truncated or malformed tokens rejected
        assert parse_http_response("HTT\r\n") is None
        assert parse_http_response("HTTP\r\n") is None
        assert parse_http_response("HTTP/1\r\n") is None
        assert parse_http_response("HTTP/1.\r\n") is None
        assert parse_http_response("HTTP/1.1\r\n") is None
        assert parse_http_response("HTTP/1.1 2\r\n") is None
        assert parse_http_response("HTTP/1.1 20\r\n") is None
        assert parse_http_response("HTTP/1.1 2000 Invalid\r\n") is None
        assert parse_http_response("HTTP/1.1 099 Invalid\r\n") is None
        assert parse_http_response("HTTP/1.1 600 Invalid\r\n") is None
        assert parse_http_response("HTTP/2 200 OK\r\n") is None
        assert parse_http_response("HTTP/3.0 200 OK\r\n") is None

    def test_exceptions_during_fallback_still_close_sockets(self):
        """Unexpected exceptions during GET fallback still reliably close sockets."""
        with patch("netprobe.fingerprint.probes.socket.socket") as mock_sock_cls:
            mock_sock1 = MagicMock()
            mock_sock2 = MagicMock()
            mock_sock_cls.side_effect = [mock_sock1, mock_sock2]

            # HEAD returns nothing
            mock_sock1.recv.return_value = b""
            # GET raises OSError during connect or send
            mock_sock2.connect.side_effect = OSError("Network reset")

            info = probe_http("127.0.0.1", 80, timeout=1.0)
            assert info is None
            mock_sock1.close.assert_called()
            mock_sock2.close.assert_called()


# ============================================================================
# 8. Phase 2.4 Protocol Coverage & Banner Disambiguation Tests
# ============================================================================


class TestPhase24ProtocolCoverage:
    """Validate Phase 2.4 protocol coverage (POP3, IMAP, VNC, MySQL) and FTP/SMTP disambiguation."""

    # --- 1. FTP / SMTP Disambiguation & New MTAs ---

    def test_parse_smtp_new_mta_signatures(self):
        """Recognize Microsoft ESMTP, OpenSMTPD, and qmail signatures."""
        ms = parse_banner("220 mail.example.com Microsoft ESMTP MAIL Service ready at Sun, 11 Oct 2026 12:00:00\r\n")
        assert ms is not None
        assert ms.name == "smtp"
        assert ms.product == "Microsoft ESMTP"

        open_smtp = parse_banner("220 mail.example.com ESMTP OpenSMTPD\r\n")
        assert open_smtp is not None
        assert open_smtp.name == "smtp"
        assert open_smtp.product == "OpenSMTPD"

        qm = parse_banner("220 mx.example.com qmail\r\n")
        assert qm is not None
        assert qm.name == "smtp"
        assert qm.product == "qmail"

    def test_parse_220_ambiguous_without_port_returns_none(self):
        """Ambiguous 220 greetings without protocol keywords or port context must not default to FTP."""
        assert parse_banner("220 mx.example.com Service ready\r\n") is None
        assert parse_banner("220 Welcome to our host\r\n") is None
        assert parse_banner("220 server.local\r\n") is None

    def test_parse_220_ambiguous_with_port_context(self):
        """Ambiguous 220 greetings use port context as supporting evidence."""
        # Port 25 or 587 -> SMTP
        info_25 = parse_banner("220 mx.example.com Service ready\r\n", port=25)
        assert info_25 is not None
        assert info_25.name == "smtp"
        assert "port-assisted" in (info_25.confidence_note or "")

        info_587 = parse_banner("220 mx.example.com Service ready\r\n", port=587)
        assert info_587 is not None
        assert info_587.name == "smtp"

        # Port 21 -> FTP
        info_21 = parse_banner("220 server.local Service ready\r\n", port=21)
        assert info_21 is not None
        assert info_21.name == "ftp"
        assert "port-assisted" in (info_21.confidence_note or "")

        # Unrelated port (e.g. 8080) -> None
        assert parse_banner("220 server.local Service ready\r\n", port=8080) is None

    def test_parse_ftp_explicit_products(self):
        """Explicit FTP signatures are correctly identified without port context."""
        pure = parse_banner("220-Pure-FTPd [privsep] [TLS]\r\n")
        assert pure is not None
        assert pure.name == "ftp"
        assert pure.product == "Pure-FTPd"

        pro = parse_banner("220 ProFTPD 1.3.8 Server ready\r\n")
        assert pro is not None
        assert pro.name == "ftp"
        assert pro.product == "ProFTPD"

        ms_ftp = parse_banner("220 Microsoft FTP Service\r\n")
        assert ms_ftp is not None
        assert ms_ftp.name == "ftp"
        assert ms_ftp.product == "Microsoft FTP Service"

    # --- 2. POP3 Recognition ---

    def test_parse_pop3_standard_and_products(self):
        """Validate standard POP3 greetings and software extraction."""
        dovecot = parse_banner("+OK Dovecot ready.\r\n")
        assert dovecot is not None
        assert dovecot.name == "pop3"
        assert dovecot.method == IdentificationMethod.BANNER
        assert dovecot.product == "Dovecot"
        assert "+OK Dovecot ready." in (dovecot.details or "")

        courier = parse_banner("+OK Courier-POP3 ready\r\n")
        assert courier is not None
        assert courier.name == "pop3"
        assert courier.product == "Courier"

        exchange = parse_banner("+OK Microsoft Exchange 2016 POP3 server ready\r\n")
        assert exchange is not None
        assert exchange.name == "pop3"
        assert exchange.product == "Microsoft Exchange"

        generic = parse_banner("+OK POP3 server ready\r\n")
        assert generic is not None
        assert generic.name == "pop3"
        assert generic.product is None

        bare = parse_banner("+OK\r\n")
        assert bare is not None
        assert bare.name == "pop3"
        assert bare.product is None

    def test_parse_pop3_rejections_and_malformed(self):
        """Reject non-POP3 lines or malformed +OK tokens."""
        assert parse_banner("-ERR Unknown command\r\n") is None
        assert parse_banner("+OKAY not pop3\r\n") is None
        assert parse_banner("Server says +OK ready\r\n") is None

    # --- 3. IMAP Recognition ---

    def test_parse_imap_standard_and_products(self):
        """Validate standard IMAP greetings and software extraction."""
        dovecot = parse_banner("* OK Dovecot ready.\r\n")
        assert dovecot is not None
        assert dovecot.name == "imap"
        assert dovecot.method == IdentificationMethod.BANNER
        assert dovecot.product == "Dovecot"
        assert "* OK Dovecot ready." in (dovecot.details or "")

        courier = parse_banner("* OK [CAPABILITY IMAP4rev1] Courier-IMAP ready.\r\n")
        assert courier is not None
        assert courier.name == "imap"
        assert courier.product == "Courier"

        exchange = parse_banner("* OK Microsoft Exchange Server IMAP4 service ready\r\n")
        assert exchange is not None
        assert exchange.name == "imap"
        assert exchange.product == "Microsoft Exchange"

        generic = parse_banner("* OK IMAP4rev1 Server Ready\r\n")
        assert generic is not None
        assert generic.name == "imap"
        assert generic.product is None

        preauth = parse_banner("* PREAUTH Connection pre-authenticated\r\n")
        assert preauth is not None
        assert preauth.name == "imap"
        assert preauth.product is None

    def test_parse_imap_rejections_and_malformed(self):
        """Reject non-IMAP lines or malformed * OK tokens."""
        assert parse_banner("* BAD Invalid command\r\n") is None
        assert parse_banner("* NO Server busy\r\n") is None
        assert parse_banner("* OKAY not imap\r\n") is None
        assert parse_banner("OK IMAP4rev1 Server Ready\r\n") is None

    # --- 4. VNC / RFB Recognition ---

    def test_parse_vnc_standard_versions(self):
        """Validate RFB protocol version parsing."""
        v38 = parse_banner("RFB 003.008\n")
        assert v38 is not None
        assert v38.name == "vnc"
        assert v38.method == IdentificationMethod.BANNER
        assert v38.product == "VNC"
        assert v38.version == "3.8"
        assert "RFB protocol 3.8 (003.008)" in (v38.details or "")

        v33 = parse_banner("RFB 003.003\r\n")
        assert v33 is not None
        assert v33.name == "vnc"
        assert v33.version == "3.3"

        v41 = parse_banner("RFB 004.001\n")
        assert v41 is not None
        assert v41.name == "vnc"
        assert v41.version == "4.1"

    def test_parse_vnc_rejections_and_malformed(self):
        """Reject invalid or truncated RFB strings."""
        assert parse_banner("RFB 3.8\n") is None
        assert parse_banner("RFB abc.def\n") is None
        assert parse_banner("RFB 003.\n") is None
        assert parse_banner("RFB_SERVER 1.0\n") is None
        assert parse_banner("RFB\n") is None

    # --- 5. MySQL Handshake Recognition ---

    @staticmethod
    def _make_mysql_packet(version: str, proto: int = 10, seq_id: int = 0, corrupt_len: int | None = None) -> bytes:
        """Construct synthetic MySQL server handshake packet."""
        payload = bytes([proto]) + version.encode("ascii") + b"\x00" + b"\x01\x02\x03\x04" + b"extra_payload_data"
        declared_len = corrupt_len if corrupt_len is not None else len(payload)
        header = declared_len.to_bytes(3, "little") + bytes([seq_id])
        return header + payload

    def test_parse_mysql_valid_handshakes(self):
        """Validate MySQL and MariaDB synthetic handshake packets."""
        pkt_mysql8 = self._make_mysql_packet("8.0.35-0ubuntu0.22.04.1")
        info8 = parse_mysql_handshake(pkt_mysql8)
        assert info8 is not None
        assert info8.name == "mysql"
        assert info8.method == IdentificationMethod.BANNER
        assert info8.product == "MySQL"
        assert info8.version == "8.0.35-0ubuntu0.22.04.1"
        assert "protocol 10 (8.0.35-0ubuntu0.22.04.1)" in (info8.details or "")
        assert info8.confidence_note == "MySQL server handshake"

        pkt_maria = self._make_mysql_packet("10.11.6-MariaDB-1:10.11.6+maria~ubu2204")
        info_maria = parse_mysql_handshake(pkt_maria)
        assert info_maria is not None
        assert info_maria.name == "mysql"
        assert info_maria.product == "MariaDB"
        assert info_maria.version == "10.11.6-MariaDB-1:10.11.6+maria~ubu2204"

        pkt_mysql5 = self._make_mysql_packet("5.7.42")
        info5 = parse_mysql_handshake(pkt_mysql5)
        assert info5 is not None
        assert info5.name == "mysql"
        assert info5.product == "MySQL"
        assert info5.version == "5.7.42"

    def test_parse_mysql_malformed_and_edge_cases(self):
        """Reject invalid headers, bounds, and corrupt packet structures."""
        # Empty and truncated header (< 5 bytes)
        assert parse_mysql_handshake(b"") is None
        assert parse_mysql_handshake(b"\x01\x02\x03\x04") is None

        # Sequence ID != 0
        pkt_bad_seq = self._make_mysql_packet("8.0.35", seq_id=1)
        assert parse_mysql_handshake(pkt_bad_seq) is None

        # Protocol version != 0x0a
        pkt_bad_proto = self._make_mysql_packet("8.0.35", proto=9)
        assert parse_mysql_handshake(pkt_bad_proto) is None

        pkt_zero_proto = self._make_mysql_packet("8.0.35", proto=0)
        assert parse_mysql_handshake(pkt_zero_proto) is None

        # Excessive declared length
        pkt_huge = self._make_mysql_packet("8.0.35", corrupt_len=20000)
        assert parse_mysql_handshake(pkt_huge) is None

        # Too short declared length (< 3 bytes)
        pkt_tiny = self._make_mysql_packet("", corrupt_len=1)
        assert parse_mysql_handshake(pkt_tiny) is None

        # Missing null terminator
        no_null = b"\x07\x00\x00\x00\x0a8.0.35"
        assert parse_mysql_handshake(no_null) is None

        # Empty version string (null byte at byte 5)
        empty_ver = b"\x06\x00\x00\x00\x0a\x00\x01\x02\x03\x04"
        assert parse_mysql_handshake(empty_ver) is None

        # Non-printable version string
        non_print = b"\x06\x00\x00\x00\x0a\x01\x02\x03\x00\x05"
        assert parse_mysql_handshake(non_print) is None

    def test_parse_mysql_truncated_payload_rejection(self):
        """Reject truncated packets where declared payload length exceeds received bytes."""
        full_pkt = self._make_mysql_packet("8.0.35-0ubuntu0.22.04.1")
        # 1. Truncated after version string and null terminator
        # Null terminator is at byte 5 + len("8.0.35-0ubuntu0.22.04.1") = 28
        # Slicing at 30 leaves version intact, but buffer < 4 + payload_len
        pkt_partial = full_pkt[:30]
        assert parse_mysql_handshake(pkt_partial) is None

        # 2. Artificially declared length larger than received buffer
        pkt_oversized_declared = self._make_mysql_packet(
            "8.0.35", corrupt_len=len(full_pkt) + 20
        )
        assert parse_mysql_handshake(pkt_oversized_declared) is None

        # 3. Truncated before version null terminator
        pkt_cut_mid_version = full_pkt[:10]
        assert parse_mysql_handshake(pkt_cut_mid_version) is None

    def test_parse_banner_accepts_bytes_or_text(self):
        """parse_banner accepts raw bytes for MySQL and falls back to text for ASCII banners."""
        mysql_pkt = self._make_mysql_packet("8.0.35")
        mysql_info = parse_banner(mysql_pkt)
        assert mysql_info is not None
        assert mysql_info.name == "mysql"

        ssh_bytes = b"SSH-2.0-OpenSSH_9.6p1\r\n"
        ssh_info = parse_banner(ssh_bytes)
        assert ssh_info is not None
        assert ssh_info.name == "ssh"

    # --- 6. Real Loopback Integration ---

    def test_probe_passive_banner_mysql_loopback(self):
        """Verify probe_passive_banner identifies MySQL over a real TCP socket."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        pkt = self._make_mysql_packet("8.0.35")

        def serve():
            try:
                conn, _ = server.accept()
                conn.sendall(pkt)
                conn.close()
            except Exception:
                pass
            finally:
                server.close()

        th = threading.Thread(target=serve, daemon=True)
        th.start()

        info = probe_passive_banner("127.0.0.1", port, timeout=1.0)
        th.join(timeout=1.0)

        assert info is not None
        assert info.name == "mysql"
        assert info.product == "MySQL"
        assert info.version == "8.0.35"

    def test_probe_passive_banner_pop3_loopback(self):
        """Verify probe_passive_banner identifies POP3 over a real TCP socket."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def serve():
            try:
                conn, _ = server.accept()
                conn.sendall(b"+OK Dovecot ready.\r\n")
                conn.close()
            except Exception:
                pass
            finally:
                server.close()

        th = threading.Thread(target=serve, daemon=True)
        th.start()

        info = probe_passive_banner("127.0.0.1", port, timeout=1.0)
        th.join(timeout=1.0)

        assert info is not None
        assert info.name == "pop3"
        assert info.product == "Dovecot"


# ============================================================================
# 9. Phase 2.5 TLS Certificate SAN Metadata Tests
# ============================================================================


class TestPhase25SANMetadata:
    """Validate extraction, formatting, error-resilience, and compatibility of SAN metadata."""

    def test_certificate_info_san_backward_compatibility(self):
        """CertificateInfo preserves default san=() and 8-arg positional compatibility."""
        # 1. Default constructor
        cert_default = CertificateInfo()
        assert cert_default.san == ()

        # 2. Positional constructor with 8 original arguments
        cert_8pos = CertificateInfo(
            "CN=legacy.test",
            "CN=Root CA",
            "Jan 1 00:00:00 2026 GMT",
            "Jan 1 00:00:00 2027 GMT",
            False,
            "http/1.1",
            "TLSv1.3",
            "TLS_AES_256_GCM_SHA384",
        )
        assert cert_8pos.subject == "CN=legacy.test"
        assert cert_8pos.san == ()

        # 3. Positional constructor with 9 arguments including san
        cert_9pos = CertificateInfo(
            "CN=modern.test",
            "CN=Root CA",
            "Jan 1 00:00:00 2026 GMT",
            "Jan 1 00:00:00 2027 GMT",
            False,
            "http/1.1",
            "TLSv1.3",
            "TLS_AES_256_GCM_SHA384",
            ("modern.test", "127.0.0.1"),
        )
        assert cert_9pos.san == ("modern.test", "127.0.0.1")

    def test_parse_certificate_der_multiple_dns_san(self):
        """Extract multiple DNS SAN entries from decoded certificate."""
        import ssl
        mock_internal = MagicMock()
        mock_internal._test_decode_cert.return_value = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "Test CA"),),),
            "notBefore": "Jan 1 00:00:00 2026 GMT",
            "notAfter": "Jan 1 00:00:00 2027 GMT",
            "subjectAltName": (
                ("DNS", "example.com"),
                ("DNS", "api.example.com"),
                ("DNS", "cdn.example.com"),
            ),
        }

        with patch.object(ssl, "_ssl", mock_internal), \
             patch("ssl.DER_cert_to_PEM_cert", return_value="-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----"):
            cert = parse_certificate_der(b"dummy-der")

        assert cert is not None
        assert cert.subject == "CN=example.com"
        assert cert.san == ("example.com", "api.example.com", "cdn.example.com")

    def test_parse_certificate_der_ip_san(self):
        """Extract IP Address SAN entries from decoded certificate."""
        import ssl
        mock_internal = MagicMock()
        mock_internal._test_decode_cert.return_value = {
            "subject": ((("commonName", "127.0.0.1"),),),
            "subjectAltName": (
                ("IP Address", "127.0.0.1"),
                ("IP Address", "10.0.0.1"),
            ),
        }

        with patch.object(ssl, "_ssl", mock_internal), \
             patch("ssl.DER_cert_to_PEM_cert", return_value="-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----"):
            cert = parse_certificate_der(b"dummy-der")

        assert cert is not None
        assert cert.san == ("127.0.0.1", "10.0.0.1")

    def test_parse_certificate_der_both_dns_and_ip_san(self):
        """Extract both DNS and IP Address SAN entries in order."""
        import ssl
        mock_internal = MagicMock()
        mock_internal._test_decode_cert.return_value = {
            "subject": ((("commonName", "service.internal"),),),
            "subjectAltName": (
                ("DNS", "service.internal"),
                ("IP Address", "192.168.1.10"),
                ("DNS", "service.local"),
            ),
        }

        with patch.object(ssl, "_ssl", mock_internal), \
             patch("ssl.DER_cert_to_PEM_cert", return_value="-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----"):
            cert = parse_certificate_der(b"dummy-der")

        assert cert is not None
        assert cert.san == ("service.internal", "192.168.1.10", "service.local")

    def test_parse_certificate_der_without_san_extension(self):
        """Certificates without subjectAltName extension yield empty tuple san=()."""
        import ssl
        mock_internal = MagicMock()
        # Case A: subjectAltName key is missing
        mock_internal._test_decode_cert.return_value = {
            "subject": ((("commonName", "legacy.example.com"),),),
        }

        with patch.object(ssl, "_ssl", mock_internal), \
             patch("ssl.DER_cert_to_PEM_cert", return_value="-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----"):
            cert = parse_certificate_der(b"dummy-der")

        assert cert is not None
        assert cert.san == ()

        # Case B: subjectAltName is None
        mock_internal._test_decode_cert.return_value = {
            "subject": ((("commonName", "legacy.example.com"),),),
            "subjectAltName": None,
        }
        with patch.object(ssl, "_ssl", mock_internal), \
             patch("ssl.DER_cert_to_PEM_cert", return_value="-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----"):
            cert_none = parse_certificate_der(b"dummy-der")
        assert cert_none is not None
        assert cert_none.san == ()

    def test_parse_certificate_der_malformed_san_or_undecodable(self):
        """Malformed SAN structures, decoder exceptions, and corrupt DER degrade safely."""
        import ssl

        # 1. Malformed DER bytes
        cert_corrupt = parse_certificate_der(b"not-der-bytes")
        assert cert_corrupt is not None
        assert cert_corrupt.san == ()

        # 2. Decoder raises exception
        mock_internal = MagicMock()
        mock_internal._test_decode_cert.side_effect = ValueError("Malformed ASN.1")
        with patch.object(ssl, "_ssl", mock_internal), \
             patch("ssl.DER_cert_to_PEM_cert", return_value="-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----"):
            cert_exc = parse_certificate_der(b"dummy-der")
        assert cert_exc is not None
        assert cert_exc.san == ()

        # 3. Malformed subjectAltName structure (e.g. non-tuple entries, missing items)
        mock_internal._test_decode_cert.side_effect = None
        mock_internal._test_decode_cert.return_value = {
            "subject": ((("commonName", "weird.example.com"),),),
            "subjectAltName": ("not-a-tuple", (1, 2, 3), ("DNS", None), ("DNS", "valid.example.com")),
        }
        with patch.object(ssl, "_ssl", mock_internal), \
             patch("ssl.DER_cert_to_PEM_cert", return_value="-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----"):
            cert_weird = parse_certificate_der(b"dummy-der")
        assert cert_weird is not None
        assert cert_weird.san == ("valid.example.com",)

    def test_probe_tls_loopback_with_san(self):
        """Real TLS loopback test verifying SAN extraction end-to-end via probe_tls."""
        import os
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, "key.pem")
            cert_path = os.path.join(tmpdir, "cert.pem")
            cmd = [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path, "-out", cert_path, "-days", "1",
                "-nodes", "-subj", "/CN=san-loopback.test",
                "-addext", "subjectAltName=DNS:san-loopback.test,DNS:alt.loopback.test,IP:127.0.0.1",
            ]
            try:
                subprocess.run(cmd, capture_output=True, check=True)
            except (subprocess.SubprocessError, FileNotFoundError):
                pytest.skip("OpenSSL CLI not available for loopback test cert generation")

            import ssl
            server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ctx.load_cert_chain(cert_path, key_path)
            server_ctx.set_alpn_protocols(["http/1.1"])

            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            port = server.getsockname()[1]

            def serve():
                try:
                    conn, _ = server.accept()
                    with server_ctx.wrap_socket(conn, server_side=True) as s_conn:
                        req = s_conn.recv(1024)
                        if b"HEAD" in req:
                            s_conn.sendall(b"HTTP/1.1 200 OK\r\nServer: NetProbe-SAN\r\nContent-Length: 0\r\n\r\n")
                except Exception:
                    pass
                finally:
                    server.close()

            th = threading.Thread(target=serve, daemon=True)
            th.start()

            info = probe_tls("127.0.0.1", port, timeout=2.0)
            th.join(timeout=2.0)

            assert info is not None
            assert info.tls_info is not None
            assert info.tls_info.san == ("san-loopback.test", "alt.loopback.test", "127.0.0.1")
            assert info.tls_info.verified is False


# ============================================================================
# 11. Phase 2.6 Probe Performance Optimization Tests
# ============================================================================


class TestPhase26ProbePerformance:
    """Validate fast-path probe ordering, fallback guarantees, and budget enforcement."""

    def test_http_common_port_skips_passive_banner_delay(self):
        """Common HTTP port (e.g. 80) attempts HTTP first and succeeds without banner delay."""
        engine = FingerprintEngine(overall_timeout=2.0)

        with patch("netprobe.fingerprint.engine.probe_http") as mock_http, \
             patch("netprobe.fingerprint.engine.probe_passive_banner") as mock_banner, \
             patch("netprobe.fingerprint.engine.probe_tls") as mock_tls:

            mock_http.return_value = ServiceInfo(
                name="http",
                method=IdentificationMethod.HTTP,
                details="HTTP/1.1 200 OK",
            )

            info = engine.fingerprint_port("127.0.0.1", 80)
            assert info.name == "http"
            assert info.method == IdentificationMethod.HTTP

            # HTTP probe was invoked immediately
            mock_http.assert_called_once()
            # Passive banner and TLS probes were not called
            mock_banner.assert_not_called()
            mock_tls.assert_not_called()

    def test_https_common_port_prioritizes_tls(self):
        """Common HTTPS port (e.g. 443) attempts TLS first and succeeds without banner delay."""
        engine = FingerprintEngine(overall_timeout=2.0)

        with patch("netprobe.fingerprint.engine.probe_tls") as mock_tls, \
             patch("netprobe.fingerprint.engine.probe_http") as mock_http, \
             patch("netprobe.fingerprint.engine.probe_passive_banner") as mock_banner:

            mock_tls.return_value = ServiceInfo(
                name="https",
                method=IdentificationMethod.TLS,
                details="TLSv1.3",
            )

            info = engine.fingerprint_port("127.0.0.1", 443)
            assert info.name == "https"
            assert info.method == IdentificationMethod.TLS

            mock_tls.assert_called_once()
            mock_http.assert_not_called()
            mock_banner.assert_not_called()

    def test_ssh_and_banner_ports_retain_passive_detection_first(self):
        """Non-web port (e.g. 22) retains passive banner probe first."""
        engine = FingerprintEngine(overall_timeout=2.0)

        with patch("netprobe.fingerprint.engine.probe_passive_banner") as mock_banner, \
             patch("netprobe.fingerprint.engine.probe_http") as mock_http, \
             patch("netprobe.fingerprint.engine.probe_tls") as mock_tls:

            mock_banner.return_value = ServiceInfo(
                name="ssh",
                method=IdentificationMethod.BANNER,
                product="OpenSSH",
            )

            info = engine.fingerprint_port("127.0.0.1", 22)
            assert info.name == "ssh"
            assert info.method == IdentificationMethod.BANNER

            mock_banner.assert_called_once()
            mock_http.assert_not_called()
            mock_tls.assert_not_called()

    def test_non_standard_port_detects_http_via_fallback(self):
        """Non-standard port (e.g. 8008) receives banner -> HTTP -> TLS sequence and detects HTTP."""
        engine = FingerprintEngine(overall_timeout=2.0)

        call_order = []

        def fake_banner(*args, **kwargs):
            call_order.append("banner")
            return None

        def fake_http(*args, **kwargs):
            call_order.append("http")
            return ServiceInfo(
                name="http",
                method=IdentificationMethod.HTTP,
                details="HTTP/1.1 200 OK",
            )

        def fake_tls(*args, **kwargs):
            call_order.append("tls")
            return None

        with patch("netprobe.fingerprint.engine.probe_passive_banner", side_effect=fake_banner), \
             patch("netprobe.fingerprint.engine.probe_http", side_effect=fake_http), \
             patch("netprobe.fingerprint.engine.probe_tls", side_effect=fake_tls):

            info = engine.fingerprint_port("127.0.0.1", 8008)
            assert info.name == "http"
            assert info.method == IdentificationMethod.HTTP
            assert call_order == ["banner", "http"]

    def test_http_port_failed_fast_path_falls_through_to_tls_and_banner(self):
        """If port 80 fails HTTP probe, it falls through to TLS then passive banner."""
        engine = FingerprintEngine(overall_timeout=2.0)

        call_order = []

        def fake_http(*args, **kwargs):
            call_order.append("http")
            return None

        def fake_tls(*args, **kwargs):
            call_order.append("tls")
            return None

        def fake_banner(*args, **kwargs):
            call_order.append("banner")
            return ServiceInfo(
                name="ssh",
                method=IdentificationMethod.BANNER,
                product="OpenSSH",
            )

        with patch("netprobe.fingerprint.engine.probe_http", side_effect=fake_http), \
             patch("netprobe.fingerprint.engine.probe_tls", side_effect=fake_tls), \
             patch("netprobe.fingerprint.engine.probe_passive_banner", side_effect=fake_banner):

            info = engine.fingerprint_port("127.0.0.1", 80)
            assert info.name == "ssh"
            assert info.method == IdentificationMethod.BANNER
            assert call_order == ["http", "tls", "banner"]

    def test_https_port_failed_fast_path_falls_through_to_http_and_banner(self):
        """If port 443 fails TLS probe, it falls through to HTTP then passive banner."""
        engine = FingerprintEngine(overall_timeout=2.0)

        call_order = []

        def fake_tls(*args, **kwargs):
            call_order.append("tls")
            return None

        def fake_http(*args, **kwargs):
            call_order.append("http")
            return ServiceInfo(
                name="http",
                method=IdentificationMethod.HTTP,
                details="HTTP/1.1 200 OK",
            )

        def fake_banner(*args, **kwargs):
            call_order.append("banner")
            return None

        with patch("netprobe.fingerprint.engine.probe_tls", side_effect=fake_tls), \
             patch("netprobe.fingerprint.engine.probe_http", side_effect=fake_http), \
             patch("netprobe.fingerprint.engine.probe_passive_banner", side_effect=fake_banner):

            info = engine.fingerprint_port("127.0.0.1", 443)
            assert info.name == "http"
            assert info.method == IdentificationMethod.HTTP
            assert call_order == ["tls", "http"]

    def test_timeout_budget_strictly_decrements_across_probes(self):
        """Timeout budget decreases across consecutive probes and enforces overall deadline and 50ms cutoff."""
        engine = FingerprintEngine(overall_timeout=0.6)

        timeouts_seen = []

        def fake_http(target, port, timeout):
            timeouts_seen.append(("http", timeout))
            return None

        def fake_tls(target, port, timeout):
            timeouts_seen.append(("tls", timeout))
            return None

        def fake_banner(target, port, timeout):
            timeouts_seen.append(("banner", timeout))
            return None

        # Sequence of time.perf_counter() values:
        # Port 80 probe sequence: _try_http, _try_tls, _try_passive
        # 1. start_time = 100.0 (deadline = 100.6)
        # 2. _try_http: perf_counter() = 100.0 -> rem = 0.6 (> 0.05) -> timeout = min(0.75, 0.6) = 0.6
        # 3. _try_tls: perf_counter() = 100.35 -> rem = 0.25 (> 0.05) -> timeout = min(1.0, 0.25) = 0.25
        # 4. _try_passive: perf_counter() = 100.56 -> rem = 0.04 (<= 0.05 cutoff) -> skipped!
        time_sequence = [100.0, 100.0, 100.35, 100.56]

        with patch("netprobe.fingerprint.engine.time.perf_counter", side_effect=time_sequence), \
             patch("netprobe.fingerprint.engine.probe_http", side_effect=fake_http), \
             patch("netprobe.fingerprint.engine.probe_tls", side_effect=fake_tls), \
             patch("netprobe.fingerprint.engine.probe_passive_banner", side_effect=fake_banner):

            info = engine.fingerprint_port("127.0.0.1", 80)

            # Conventional fallback when all active probes fail or are skipped
            assert info.method == IdentificationMethod.CONVENTIONAL

            # http was called first with initial remaining budget (0.6)
            assert len(timeouts_seen) == 2
            assert timeouts_seen[0][0] == "http"
            assert timeouts_seen[0][1] == pytest.approx(0.6)

            # tls was called second with diminished remaining budget (0.25 < 0.6)
            assert timeouts_seen[1][0] == "tls"
            assert timeouts_seen[1][1] == pytest.approx(0.25)
            assert timeouts_seen[1][1] < timeouts_seen[0][1]

            # passive banner probe was skipped because rem (0.04) <= 50ms (0.05) cutoff
            banner_calls = [name for name, _ in timeouts_seen if name == "banner"]
            assert len(banner_calls) == 0


    def test_fingerprinting_remains_opt_in_in_scanner(self):
        """Verify TCP scanner defaults to conventional service lookup without fingerprinting."""
        from netprobe.cli import create_parser
        from netprobe.scanner import scan_single_port

        # 1. Base scan produces ScanResult without service_info by default
        with patch("socket.socket") as mock_sock_cls:
            mock_inst = MagicMock()
            mock_sock_cls.return_value = mock_inst
            mock_inst.connect.return_value = None
            res = scan_single_port("127.0.0.1", 80)
            assert res.service_info is None

        # 2. CLI parser defaults --fingerprint / -sV to False
        parser = create_parser()
        args = parser.parse_args(["127.0.0.1"])
        assert args.fingerprint is False




