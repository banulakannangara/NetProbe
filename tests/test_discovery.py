"""Comprehensive unit tests for NetProbe Phase 3, Milestone 3.1: Discovery Models & Validation."""

import ipaddress
import socket
import pytest

from unittest.mock import MagicMock, patch

from netprobe.discovery import (
    DEFAULT_SWEEP_PORTS,
    DiscoveredHost,
    DiscoveryInterruptedError,
    DiscoverySummary,
    HostReachability,
    SubnetScanner,
    parse_cidr,
    parse_sweep_ports,
    probe_candidate_host,
    probe_single_tcp_port,
    resolve_reverse_dns,
)
from netprobe.scanner import PortState


class TestDiscoveryModels:
    """Test HostReachability enum and immutable dataclass models."""

    def test_host_reachability_enum_values(self):
        assert HostReachability.TCP_RESPONSIVE == "tcp_responsive"
        assert HostReachability.NO_RESPONSE == "no_response"
        assert HostReachability.UNREACHABLE == "unreachable"

        # Verify string subclassing
        assert isinstance(HostReachability.TCP_RESPONSIVE, str)
        assert isinstance(HostReachability.NO_RESPONSE, str)
        assert isinstance(HostReachability.UNREACHABLE, str)

        # Verify no online/offline labels
        assert "online" not in [e.value for e in HostReachability]
        assert "offline" not in [e.value for e in HostReachability]

    def test_discovered_host_frozen_immutability(self):
        host = DiscoveredHost(
            ip="192.168.1.10",
            status=HostReachability.TCP_RESPONSIVE,
            responsive_port=80,
            responsive_state=PortState.OPEN,
            tested_ports=(80,),
            hostname="gateway.local",
            reason="Connection established on port 80",
        )

        assert host.ip == "192.168.1.10"
        assert host.status == HostReachability.TCP_RESPONSIVE
        assert host.responsive_port == 80
        assert host.responsive_state == PortState.OPEN
        assert host.tested_ports == (80,)
        assert host.hostname == "gateway.local"
        assert host.reason == "Connection established on port 80"

        # Mutation must raise FrozenInstanceError
        with pytest.raises(AttributeError):
            host.ip = "192.168.1.20"  # type: ignore

    def test_discovered_host_defaults(self):
        host = DiscoveredHost(
            ip="10.0.0.1",
            status=HostReachability.NO_RESPONSE,
            responsive_port=None,
            responsive_state=None,
            tested_ports=(80, 443, 22),
        )
        assert host.hostname is None
        assert host.reason == ""

    def test_discovery_summary_frozen_immutability_and_tuples(self):
        host1 = DiscoveredHost(
            ip="192.168.1.1",
            status=HostReachability.TCP_RESPONSIVE,
            responsive_port=80,
            responsive_state=PortState.OPEN,
            tested_ports=(80,),
        )
        summary = DiscoverySummary(
            network="192.168.1.0/24",
            total_candidates=254,
            responsive_count=1,
            no_response_count=253,
            unreachable_count=0,
            elapsed_seconds=1.234,
            hosts=(host1,),
            interrupted=False,
            sweep_ports=(80, 443, 22, 445),
        )

        assert summary.network == "192.168.1.0/24"
        assert summary.total_candidates == 254
        assert summary.responsive_count == 1
        assert summary.no_response_count == 253
        assert summary.unreachable_count == 0
        assert summary.elapsed_seconds == 1.234
        assert isinstance(summary.hosts, tuple)
        assert len(summary.hosts) == 1
        assert summary.interrupted is False
        assert summary.sweep_ports == (80, 443, 22, 445)

        with pytest.raises(AttributeError):
            summary.interrupted = True  # type: ignore


class TestCIDRParsing:
    """Test parse_cidr validation, prefix normalization, and bounds."""

    def test_valid_cidr_networks(self):
        # /24 boundary (256 addresses)
        net24 = parse_cidr("192.168.1.0/24")
        assert isinstance(net24, ipaddress.IPv4Network)
        assert str(net24) == "192.168.1.0/24"
        assert net24.num_addresses == 256

        # /28 (16 addresses)
        net28 = parse_cidr("10.0.0.0/28")
        assert str(net28) == "10.0.0.0/28"
        assert net28.num_addresses == 16

        # /30 (4 addresses)
        net30 = parse_cidr("172.16.0.0/30")
        assert str(net30) == "172.16.0.0/30"
        assert net30.num_addresses == 4

        # /31 (2 addresses)
        net31 = parse_cidr("192.168.0.2/31")
        assert str(net31) == "192.168.0.2/31"
        assert net31.num_addresses == 2

        # /32 (1 address)
        net32 = parse_cidr("192.168.1.100/32")
        assert str(net32) == "192.168.1.100/32"
        assert net32.num_addresses == 1

    def test_host_address_normalization_with_prefix(self):
        # When user provides a host IP inside a network with prefix, it normalizes to the containing network
        net = parse_cidr("192.168.1.55/24")
        assert str(net) == "192.168.1.0/24"
        assert net.network_address == ipaddress.IPv4Address("192.168.1.0")

        net28 = parse_cidr("10.1.2.19/28")
        assert str(net28) == "10.1.2.16/28"

    def test_rejection_missing_prefix_or_single_ip(self):
        with pytest.raises(ValueError, match="missing prefix length"):
            parse_cidr("192.168.1.1")
        with pytest.raises(ValueError, match="missing prefix length"):
            parse_cidr("10.0.0.1")

    def test_rejection_empty_or_whitespace(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            parse_cidr("")
        with pytest.raises(ValueError, match="cannot be empty"):
            parse_cidr("   ")

    def test_rejection_ipv6_networks(self):
        with pytest.raises(ValueError, match="IPv6 network. NetProbe only supports IPv4"):
            parse_cidr("2001:db8::/32")
        with pytest.raises(ValueError, match="IPv6 network. NetProbe only supports IPv4"):
            parse_cidr("::1/128")

    def test_rejection_malformed_cidr(self):
        with pytest.raises(ValueError, match="Invalid CIDR specification"):
            parse_cidr("not_an_ip/24")
        with pytest.raises(ValueError, match="Invalid CIDR specification"):
            parse_cidr("192.168.1.1/abc")
        with pytest.raises(ValueError, match="Invalid CIDR specification"):
            parse_cidr("192.168.1.1/33")
        with pytest.raises(ValueError, match="Invalid CIDR specification"):
            parse_cidr("999.1.1.1/24")

    def test_rejection_subnets_larger_than_256_addresses(self):
        # /23 has 512 addresses -> must reject
        with pytest.raises(ValueError, match="exceeds the maximum allowed subnet size of 256 addresses"):
            parse_cidr("192.168.0.0/23")

        # /16 has 65536 addresses -> must reject
        with pytest.raises(ValueError, match="exceeds the maximum allowed subnet size of 256 addresses"):
            parse_cidr("10.0.0.0/16")

        # /8 has 16777216 addresses -> must reject
        with pytest.raises(ValueError, match="exceeds the maximum allowed subnet size of 256 addresses"):
            parse_cidr("10.0.0.0/8")

        # /0 has 2^32 addresses -> must reject
        with pytest.raises(ValueError, match="exceeds the maximum allowed subnet size of 256 addresses"):
            parse_cidr("0.0.0.0/0")

    def test_candidate_iteration_semantics_31_and_32(self):
        # Python's ipaddress network.hosts() returns both IPs for /31 (RFC 3021) and the single IP for /32
        net31 = parse_cidr("10.0.0.0/31")
        hosts31 = [str(ip) for ip in net31.hosts()]
        assert hosts31 == ["10.0.0.0", "10.0.0.1"]

        net32 = parse_cidr("10.0.0.5/32")
        hosts32 = [str(ip) for ip in net32.hosts()]
        assert hosts32 == ["10.0.0.5"]

        # Contrast with /30 where network (.0) and broadcast (.3) are excluded by network.hosts()
        net30 = parse_cidr("10.0.0.0/30")
        hosts30 = [str(ip) for ip in net30.hosts()]
        assert hosts30 == ["10.0.0.1", "10.0.0.2"]

        # Standard /24 has 254 hosts (.1 through .254)
        net24 = parse_cidr("192.168.1.0/24")
        hosts24 = [str(ip) for ip in net24.hosts()]
        assert len(hosts24) == 254
        assert hosts24[0] == "192.168.1.1"
        assert hosts24[-1] == "192.168.1.254"


class TestSweepPortsParsing:
    """Test parse_sweep_ports input validation, deduplication, and ordering."""

    def test_valid_ports_and_order_preservation(self):
        ports = parse_sweep_ports("80,443,22,445")
        assert ports == (80, 443, 22, 445)
        assert isinstance(ports, tuple)

        # Single port
        assert parse_sweep_ports("80") == (80,)

        # Boundary ports 1 and 65535
        assert parse_sweep_ports("1,65535") == (1, 65535)

    def test_deduplication_preserves_first_occurrence(self):
        # When duplicate ports are present, first position is kept
        assert parse_sweep_ports("80,443,80,22,443") == (80, 443, 22)
        assert parse_sweep_ports("8080,8080,8080") == (8080,)

    def test_whitespace_handling(self):
        assert parse_sweep_ports("  80 ,  443 , 22  ") == (80, 443, 22)

    def test_rejection_empty_or_whitespace(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            parse_sweep_ports("")
        with pytest.raises(ValueError, match="cannot be empty"):
            parse_sweep_ports("   ")

    def test_rejection_empty_tokens_and_consecutive_commas(self):
        with pytest.raises(ValueError, match="contains empty token or consecutive commas"):
            parse_sweep_ports("80,,443")
        with pytest.raises(ValueError, match="contains empty token or consecutive commas"):
            parse_sweep_ports(",80,443")
        with pytest.raises(ValueError, match="contains empty token or consecutive commas"):
            parse_sweep_ports("80,443,")

    def test_rejection_non_numeric_and_invalid_tokens(self):
        with pytest.raises(ValueError, match="must be an integer between 1 and 65535"):
            parse_sweep_ports("80,http,443")
        with pytest.raises(ValueError, match="must be an integer between 1 and 65535"):
            parse_sweep_ports("80-443")  # Sweep ports take comma list, not range notation
        with pytest.raises(ValueError, match="must be an integer between 1 and 65535"):
            parse_sweep_ports("-80")

    def test_rejection_out_of_range_ports(self):
        with pytest.raises(ValueError, match="out of range"):
            parse_sweep_ports("0")
        with pytest.raises(ValueError, match="out of range"):
            parse_sweep_ports("65536")
        with pytest.raises(ValueError, match="out of range"):
            parse_sweep_ports("80,99999")


class TestProbingAndClassification:
    """Test TCP port probing, socket lifecycle, and reachability classification rules."""

    @patch("socket.socket")
    def test_open_port_classified_tcp_responsive_open(self, mock_socket_class: MagicMock) -> None:
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        outcome, reason = probe_single_tcp_port("192.168.1.1", 80, timeout=0.5)
        assert outcome == PortState.OPEN
        assert "established" in reason.lower()
        mock_sock.connect.assert_called_once_with(("192.168.1.1", 80))
        mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_refusal_classified_tcp_responsive_closed(self, mock_socket_class: MagicMock) -> None:
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError("Connection refused")
        mock_socket_class.return_value = mock_sock

        outcome, reason = probe_single_tcp_port("192.168.1.1", 80, timeout=0.5)
        assert outcome == PortState.CLOSED
        assert "refused" in reason.lower()
        mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_timeout_classified_as_timeout(self, mock_socket_class: MagicMock) -> None:
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = TimeoutError("Timed out")
        mock_socket_class.return_value = mock_sock

        outcome, reason = probe_single_tcp_port("192.168.1.1", 80, timeout=0.5)
        assert outcome == "TIMEOUT"
        mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_unreachable_errno_classified_as_unreachable(self, mock_socket_class: MagicMock) -> None:
        import errno

        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(errno.EHOSTUNREACH, "No route to host")
        mock_socket_class.return_value = mock_sock

        outcome, reason = probe_single_tcp_port("192.168.1.1", 80, timeout=0.5)
        assert outcome == "UNREACHABLE"
        assert "Unreachable" in reason
        mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_unexpected_oserror_is_reraised(self, mock_socket_class: MagicMock) -> None:
        import errno

        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError(errno.EMFILE, "Too many open files")
        mock_socket_class.return_value = mock_sock

        with pytest.raises(OSError) as exc_info:
            probe_single_tcp_port("192.168.1.1", 80, timeout=0.5)
        assert exc_info.value.errno == errno.EMFILE
        mock_sock.close.assert_called_once()

    def test_candidate_host_fast_exit_on_first_open_port(self) -> None:
        with patch("netprobe.discovery.probe_single_tcp_port") as mock_probe:
            mock_probe.side_effect = [
                (PortState.OPEN, "Connection established"),
            ]
            host = probe_candidate_host("192.168.1.10", sweep_ports=(80, 443, 22, 445), timeout=0.5)

            assert host.ip == "192.168.1.10"
            assert host.status == HostReachability.TCP_RESPONSIVE
            assert host.responsive_port == 80
            assert host.responsive_state == PortState.OPEN
            assert host.tested_ports == (80,)
            # Probing stopped immediately on first port
            mock_probe.assert_called_once_with("192.168.1.10", 80, 0.5)

    def test_candidate_host_fast_exit_on_refusal_closed(self) -> None:
        with patch("netprobe.discovery.probe_single_tcp_port") as mock_probe:
            mock_probe.side_effect = [
                (PortState.CLOSED, "Connection refused (RST)"),
            ]
            host = probe_candidate_host("192.168.1.10", sweep_ports=(80, 443, 22), timeout=0.5)

            assert host.status == HostReachability.TCP_RESPONSIVE
            assert host.responsive_port == 80
            assert host.responsive_state == PortState.CLOSED
            assert host.tested_ports == (80,)
            mock_probe.assert_called_once()

    def test_candidate_host_timeout_followed_by_refusal_is_responsive(self) -> None:
        with patch("netprobe.discovery.probe_single_tcp_port") as mock_probe:
            mock_probe.side_effect = [
                ("TIMEOUT", "Timed out"),
                (PortState.CLOSED, "Connection refused (RST)"),
            ]
            host = probe_candidate_host("192.168.1.10", sweep_ports=(80, 443, 22), timeout=0.5)

            assert host.status == HostReachability.TCP_RESPONSIVE
            assert host.responsive_port == 443
            assert host.responsive_state == PortState.CLOSED
            assert host.tested_ports == (80, 443)
            assert mock_probe.call_count == 2

    def test_candidate_host_unreachable_followed_by_open_is_responsive(self) -> None:
        with patch("netprobe.discovery.probe_single_tcp_port") as mock_probe:
            mock_probe.side_effect = [
                ("UNREACHABLE", "Unreachable"),
                (PortState.OPEN, "Connection established"),
            ]
            host = probe_candidate_host("192.168.1.10", sweep_ports=(80, 443), timeout=0.5)

            assert host.status == HostReachability.TCP_RESPONSIVE
            assert host.responsive_port == 443
            assert host.responsive_state == PortState.OPEN
            assert host.tested_ports == (80, 443)
            assert mock_probe.call_count == 2

    def test_candidate_host_all_timeouts_classified_no_response(self) -> None:
        with patch("netprobe.discovery.probe_single_tcp_port") as mock_probe:
            mock_probe.side_effect = [
                ("TIMEOUT", "Timed out"),
                ("TIMEOUT", "Timed out"),
            ]
            host = probe_candidate_host("192.168.1.10", sweep_ports=(80, 443), timeout=0.5)

            assert host.status == HostReachability.NO_RESPONSE
            assert host.responsive_port is None
            assert host.responsive_state is None
            assert host.tested_ports == (80, 443)
            assert "inconclusive" in host.reason.lower()

    def test_candidate_host_all_unreachable_classified_unreachable(self) -> None:
        with patch("netprobe.discovery.probe_single_tcp_port") as mock_probe:
            mock_probe.side_effect = [
                ("UNREACHABLE", "Unreachable (No route to host)"),
                ("UNREACHABLE", "Unreachable (Host is down)"),
            ]
            host = probe_candidate_host("192.168.1.10", sweep_ports=(80, 443), timeout=0.5)

            assert host.status == HostReachability.UNREACHABLE
            assert host.responsive_port is None
            assert host.responsive_state is None
            assert host.tested_ports == (80, 443)
            assert "unreachable" in host.reason.lower()

    def test_candidate_host_timeout_and_unreachable_classified_no_response(self) -> None:
        # Rule: If at least one probe timed out, classify as NO_RESPONSE (inconclusive),
        # not UNREACHABLE.
        with patch("netprobe.discovery.probe_single_tcp_port") as mock_probe:
            mock_probe.side_effect = [
                ("UNREACHABLE", "Unreachable"),
                ("TIMEOUT", "Timed out"),
            ]
            host = probe_candidate_host("192.168.1.10", sweep_ports=(80, 443), timeout=0.5)

            assert host.status == HostReachability.NO_RESPONSE
            assert host.responsive_port is None
            assert host.tested_ports == (80, 443)


class TestSubnetScannerExecution:
    """Test SubnetScanner configuration, concurrency, ordering, and cancellation."""

    def test_scanner_constructor_validations(self) -> None:
        # Invalid network string
        with pytest.raises(ValueError, match="missing prefix length"):
            SubnetScanner("192.168.1.1")

        # Network > 256 addresses
        with pytest.raises(ValueError, match="exceeds the maximum allowed subnet size"):
            SubnetScanner("10.0.0.0/16")

        # Invalid network type
        with pytest.raises(ValueError, match="expected str or IPv4Network"):
            SubnetScanner(12345)  # type: ignore

        # Invalid timeouts
        with pytest.raises(ValueError, match="Timeout must be between"):
            SubnetScanner("192.168.1.0/24", timeout=0.01)
        with pytest.raises(ValueError, match="Timeout must be between"):
            SubnetScanner("192.168.1.0/24", timeout=100.0)

        # Invalid worker counts
        with pytest.raises(ValueError, match="Workers must be an integer between"):
            SubnetScanner("192.168.1.0/24", max_workers=0)
        with pytest.raises(ValueError, match="Workers must be an integer between"):
            SubnetScanner("192.168.1.0/24", max_workers=101)

        # Invalid sweep ports sequence
        with pytest.raises(ValueError, match="Invalid sweep port"):
            SubnetScanner("192.168.1.0/24", sweep_ports=[80, 70000])
        with pytest.raises(ValueError, match="Sweep ports cannot be empty"):
            SubnetScanner("192.168.1.0/24", sweep_ports=[])

    def test_scanner_defaults_and_ipv4network_instance(self) -> None:
        net = ipaddress.IPv4Network("192.168.1.0/24")
        scanner = SubnetScanner(net)
        assert scanner.network == net
        assert scanner.sweep_ports == DEFAULT_SWEEP_PORTS
        assert scanner.timeout == 0.5
        assert scanner.max_workers == 50

    def test_scanner_preserves_custom_port_order(self) -> None:
        scanner = SubnetScanner("192.168.1.0/24", sweep_ports="443,80,22,80")
        assert scanner.sweep_ports == (443, 80, 22)

        scanner_seq = SubnetScanner("192.168.1.0/24", sweep_ports=[443, 80, 22, 443])
        assert scanner_seq.sweep_ports == (443, 80, 22)

    def test_deterministic_ip_ordering_despite_unordered_completion(self) -> None:
        """Verify results are sorted by IPv4 address even if worker threads complete in reverse order."""
        def fake_probe_host(ip: str, sweep_ports: tuple[int, ...], timeout: float) -> DiscoveredHost:
            if ip == "192.168.1.3":
                return DiscoveredHost(
                    ip=ip,
                    status=HostReachability.TCP_RESPONSIVE,
                    responsive_port=80,
                    responsive_state=PortState.OPEN,
                    tested_ports=(80,),
                )
            elif ip == "192.168.1.2":
                return DiscoveredHost(
                    ip=ip,
                    status=HostReachability.TCP_RESPONSIVE,
                    responsive_port=443,
                    responsive_state=PortState.CLOSED,
                    tested_ports=(80, 443),
                )
            else:
                return DiscoveredHost(
                    ip=ip,
                    status=HostReachability.NO_RESPONSE,
                    responsive_port=None,
                    responsive_state=None,
                    tested_ports=(80, 443, 22, 445),
                )

        with patch("netprobe.discovery.probe_candidate_host", side_effect=fake_probe_host):
            # /29 network has 6 hosts (.1 through .6)
            scanner = SubnetScanner("192.168.1.0/29", max_workers=4)
            summary = scanner.scan()

            assert summary.total_candidates == 6
            assert summary.responsive_count == 2
            assert summary.no_response_count == 4
            assert summary.unreachable_count == 0
            assert summary.interrupted is False
            assert summary.elapsed_seconds >= 0.0

            # Verify deterministic IP ordering: 192.168.1.1 -> 192.168.1.6
            result_ips = [h.ip for h in summary.hosts]
            assert result_ips == [
                "192.168.1.1",
                "192.168.1.2",
                "192.168.1.3",
                "192.168.1.4",
                "192.168.1.5",
                "192.168.1.6",
            ]

    def test_scan_31_and_32_networks(self) -> None:
        def fake_probe_host(ip: str, sweep_ports: tuple[int, ...], timeout: float) -> DiscoveredHost:
            return DiscoveredHost(
                ip=ip,
                status=HostReachability.NO_RESPONSE,
                responsive_port=None,
                responsive_state=None,
                tested_ports=(80,),
            )

        with patch("netprobe.discovery.probe_candidate_host", side_effect=fake_probe_host):
            # /31 has 2 hosts (.0, .1)
            scanner31 = SubnetScanner("10.0.0.0/31", sweep_ports="80")
            summary31 = scanner31.scan()
            assert summary31.total_candidates == 2
            assert [h.ip for h in summary31.hosts] == ["10.0.0.0", "10.0.0.1"]

            # /32 has 1 host (.5)
            scanner32 = SubnetScanner("10.0.0.5/32", sweep_ports="80")
            summary32 = scanner32.scan()
            assert summary32.total_candidates == 1
            assert [h.ip for h in summary32.hosts] == ["10.0.0.5"]

    def test_empty_candidates_handled_gracefully(self) -> None:
        mock_net = MagicMock(spec=ipaddress.IPv4Network)
        mock_net.num_addresses = 0
        mock_net.hosts.return_value = []
        mock_net.__str__.return_value = "0.0.0.0/32"

        scanner = SubnetScanner("192.168.1.1/32")
        scanner.network = mock_net
        summary = scanner.scan()

        assert summary.total_candidates == 0
        assert summary.hosts == ()
        assert summary.interrupted is False

    def test_keyboard_interrupt_raises_interrupted_error_with_partial_results(self) -> None:
        """Verify KeyboardInterrupt captures completed hosts, sets interrupted=True, and preserves sorted results."""
        call_count = 0

        def fake_probe_interrupt(ip: str, sweep_ports: tuple[int, ...], timeout: float) -> DiscoveredHost:
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise KeyboardInterrupt("Simulated Ctrl+C")
            return DiscoveredHost(
                ip=ip,
                status=HostReachability.TCP_RESPONSIVE,
                responsive_port=80,
                responsive_state=PortState.OPEN,
                tested_ports=(80,),
            )

        with patch("netprobe.discovery.probe_candidate_host", side_effect=fake_probe_interrupt):
            scanner = SubnetScanner("192.168.1.0/29", max_workers=1)

            with pytest.raises(DiscoveryInterruptedError) as exc_info:
                scanner.scan()

            err = exc_info.value
            assert err.summary.interrupted is True
            assert err.summary.total_candidates == 6
            assert err.summary.elapsed_seconds >= 0.0
            # At least 1 host completed before interrupt
            assert len(err.summary.hosts) >= 1
            assert err.summary.responsive_count == len(err.summary.hosts)
            # Ensure completed hosts are properly sorted
            assert [h.ip for h in err.summary.hosts] == sorted(
                [h.ip for h in err.summary.hosts], key=lambda x: ipaddress.IPv4Address(x)
            )

    def test_unexpected_worker_exception_propagates(self) -> None:
        """Verify unexpected runtime errors in workers propagate and do not invent fake status."""
        def fake_probe_crash(ip: str, sweep_ports: tuple[int, ...], timeout: float) -> DiscoveredHost:
            raise RuntimeError("Fatal memory error or OS resource exhaustion")

        with patch("netprobe.discovery.probe_candidate_host", side_effect=fake_probe_crash):
            scanner = SubnetScanner("192.168.1.0/30", max_workers=2)
            with pytest.raises(RuntimeError, match="Fatal memory error"):
                scanner.scan()

    def test_interruption_harvests_completed_futures_not_yet_gathered(self) -> None:
        """Verify completed futures that were not yet yielded by as_completed are harvested on interrupt."""
        host1 = DiscoveredHost(
            ip="10.0.0.0",
            status=HostReachability.TCP_RESPONSIVE,
            responsive_port=80,
            responsive_state=PortState.OPEN,
            tested_ports=(80,),
        )
        host2 = DiscoveredHost(
            ip="10.0.0.1",
            status=HostReachability.NO_RESPONSE,
            responsive_port=None,
            responsive_state=None,
            tested_ports=(80, 443),
        )

        mock_fut1 = MagicMock()
        mock_fut1.done.return_value = True
        mock_fut1.cancelled.return_value = False
        mock_fut1.exception.return_value = None
        mock_fut1.result.return_value = host1

        mock_fut2 = MagicMock()
        mock_fut2.done.return_value = True
        mock_fut2.cancelled.return_value = False
        mock_fut2.exception.return_value = None
        mock_fut2.result.return_value = host2

        # Generator for as_completed that yields mock_fut1, then raises KeyboardInterrupt before yielding mock_fut2
        def fake_as_completed(future_dict):
            yield mock_fut1
            raise KeyboardInterrupt("Operator Ctrl+C")

        with patch("concurrent.futures.as_completed", side_effect=fake_as_completed):
            scanner = SubnetScanner("10.0.0.0/31", max_workers=2)
            # Patch ThreadPoolExecutor.submit to return our mock futures in order
            with patch("concurrent.futures.ThreadPoolExecutor.submit", side_effect=[mock_fut1, mock_fut2]):
                with pytest.raises(DiscoveryInterruptedError) as exc_info:
                    scanner.scan()

                summary = exc_info.value.summary
                assert summary.interrupted is True
                assert summary.total_candidates == 2
                # Both host1 (from loop) and host2 (harvested from completed futures) should be present
                assert len(summary.hosts) == 2
                assert [h.ip for h in summary.hosts] == ["10.0.0.0", "10.0.0.1"]
                assert summary.responsive_count == 1
                assert summary.no_response_count == 1
                assert summary.unreachable_count == 0

    def test_interruption_harvest_avoids_duplicate_hosts(self) -> None:
        """Verify harvesting does not duplicate a host already in completed_hosts."""
        host1 = DiscoveredHost(
            ip="10.0.0.0",
            status=HostReachability.TCP_RESPONSIVE,
            responsive_port=80,
            responsive_state=PortState.OPEN,
            tested_ports=(80,),
        )

        mock_fut1 = MagicMock()
        mock_fut1.done.return_value = True
        mock_fut1.cancelled.return_value = False
        mock_fut1.exception.return_value = None
        mock_fut1.result.return_value = host1

        def fake_as_completed(future_dict):
            yield mock_fut1
            raise KeyboardInterrupt("Operator Ctrl+C")

        with patch("concurrent.futures.as_completed", side_effect=fake_as_completed):
            scanner = SubnetScanner("10.0.0.0/32", max_workers=1)
            with patch("concurrent.futures.ThreadPoolExecutor.submit", return_value=mock_fut1):
                with pytest.raises(DiscoveryInterruptedError) as exc_info:
                    scanner.scan()

                summary = exc_info.value.summary
                assert len(summary.hosts) == 1
                assert summary.hosts[0].ip == "10.0.0.0"

    def test_interruption_ignores_unfinished_or_failing_futures_during_cleanup(self) -> None:
        """Verify unfinished or errored futures during cleanup do not block or replace KeyboardInterrupt."""
        # Unfinished future
        mock_fut_running = MagicMock()
        mock_fut_running.done.return_value = False
        mock_fut_running.cancelled.return_value = False

        # Errored future
        mock_fut_error = MagicMock()
        mock_fut_error.done.return_value = True
        mock_fut_error.cancelled.return_value = False
        mock_fut_error.exception.return_value = OSError("Host unreachable socket error")

        def fake_as_completed(future_dict):
            raise KeyboardInterrupt("Ctrl+C immediately")

        with patch("concurrent.futures.as_completed", side_effect=fake_as_completed):
            scanner = SubnetScanner("10.0.0.0/31", max_workers=2)
            with patch("concurrent.futures.ThreadPoolExecutor.submit", side_effect=[mock_fut_running, mock_fut_error]):
                with pytest.raises(DiscoveryInterruptedError) as exc_info:
                    scanner.scan()

                summary = exc_info.value.summary
                assert summary.interrupted is True
                assert len(summary.hosts) == 0
                assert summary.responsive_count == 0
                # result() must not have been called on the unfinished or errored futures
                mock_fut_running.result.assert_not_called()
                mock_fut_error.result.assert_not_called()

    def test_second_interrupt_during_summary_aggregation_handled(self) -> None:
        """Verify a second KeyboardInterrupt during summary generation produces best-effort summary."""
        call_count = 0

        def fake_probe(ip: str, sweep_ports: tuple[int, ...], timeout: float) -> DiscoveredHost:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return DiscoveredHost(
                    ip=ip,
                    status=HostReachability.TCP_RESPONSIVE,
                    responsive_port=80,
                    responsive_state=PortState.OPEN,
                    tested_ports=(80,),
                )
            raise KeyboardInterrupt("First interrupt")

        # Simulate second KeyboardInterrupt by raising inside time.monotonic() during summary calculation
        import time
        orig_monotonic = time.monotonic
        monotonic_calls = 0

        def flaky_monotonic() -> float:
            nonlocal monotonic_calls
            monotonic_calls += 1
            # Call 1 is start_time; Call 2 is elapsed calculation in outer block of except KeyboardInterrupt
            if monotonic_calls == 2:
                raise KeyboardInterrupt("Second interrupt during elapsed calculation")
            return orig_monotonic()

        with patch("netprobe.discovery.probe_candidate_host", side_effect=fake_probe):
            with patch("time.monotonic", side_effect=flaky_monotonic):
                scanner = SubnetScanner("192.168.1.0/30", max_workers=1)
                with pytest.raises(DiscoveryInterruptedError) as exc_info:
                    scanner.scan()

                summary = exc_info.value.summary
                assert summary.interrupted is True
                assert summary.total_candidates == 2
                assert len(summary.hosts) == 1
                assert summary.responsive_count == 1


class TestReverseDNS:
    """Test optional reverse DNS resolution in SubnetScanner."""

    def test_reverse_dns_disabled_by_default(self) -> None:
        scanner = SubnetScanner("192.168.1.0/24")
        assert scanner.resolve_hostnames is False

    def test_resolve_hostnames_invalid_type_rejected(self) -> None:
        with pytest.raises(ValueError, match="resolve_hostnames must be a boolean"):
            SubnetScanner("192.168.1.0/24", resolve_hostnames="yes")  # type: ignore

    @patch("socket.gethostbyaddr")
    def test_disabled_mode_never_calls_gethostbyaddr(self, mock_ghba: MagicMock) -> None:
        with patch("netprobe.discovery.probe_candidate_host") as mock_probe:
            mock_probe.return_value = DiscoveredHost(
                ip="192.168.1.1",
                status=HostReachability.TCP_RESPONSIVE,
                responsive_port=80,
                responsive_state=PortState.OPEN,
                tested_ports=(80,),
            )
            scanner = SubnetScanner("192.168.1.1/32", resolve_hostnames=False)
            summary = scanner.scan()

            assert len(summary.hosts) == 1
            assert summary.hosts[0].hostname is None
            mock_ghba.assert_not_called()

    @patch("socket.gethostbyaddr")
    def test_successful_reverse_lookup_populates_hostname(self, mock_ghba: MagicMock) -> None:
        mock_ghba.return_value = ("gateway.corp.local", [], ["192.168.1.1"])

        with patch("netprobe.discovery.probe_candidate_host") as mock_probe:
            mock_probe.return_value = DiscoveredHost(
                ip="192.168.1.1",
                status=HostReachability.TCP_RESPONSIVE,
                responsive_port=80,
                responsive_state=PortState.OPEN,
                tested_ports=(80,),
            )
            scanner = SubnetScanner("192.168.1.1/32", resolve_hostnames=True)
            summary = scanner.scan()

            assert len(summary.hosts) == 1
            host = summary.hosts[0]
            assert host.hostname == "gateway.corp.local"
            assert host.status == HostReachability.TCP_RESPONSIVE
            assert host.responsive_port == 80
            assert host.responsive_state == PortState.OPEN
            mock_ghba.assert_called_once_with("192.168.1.1")

    @patch("socket.gethostbyaddr")
    def test_resolver_failures_leave_hostname_none(self, mock_ghba: MagicMock) -> None:
        # Test various socket resolver errors
        errors = [
            socket.herror(1, "Unknown host"),
            socket.gaierror(11001, "getaddrinfo failed"),
            TimeoutError("DNS query timed out"),
            OSError(10065, "Network is unreachable"),
        ]

        for err in errors:
            mock_ghba.reset_mock()
            mock_ghba.side_effect = err
            hostname = resolve_reverse_dns("192.168.1.50")
            assert hostname is None
            mock_ghba.assert_called_once_with("192.168.1.50")

    @patch("socket.gethostbyaddr")
    def test_reverse_lookup_failure_does_not_alter_reachability_or_counts(self, mock_ghba: MagicMock) -> None:
        mock_ghba.side_effect = socket.herror(1, "Unknown host")

        with patch("netprobe.discovery.probe_candidate_host") as mock_probe:
            mock_probe.side_effect = [
                DiscoveredHost(
                    ip="10.0.0.0",
                    status=HostReachability.TCP_RESPONSIVE,
                    responsive_port=80,
                    responsive_state=PortState.OPEN,
                    tested_ports=(80,),
                ),
                DiscoveredHost(
                    ip="10.0.0.1",
                    status=HostReachability.NO_RESPONSE,
                    responsive_port=None,
                    responsive_state=None,
                    tested_ports=(80, 443),
                ),
            ]
            scanner = SubnetScanner("10.0.0.0/31", resolve_hostnames=True)
            summary = scanner.scan()

            assert summary.total_candidates == 2
            assert summary.responsive_count == 1
            assert summary.no_response_count == 1
            assert summary.unreachable_count == 0
            assert summary.hosts[0].status == HostReachability.TCP_RESPONSIVE
            assert summary.hosts[0].hostname is None
            assert summary.hosts[1].status == HostReachability.NO_RESPONSE
            assert summary.hosts[1].hostname is None

    @patch("socket.gethostbyaddr")
    def test_resolver_only_receives_ip_literals_never_cidr(self, mock_ghba: MagicMock) -> None:
        mock_ghba.return_value = ("host.local", [], [])

        with patch("netprobe.discovery.probe_candidate_host") as mock_probe:
            mock_probe.side_effect = lambda ip, ports, timeout: DiscoveredHost(
                ip=ip,
                status=HostReachability.NO_RESPONSE,
                responsive_port=None,
                responsive_state=None,
                tested_ports=(80,),
            )
            scanner = SubnetScanner("192.168.1.0/30", resolve_hostnames=True)
            scanner.scan()

            # Resolver was called for the hosts (.1 and .2), never for "192.168.1.0/30"
            for call in mock_ghba.call_args_list:
                arg = call[0][0]
                assert "/" not in arg
                assert ipaddress.IPv4Address(arg)

    @patch("socket.gethostbyaddr")
    def test_deterministic_sorting_preserved_with_hostnames(self, mock_ghba: MagicMock) -> None:
        # Return hostnames that would sort alphabetically in reverse of IP order
        def fake_ghba(ip: str):
            if ip == "10.0.0.0":
                return ("z-server.local", [], [ip])
            else:
                return ("a-server.local", [], [ip])

        mock_ghba.side_effect = fake_ghba

        with patch("netprobe.discovery.probe_candidate_host") as mock_probe:
            mock_probe.side_effect = lambda ip, ports, timeout: DiscoveredHost(
                ip=ip,
                status=HostReachability.TCP_RESPONSIVE,
                responsive_port=80,
                responsive_state=PortState.OPEN,
                tested_ports=(80,),
            )
            scanner = SubnetScanner("10.0.0.0/31", resolve_hostnames=True)
            summary = scanner.scan()

            # Despite "z-server" vs "a-server", IP order must be preserved: 10.0.0.0 then 10.0.0.1
            assert [h.ip for h in summary.hosts] == ["10.0.0.0", "10.0.0.1"]
            assert summary.hosts[0].hostname == "z-server.local"
            assert summary.hosts[1].hostname == "a-server.local"

    def test_discovered_host_immutable_semantics_preserved(self) -> None:
        original = DiscoveredHost(
            ip="192.168.1.1",
            status=HostReachability.TCP_RESPONSIVE,
            responsive_port=80,
            responsive_state=PortState.OPEN,
            tested_ports=(80,),
            hostname=None,
        )

        with pytest.raises(AttributeError):
            original.hostname = "new.local"  # type: ignore

    @patch("socket.gethostbyaddr")
    def test_interruption_during_reverse_dns_preserves_results(self, mock_ghba: MagicMock) -> None:
        mock_ghba.side_effect = KeyboardInterrupt("Ctrl+C during reverse DNS")

        with patch("netprobe.discovery.probe_candidate_host") as mock_probe:
            mock_probe.return_value = DiscoveredHost(
                ip="192.168.1.1",
                status=HostReachability.TCP_RESPONSIVE,
                responsive_port=80,
                responsive_state=PortState.OPEN,
                tested_ports=(80,),
            )
            scanner = SubnetScanner("192.168.1.1/32", resolve_hostnames=True)
            with pytest.raises(DiscoveryInterruptedError) as exc_info:
                scanner.scan()

            summary = exc_info.value.summary
            assert summary.interrupted is True
            assert len(summary.hosts) == 1
            assert summary.hosts[0].ip == "192.168.1.1"
            assert summary.responsive_count == 1

    def test_interruption_during_reverse_dns_harvests_completed_hostnames(self) -> None:
        """Verify completed DNS lookups are retained and pending lookups leave hostname=None on Ctrl+C."""
        host1 = DiscoveredHost(
            ip="10.0.0.0",
            status=HostReachability.TCP_RESPONSIVE,
            responsive_port=80,
            responsive_state=PortState.OPEN,
            tested_ports=(80,),
        )
        host2 = DiscoveredHost(
            ip="10.0.0.1",
            status=HostReachability.NO_RESPONSE,
            responsive_port=None,
            responsive_state=None,
            tested_ports=(80, 443),
        )

        mock_fut1 = MagicMock()
        mock_fut1.done.return_value = True
        mock_fut1.cancelled.return_value = False
        mock_fut1.exception.return_value = None
        mock_fut1.result.return_value = "router.local"

        mock_fut2 = MagicMock()
        mock_fut2.done.return_value = False
        mock_fut2.cancelled.return_value = False

        call_idx = 0

        def fake_as_completed(future_dict):
            nonlocal call_idx
            call_idx += 1
            # First as_completed is for TCP probe loop - yield all futures
            if call_idx == 1:
                for f in future_dict:
                    yield f
            else:
                # Second as_completed is for DNS phase - yield first completed, then interrupt
                yield mock_fut1
                raise KeyboardInterrupt("Ctrl+C during DNS phase")

        fut_tcp1 = MagicMock()
        fut_tcp1.result.return_value = host1
        fut_tcp2 = MagicMock()
        fut_tcp2.result.return_value = host2

        submit_returns = [fut_tcp1, fut_tcp2, mock_fut1, mock_fut2]

        with patch("concurrent.futures.as_completed", side_effect=fake_as_completed):
            scanner = SubnetScanner("10.0.0.0/31", max_workers=2, resolve_hostnames=True)
            with patch("concurrent.futures.ThreadPoolExecutor.submit", side_effect=submit_returns):
                with pytest.raises(DiscoveryInterruptedError) as exc_info:
                    scanner.scan()

                summary = exc_info.value.summary
                assert summary.interrupted is True
                assert summary.total_candidates == 2
                assert len(summary.hosts) == 2

                # Deterministic IP numerical sorting preserved
                assert summary.hosts[0].ip == "10.0.0.0"
                assert summary.hosts[0].hostname == "router.local"
                assert summary.hosts[0].status == HostReachability.TCP_RESPONSIVE

                assert summary.hosts[1].ip == "10.0.0.1"
                assert summary.hosts[1].hostname is None
                assert summary.hosts[1].status == HostReachability.NO_RESPONSE

                # Summary counts remain exact and unaffected
                assert summary.responsive_count == 1
                assert summary.no_response_count == 1
                assert summary.unreachable_count == 0


class TestCLIDiscovery:
    """Deterministic tests for Subnet Discovery CLI argument parsing, modes, and output."""

    def test_parser_options_present(self) -> None:
        from netprobe.cli import create_parser

        parser = create_parser()
        args = parser.parse_args(["--discover", "192.168.1.0/24", "--sweep-ports", "80,443", "-R"])
        assert args.discover == "192.168.1.0/24"
        assert args.sweep_ports == "80,443"
        assert args.resolve_dns is True
        assert args.target is None

    def test_missing_both_target_and_discover_returns_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        from netprobe.cli import main

        exit_code = main([])
        assert exit_code == 2
        captured = capsys.readouterr()
        assert "Target host is required when not in --discover mode" in captured.err

    def test_conflicting_target_and_discover_rejected(self, capsys: pytest.CaptureFixture[str]) -> None:
        from netprobe.cli import main

        exit_code = main(["127.0.0.1", "--discover", "192.168.1.0/24"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Cannot specify both a target host and --discover mode" in captured.err

    def test_invalid_cidr_returns_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        from netprobe.cli import main

        exit_code = main(["--discover", "invalid_cidr"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Invalid subnet CIDR" in captured.err

    def test_invalid_sweep_ports_returns_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        from netprobe.cli import main

        exit_code = main(["--discover", "192.168.1.0/24", "--sweep-ports", "80,abc"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Invalid sweep ports" in captured.err

    def test_invalid_output_path_rejected_before_scanning(self, capsys: pytest.CaptureFixture[str], tmp_path) -> None:
        from netprobe.cli import main

        bad_path = str(tmp_path / "nonexistent_dir" / "out.txt")
        exit_code = main(["--discover", "192.168.1.0/30", "-o", bad_path])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Output file validation failed" in captured.err

    def test_successful_discovery_table_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        from netprobe.cli import main

        dummy_host = DiscoveredHost(
            ip="192.168.1.1",
            status=HostReachability.TCP_RESPONSIVE,
            responsive_port=80,
            responsive_state=PortState.OPEN,
            tested_ports=(80,),
            reason="Connection established on port 80",
        )
        dummy_summary = DiscoverySummary(
            network="192.168.1.0/30",
            total_candidates=2,
            responsive_count=1,
            no_response_count=1,
            unreachable_count=0,
            elapsed_seconds=0.45,
            hosts=(dummy_host,),
            interrupted=False,
            sweep_ports=(80, 443),
        )

        with patch.object(SubnetScanner, "scan", return_value=dummy_summary):
            exit_code = main(["--discover", "192.168.1.0/30", "--sweep-ports", "80,443"])
            assert exit_code == 0
            captured = capsys.readouterr()
            assert "NetProbe v" in captured.out
            assert "Subnet:       192.168.1.0/30" in captured.out
            assert "192.168.1.1" in captured.out
            assert "TCP_RESPONSIVE" in captured.out
            assert "80/tcp" in captured.out
            assert "Discovery Summary:" in captured.out
            assert "Responsive:      1" in captured.out

    def test_successful_discovery_with_hostnames_displays_hostname_column(self, capsys: pytest.CaptureFixture[str]) -> None:
        from netprobe.cli import main

        dummy_host = DiscoveredHost(
            ip="192.168.1.1",
            status=HostReachability.TCP_RESPONSIVE,
            responsive_port=80,
            responsive_state=PortState.OPEN,
            tested_ports=(80,),
            hostname="gw.internal",
            reason="Connection established on port 80",
        )
        dummy_summary = DiscoverySummary(
            network="192.168.1.0/30",
            total_candidates=2,
            responsive_count=1,
            no_response_count=1,
            unreachable_count=0,
            elapsed_seconds=0.5,
            hosts=(dummy_host,),
            interrupted=False,
            sweep_ports=(80,),
        )

        with patch.object(SubnetScanner, "scan", return_value=dummy_summary):
            exit_code = main(["--discover", "192.168.1.0/30", "-R"])
            assert exit_code == 0
            captured = capsys.readouterr()
            assert "HOSTNAME" in captured.out
            assert "gw.internal" in captured.out

    def test_successful_discovery_json_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        import json
        from netprobe.cli import main

        dummy_host = DiscoveredHost(
            ip="192.168.1.1",
            status=HostReachability.TCP_RESPONSIVE,
            responsive_port=80,
            responsive_state=PortState.OPEN,
            tested_ports=(80,),
            hostname="router.lan",
            reason="Connection established",
        )
        dummy_summary = DiscoverySummary(
            network="192.168.1.0/30",
            total_candidates=2,
            responsive_count=1,
            no_response_count=1,
            unreachable_count=0,
            elapsed_seconds=0.25,
            hosts=(dummy_host,),
            interrupted=False,
            sweep_ports=(80, 443),
        )

        with patch.object(SubnetScanner, "scan", return_value=dummy_summary):
            exit_code = main(["--discover", "192.168.1.0/30", "--json"])
            assert exit_code == 0
            captured = capsys.readouterr()
            # In json mode, stdout must be purely valid JSON
            data = json.loads(captured.out)
            assert data["mode"] == "discovery"
            assert data["network"] == "192.168.1.0/30"
            assert data["total_candidates"] == 2
            assert data["responsive_count"] == 1
            assert len(data["hosts"]) == 1
            assert data["hosts"][0]["ip"] == "192.168.1.1"
            assert data["hosts"][0]["hostname"] == "router.lan"

    def test_discovery_file_export_alone_and_with_json(self, capsys: pytest.CaptureFixture[str], tmp_path) -> None:
        import json
        from netprobe.cli import main

        dummy_host = DiscoveredHost(
            ip="192.168.1.1",
            status=HostReachability.TCP_RESPONSIVE,
            responsive_port=80,
            responsive_state=PortState.OPEN,
            tested_ports=(80,),
        )
        dummy_summary = DiscoverySummary(
            network="192.168.1.0/30",
            total_candidates=2,
            responsive_count=1,
            no_response_count=1,
            unreachable_count=0,
            elapsed_seconds=0.2,
            hosts=(dummy_host,),
            interrupted=False,
        )

        out_txt = tmp_path / "disc.txt"
        out_json = tmp_path / "disc.json"

        with patch.object(SubnetScanner, "scan", return_value=dummy_summary):
            # 1. Output file alone writes table text to file and stdout
            exit_code = main(["--discover", "192.168.1.0/30", "-o", str(out_txt)])
            assert exit_code == 0
            assert out_txt.exists()
            assert "Discovery Summary:" in out_txt.read_text(encoding="utf-8")

            # 2. Output file with --json writes JSON to file and keeps stdout silent
            capsys.readouterr()
            exit_code_json = main(["--discover", "192.168.1.0/30", "--json", "-o", str(out_json)])
            assert exit_code_json == 0
            captured = capsys.readouterr()
            assert captured.out == ""
            assert out_json.exists()
            doc = json.loads(out_json.read_text(encoding="utf-8"))
            assert doc["mode"] == "discovery"

    def test_interrupted_discovery_returns_exit_code_130_with_partial_results(self, capsys: pytest.CaptureFixture[str]) -> None:
        from netprobe.cli import main

        partial_host = DiscoveredHost(
            ip="192.168.1.1",
            status=HostReachability.TCP_RESPONSIVE,
            responsive_port=80,
            responsive_state=PortState.OPEN,
            tested_ports=(80,),
        )
        partial_summary = DiscoverySummary(
            network="192.168.1.0/30",
            total_candidates=2,
            responsive_count=1,
            no_response_count=0,
            unreachable_count=0,
            elapsed_seconds=0.1,
            hosts=(partial_host,),
            interrupted=True,
        )

        with patch.object(SubnetScanner, "scan", side_effect=DiscoveryInterruptedError(partial_summary)):
            exit_code = main(["--discover", "192.168.1.0/30"])
            assert exit_code == 130
            captured = capsys.readouterr()
            assert "interrupted by operator" in captured.err
            assert "Partial Discovery Summary (Interrupted):" in captured.out
            assert "192.168.1.1" in captured.out

    def test_discovery_workers_limit_accepted_at_maximum(self) -> None:
        from netprobe.cli import main

        dummy_summary = DiscoverySummary(
            network="192.168.1.0/30",
            total_candidates=2,
            responsive_count=0,
            no_response_count=2,
            unreachable_count=0,
            elapsed_seconds=0.1,
            hosts=(),
            interrupted=False,
        )
        with patch.object(SubnetScanner, "scan", return_value=dummy_summary) as mock_scan:
            exit_code = main(["--discover", "192.168.1.0/30", "-w", "100"])
            assert exit_code == 0
            assert mock_scan.called

    def test_discovery_workers_exceeding_maximum_rejected(self, capsys: pytest.CaptureFixture[str]) -> None:
        from netprobe.cli import main

        exit_code = main(["--discover", "192.168.1.0/30", "-w", "101"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Configuration error" in captured.err
        assert "Workers must be an integer between 1 and 100 (received 101)" in captured.err

    def test_single_host_workers_above_discovery_limit_preserved(self) -> None:
        from netprobe.cli import main
        from netprobe.scanner import ScanSummary, TCPScanner

        dummy_summary = ScanSummary(
            target="127.0.0.1",
            total_ports=1,
            open_count=0,
            closed_count=1,
            unknown_count=0,
            elapsed_seconds=0.01,
            results=[],
            interrupted=False,
        )
        with patch.object(TCPScanner, "scan", return_value=dummy_summary):
            exit_code = main(["127.0.0.1", "-w", "500", "-p", "80"])
            assert exit_code == 0

    def test_subnet_alias_equivalent_to_discover(self) -> None:
        from netprobe.cli import create_parser, main

        parser = create_parser()
        args_discover = parser.parse_args(["--discover", "10.0.0.0/24"])
        args_subnet = parser.parse_args(["--subnet", "10.0.0.0/24"])
        assert args_subnet.discover == "10.0.0.0/24"
        assert args_subnet.discover == args_discover.discover

        dummy_summary = DiscoverySummary(
            network="10.0.0.0/30",
            total_candidates=2,
            responsive_count=0,
            no_response_count=2,
            unreachable_count=0,
            elapsed_seconds=0.1,
            hosts=(),
            interrupted=False,
        )
        with patch.object(SubnetScanner, "scan", return_value=dummy_summary):
            exit_code = main(["--subnet", "10.0.0.0/30"])
            assert exit_code == 0

    def test_discovery_auto_filtering_over_50_hosts(self, capsys: pytest.CaptureFixture[str]) -> None:
        from netprobe.cli import main

        hosts = [
            DiscoveredHost(
                ip="10.0.0.1",
                status=HostReachability.TCP_RESPONSIVE,
                responsive_port=80,
                responsive_state=PortState.OPEN,
                tested_ports=(80,),
                reason="Connection established",
            ),
            DiscoveredHost(
                ip="10.0.0.2",
                status=HostReachability.TCP_RESPONSIVE,
                responsive_port=443,
                responsive_state=PortState.OPEN,
                tested_ports=(443,),
                reason="Connection established",
            ),
        ] + [
            DiscoveredHost(
                ip=f"10.0.0.{i}",
                status=HostReachability.NO_RESPONSE,
                responsive_port=None,
                responsive_state=None,
                tested_ports=(80, 443),
                reason="Probes timed out",
            )
            for i in range(3, 61)
        ]
        summary = DiscoverySummary(
            network="10.0.0.0/26",
            total_candidates=60,
            responsive_count=2,
            no_response_count=58,
            unreachable_count=0,
            elapsed_seconds=0.5,
            hosts=tuple(hosts),
            interrupted=False,
        )

        with patch.object(SubnetScanner, "scan", return_value=summary):
            # 1. Default run auto-filters non-responsive hosts
            exit_code = main(["--discover", "10.0.0.0/26"])
            assert exit_code == 0
            captured = capsys.readouterr()
            assert "10.0.0.1" in captured.out
            assert "10.0.0.2" in captured.out
            assert "10.0.0.3" not in captured.out
            assert "[*] Note: 58 non-responsive/unreachable hosts hidden. Use --all to list all hosts." in captured.out

            # 2. Run with --all shows all hosts and omits the notice
            exit_code_all = main(["--discover", "10.0.0.0/26", "--all"])
            assert exit_code_all == 0
            captured_all = capsys.readouterr()
            assert "10.0.0.1" in captured_all.out
            assert "10.0.0.2" in captured_all.out
            assert "10.0.0.3" in captured_all.out
            assert "non-responsive/unreachable hosts hidden" not in captured_all.out

    def test_interrupted_discovery_json_output(self, capsys: pytest.CaptureFixture[str], tmp_path) -> None:
        import json
        from netprobe.cli import main

        partial_host = DiscoveredHost(
            ip="192.168.1.1",
            status=HostReachability.TCP_RESPONSIVE,
            responsive_port=80,
            responsive_state=PortState.OPEN,
            tested_ports=(80,),
            reason="Connection established",
        )
        partial_summary = DiscoverySummary(
            network="192.168.1.0/30",
            total_candidates=2,
            responsive_count=1,
            no_response_count=0,
            unreachable_count=0,
            elapsed_seconds=0.15,
            hosts=(partial_host,),
            interrupted=True,
            sweep_ports=(80, 443),
        )

        with patch.object(SubnetScanner, "scan", side_effect=DiscoveryInterruptedError(partial_summary)):
            # 1. Interrupted discovery to stdout in JSON mode
            exit_code = main(["--discover", "192.168.1.0/30", "--json"])
            assert exit_code == 130
            captured = capsys.readouterr()
            assert "[WARN] Discovery scan interrupted by operator" in captured.err
            data = json.loads(captured.out)
            assert data["mode"] == "discovery"
            assert data["interrupted"] is True
            assert data["network"] == "192.168.1.0/30"
            assert data["total_candidates"] == 2
            assert data["responsive_count"] == 1
            assert data["no_response_count"] == 0
            assert len(data["hosts"]) == 1
            assert data["hosts"][0]["ip"] == "192.168.1.1"

            # 2. Interrupted discovery with --json and -o FILE
            out_file = tmp_path / "interrupted.json"
            capsys.readouterr()
            exit_code_file = main(["--discover", "192.168.1.0/30", "--json", "-o", str(out_file)])
            assert exit_code_file == 130
            captured_file = capsys.readouterr()
            assert captured_file.out == ""
            assert "[WARN] Discovery scan interrupted by operator" in captured_file.err
            assert out_file.exists()
            file_data = json.loads(out_file.read_text(encoding="utf-8"))
            assert file_data["interrupted"] is True
            assert file_data["responsive_count"] == 1
            assert len(file_data["hosts"]) == 1








