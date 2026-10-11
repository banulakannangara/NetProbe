"""Structured serialization and export helpers for NetProbe.

Provides standard-library-only JSON serialization for scan summaries and results.
"""

from dataclasses import asdict, is_dataclass
from enum import Enum
import json
from pathlib import Path
from typing import Any

from netprobe import __version__
from netprobe.fingerprint.models import CertificateInfo, IdentificationMethod, ServiceInfo
from netprobe.scanner import PortState, ScanResult, ScanSummary


def _serialize_value(val: Any) -> Any:
    """Recursively convert domain objects to JSON-serializable primitives."""
    if isinstance(val, Enum):
        return val.value
    if isinstance(val, tuple):
        return [_serialize_value(item) for item in val]
    if isinstance(val, list):
        return [_serialize_value(item) for item in val]
    if isinstance(val, dict):
        return {k: _serialize_value(v) for k, v in val.items()}
    if is_dataclass(val):
        return {k: _serialize_value(v) for k, v in asdict(val).items()}
    return val


def certificate_info_to_dict(cert: CertificateInfo | None) -> dict[str, Any] | None:
    """Serialize CertificateInfo to a clean dictionary."""
    if cert is None:
        return None
    return {
        "subject": cert.subject,
        "issuer": cert.issuer,
        "not_before": cert.not_before,
        "not_after": cert.not_after,
        "verified": cert.verified,
        "alpn_protocol": cert.alpn_protocol,
        "tls_version": cert.tls_version,
        "cipher_suite": cert.cipher_suite,
        "san": list(cert.san),
    }


def service_info_to_dict(svc: ServiceInfo | None) -> dict[str, Any] | None:
    """Serialize ServiceInfo to a clean dictionary."""
    if svc is None:
        return None
    return {
        "name": svc.name,
        "method": svc.method.value if isinstance(svc.method, Enum) else svc.method,
        "product": svc.product,
        "version": svc.version,
        "details": svc.details,
        "confidence_note": svc.confidence_note,
        "raw_response": svc.raw_response,
        "tls_info": certificate_info_to_dict(svc.tls_info),
    }


def scan_result_to_dict(result: ScanResult) -> dict[str, Any]:
    """Serialize a single ScanResult to a dictionary."""
    data: dict[str, Any] = {
        "port": result.port,
        "state": result.state.value if isinstance(result.state, Enum) else result.state,
        "service": result.service,
        "reason": result.reason,
    }
    data["service_info"] = service_info_to_dict(result.service_info)
    return data


def scan_summary_to_dict(summary: ScanSummary) -> dict[str, Any]:
    """Serialize ScanSummary to a structured dictionary."""
    return {
        "version": __version__,
        "target": summary.target,
        "resolved_target": summary.resolved_target or summary.target,
        "total_ports": summary.total_ports,
        "open_count": summary.open_count,
        "closed_count": summary.closed_count,
        "unknown_count": summary.unknown_count,
        "elapsed_seconds": round(summary.elapsed_seconds, 4),
        "interrupted": summary.interrupted,
        "results": [scan_result_to_dict(r) for r in summary.results],
    }


def scan_summary_to_json(summary: ScanSummary, indent: int = 2) -> str:
    """Serialize ScanSummary to a formatted JSON string."""
    return json.dumps(scan_summary_to_dict(summary), indent=indent)


def udp_scan_result_to_dict(result: Any) -> dict[str, Any]:
    """Serialize a single UDPScanResult to a dictionary."""
    data: dict[str, Any] = {
        "port": result.port,
        "state": result.state.value if isinstance(result.state, Enum) else str(result.state),
        "service": result.service,
        "reason": result.reason,
    }
    if getattr(result, "protocol_info", None) is not None:
        data["protocol_info"] = {
            "protocol": result.protocol_info.protocol,
            "verified": result.protocol_info.verified,
            "details": result.protocol_info.details,
            "metadata": result.protocol_info.metadata,
        }
    return data


def udp_scan_summary_to_dict(summary: Any) -> dict[str, Any]:
    """Serialize UDPScanSummary to a structured dictionary."""
    data: dict[str, Any] = {
        "version": __version__,
        "mode": "udp",
        "target": summary.target,
        "resolved_target": summary.resolved_target or summary.target,
        "total_ports": summary.total_ports,
        "open_count": summary.open_count,
        "closed_count": summary.closed_count,
        "open_filtered_count": summary.open_filtered_count,
        "unknown_count": summary.unknown_count,
        "elapsed_seconds": round(summary.elapsed_seconds, 4),
        "interrupted": summary.interrupted,
        "results": [udp_scan_result_to_dict(r) for r in summary.results],
    }
    if getattr(summary, "probe", None) is not None:
        data["probe"] = summary.probe
    return data


def udp_scan_summary_to_json(summary: Any, indent: int = 2) -> str:
    """Serialize UDPScanSummary to a formatted JSON string."""
    return json.dumps(udp_scan_summary_to_dict(summary), indent=indent)


def discovered_host_to_dict(host: Any) -> dict[str, Any]:
    """Serialize a single DiscoveredHost to a clean dictionary."""
    return {
        "ip": host.ip,
        "status": host.status.value if hasattr(host.status, "value") else str(host.status),
        "responsive_port": host.responsive_port,
        "responsive_state": (
            host.responsive_state.value
            if hasattr(host.responsive_state, "value")
            else (str(host.responsive_state) if host.responsive_state is not None else None)
        ),
        "tested_ports": list(host.tested_ports),
        "hostname": host.hostname,
        "reason": host.reason,
    }


def discovery_summary_to_dict(summary: Any) -> dict[str, Any]:
    """Serialize DiscoverySummary to a structured dictionary."""
    return {
        "version": __version__,
        "mode": "discovery",
        "network": summary.network,
        "total_candidates": summary.total_candidates,
        "responsive_count": summary.responsive_count,
        "no_response_count": summary.no_response_count,
        "unreachable_count": summary.unreachable_count,
        "elapsed_seconds": round(summary.elapsed_seconds, 4),
        "interrupted": summary.interrupted,
        "sweep_ports": list(summary.sweep_ports),
        "hosts": [discovered_host_to_dict(h) for h in summary.hosts],
    }


def discovery_summary_to_json(summary: Any, indent: int = 2) -> str:
    """Serialize DiscoverySummary to a formatted JSON string."""
    return json.dumps(discovery_summary_to_dict(summary), indent=indent)


def validate_output_path(file_path: str) -> Path:
    """Validate that the target file path is writable before initiating a scan.

    Checks:
    - Path is not an existing directory.
    - Parent directory exists or is non-empty.
    - We can open/create the path in append mode without truncating existing content.

    Args:
        file_path: Destination path string.

    Returns:
        Resolved Path object.

    Raises:
        ValueError: If file path is empty.
        OSError: If destination cannot be written to.
    """
    cleaned = (file_path or "").strip()
    if not cleaned:
        raise ValueError("Output file path cannot be empty.")

    p = Path(cleaned)
    if p.exists() and p.is_dir():
        raise IsADirectoryError(f"Output path '{cleaned}' is an existing directory.")

    parent = p.parent
    if parent and str(parent) != "." and not parent.exists():
        raise FileNotFoundError(f"Destination directory '{parent}' does not exist.")

    # Probe writability safely using append mode 'a' without truncating
    try:
        with open(p, "a", encoding="utf-8"):
            pass
    except Exception as exc:
        raise OSError(f"Cannot write to output file '{cleaned}': {exc}") from exc

    return p
