"""Data models for NetProbe service fingerprinting."""

from dataclasses import dataclass
from enum import Enum


class IdentificationMethod(str, Enum):
    """Method used to determine service identity."""

    CONVENTIONAL = "conventional"  # Static port-number lookup (unverified guess)
    BANNER = "banner"              # Passive server greeting (e.g. SSH, FTP, SMTP)
    HTTP = "http"                  # Active plain HTTP request/response
    TLS = "tls"                    # Confirmed TLS transport / HTTPS
    UNKNOWN = "unknown"            # Open port with no recognizable protocol response


@dataclass(frozen=True)
class CertificateInfo:
    """X.509 peer certificate diagnostic metadata.

    Attributes:
        subject: Formatted subject distinguished name (or common name).
        issuer: Formatted issuer distinguished name.
        not_before: Validity start date/time string.
        not_after: Validity expiration date/time string.
        verified: Whether certificate was verified against a trust store (False for CERT_NONE).
        alpn_protocol: Negotiated ALPN protocol (e.g. 'h2', 'http/1.1') if any.
        tls_version: Negotiated TLS protocol version (e.g. 'TLSv1.3').
        cipher_suite: Negotiated cipher suite name (e.g. 'TLS_AES_256_GCM_SHA384').
        san: Extracted Subject Alternative Names (DNS names and IP addresses) if any.
    """

    subject: str | None = None
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    verified: bool = False
    alpn_protocol: str | None = None
    tls_version: str | None = None
    cipher_suite: str | None = None
    san: tuple[str, ...] = ()


@dataclass(frozen=True)
class ServiceInfo:
    """Application-layer service metadata.

    Attributes:
        name: Canonical protocol or service name (e.g. 'http', 'https', 'ssh', 'ftp', 'smtp', 'tls').
        method: The IdentificationMethod used to identify the service.
        product: Self-reported or inferred software product name (e.g. 'OpenSSH', 'nginx').
        version: Self-reported or inferred software version string.
        details: Human-readable diagnostic description or status line.
        confidence_note: Note explaining confidence level (e.g. self-reported vs inferred).
        raw_response: Truncated sample of raw protocol response for diagnostics.
        tls_info: Associated TLS/certificate metadata when TLS is negotiated.
    """

    name: str
    method: IdentificationMethod
    product: str | None = None
    version: str | None = None
    details: str | None = None
    confidence_note: str | None = None
    raw_response: str | None = None
    tls_info: CertificateInfo | None = None
