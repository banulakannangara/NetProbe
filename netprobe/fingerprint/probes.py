"""Protocol-specific fingerprinting probes for NetProbe Phase 2.1."""

import re
import socket
import ssl

from netprobe.fingerprint.models import CertificateInfo, IdentificationMethod, ServiceInfo

# Standard bounds for probe responses
MAX_BANNER_BYTES: int = 512
MAX_HTTP_BYTES: int = 2048

# Regex patterns for server greeting banners
SSH_BANNER_PATTERN = re.compile(r"^SSH-([12]\.[0-9]+)-([^\r\n]+)")
FTP_BANNER_PATTERN = re.compile(r"^220[- ]([^\r\n]*)")
POP3_BANNER_PATTERN = re.compile(r"^\+OK(?:\s+([^\r\n]*)|$)", re.IGNORECASE)
IMAP_BANNER_PATTERN = re.compile(r"^\*\s+(OK|PREAUTH)\b(?:\s+([^\r\n]*))?", re.IGNORECASE)
VNC_BANNER_PATTERN = re.compile(r"^RFB\s+(\d{3})\.(\d{3})(?:[\r\n\s]|$)")
HTTP_STATUS_PATTERN = re.compile(
    r"^HTTP/(1\.[01])\s+([1-5][0-9]{2})(?:[ \t]+([^\r\n]*))?(?:\r\n|\r|\n|$)",
    re.IGNORECASE,
)


def parse_mysql_handshake(data: bytes) -> ServiceInfo | None:
    """Parse a MySQL initial server handshake packet and return ServiceInfo if valid.

    Safely parses MySQL HandshakeV10 packet header:
    - 3-byte little-endian payload length
    - 1-byte sequence ID (must be 0 for initial handshake)
    - 1-byte protocol version (must be 0x0a)
    - Null-terminated server version string

    Args:
        data: Raw binary packet received from server.

    Returns:
        ServiceInfo if data is a valid MySQL handshake, otherwise None.
    """
    if not data or len(data) < 5:
        return None

    # Parse 3-byte payload length (little-endian) and sequence ID
    payload_len = data[0] | (data[1] << 8) | (data[2] << 16)
    seq_id = data[3]

    # Server handshake packet must have sequence ID 0
    if seq_id != 0:
        return None

    # Enforce safe payload length bounds (min: proto(1) + version(1) + null(1) = 3)
    # Never trust unbounded server-provided lengths
    if payload_len < 3 or payload_len > 16384:
        return None

    # Check packet completeness: buffer must contain the entire declared payload
    if len(data) < 4 + payload_len:
        return None

    # Validate protocol version byte (0x0a = HandshakeV10)
    proto_ver = data[4]
    if proto_ver != 0x0A:
        return None

    # Locate null terminator for server version string
    try:
        null_idx = data.index(b"\x00", 5, 4 + payload_len)
    except ValueError:
        return None

    version_bytes = data[5:null_idx]
    if not version_bytes:
        return None

    try:
        version_str = version_bytes.decode("ascii")
    except (UnicodeDecodeError, ValueError):
        return None

    if not version_str.isprintable():
        return None

    version_lower = version_str.lower()
    product = "MariaDB" if "mariadb" in version_lower else "MySQL"

    return ServiceInfo(
        name="mysql",
        method=IdentificationMethod.BANNER,
        product=product,
        version=version_str,
        details=f"protocol {proto_ver} ({version_str})",
        confidence_note="MySQL server handshake",
        raw_response=version_str[:120],
    )


def parse_banner(raw_text: str | bytes, port: int | None = None) -> ServiceInfo | None:
    """Parse a passive greeting line or handshake and return a ServiceInfo if recognized.

    Args:
        raw_text: Decoded greeting string or raw binary packet from server.
        port: Optional TCP port number for disambiguation of ambiguous greetings.

    Returns:
        ServiceInfo if greeting matches a supported protocol, otherwise None.
    """
    if not raw_text:
        return None

    if isinstance(raw_text, bytes):
        mysql_info = parse_mysql_handshake(raw_text)
        if mysql_info is not None:
            return mysql_info
        text = raw_text.decode("utf-8", errors="replace")
    else:
        text = raw_text

    lines = text.splitlines()
    first_line = lines[0].strip() if lines else ""
    if not first_line:
        return None

    # 1. SSH banner check (RFC 4253: SSH-protoversion-softwareversion)
    ssh_match = SSH_BANNER_PATTERN.match(first_line)
    if ssh_match:
        proto_ver = ssh_match.group(1)
        software = ssh_match.group(2).strip()
        product = None
        version = None

        # Parse software token (e.g. OpenSSH_9.6p1 -> OpenSSH, 9.6p1)
        if "_" in software:
            parts = software.split("_", 1)
            product, version = parts[0], parts[1].split()[0]
        elif "-" in software:
            parts = software.split("-", 1)
            product, version = parts[0], parts[1].split()[0]
        else:
            product = software

        return ServiceInfo(
            name="ssh",
            method=IdentificationMethod.BANNER,
            product=product,
            version=version,
            details=f"protocol {proto_ver} ({software})",
            confidence_note="Server greeting banner",
            raw_response=first_line[:120],
        )

    # 2. 220 banner check (FTP or SMTP)
    ftp_match = FTP_BANNER_PATTERN.match(first_line)
    if ftp_match:
        line_lower = first_line.lower()

        # Explicit FTP indicators (RFC 959 greeting phrase, FTP keyword, or known FTP products)
        is_explicit_ftp = (
            "service ready for new user" in line_lower
            or bool(re.search(r"\bftp(?:d)?\b", first_line, re.IGNORECASE))
            or any(kw in line_lower for kw in ("vsftpd", "proftpd", "filezilla", "pure-ftpd", "microsoft ftp"))
        )

        # Explicit SMTP/ESMTP indicators (ESMTP/SMTP tokens, mail service phrase, known MTAs)
        is_explicit_smtp = (
            bool(re.search(r"\bE?SMTP\b", first_line, re.IGNORECASE))
            or bool(re.search(r"\bmail\s+service\s+ready\b", first_line, re.IGNORECASE))
            or any(mta in line_lower for mta in ("postfix", "exim", "sendmail", "qmail", "opensmtpd", "microsoft esmtp"))
        )

        if is_explicit_smtp and not is_explicit_ftp:
            product = None
            if "postfix" in line_lower:
                product = "Postfix"
            elif "exim" in line_lower:
                product = "Exim"
            elif "sendmail" in line_lower:
                product = "Sendmail"
            elif "opensmtpd" in line_lower:
                product = "OpenSMTPD"
            elif "qmail" in line_lower:
                product = "qmail"
            elif "microsoft esmtp" in line_lower:
                product = "Microsoft ESMTP"

            return ServiceInfo(
                name="smtp",
                method=IdentificationMethod.BANNER,
                product=product,
                details=first_line[:80],
                confidence_note="Server greeting banner",
                raw_response=first_line[:120],
            )

        if is_explicit_ftp and not is_explicit_smtp:
            product = None
            if "vsftpd" in line_lower:
                product = "vsFTPd"
            elif "proftpd" in line_lower:
                product = "ProFTPD"
            elif "filezilla" in line_lower:
                product = "FileZilla"
            elif "pure-ftpd" in line_lower:
                product = "Pure-FTPd"
            elif "microsoft ftp" in line_lower:
                product = "Microsoft FTP Service"

            return ServiceInfo(
                name="ftp",
                method=IdentificationMethod.BANNER,
                product=product,
                details=first_line[:80],
                confidence_note="Server greeting banner",
                raw_response=first_line[:120],
            )

        # Port-assisted disambiguation for ambiguous 220 greetings
        if port is not None:
            if port in (25, 465, 587):
                return ServiceInfo(
                    name="smtp",
                    method=IdentificationMethod.BANNER,
                    product=None,
                    details=first_line[:80],
                    confidence_note="Server greeting banner (port-assisted 220)",
                    raw_response=first_line[:120],
                )
            if port == 21:
                return ServiceInfo(
                    name="ftp",
                    method=IdentificationMethod.BANNER,
                    product=None,
                    details=first_line[:80],
                    confidence_note="Server greeting banner (port-assisted 220)",
                    raw_response=first_line[:120],
                )

        # Ambiguous 220 greeting without supporting indicators returns None
        return None

    # 3. POP3 banner check (RFC 1939: +OK [greeting])
    pop3_match = POP3_BANNER_PATTERN.match(first_line)
    if pop3_match:
        content = (pop3_match.group(1) or "").strip()
        product = None
        version = None
        content_lower = content.lower()

        if "dovecot" in content_lower:
            product = "Dovecot"
        elif "courier" in content_lower:
            product = "Courier"
        elif "exchange" in content_lower:
            product = "Microsoft Exchange"

        return ServiceInfo(
            name="pop3",
            method=IdentificationMethod.BANNER,
            product=product,
            version=version,
            details=first_line[:80],
            confidence_note="Server greeting banner",
            raw_response=first_line[:120],
        )

    # 4. IMAP banner check (RFC 3501: * OK ... or * PREAUTH ...)
    imap_match = IMAP_BANNER_PATTERN.match(first_line)
    if imap_match:
        content = (imap_match.group(2) or "").strip()
        product = None
        version = None
        content_lower = content.lower()

        if "dovecot" in content_lower:
            product = "Dovecot"
        elif "courier" in content_lower:
            product = "Courier"
        elif "exchange" in content_lower:
            product = "Microsoft Exchange"

        return ServiceInfo(
            name="imap",
            method=IdentificationMethod.BANNER,
            product=product,
            version=version,
            details=first_line[:80],
            confidence_note="Server greeting banner",
            raw_response=first_line[:120],
        )

    # 5. VNC / RFB banner check (RFC 6143: RFB 003.008)
    vnc_match = VNC_BANNER_PATTERN.match(first_line)
    if vnc_match:
        major_str = vnc_match.group(1)
        minor_str = vnc_match.group(2)
        rfb_version = f"{int(major_str)}.{int(minor_str)}"

        return ServiceInfo(
            name="vnc",
            method=IdentificationMethod.BANNER,
            product="VNC",
            version=rfb_version,
            details=f"RFB protocol {rfb_version} ({major_str}.{minor_str})",
            confidence_note="Server greeting banner",
            raw_response=first_line[:120],
        )

    # Do not mistake arbitrary text for a recognized service
    return None


def parse_http_response(raw_text: str) -> ServiceInfo | None:
    """Parse an HTTP response buffer and return a ServiceInfo if valid.

    Treats any syntactically valid HTTP/1.x status line (including 400, 404, 500)
    as confirmation of HTTP service. Treats Server header strictly as
    self-reported metadata.

    Args:
        raw_text: Decoded response string.

    Returns:
        ServiceInfo if response contains a valid HTTP status line, otherwise None.
    """
    if not raw_text:
        return None

    # Handle CRLF, LF, or CR line split
    lines = raw_text.splitlines()
    if not lines:
        return None

    first_line = lines[0].strip("\r\n")
    status_match = HTTP_STATUS_PATTERN.match(first_line)
    if not status_match:
        return None

    http_ver = status_match.group(1)
    status_code = status_match.group(2)
    reason = (status_match.group(3) or "").strip()
    status_desc = f"HTTP/{http_ver} {status_code} {reason}".strip()

    # Parse headers for self-reported Server header
    server_header: str | None = None
    for line in lines[1:]:
        if not line.strip():
            # End of HTTP headers
            break
        if line.lower().startswith("server:"):
            server_header = line.split(":", 1)[1].strip()
            break

    product = None
    version = None
    confidence = "Syntactically valid HTTP status line"

    if server_header:
        confidence = "Self-reported by Server header (unverified)"
        # Try extracting primary token (e.g. nginx/1.24.0 -> nginx, 1.24.0)
        parts = server_header.split()[0].split("/", 1)
        product = parts[0]
        if len(parts) == 2:
            version = parts[1]
        details = f"{status_desc} (Server: {server_header})"
    else:
        details = status_desc

    return ServiceInfo(
        name="http",
        method=IdentificationMethod.HTTP,
        product=product,
        version=version,
        details=details,
        confidence_note=confidence,
        raw_response=first_line[:120],
    )


def probe_passive_banner(
    target: str,
    port: int,
    timeout: float = 0.5,
    max_bytes: int = MAX_BANNER_BYTES,
) -> ServiceInfo | None:
    """Connect to a port and passively listen for an initial greeting banner.

    Sends no payload. Treats timeout as an overall shared budget across connect
    and recv operations. Returns None if connection fails, times out, budget is
    exhausted, or response does not match a supported greeting.

    Args:
        target: Target IPv4 address.
        port: TCP port to inspect.
        timeout: Total budget in seconds for connection and read.
        max_bytes: Maximum bytes to read.

    Returns:
        ServiceInfo if recognized, otherwise None.
    """
    if timeout <= 0.0:
        return None

    import time
    start = time.perf_counter()
    sock: socket.socket | None = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))

        # Recalculate remaining budget after connect
        elapsed = time.perf_counter() - start
        remaining = timeout - elapsed
        if remaining <= 0.01:
            return None

        sock.settimeout(remaining)
        data = sock.recv(max_bytes)
        if not data:
            return None
        return parse_banner(data, port=port)
    except (socket.timeout, TimeoutError, ConnectionRefusedError, OSError):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def probe_http(
    target: str,
    port: int,
    timeout: float = 0.75,
    max_bytes: int = MAX_HTTP_BYTES,
) -> ServiceInfo | None:
    """Send an HTTP HEAD request and parse response, falling back to GET if needed.

    Treats timeout as an overall shared budget across connect, send, and recv.
    If HEAD returns a valid HTTP status line, no GET request is sent.
    If HEAD receives no valid status line, connection resets, or empty response,
    a single conditional GET request with Range: bytes=0-512 is sent if sufficient
    time budget remains.

    Args:
        target: Target IPv4 address.
        port: TCP port to inspect.
        timeout: Total budget in seconds for connect, send, and read.
        max_bytes: Maximum response bytes to read.

    Returns:
        ServiceInfo if valid HTTP response received, otherwise None.
    """
    if timeout <= 0.0:
        return None

    import time
    start = time.perf_counter()
    sock: socket.socket | None = None

    head_request = (
        f"HEAD / HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        f"User-Agent: NetProbe/0.2.0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii")

    get_request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        f"User-Agent: NetProbe/0.2.0\r\n"
        f"Range: bytes=0-512\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))

        # Check remaining budget before HEAD send
        elapsed = time.perf_counter() - start
        remaining = timeout - elapsed
        if remaining <= 0.01:
            return None

        sock.settimeout(remaining)
        sock.sendall(head_request)

        # Check remaining budget before HEAD recv
        elapsed = time.perf_counter() - start
        remaining = timeout - elapsed
        if remaining <= 0.01:
            return None

        sock.settimeout(remaining)
        head_data = b""
        try:
            head_data = sock.recv(max_bytes)
        except (socket.timeout, TimeoutError, ConnectionRefusedError, OSError):
            pass

        if head_data:
            head_text = head_data.decode("utf-8", errors="replace")
            info = parse_http_response(head_text)
            if info is not None:
                return info

        # Close first socket before deciding on GET fallback
        try:
            sock.close()
        except Exception:
            pass
        sock = None

        # Check remaining budget for conditional GET fallback
        elapsed = time.perf_counter() - start
        remaining = timeout - elapsed
        if remaining <= 0.05:
            return None

        # Execute single fallback GET request in a clean connection
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(remaining)
            sock.connect((target, port))

            elapsed = time.perf_counter() - start
            remaining = timeout - elapsed
            if remaining <= 0.01:
                return None

            sock.settimeout(remaining)
            sock.sendall(get_request)

            elapsed = time.perf_counter() - start
            remaining = timeout - elapsed
            if remaining <= 0.01:
                return None

            sock.settimeout(remaining)
            get_data = sock.recv(max_bytes)
            if not get_data:
                return None
            get_text = get_data.decode("utf-8", errors="replace")
            return parse_http_response(get_text)
        except (socket.timeout, TimeoutError, ConnectionRefusedError, OSError):
            return None

    except (socket.timeout, TimeoutError, ConnectionRefusedError, OSError):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def _format_dn(dn_tuple: tuple | None) -> str | None:
    """Format an X.509 distinguished name tuple from _test_decode_cert into a string.

    Example input: ((('commonName', 'example.com'),), (('organizationName', 'Acme'),))
    Output: 'CN=example.com, O=Acme'
    """
    if not dn_tuple:
        return None

    short_names = {
        "commonName": "CN",
        "organizationName": "O",
        "organizationalUnitName": "OU",
        "countryName": "C",
        "stateOrProvinceName": "ST",
        "localityName": "L",
    }
    parts: list[str] = []
    for rdn in dn_tuple:
        for attr, val in rdn:
            key = short_names.get(attr, attr)
            parts.append(f"{key}={val}")
    return ", ".join(parts) if parts else None


def parse_certificate_der(der_bytes: bytes) -> CertificateInfo | None:
    """Safely parse DER certificate bytes using Python's standard library.

    Uses ssl.DER_cert_to_PEM_cert and internal ssl._ssl._test_decode_cert if available,
    falling back cleanly if parsing cannot be safely completed without dependencies.

    Args:
        der_bytes: Raw binary DER-encoded X.509 certificate.

    Returns:
        CertificateInfo with extracted fields, or None if decoding fails.
    """
    if not der_bytes:
        return None

    import os
    import tempfile

    try:
        pem_str = ssl.DER_cert_to_PEM_cert(der_bytes)
        if hasattr(ssl, "_ssl") and hasattr(ssl._ssl, "_test_decode_cert"):
            with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as tf:
                tf.write(pem_str.encode("ascii"))
                tf_path = tf.name
            try:
                decoded = ssl._ssl._test_decode_cert(tf_path)
                subject_str = _format_dn(decoded.get("subject"))
                issuer_str = _format_dn(decoded.get("issuer"))

                san_list: list[str] = []
                raw_san = decoded.get("subjectAltName")
                if raw_san and isinstance(raw_san, (tuple, list)):
                    for item in raw_san:
                        if isinstance(item, (tuple, list)) and len(item) == 2:
                            tag, val = item
                            if tag in ("DNS", "IP Address") and val:
                                san_list.append(str(val))
                san_tuple = tuple(san_list)

                return CertificateInfo(
                    subject=subject_str,
                    issuer=issuer_str,
                    not_before=decoded.get("notBefore"),
                    not_after=decoded.get("notAfter"),
                    verified=False,
                    san=san_tuple,
                )
            finally:
                try:
                    os.remove(tf_path)
                except OSError:
                    pass
    except Exception:
        pass

    return CertificateInfo(verified=False)


def probe_tls(
    target: str,
    port: int,
    timeout: float = 1.0,
    max_bytes: int = MAX_HTTP_BYTES,
) -> ServiceInfo | None:
    """Connect to a port, perform a TLS handshake, inspect certificate, and test for HTTPS.

    Uses a separate TCP connection with bounded timeout and shared time budget across
    connect, handshake, and application detection operations. Operates with CERT_NONE
    and clearly identifies certificates as unverified.

    Args:
        target: Target IPv4 address or hostname.
        port: TCP port to inspect.
        timeout: Total shared budget in seconds for TLS probe.
        max_bytes: Maximum response bytes to read if probing application layer.

    Returns:
        ServiceInfo if TLS handshake succeeds, otherwise None.
    """
    if timeout <= 0.0:
        return None

    import time
    start = time.perf_counter()
    raw_sock: socket.socket | None = None
    ssl_sock: ssl.SSLSocket | None = None

    # Configure client SSL context
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except (NotImplementedError, ssl.SSLError):
        pass

    # Determine SNI server hostname safely (only if not an IP address)
    is_ip = True
    try:
        socket.inet_aton(target)
    except OSError:
        is_ip = False
    server_hostname = None if is_ip else target

    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.connect((target, port))

        # Check remaining budget after TCP connect
        elapsed = time.perf_counter() - start
        remaining = timeout - elapsed
        if remaining <= 0.01:
            return None

        raw_sock.settimeout(remaining)
        ssl_sock = ctx.wrap_socket(
            raw_sock,
            server_side=False,
            server_hostname=server_hostname,
            do_handshake_on_connect=False,
        )
        ssl_sock.settimeout(remaining)
        ssl_sock.do_handshake()

        # Capture TLS metadata
        tls_version = ssl_sock.version()
        cipher_tuple = ssl_sock.cipher()
        cipher_suite = cipher_tuple[0] if cipher_tuple else None
        alpn = ssl_sock.selected_alpn_protocol()

        # Extract certificate metadata from peer chain
        cert_info: CertificateInfo | None = None
        try:
            chain = ssl_sock.get_unverified_chain()
            if chain:
                base_cert = parse_certificate_der(chain[0])
                if base_cert:
                    cert_info = CertificateInfo(
                        subject=base_cert.subject,
                        issuer=base_cert.issuer,
                        not_before=base_cert.not_before,
                        not_after=base_cert.not_after,
                        verified=False,
                        alpn_protocol=alpn,
                        tls_version=tls_version,
                        cipher_suite=cipher_suite,
                        san=base_cert.san,
                    )
        except (AttributeError, ssl.SSLError, OSError):
            pass

        if cert_info is None:
            cert_info = CertificateInfo(
                verified=False,
                alpn_protocol=alpn,
                tls_version=tls_version,
                cipher_suite=cipher_suite,
                san=(),
            )

        # Check if application layer over TLS is HTTP
        # Check remaining budget before sending HEAD request
        elapsed = time.perf_counter() - start
        remaining = timeout - elapsed
        http_info: ServiceInfo | None = None

        if remaining > 0.05:
            try:
                ssl_sock.settimeout(remaining)
                head_request = (
                    f"HEAD / HTTP/1.1\r\n"
                    f"Host: {target}\r\n"
                    f"User-Agent: NetProbe/0.2.0\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("ascii")
                ssl_sock.sendall(head_request)

                elapsed = time.perf_counter() - start
                remaining = timeout - elapsed
                if remaining > 0.01:
                    ssl_sock.settimeout(remaining)
                    head_resp_data = b""
                    try:
                        head_resp_data = ssl_sock.recv(max_bytes)
                    except (socket.timeout, TimeoutError, ssl.SSLError, ssl.SSLZeroReturnError, OSError):
                        pass

                    if head_resp_data:
                        resp_text = head_resp_data.decode("utf-8", errors="replace")
                        http_info = parse_http_response(resp_text)

                # Conditional GET fallback within same TLS session if HEAD failed and budget remains
                if http_info is None:
                    elapsed = time.perf_counter() - start
                    remaining = timeout - elapsed
                    if remaining > 0.05:
                        get_request = (
                            f"GET / HTTP/1.1\r\n"
                            f"Host: {target}\r\n"
                            f"User-Agent: NetProbe/0.2.0\r\n"
                            f"Range: bytes=0-512\r\n"
                            f"Connection: close\r\n\r\n"
                        ).encode("ascii")
                        ssl_sock.settimeout(remaining)
                        ssl_sock.sendall(get_request)

                        elapsed = time.perf_counter() - start
                        remaining = timeout - elapsed
                        if remaining > 0.01:
                            ssl_sock.settimeout(remaining)
                            get_resp_data = ssl_sock.recv(max_bytes)
                            if get_resp_data:
                                resp_text = get_resp_data.decode("utf-8", errors="replace")
                                http_info = parse_http_response(resp_text)
            except (socket.timeout, TimeoutError, ssl.SSLError, OSError):
                pass

        if http_info is not None:
            # Verified HTTPS service (HTTP application confirmed over TLS transport)
            details_parts: list[str] = [f"{tls_version} ({cipher_suite or 'cipher'})"]
            if http_info.details:
                details_parts.append(http_info.details)
            if cert_info.subject:
                details_parts.append(f"CN: {cert_info.subject}")

            return ServiceInfo(
                name="https",
                method=IdentificationMethod.TLS,
                product=http_info.product,
                version=http_info.version,
                details="; ".join(details_parts),
                confidence_note="HTTP confirmed over TLS (Certificate unverified / CERT_NONE)",
                raw_response=http_info.raw_response,
                tls_info=cert_info,
            )

        # TLS transport confirmed, but application is not confirmed HTTP (e.g. ALPN h2, FTPS, SMTPS, or generic TLS)
        details_parts = [f"{tls_version} ({cipher_suite or 'cipher'})"]
        if alpn:
            details_parts.append(f"ALPN: {alpn}")
        if cert_info.subject:
            details_parts.append(f"CN: {cert_info.subject}")

        # If ALPN explicitly negotiated 'h2' or 'http/1.1', we can identify service as https
        service_name = "https" if alpn in ("h2", "http/1.1") else "tls"
        return ServiceInfo(
            name=service_name,
            method=IdentificationMethod.TLS,
            details="; ".join(details_parts),
            confidence_note="TLS handshake successful (Certificate unverified / CERT_NONE)",
            tls_info=cert_info,
        )

    except (socket.timeout, TimeoutError, ConnectionRefusedError, ssl.SSLError, OSError):
        return None
    finally:
        if ssl_sock is not None:
            try:
                ssl_sock.close()
            except Exception:
                pass
        elif raw_sock is not None:
            try:
                raw_sock.close()
            except Exception:
                pass
