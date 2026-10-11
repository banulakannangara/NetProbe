"""Protocol-specific UDP probe generators and response validators for NetProbe Phase 4B.

Implements small, bounded DNS (RFC 1035), NTP (RFC 5905/1305), and SNMPv1 (RFC 1157)
packet builders and parsers using only Python standard library modules.
"""

from dataclasses import dataclass, field
import re
import secrets
import struct
from typing import Any

# DNS constants
DNS_PORT: int = 53
DNS_DEFAULT_QNAME: str = "example.com"
DNS_MAX_LABEL_LEN: int = 63
DNS_MAX_NAME_LEN: int = 253
DNS_HEADER_LEN: int = 12

# DNS RCODE names
DNS_RCODES: dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

# NTP constants
NTP_PORT: int = 123
NTP_PACKET_LEN: int = 48
NTP_MODE_NAMES: dict[int, str] = {
    4: "server",
    5: "broadcast",
}


@dataclass(frozen=True)
class UDPProtocolInfo:
    """Diagnostic metadata for a verified application-layer UDP protocol response.

    Attributes:
        protocol: Canonical protocol name ('dns', 'ntp', or 'snmp').
        verified: True if the datagram conformed to expected protocol structure.
        details: Human-readable diagnostic summary.
        metadata: Key-value dictionary of extracted protocol fields.
    """

    protocol: str
    verified: bool
    details: str
    metadata: dict[str, Any] = field(default_factory=dict)


def encode_dns_name(name: str) -> bytes:
    """Encode a hostname into DNS wire-format labels.

    Args:
        name: Fully-qualified or relative hostname string (e.g. 'example.com').

    Returns:
        Wire-encoded name bytes terminated with a null byte (b"\\x00").

    Raises:
        ValueError: If name is invalid, exceeds 253 characters, or contains invalid labels.
    """
    cleaned = (name or "").strip().rstrip(".")
    if not cleaned:
        # Root domain
        return b"\x00"

    if len(cleaned) > DNS_MAX_NAME_LEN:
        raise ValueError(
            f"DNS query name '{cleaned}' exceeds maximum allowed length of {DNS_MAX_NAME_LEN} characters."
        )

    labels = cleaned.split(".")
    encoded_parts: list[bytes] = []

    for label in labels:
        if not label:
            raise ValueError(f"Invalid DNS query name '{cleaned}': consecutive dots or empty label.")

        label_bytes = label.encode("ascii", errors="strict")
        if len(label_bytes) > DNS_MAX_LABEL_LEN:
            raise ValueError(
                f"DNS label '{label}' exceeds maximum length of {DNS_MAX_LABEL_LEN} bytes ({len(label_bytes)} bytes)."
            )

        # Ensure label consists of valid characters (RFC 1123: alphanumeric and hyphens)
        if not re.fullmatch(r"[A-Za-z0-9_-]+", label):
            raise ValueError(f"DNS label '{label}' contains invalid characters.")

        encoded_parts.append(bytes([len(label_bytes)]) + label_bytes)

    encoded_parts.append(b"\x00")
    full_encoded = b"".join(encoded_parts)

    if len(full_encoded) > 255:
        raise ValueError(
            f"Wire-encoded DNS name length ({len(full_encoded)} bytes) exceeds RFC 1035 limit of 255 bytes."
        )

    return full_encoded


def build_dns_query(
    qname: str = DNS_DEFAULT_QNAME,
    tx_id: int | None = None,
    qtype: int = 1,  # A record
) -> tuple[bytes, int]:
    """Construct a standard DNS A-record query packet.

    Args:
        qname: Hostname to query. Defaults to 'example.com'.
        tx_id: Optional 16-bit transaction ID. Generated randomly if None.
        qtype: DNS question type (default 1 for A).

    Returns:
        tuple[bytes, int]: (query_packet_bytes, transaction_id)

    Raises:
        ValueError: If qname is invalid or tx_id is out of bounds (0-65535).
    """
    if tx_id is None:
        tx_id = secrets.randbelow(0xFFFF) + 1
    elif not isinstance(tx_id, int) or tx_id < 0 or tx_id > 0xFFFF:
        raise ValueError(f"Transaction ID must be an integer between 0 and 65535 (received {tx_id}).")

    name_bytes = encode_dns_name(qname)

    # Flags: 0x0100 (Standard Query, RD = 1 Recursion Desired)
    flags = 0x0100
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack("!HHHHHH", tx_id, flags, qdcount, ancount, nscount, arcount)
    question = name_bytes + struct.pack("!HH", qtype, 1)  # QCLASS = 1 (IN)

    return header + question, tx_id


def _skip_dns_name(packet: bytes, offset: int) -> int | None:
    """Validate and advance past a domain name in DNS wire format (RFC 1035).

    Supports standard labels and compression pointers (0xC0).
    Guarantees bounds checking, validates pointer targets (must be within
    packet and >= DNS_HEADER_LEN), and prevents infinite loops.

    Args:
        packet: Raw DNS packet bytes.
        offset: Starting offset of the domain name.

    Returns:
        The next offset in packet immediately after this domain name in the
        wire stream, or None if malformed, out-of-bounds, or cyclic.
    """
    if offset < 0 or offset >= len(packet):
        return None

    curr = offset
    consumed: int | None = None
    visited_pointers: set[int] = set()
    hops = 0
    max_hops = 20

    while True:
        if curr >= len(packet):
            return None
        length = packet[curr]

        if length == 0:
            curr += 1
            if consumed is None:
                consumed = curr
            break
        elif (length & 0xC0) == 0xC0:
            # Compression pointer: 2 octets
            if curr + 1 >= len(packet):
                return None
            pointer_offset = ((length & 0x3F) << 8) | packet[curr + 1]
            if consumed is None:
                consumed = curr + 2

            if pointer_offset >= len(packet) or pointer_offset < DNS_HEADER_LEN:
                return None
            if pointer_offset in visited_pointers:
                # Pointer loop detected
                return None
            visited_pointers.add(pointer_offset)
            hops += 1
            if hops > max_hops:
                return None
            curr = pointer_offset
        elif (length & 0xC0) == 0:
            # Normal label (1 byte length followed by label octets)
            if length > DNS_MAX_LABEL_LEN or curr + 1 + length > len(packet):
                return None
            curr += 1 + length
        else:
            # Reserved or invalid label format (e.g. 0x40 or 0x80)
            return None

    return consumed


def _parse_dns_section_rrs(
    packet: bytes,
    offset: int,
    count: int,
    section_name: str,
) -> tuple[int | None, str | None]:
    """Parse and validate a sequence of Resource Records in a DNS section.

    Args:
        packet: Raw DNS packet bytes.
        offset: Starting offset of the section.
        count: Declared count of Resource Records.
        section_name: Section name ('Answer', 'Authority', or 'Additional').

    Returns:
        tuple[new_offset, None] on success, or tuple[None, error_message] on failure.
    """
    curr = offset
    for idx in range(count):
        next_offset = _skip_dns_name(packet, curr)
        if next_offset is None:
            return None, f"Malformed owner name in {section_name} record #{idx + 1}"

        curr = next_offset

        # Fixed fields: TYPE (2), CLASS (2), TTL (4), RDLENGTH (2) = 10 bytes
        if curr + 10 > len(packet):
            return None, f"Incomplete fixed fields in {section_name} record #{idx + 1}"

        _rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", packet[curr : curr + 10])
        curr += 10

        if curr + rdlength > len(packet):
            return (
                None,
                f"Truncated RDATA in {section_name} record #{idx + 1} (rdlength={rdlength}, available={len(packet) - curr})",
            )

        curr += rdlength

    return curr, None


def validate_dns_response(
    response: bytes,
    expected_tx_id: int,
) -> tuple[bool, str, dict[str, Any]]:
    """Validate and parse a raw UDP datagram as a DNS response.

    Args:
        response: Raw bytes received from the UDP socket.
        expected_tx_id: The transaction ID from the query.

    Returns:
        tuple[bool, str, dict[str, Any]]:
            - verified: True if response is a valid DNS response from a live resolver/server.
            - details: Diagnostic summary string.
            - metadata: Extracted header attributes.
    """
    if len(response) < DNS_HEADER_LEN:
        return False, f"DNS response too short ({len(response)} bytes, expected >= {DNS_HEADER_LEN})", {}

    rx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", response[:DNS_HEADER_LEN])

    metadata: dict[str, Any] = {
        "tx_id": rx_id,
        "flags": flags,
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
    }

    if rx_id != expected_tx_id:
        return (
            False,
            f"Transaction ID mismatch (expected {expected_tx_id}, got {rx_id})",
            metadata,
        )

    # QR bit (bit 15) must be 1 for response
    is_response = bool(flags & 0x8000)
    if not is_response:
        return False, "Not a DNS response (QR bit is 0)", metadata

    opcode = (flags >> 11) & 0x0F
    tc = bool(flags & 0x0200)  # Truncated
    rcode = flags & 0x000F

    rcode_name = DNS_RCODES.get(rcode, f"RCODE_{rcode}")
    metadata["rcode"] = rcode
    metadata["rcode_name"] = rcode_name
    metadata["truncated"] = tc
    metadata["opcode"] = opcode

    # Truncated responses (TC=1) indicate the server answered but truncated the datagram.
    # Respecting the TC bit: they cannot be verified as complete, structurally sound answers.
    if tc:
        return (
            False,
            f"Truncated DNS response (TC bit set, incomplete payload, RCODE={rcode_name})",
            metadata,
        )

    # Validate Question section
    offset = DNS_HEADER_LEN
    for q_idx in range(qdcount):
        next_offset = _skip_dns_name(response, offset)
        if next_offset is None or next_offset + 4 > len(response):
            return False, f"Malformed question section in DNS response (entry #{q_idx + 1})", metadata
        offset = next_offset + 4  # QTYPE (2) + QCLASS (2)

    # Validate Answer section
    offset, err = _parse_dns_section_rrs(response, offset, ancount, "Answer")
    if err:
        return False, err, metadata

    # Validate Authority section
    offset, err = _parse_dns_section_rrs(response, offset, nscount, "Authority")
    if err:
        return False, err, metadata

    # Validate Additional section
    offset, err = _parse_dns_section_rrs(response, offset, arcount, "Additional")
    if err:
        return False, err, metadata

    details = f"DNS response (RCODE={rcode_name}, QD={qdcount}, AN={ancount}"
    if nscount or arcount:
        details += f", NS={nscount}, AR={arcount}"
    details += ")"

    return True, details, metadata


def build_ntp_request(version: int = 4) -> bytes:
    """Construct a minimal 48-byte NTP client mode-3 request.

    Args:
        version: NTP version number (3 or 4). Default 4.

    Returns:
        48-byte NTP request datagram.

    Raises:
        ValueError: If version is not 3 or 4.
    """
    if version not in (3, 4):
        raise ValueError(f"Unsupported NTP version {version}. Must be 3 or 4.")

    # LI = 0 (2 bits), VN = version (3 bits), Mode = 3 Client (3 bits)
    first_byte = (0 << 6) | (version << 3) | 3
    # Followed by 47 zero bytes
    return bytes([first_byte]) + (b"\x00" * 47)


def validate_ntp_response(response: bytes) -> tuple[bool, str, dict[str, Any]]:
    """Validate and parse a raw UDP datagram as an NTP server response.

    Args:
        response: Raw bytes received from the UDP socket.

    Returns:
        tuple[bool, str, dict[str, Any]]:
            - verified: True if response is a valid NTP server response.
            - details: Diagnostic summary string.
            - metadata: Extracted NTP header attributes.
    """
    if len(response) < NTP_PACKET_LEN:
        return (
            False,
            f"NTP response too short ({len(response)} bytes, expected >= {NTP_PACKET_LEN})",
            {},
        )

    first_byte = response[0]
    li = (first_byte >> 6) & 0x03
    vn = (first_byte >> 3) & 0x07
    mode = first_byte & 0x07
    stratum = response[1]
    poll = response[2]
    precision = struct.unpack("!b", response[3:4])[0]

    # Reference Identifier (bytes 12-16)
    ref_id_bytes = response[12:16]
    kiss_code: str | None = None
    if stratum == 0:
        try:
            ascii_code = ref_id_bytes.decode("ascii").strip()
            if ascii_code and all(c.isprintable() for c in ascii_code):
                kiss_code = ascii_code
        except UnicodeDecodeError:
            pass

    metadata: dict[str, Any] = {
        "li": li,
        "leap_indicator": li,
        "vn": vn,
        "mode": mode,
        "stratum": stratum,
        "poll": poll,
        "precision": precision,
        "synchronized": bool(li != 3 and 1 <= stratum <= 15),
        "kiss_of_death": bool(stratum == 0),
        "kiss_code": kiss_code,
    }

    # NTP version must be between 1 and 4
    if vn < 1 or vn > 4:
        return False, f"Invalid NTP version {vn} (expected 1-4)", metadata

    # Server response mode must be 4 (server) or 5 (broadcast)
    if mode not in (4, 5):
        return (
            False,
            f"Invalid NTP mode {mode} (expected 4=server or 5=broadcast)",
            metadata,
        )

    mode_name = NTP_MODE_NAMES.get(mode, f"mode_{mode}")

    if stratum == 0:
        kod_desc = f" '{kiss_code}'" if kiss_code else ""
        details = (
            f"NTP v{vn} {mode_name} response (stratum 0 Kiss-o'-Death/control{kod_desc})"
        )
    else:
        sync_desc = ", clock unsynchronized (LI=3)" if li == 3 else ""
        details = f"NTP v{vn} {mode_name} response (stratum {stratum}{sync_desc})"

    return True, details, metadata


# =============================================================================
# SNMP Constants and BER Helpers (RFC 1157)
# =============================================================================

SNMP_PORT: int = 161
SNMP_DEFAULT_COMMUNITY: str = "public"
SNMP_SYSDESCR_OID: str = "1.3.6.1.2.1.1.1.0"
SNMP_SYSDESCR_OID_RAW: bytes = b"\x2b\x06\x01\x02\x01\x01\x01\x00"
SNMP_GET_REQUEST_PDU: int = 0xA0
SNMP_GET_RESPONSE_PDU: int = 0xA2

SNMP_ERROR_NAMES: dict[int, str] = {
    0: "noError",
    1: "tooBig",
    2: "noSuchName",
    3: "badValue",
    4: "readOnly",
    5: "genErr",
}


def _encode_ber_length(length: int) -> bytes:
    """Encode an integer length into BER short or long form."""
    if length < 0:
        raise ValueError("BER length cannot be negative.")
    if length < 0x80:
        return bytes([length])
    elif length <= 0xFF:
        return bytes([0x81, length])
    elif length <= 0xFFFF:
        return struct.pack("!BH", 0x82, length)
    else:
        raise ValueError(f"Length {length} exceeds maximum supported BER length.")


def _encode_ber_integer(val: int) -> bytes:
    """Encode an integer value into a minimal BER INTEGER (Tag 0x02)."""
    if val == 0:
        return b"\x02\x01\x00"
    if val > 0:
        byte_len = (val.bit_length() + 8) // 8
    else:
        byte_len = ((val + 1).bit_length() + 8) // 8
    raw = val.to_bytes(byte_len, byteorder="big", signed=True)
    return b"\x02" + _encode_ber_length(len(raw)) + raw


def _read_ber_tlv(
    data: bytes,
    offset: int,
) -> tuple[int, int, int, int] | None:
    """Read a BER Tag, Length, and content offset bounds.

    Enforces bounds checking, rejects indefinite lengths (0x80), and bounds
    long-form length bytes to 1-2 octets (max 65535 octets).

    Args:
        data: Raw byte buffer.
        offset: Starting offset of the TLV.

    Returns:
        tuple[tag, content_offset, content_length, next_offset] or None if malformed.
    """
    if offset < 0 or offset >= len(data):
        return None

    tag = data[offset]
    curr = offset + 1
    if curr >= len(data):
        return None

    first_len_byte = data[curr]
    curr += 1

    if first_len_byte < 0x80:
        content_len = first_len_byte
    elif first_len_byte == 0x80:
        # Indefinite length: prohibited in SNMP BER
        return None
    else:
        num_octets = first_len_byte & 0x7F
        if num_octets < 1 or num_octets > 2:
            return None
        if curr + num_octets > len(data):
            return None
        content_len = int.from_bytes(data[curr : curr + num_octets], byteorder="big", signed=False)
        curr += num_octets

    content_offset = curr
    next_offset = curr + content_len

    if next_offset > len(data):
        return None

    return tag, content_offset, content_len, next_offset


def _read_ber_integer(data: bytes, offset: int) -> tuple[int, int] | None:
    """Read a BER INTEGER (Tag 0x02).

    Enforces minimal encoding rules according to ITU-T X.690 Section 8.3.2:
    - Contents must not be empty.
    - Contents must not exceed 8 octets.
    - If length >= 2, the first octet and bit 8 of the second octet shall not
      all be ones (redundant 0xFF for negative) and shall not all be zeros
      (redundant 0x00 for non-negative).

    Returns:
        tuple[val, next_offset] or None if malformed or non-minimal.
    """
    tlv = _read_ber_tlv(data, offset)
    if tlv is None:
        return None
    tag, c_off, c_len, next_off = tlv
    if tag != 0x02 or c_len == 0 or c_len > 8:
        return None

    # Check for non-minimal leading octets (ITU-T X.690 Section 8.3.2)
    if c_len >= 2:
        first_b = data[c_off]
        second_msb = data[c_off + 1] & 0x80
        if first_b == 0x00 and second_msb == 0:
            # Redundant leading 0x00 for non-negative integer
            return None
        if first_b == 0xFF and second_msb != 0:
            # Redundant leading 0xFF for negative integer
            return None

    val = int.from_bytes(data[c_off : c_off + c_len], byteorder="big", signed=True)
    return val, next_off


def _read_ber_octet_string(data: bytes, offset: int) -> tuple[bytes, int] | None:
    """Read a BER OCTET STRING (Tag 0x04).

    Returns:
        tuple[raw_bytes, next_offset] or None if malformed.
    """
    tlv = _read_ber_tlv(data, offset)
    if tlv is None:
        return None
    tag, c_off, c_len, next_off = tlv
    if tag != 0x04:
        return None
    return data[c_off : c_off + c_len], next_off


def _read_ber_oid(data: bytes, offset: int) -> tuple[bytes, str, int] | None:
    """Read a BER OBJECT IDENTIFIER (Tag 0x06).

    Decodes the combined first subidentifier and subsequent subidentifiers
    using bounded base-128 VLQ rules. Rejects unterminated continuation octets,
    values exceeding 32-bit limits, and derives arcs 0, 1, or 2 correctly.

    Returns:
        tuple[raw_oid_bytes, dotted_oid_str, next_offset] or None if malformed.
    """
    tlv = _read_ber_tlv(data, offset)
    if tlv is None:
        return None
    tag, c_off, c_len, next_off = tlv
    if tag != 0x06 or c_len == 0:
        return None

    raw_oid = data[c_off : c_off + c_len]
    parsed_values: list[int] = []
    curr_subid = 0
    in_multibyte = False
    shift_count = 0
    MAX_SUBID = 0xFFFFFFFF  # 32-bit unsigned limit for SNMP OID arcs

    for b in raw_oid:
        if shift_count > 4:
            # Exceeds max 5 octets for 32-bit base-128 VLQ
            return None
        curr_subid = (curr_subid << 7) | (b & 0x7F)
        shift_count += 1
        if curr_subid > MAX_SUBID:
            return None

        if b & 0x80:
            in_multibyte = True
        else:
            in_multibyte = False
            parsed_values.append(curr_subid)
            curr_subid = 0
            shift_count = 0

    if in_multibyte or not parsed_values:
        return None

    # First combined value decomposes into two arcs (ITU-T X.690 Section 8.19.4):
    # - combined < 40: arc 0, arc (combined)
    # - 40 <= combined < 80: arc 1, arc (combined - 40)
    # - combined >= 80: arc 2, arc (combined - 80)
    first_val = parsed_values[0]
    if first_val < 40:
        subids = ["0", str(first_val)]
    elif first_val < 80:
        subids = ["1", str(first_val - 40)]
    else:
        subids = ["2", str(first_val - 80)]

    for val in parsed_values[1:]:
        subids.append(str(val))

    return raw_oid, ".".join(subids), next_off


def build_snmp_get_request(
    community: str = SNMP_DEFAULT_COMMUNITY,
    req_id: int | None = None,
    oid: str = SNMP_SYSDESCR_OID,
) -> tuple[bytes, int]:
    """Construct an SNMPv1 GetRequest datagram for an OID (default sysDescr.0).

    Args:
        community: SNMP community string. Defaults to 'public'.
        req_id: Optional 32-bit positive request ID. Generated randomly if None.
        oid: Dotted string OID. Defaults to '1.3.6.1.2.1.1.1.0' (sysDescr.0).

    Returns:
        tuple[bytes, int]: (request_packet_bytes, request_id)

    Raises:
        ValueError: If community string is empty or req_id is out of bounds.
    """
    if req_id is None:
        req_id = secrets.randbelow(0x7FFFFFFF) + 1
    elif not isinstance(req_id, int) or req_id <= 0 or req_id > 0x7FFFFFFF:
        raise ValueError(f"Request ID must be an integer between 1 and 2147483647 (received {req_id}).")

    comm_clean = (community or "").strip()
    if not comm_clean:
        raise ValueError("Community string cannot be empty.")

    comm_bytes = comm_clean.encode("ascii", errors="strict")

    # Encode OID: for sysDescr.0 use pre-encoded raw octets, or parse dotted notation
    if oid == SNMP_SYSDESCR_OID:
        oid_content = SNMP_SYSDESCR_OID_RAW
    else:
        parts = [int(p) for p in oid.strip(".").split(".")]
        if len(parts) < 2 or parts[0] > 2 or parts[1] > 39:
            raise ValueError(f"Invalid OID '{oid}'.")
        first_b = 40 * parts[0] + parts[1]
        enc_subids = [bytes([first_b])]
        for subid in parts[2:]:
            if subid < 0:
                raise ValueError("Sub-identifier cannot be negative.")
            if subid == 0:
                enc_subids.append(b"\x00")
            else:
                chunks = []
                n = subid
                while n > 0:
                    chunks.append(n & 0x7F)
                    n >>= 7
                chunks.reverse()
                enc_bytes = bytes([c | 0x80 for c in chunks[:-1]] + [chunks[-1]])
                enc_subids.append(enc_bytes)
        oid_content = b"".join(enc_subids)

    # VarBind: SEQUENCE { name: OID, value: NULL }
    oid_tlv = b"\x06" + _encode_ber_length(len(oid_content)) + oid_content
    null_val = b"\x05\x00"
    varbind_content = oid_tlv + null_val
    varbind = b"\x30" + _encode_ber_length(len(varbind_content)) + varbind_content

    # VarBindList: SEQUENCE OF VarBind
    varbind_list = b"\x30" + _encode_ber_length(len(varbind)) + varbind

    # PDU: GetRequest-PDU (0xA0) { request-id, error-status=0, error-index=0, varbind_list }
    req_id_tlv = _encode_ber_integer(req_id)
    err_status_tlv = b"\x02\x01\x00"
    err_index_tlv = b"\x02\x01\x00"
    pdu_content = req_id_tlv + err_status_tlv + err_index_tlv + varbind_list
    pdu = bytes([SNMP_GET_REQUEST_PDU]) + _encode_ber_length(len(pdu_content)) + pdu_content

    # SNMP Message: SEQUENCE { version=0 (SNMPv1), community, pdu }
    version_tlv = b"\x02\x01\x00"  # version 0 = SNMPv1
    comm_tlv = b"\x04" + _encode_ber_length(len(comm_bytes)) + comm_bytes
    msg_content = version_tlv + comm_tlv + pdu
    message = b"\x30" + _encode_ber_length(len(msg_content)) + msg_content

    return message, req_id


def validate_snmp_response(
    response: bytes,
    expected_req_id: int,
    expected_community: str | bytes | None = None,
) -> tuple[bool, str, dict[str, Any]]:
    """Validate and parse a raw UDP datagram as an SNMPv1 response.

    Args:
        response: Raw bytes received from the UDP socket.
        expected_req_id: The request ID from the query used for response correlation.
        expected_community: Optional expected community string to verify echo.

    Returns:
        tuple[bool, str, dict[str, Any]]:
            - verified: True if response is a valid SNMP response from an agent.
            - details: Diagnostic summary string.
            - metadata: Extracted SNMP attributes (safe, without community string).
    """
    if len(response) < 16:
        return False, f"SNMP response too short ({len(response)} bytes)", {}

    # 1. Outer SEQUENCE
    outer_tlv = _read_ber_tlv(response, 0)
    if outer_tlv is None:
        return False, "Malformed outer BER TLV in SNMP response", {}
    tag, c_off, c_len, next_off = outer_tlv
    if tag != 0x30:
        return False, f"Invalid outer tag 0x{tag:02X} (expected SEQUENCE 0x30)", {}
    if next_off != len(response):
        return False, f"Trailing garbage bytes after outer SNMP sequence ({len(response) - next_off} bytes)", {}

    curr = c_off
    outer_end = next_off

    # 2. Version (INTEGER)
    ver_res = _read_ber_integer(response, curr)
    if ver_res is None:
        return False, "Malformed SNMP version field", {}
    version_val, curr = ver_res

    metadata: dict[str, Any] = {
        "version": "v1" if version_val == 0 else f"v{version_val + 1}",
    }

    if version_val != 0:
        return False, f"Unsupported SNMP version {version_val} (expected 0 for SNMPv1)", metadata

    # 3. Community (OCTET STRING) - structure verified, echo verified, content never exposed
    comm_res = _read_ber_octet_string(response, curr)
    if comm_res is None:
        return False, "Malformed SNMP community field", metadata
    comm_bytes, curr = comm_res

    if expected_community is not None:
        if isinstance(expected_community, str):
            exp_bytes = expected_community.encode("ascii", errors="replace")
        else:
            exp_bytes = bytes(expected_community)
        if comm_bytes != exp_bytes:
            return False, "SNMP community string mismatch", metadata

    # 4. PDU TLV
    pdu_tlv = _read_ber_tlv(response, curr)
    if pdu_tlv is None:
        return False, "Malformed SNMP PDU TLV", metadata
    pdu_tag, pdu_c_off, pdu_c_len, pdu_next = pdu_tlv
    if pdu_next != outer_end:
        return False, "Inconsistent PDU boundary within SNMP message", metadata

    metadata["pdu_type"] = "GetResponse" if pdu_tag == SNMP_GET_RESPONSE_PDU else f"0x{pdu_tag:02X}"

    if pdu_tag != SNMP_GET_RESPONSE_PDU:
        if pdu_tag == SNMP_GET_REQUEST_PDU:
            return False, "Received SNMP GetRequest PDU (0xA0) instead of GetResponse", metadata
        elif pdu_tag == 0xA1:
            return False, "Received SNMP GetNextRequest PDU (0xA1) instead of GetResponse", metadata
        elif pdu_tag == 0xA3:
            return False, "Received SNMP SetRequest PDU (0xA3) instead of GetResponse", metadata
        else:
            return False, f"Invalid SNMP PDU tag 0x{pdu_tag:02X} (expected GetResponse 0xA2)", metadata

    p_curr = pdu_c_off
    p_end = pdu_next

    # 5. Request ID (INTEGER)
    req_res = _read_ber_integer(response, p_curr)
    if req_res is None:
        return False, "Malformed SNMP request ID field", metadata
    rx_req_id, p_curr = req_res
    metadata["request_id"] = rx_req_id

    if rx_req_id != expected_req_id:
        return (
            False,
            f"SNMP request ID mismatch (expected {expected_req_id}, got {rx_req_id})",
            metadata,
        )

    # 6. Error status (INTEGER)
    err_res = _read_ber_integer(response, p_curr)
    if err_res is None:
        return False, "Malformed SNMP error status field", metadata
    error_status, p_curr = err_res
    if error_status < 0:
        return False, f"Invalid negative SNMP error status ({error_status})", metadata
    error_name = SNMP_ERROR_NAMES.get(error_status, f"error_{error_status}")
    metadata["error_status"] = error_status
    metadata["error_status_name"] = error_name

    # 7. Error index (INTEGER)
    idx_res = _read_ber_integer(response, p_curr)
    if idx_res is None:
        return False, "Malformed SNMP error index field", metadata
    error_index, p_curr = idx_res
    if error_index < 0:
        return False, f"Invalid negative SNMP error index ({error_index})", metadata
    metadata["error_index"] = error_index

    # 8. VarBindList (SEQUENCE)
    vb_list_tlv = _read_ber_tlv(response, p_curr)
    if vb_list_tlv is None:
        return False, "Malformed SNMP VarBindList TLV", metadata
    vb_list_tag, vb_list_c_off, vb_list_c_len, vb_list_next = vb_list_tlv
    if vb_list_tag != 0x30:
        return False, f"Invalid VarBindList tag 0x{vb_list_tag:02X} (expected SEQUENCE 0x30)", metadata
    if vb_list_next != p_end:
        return False, "Inconsistent VarBindList boundary within SNMP PDU", metadata

    # 9. Walk VarBinds
    vb_curr = vb_list_c_off
    vb_end = vb_list_next
    varbind_count = 0
    sys_descr_found = False
    sys_descr_text: str | None = None

    while vb_curr < vb_end:
        vb_tlv = _read_ber_tlv(response, vb_curr)
        if vb_tlv is None:
            return False, f"Malformed VarBind #{varbind_count + 1} TLV", metadata
        v_tag, v_c_off, v_c_len, vb_curr = vb_tlv
        if v_tag != 0x30:
            return False, f"Invalid VarBind #{varbind_count + 1} tag 0x{v_tag:02X} (expected SEQUENCE 0x30)", metadata

        varbind_count += 1
        entry_curr = v_c_off
        entry_end = v_c_off + v_c_len

        # OID
        oid_res = _read_ber_oid(response, entry_curr)
        if oid_res is None:
            return False, f"Malformed OID in VarBind #{varbind_count}", metadata
        _raw_oid, dotted_oid, entry_curr = oid_res

        # Value TLV
        val_tlv = _read_ber_tlv(response, entry_curr)
        if val_tlv is None:
            return False, f"Malformed value in VarBind #{varbind_count}", metadata
        val_tag, val_c_off, val_c_len, val_next = val_tlv
        if val_next != entry_end:
            return False, f"Trailing bytes inside VarBind #{varbind_count}", metadata

        if dotted_oid == SNMP_SYSDESCR_OID:
            sys_descr_found = True
            if val_tag == 0x04:  # OCTET STRING
                raw_bytes = response[val_c_off : val_c_off + val_c_len]
                try:
                    text = raw_bytes.decode("utf-8", errors="replace")
                except Exception:
                    text = raw_bytes.decode("latin-1", errors="replace")
                clean = "".join(c if c.isprintable() or c in " \t\r\n" else "?" for c in text).strip()
                MAX_LEN = 120
                if len(clean) > MAX_LEN:
                    clean = clean[:MAX_LEN] + "..."
                sys_descr_text = clean

    metadata["varbind_count"] = varbind_count
    metadata["sys_descr_oid"] = sys_descr_found
    metadata["sys_descr"] = sys_descr_text

    if error_status == 0:
        if sys_descr_text:
            details = f"SNMPv1 response (noError, sysDescr: '{sys_descr_text}')"
        else:
            details = f"SNMPv1 response (noError, varbinds: {varbind_count})"
    else:
        details = f"SNMPv1 error response ({error_name}, status={error_status}, index={error_index})"

    return True, details, metadata
