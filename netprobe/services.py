"""Common TCP port-to-service name mappings for NetProbe.

DISCLAIMER:
Port numbers indicate standard or commonly assigned services according to IANA
and widespread industry convention. A responsive port does NOT prove that the
stated service is actually running; verification requires protocol-specific
fingerprinting (planned for later phases).
"""

from typing import Final

# Curated list of well-known and commonly targeted TCP services
COMMON_SERVICES: Final[dict[int, str]] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp-server",
    68: "dhcp-client",
    69: "tftp",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    179: "bgp",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    514: "syslog",
    587: "submission",
    636: "ldaps",
    873: "rsync",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1433: "ms-sql-s",
    1521: "oracle",
    2049: "nfs",
    2181: "zookeeper",
    2375: "docker-plain",
    2376: "docker-tls",
    3306: "mysql",
    3389: "ms-wbt-server",  # RDP
    5000: "upnp/flask",
    5432: "postgresql",
    5672: "amqp",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
    9000: "sonar/http-alt",
    9092: "kafka",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}


def get_service_name(port: int, default: str = "unknown") -> str:
    """Return the conventional service name for a given TCP port.

    Args:
        port: The TCP port number (1-65535).
        default: Fallback string if no known mapping exists.

    Returns:
        The canonical service name string or the default value.
    """
    return COMMON_SERVICES.get(port, default)
