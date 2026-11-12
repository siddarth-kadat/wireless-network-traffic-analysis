"""System-wide constants, protocol types, and configuration defaults."""

from enum import Enum
from typing import Final

# Supported File Formats and Magic Numbers
SUPPORTED_EXTENSIONS: Final[tuple[str, ...]] = (".pcap", ".pcapng")

# PCAP 32-bit Magic Numbers
PCAP_MAGIC_MICROSECONDS: Final[bytes] = b"\xa1\xb2\xc3\xd4"
PCAP_MAGIC_MICROSECONDS_SWAPPED: Final[bytes] = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_NANOSECONDS: Final[bytes] = b"\xa1\xb2\x3c\x4d"
PCAP_MAGIC_NANOSECONDS_SWAPPED: Final[bytes] = b"\x4d\x3c\xb2\xa1"
PCAPNG_MAGIC_SECTION_HEADER: Final[bytes] = b"\x0a\x0d\x0d\x0a"

VALID_PCAP_MAGICS: Final[tuple[bytes, ...]] = (
    PCAP_MAGIC_MICROSECONDS,
    PCAP_MAGIC_MICROSECONDS_SWAPPED,
    PCAP_MAGIC_NANOSECONDS,
    PCAP_MAGIC_NANOSECONDS_SWAPPED,
)

# Standard PCAP Global and Packet Header Sizes
PCAP_GLOBAL_HEADER_LENGTH: Final[int] = 24
PCAP_PACKET_HEADER_LENGTH: Final[int] = 16


class ValidationStatus(str, Enum):
    """File validation status enumeration."""
    VALID = "VALID"
    INVALID = "INVALID"
    PARTIALLY_READABLE = "PARTIALLY_READABLE"
    UNSUPPORTED_FORMAT = "UNSUPPORTED_FORMAT"


class ProcessingStatus(str, Enum):
    """Batch processing status enumeration."""
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    SUCCESS = "SUCCESS"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    FAILED = "FAILED"


class ProtocolType(str, Enum):
    """Normalized network protocol identifiers."""
    ETHERNET = "ETHERNET"
    IPV4 = "IPv4"
    IPV6 = "IPv6"
    ARP = "ARP"
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ICMPV6 = "ICMPv6"
    DOT11 = "802.11"
    DOT11_MGMT = "802.11_MGMT"
    DOT11_CTRL = "802.11_CTRL"
    DOT11_DATA = "802.11_DATA"
    DNS = "DNS"
    DHCP = "DHCP"
    RADIOTAP = "RADIOTAP"
    UNKNOWN = "UNKNOWN"


# IEEE 802.11 Frame Type and Subtype mappings
DOT11_TYPE_NAMES: Final[dict[int, str]] = {
    0: "Management",
    1: "Control",
    2: "Data",
    3: "Extension",
}

DOT11_MGMT_SUBTYPES: Final[dict[int, str]] = {
    0: "Association Request",
    1: "Association Response",
    2: "Reassociation Request",
    3: "Reassociation Response",
    4: "Probe Request",
    5: "Probe Response",
    8: "Beacon",
    9: "ATIM",
    10: "Disassociation",
    11: "Authentication",
    12: "Deauthentication",
    13: "Action",
}

DOT11_CTRL_SUBTYPES: Final[dict[int, str]] = {
    7: "Control Wrapper",
    8: "Block Ack Request",
    9: "Block Ack",
    10: "PS-Poll",
    11: "RTS",
    12: "CTS",
    13: "ACK",
    14: "CF-End",
    15: "CF-End + CF-Ack",
}

DOT11_DATA_SUBTYPES: Final[dict[int, str]] = {
    0: "Data",
    1: "Data + CF-Ack",
    2: "Data + CF-Poll",
    3: "Data + CF-Ack + CF-Poll",
    4: "Null (no data)",
    5: "CF-Ack (no data)",
    6: "CF-Poll (no data)",
    7: "CF-Ack + CF-Poll (no data)",
    8: "QoS Data",
    9: "QoS Data + CF-Ack",
    10: "QoS Data + CF-Poll",
    11: "QoS Data + CF-Ack + CF-Poll",
    12: "QoS Null (no data)",
}

# Standard Link-Layer Type Values (DLT values)
LINKTYPE_NULL: Final[int] = 0
LINKTYPE_ETHERNET: Final[int] = 1
LINKTYPE_RAW: Final[int] = 12
LINKTYPE_IEEE802_11: Final[int] = 105
LINKTYPE_LINUX_SLL: Final[int] = 113
LINKTYPE_IEEE802_11_RADIOTAP: Final[int] = 127
LINKTYPE_IPV4: Final[int] = 228
LINKTYPE_IPV6: Final[int] = 229

SUPPORTED_LINK_TYPES: Final[dict[int, str]] = {
    LINKTYPE_NULL: "BSD Loopback",
    LINKTYPE_ETHERNET: "Ethernet",
    LINKTYPE_RAW: "Raw IP",
    LINKTYPE_IEEE802_11: "IEEE 802.11 Wireless",
    LINKTYPE_LINUX_SLL: "Linux Cooked (SLL)",
    LINKTYPE_IEEE802_11_RADIOTAP: "IEEE 802.11 with RadioTap",
    LINKTYPE_IPV4: "Raw IPv4",
    LINKTYPE_IPV6: "Raw IPv6",
}
