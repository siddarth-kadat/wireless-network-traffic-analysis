"""Pytest test fixtures and synthetic PCAP generation utilities for E1 testing.

Note: All PCAPs generated here are synthetic test artifacts for unit and integration testing.
They do not represent the final project dataset.
"""

import os
import struct
import tempfile
from pathlib import Path
from typing import Generator

import pytest
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Provides an isolated temporary directory for test file generation."""
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp)


@pytest.fixture
def valid_ethernet_pcap(temp_dir: Path) -> Path:
    """Creates a valid PCAP file with Ethernet, IPv4, TCP, UDP, ARP, and ICMP packets."""
    pcap_path = temp_dir / "valid_ethernet.pcap"

    p1 = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(
        src="192.168.1.100", dst="192.168.1.1"
    ) / TCP(sport=54321, dport=80, flags="S")

    p2 = Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55") / IP(
        src="192.168.1.1", dst="192.168.1.100"
    ) / TCP(sport=80, dport=54321, flags="SA")

    p3 = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / IP(
        src="192.168.1.100", dst="192.168.1.255"
    ) / UDP(sport=5353, dport=5353)

    p4 = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, psrc="192.168.1.100", pdst="192.168.1.1", hwsrc="00:11:22:33:44:55"
    )

    p5 = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(
        src="192.168.1.100", dst="8.8.8.8"
    ) / ICMP(type=8, code=0)

    wrpcap(str(pcap_path), [p1, p2, p3, p4, p5])
    return pcap_path


@pytest.fixture
def valid_ipv6_pcap(temp_dir: Path) -> Path:
    """Creates a valid PCAP file with IPv6 traffic."""
    pcap_path = temp_dir / "valid_ipv6.pcap"
    p1 = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IPv6(
        src="fe80::1", dst="fe80::2"
    ) / UDP(sport=1234, dport=5678)
    wrpcap(str(pcap_path), [p1])
    return pcap_path


@pytest.fixture
def valid_wireless_pcap(temp_dir: Path) -> Path:
    """Creates a synthetic PCAP with IEEE 802.11 Wireless Beacon management frames."""
    pcap_path = temp_dir / "valid_wireless.pcap"

    # RadioTap with enabled Channel + dBm_AntSignal flags
    rt = RadioTap(
        present="Channel+dBm_AntSignal",
        ChannelFrequency=2412,
        dBm_AntSignal=-65,
    )
    d11 = Dot11(
        type=0,  # Management
        subtype=8,  # Beacon
        addr1="ff:ff:ff:ff:ff:ff",
        addr2="00:14:22:01:23:45",
        addr3="00:14:22:01:23:45",
    )
    beacon = Dot11Beacon(cap="ESS")
    ssid_elt = Dot11Elt(ID=0, info=b"SecureLabWiFi")

    pkt = rt / d11 / beacon / ssid_elt
    wrpcap(str(pcap_path), [pkt])
    return pcap_path


@pytest.fixture
def empty_file(temp_dir: Path) -> Path:
    """Creates an empty 0-byte file."""
    empty_path = temp_dir / "empty.pcap"
    empty_path.touch()
    return empty_path


@pytest.fixture
def corrupted_header_pcap(temp_dir: Path) -> Path:
    """Creates a file with corrupted magic header bytes."""
    corrupt_path = temp_dir / "corrupted_magic.pcap"
    with open(corrupt_path, "wb") as f:
        f.write(b"NOT_A_VALID_PCAP_MAGIC_DATA_1234567890")
    return corrupt_path


@pytest.fixture
def truncated_pcap(temp_dir: Path, valid_ethernet_pcap: Path) -> Path:
    """Creates a truncated PCAP file by slicing off trailing bytes mid-packet."""
    truncated_path = temp_dir / "truncated.pcap"
    content = valid_ethernet_pcap.read_bytes()
    # Write global header (24 bytes) + first packet + half of second packet
    truncated_path.write_bytes(content[: len(content) - 40])
    return truncated_path
