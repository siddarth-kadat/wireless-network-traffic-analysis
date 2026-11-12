"""Unit tests for E1 PCAP Parser Module."""

from pathlib import Path
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from src.common.constants import ProtocolType
from src.engines.e1_log_processing.log_parser import ParsedPacket, PcapParser


def test_parse_ethernet_tcp_packet(valid_ethernet_pcap: Path) -> None:
    """Tests dissection of Ethernet, IPv4, and TCP layers."""
    parser = PcapParser()
    packets = list(parser.parse_file(valid_ethernet_pcap))

    assert len(packets) == 5

    # First packet is TCP SYN
    p1 = packets[0]
    assert p1.packet_index == 1
    assert p1.link_layer_type == "Ethernet"
    assert p1.source_mac == "00:11:22:33:44:55"
    assert p1.destination_mac == "66:77:88:99:aa:bb"
    assert p1.source_address == "192.168.1.100"
    assert p1.destination_address == "192.168.1.1"
    assert p1.ip_version == 4
    assert p1.protocol == ProtocolType.TCP.value
    assert p1.source_port == 54321
    assert p1.destination_port == 80
    assert p1.tcp_flags is not None
    assert p1.tcp_flags["SYN"] is True
    assert p1.tcp_flags["ACK"] is False


def test_parse_udp_and_arp_packets(valid_ethernet_pcap: Path) -> None:
    """Tests dissection of UDP and ARP packets."""
    parser = PcapParser()
    packets = list(parser.parse_file(valid_ethernet_pcap))

    # Third packet is UDP
    p3 = packets[2]
    assert p3.protocol == ProtocolType.UDP.value
    assert p3.source_port == 5353
    assert p3.destination_port == 5353

    # Fourth packet is ARP
    p4 = packets[3]
    assert p4.protocol == ProtocolType.ARP.value
    assert p4.network_protocol == ProtocolType.ARP.value
    assert p4.source_address == "192.168.1.100"
    assert p4.destination_address == "192.168.1.1"
    assert p4.source_mac == "00:11:22:33:44:55"


def test_parse_ipv6_packet(valid_ipv6_pcap: Path) -> None:
    """Tests dissection of IPv6 protocol layers."""
    parser = PcapParser()
    packets = list(parser.parse_file(valid_ipv6_pcap))

    assert len(packets) == 1
    p = packets[0]
    assert p.ip_version == 6
    assert p.network_protocol == ProtocolType.IPV6.value
    assert p.source_address == "fe80::1"
    assert p.destination_address == "fe80::2"
    assert p.source_port == 1234
    assert p.destination_port == 5678


def test_parse_wireless_80211_frame(valid_wireless_pcap: Path) -> None:
    """Tests dissection of RadioTap and 802.11 Beacon frame attributes."""
    parser = PcapParser()
    packets = list(parser.parse_file(valid_wireless_pcap))

    assert len(packets) == 1
    p = packets[0]
    assert "802.11" in p.link_layer_type
    assert p.frame_type == "Management"
    assert p.frame_subtype == "Beacon"
    assert p.protocol == ProtocolType.DOT11_MGMT.value
    assert p.ssid == "SecureLabWiFi"
    assert p.bssid == "00:14:22:01:23:45"
    assert p.signal_strength == -65
    assert p.channel == 2412


def test_parse_packet_with_missing_layers(temp_dir: Path) -> None:
    """Tests that packets missing network/transport layers are parsed without crashing."""
    pcap_path = temp_dir / "raw_ether.pcap"
    # Pure Ethernet frame with arbitrary payload (no IP, no TCP/UDP)
    raw_pkt = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66") / b"arbitrary_payload"
    wrpcap(str(pcap_path), [raw_pkt])

    parser = PcapParser()
    packets = list(parser.parse_file(pcap_path))

    assert len(packets) == 1
    p = packets[0]
    assert p.link_layer_type == "Ethernet"
    assert p.source_mac == "aa:bb:cc:dd:ee:ff"
    assert p.destination_mac == "11:22:33:44:55:66"
    assert p.source_address is None
    assert p.destination_address is None
    assert p.source_port is None
    assert p.destination_port is None
    assert p.is_corrupt is False

