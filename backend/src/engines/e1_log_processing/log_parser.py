"""E1: PCAP Parsing Module.

Dissects PCAP and PCAPNG packets using Scapy streaming readers, extracting
General, Network, Transport, and Wireless (802.11) attributes without fabricating values.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Generator, Optional, Union

from scapy.layers.dot11 import Dot11, Dot11Elt, RadioTap
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet
from scapy.utils import PcapNgReader, PcapReader

from ...common.constants import (
    DOT11_CTRL_SUBTYPES,
    DOT11_DATA_SUBTYPES,
    DOT11_MGMT_SUBTYPES,
    DOT11_TYPE_NAMES,
    ProtocolType,
)
from ...common.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ParsedPacket:
    """Standardized representation of a single parsed network packet."""

    packet_index: int
    timestamp: float
    packet_length: int
    captured_length: int
    link_layer_type: Optional[str] = None
    protocol: str = ProtocolType.UNKNOWN.value

    # Network Layer
    source_address: Optional[str] = None
    destination_address: Optional[str] = None
    network_protocol: Optional[str] = None
    ip_version: Optional[int] = None
    ip_ttl: Optional[int] = None

    # Transport Layer
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    transport_protocol: Optional[str] = None
    tcp_flags: Optional[Dict[str, bool]] = None

    # Wireless / MAC Layer
    source_mac: Optional[str] = None
    destination_mac: Optional[str] = None
    bssid: Optional[str] = None
    ssid: Optional[str] = None
    frame_type: Optional[str] = None
    frame_subtype: Optional[str] = None
    channel: Optional[int] = None
    signal_strength: Optional[int] = None

    # Diagnostic & Raw Context
    payload_size: int = 0
    raw_details: Dict[str, Any] = field(default_factory=dict)
    is_corrupt: bool = False
    parsing_error: Optional[str] = None


class PcapParser:
    """Streams and parses packets from PCAP/PCAPNG files."""

    def __init__(self, capture_payload_summary: bool = True) -> None:
        """Initializes the parser.

        Args:
            capture_payload_summary: Whether to retain structured payload size and metadata.
        """
        self.capture_payload_summary = capture_payload_summary

    def parse_file(
        self, file_path: Union[str, Path], max_packets: Optional[int] = None
    ) -> Generator[ParsedPacket, None, None]:
        """Streams parsed packets from a capture file.

        Args:
            file_path: Path to the .pcap or .pcapng file.
            max_packets: Optional upper bound on packets to parse.

        Yields:
            ParsedPacket objects sequentially.
        """
        path_str = str(Path(file_path).resolve())
        is_pcapng = path_str.lower().endswith(".pcapng")

        reader_cls = PcapNgReader if is_pcapng else PcapReader
        packet_idx = 0

        try:
            with reader_cls(path_str) as reader:
                for pkt in reader:
                    packet_idx += 1
                    try:
                        parsed = self.parse_packet(pkt, packet_idx)
                        yield parsed
                    except Exception as exc:
                        logger.warning(
                            "Packet #%d in '%s' parsing failed: %s",
                            packet_idx,
                            Path(file_path).name,
                            exc,
                        )
                        yield ParsedPacket(
                            packet_index=packet_idx,
                            timestamp=float(getattr(pkt, "time", 0.0)),
                            packet_length=len(pkt) if hasattr(pkt, "__len__") else 0,
                            captured_length=len(pkt) if hasattr(pkt, "__len__") else 0,
                            is_corrupt=True,
                            parsing_error=str(exc),
                        )

                    if max_packets and packet_idx >= max_packets:
                        break

        except Exception as exc:
            logger.error("Fatal reader failure on '%s': %s", path_str, exc)
            raise

    def parse_packet(self, pkt: Packet, packet_idx: int) -> ParsedPacket:
        """Dissects an individual Scapy packet and populates all available layer attributes.

        Args:
            pkt: Scapy Packet object.
            packet_idx: 1-based sequential index.

        Returns:
            ParsedPacket dataclass.
        """
        timestamp = float(getattr(pkt, "time", 0.0))
        pkt_len = len(pkt)
        cap_len = getattr(pkt, "wirelen", pkt_len) or pkt_len

        parsed = ParsedPacket(
            packet_index=packet_idx,
            timestamp=timestamp,
            packet_length=pkt_len,
            captured_length=cap_len,
        )

        details: Dict[str, Any] = {}

        # 1. Inspect Link Layer (Ethernet or RadioTap / Dot11)
        if pkt.haslayer(RadioTap):
            parsed.link_layer_type = "IEEE 802.11 RadioTap"
            rt = pkt[RadioTap]
            # Safely extract channel frequency
            chan_val = (
                rt.fields.get("ChannelFrequency")
                or rt.fields.get("Channel")
                or getattr(rt, "ChannelFrequency", None)
                or getattr(rt, "Channel", None)
            )
            if chan_val is not None:
                try:
                    parsed.channel = int(chan_val)
                except (ValueError, TypeError):
                    pass

            # Safely extract signal strength in dBm
            sig_val = (
                rt.fields.get("dBm_AntSignal")
                or rt.fields.get("dB_AntSignal")
                or getattr(rt, "dBm_AntSignal", None)
                or getattr(rt, "dB_AntSignal", None)
            )
            if sig_val is not None:
                try:
                    parsed.signal_strength = int(sig_val)
                except (ValueError, TypeError):
                    pass

        elif pkt.haslayer(Ether):
            parsed.link_layer_type = "Ethernet"
            eth = pkt[Ether]
            parsed.source_mac = eth.src.lower() if eth.src else None
            parsed.destination_mac = eth.dst.lower() if eth.dst else None

        # 2. Inspect 802.11 Wireless Frames
        if pkt.haslayer(Dot11):
            d11 = pkt[Dot11]
            f_type = getattr(d11, "type", None)
            f_subtype = getattr(d11, "subtype", None)

            if f_type is not None:
                parsed.frame_type = DOT11_TYPE_NAMES.get(f_type, f"Type_{f_type}")
                if f_type == 0:
                    parsed.frame_subtype = DOT11_MGMT_SUBTYPES.get(f_subtype, f"Subtype_{f_subtype}")
                    parsed.protocol = ProtocolType.DOT11_MGMT.value
                elif f_type == 1:
                    parsed.frame_subtype = DOT11_CTRL_SUBTYPES.get(f_subtype, f"Subtype_{f_subtype}")
                    parsed.protocol = ProtocolType.DOT11_CTRL.value
                elif f_type == 2:
                    parsed.frame_subtype = DOT11_DATA_SUBTYPES.get(f_subtype, f"Subtype_{f_subtype}")
                    parsed.protocol = ProtocolType.DOT11_DATA.value
                else:
                    parsed.protocol = ProtocolType.DOT11.value

            # Extract 802.11 addresses
            # addr1: Receiver / Destination; addr2: Transmitter / Source; addr3: BSSID
            if getattr(d11, "addr1", None):
                parsed.destination_mac = d11.addr1.lower()
            if getattr(d11, "addr2", None):
                parsed.source_mac = d11.addr2.lower()
            elif not parsed.source_mac and getattr(d11, "addr1", None):
                parsed.source_mac = d11.addr1.lower()

            if getattr(d11, "addr3", None):
                parsed.bssid = d11.addr3.lower()

            # Extract SSID from Information Elements if present (Management frames)
            if pkt.haslayer(Dot11Elt):
                elt = pkt.getlayer(Dot11Elt)
                while elt:
                    if getattr(elt, "ID", None) == 0 and elt.info:
                        try:
                            parsed.ssid = elt.info.decode("utf-8", errors="replace")
                        except Exception:
                            parsed.ssid = str(elt.info)
                        break
                    elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt.payload, "getlayer") else None

        # 3. Inspect Network Layer (IPv4, IPv6, ARP)
        if pkt.haslayer(IP):
            ip = pkt[IP]
            parsed.source_address = str(ip.src)
            parsed.destination_address = str(ip.dst)
            parsed.network_protocol = ProtocolType.IPV4.value
            parsed.ip_version = 4
            parsed.ip_ttl = int(ip.ttl)
            if parsed.protocol == ProtocolType.UNKNOWN.value:
                parsed.protocol = ProtocolType.IPV4.value
            details["ip_id"] = getattr(ip, "id", None)
            details["ip_flags"] = str(ip.flags) if hasattr(ip, "flags") else None

        elif pkt.haslayer(IPv6):
            ip6 = pkt[IPv6]
            parsed.source_address = str(ip6.src)
            parsed.destination_address = str(ip6.dst)
            parsed.network_protocol = ProtocolType.IPV6.value
            parsed.ip_version = 6
            parsed.ip_ttl = int(ip6.hlim)
            if parsed.protocol == ProtocolType.UNKNOWN.value:
                parsed.protocol = ProtocolType.IPV6.value

        elif pkt.haslayer(ARP):
            arp = pkt[ARP]
            parsed.network_protocol = ProtocolType.ARP.value
            parsed.source_address = str(arp.psrc) if arp.psrc else None
            parsed.destination_address = str(arp.pdst) if arp.pdst else None
            if arp.hwsrc:
                parsed.source_mac = arp.hwsrc.lower()
            if arp.hwdst:
                parsed.destination_mac = arp.hwdst.lower()
            parsed.protocol = ProtocolType.ARP.value
            details["arp_op"] = int(arp.op) if hasattr(arp, "op") else None

        # 4. Inspect Transport Layer (TCP, UDP, ICMP)
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            parsed.transport_protocol = ProtocolType.TCP.value
            parsed.source_port = int(tcp.sport)
            parsed.destination_port = int(tcp.dport)
            flags_val = int(tcp.flags)
            parsed.tcp_flags = {
                "SYN": bool(flags_val & 0x02),
                "ACK": bool(flags_val & 0x10),
                "FIN": bool(flags_val & 0x01),
                "RST": bool(flags_val & 0x04),
                "PSH": bool(flags_val & 0x08),
                "URG": bool(flags_val & 0x20),
            }
            parsed.protocol = ProtocolType.TCP.value
            details["tcp_seq"] = getattr(tcp, "seq", None)
            details["tcp_ack"] = getattr(tcp, "ack", None)
            details["tcp_window"] = getattr(tcp, "window", None)

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            parsed.transport_protocol = ProtocolType.UDP.value
            parsed.source_port = int(udp.sport)
            parsed.destination_port = int(udp.dport)
            parsed.protocol = ProtocolType.UDP.value
            details["udp_len"] = getattr(udp, "len", None)

        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            parsed.transport_protocol = ProtocolType.ICMP.value
            parsed.protocol = ProtocolType.ICMP.value
            details["icmp_type"] = getattr(icmp, "type", None)
            details["icmp_code"] = getattr(icmp, "code", None)

        # 5. Extract Payload Size
        if hasattr(pkt, "payload") and pkt.payload:
            payload_data = bytes(pkt.payload)
            parsed.payload_size = len(payload_data)

        # If protocol is still UNKNOWN but link_layer_type is known
        if parsed.protocol == ProtocolType.UNKNOWN.value and parsed.link_layer_type:
            parsed.protocol = parsed.link_layer_type

        parsed.raw_details = details
        return parsed
