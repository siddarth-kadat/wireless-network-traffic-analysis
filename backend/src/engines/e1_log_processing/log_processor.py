"""E1: Log Processing Module.

Normalizes extracted packet records, enforces standardized address representations,
formats ISO 8601 timestamps, builds structured Traffic_Log records, and tracks processing counters.
"""

import ipaddress
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Generator, Iterable, List, Optional, Tuple

from ...common.constants import ProtocolType
from ...common.logger import get_logger
from .log_parser import ParsedPacket

logger = get_logger(__name__)

MAC_REGEX = re.compile(r"^([0-9a-f]{2}[:-]){5}([0-9a-f]{2})$", re.IGNORECASE)


@dataclass
class ProcessedRecord:
    """Normalized packet record matching the approved Traffic_Log database schema."""

    log_id: str
    batch_id: str
    timestamp: str  # ISO 8601 format: YYYY-MM-DDTHH:MM:SS.ffffffZ
    source_address: Optional[str]
    destination_address: Optional[str]
    source_mac: Optional[str]
    destination_mac: Optional[str]
    protocol: str
    log_details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Converts record to dictionary representation matching Traffic_Log entity."""
        return {
            "log_id": self.log_id,
            "batch_id": self.batch_id,
            "timestamp": self.timestamp,
            "source_address": self.source_address,
            "destination_address": self.destination_address,
            "source_mac": self.source_mac,
            "destination_mac": self.destination_mac,
            "protocol": self.protocol,
            "log_details": self.log_details,
        }


@dataclass
class ProcessingErrorRecord:
    """Record capturing an error encountered during packet ingestion, validation, or processing."""

    error_id: str
    batch_id: str
    log_id: Optional[str]
    error_type: str
    error_message: str
    error_timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        """Converts error to dictionary matching Processing_Error entity."""
        return asdict(self)


@dataclass
class ProcessingCounters:
    """Operational metrics tracked during packet processing."""

    total_packets: int = 0
    processed_packets: int = 0
    failed_packets: int = 0
    skipped_packets: int = 0


class LogProcessor:
    """Processes and normalizes raw parsed packet streams into standardized engine outputs."""

    def __init__(self, batch_id: str) -> None:
        """Initializes processor with a unique batch identifier.

        Args:
            batch_id: The batch ID to attach to all processed records.
        """
        self.batch_id = batch_id
        self.counters = ProcessingCounters()
        self.errors: List[ProcessingErrorRecord] = []

    def _normalize_timestamp(self, ts: float) -> str:
        """Converts float epoch seconds to standard ISO 8601 UTC string."""
        if ts <= 0:
            return datetime.now(timezone.utc).isoformat()
        try:
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            return dt.isoformat()
        except (ValueError, OverflowError, OSError):
            return datetime.now(timezone.utc).isoformat()

    def _normalize_ip(self, ip_str: Optional[str]) -> Optional[str]:
        """Validates and returns normalized IP address string."""
        if not ip_str:
            return None
        clean_ip = ip_str.strip()
        try:
            addr = ipaddress.ip_address(clean_ip)
            return str(addr)
        except ValueError:
            return clean_ip

    def _normalize_mac(self, mac_str: Optional[str]) -> Optional[str]:
        """Standardizes MAC address formatting to lowercase colon-separated hex."""
        if not mac_str:
            return None
        clean_mac = mac_str.strip().lower()
        clean_mac = clean_mac.replace("-", ":")
        if MAC_REGEX.match(clean_mac):
            return clean_mac
        return clean_mac

    def process_packet(
        self, parsed: ParsedPacket
    ) -> Tuple[Optional[ProcessedRecord], Optional[ProcessingErrorRecord]]:
        """Normalizes a single ParsedPacket into a ProcessedRecord.

        Args:
            parsed: Dissected packet from log_parser.

        Returns:
            Tuple of (ProcessedRecord or None, ProcessingErrorRecord or None).
        """
        self.counters.total_packets += 1

        # Check if parser flagged the packet as corrupted
        if parsed.is_corrupt:
            self.counters.failed_packets += 1
            error_rec = ProcessingErrorRecord(
                error_id=str(uuid.uuid4()),
                batch_id=self.batch_id,
                log_id=None,
                error_type="PacketParsingCorruption",
                error_message=parsed.parsing_error or "Unknown packet parsing failure",
                error_timestamp=datetime.now(timezone.utc).isoformat(),
            )
            self.errors.append(error_rec)
            return None, error_rec

        try:
            log_id = str(uuid.uuid4())
            iso_timestamp = self._normalize_timestamp(parsed.timestamp)
            src_addr = self._normalize_ip(parsed.source_address)
            dst_addr = self._normalize_ip(parsed.destination_address)
            src_mac = self._normalize_mac(parsed.source_mac)
            dst_mac = self._normalize_mac(parsed.destination_mac)

            # Build rich log_details dictionary without losing packet metadata
            log_details: Dict[str, Any] = {
                "packet_index": parsed.packet_index,
                "packet_length": parsed.packet_length,
                "captured_length": parsed.captured_length,
                "link_layer_type": parsed.link_layer_type,
                "network_protocol": parsed.network_protocol,
                "ip_version": parsed.ip_version,
                "ip_ttl": parsed.ip_ttl,
                "transport_protocol": parsed.transport_protocol,
                "source_port": parsed.source_port,
                "destination_port": parsed.destination_port,
                "tcp_flags": parsed.tcp_flags,
                "wireless": {
                    "bssid": parsed.bssid,
                    "ssid": parsed.ssid,
                    "frame_type": parsed.frame_type,
                    "frame_subtype": parsed.frame_subtype,
                    "channel": parsed.channel,
                    "signal_strength": parsed.signal_strength,
                },
                "payload_size": parsed.payload_size,
                "raw_details": parsed.raw_details,
            }

            processed = ProcessedRecord(
                log_id=log_id,
                batch_id=self.batch_id,
                timestamp=iso_timestamp,
                source_address=src_addr,
                destination_address=dst_addr,
                source_mac=src_mac,
                destination_mac=dst_mac,
                protocol=parsed.protocol,
                log_details=log_details,
            )

            self.counters.processed_packets += 1
            return processed, None

        except Exception as exc:
            self.counters.failed_packets += 1
            error_rec = ProcessingErrorRecord(
                error_id=str(uuid.uuid4()),
                batch_id=self.batch_id,
                log_id=None,
                error_type="PacketNormalizationError",
                error_message=f"Failed to normalize packet #{parsed.packet_index}: {str(exc)}",
                error_timestamp=datetime.now(timezone.utc).isoformat(),
            )
            self.errors.append(error_rec)
            logger.warning("Normalization error on packet #%d: %s", parsed.packet_index, exc)
            return None, error_rec

    def process_stream(
        self, packet_stream: Iterable[ParsedPacket]
    ) -> Generator[ProcessedRecord, None, None]:
        """Processes an iterable stream of ParsedPackets, yielding ProcessedRecords.

        Args:
            packet_stream: Iterable or Generator of ParsedPacket instances.

        Yields:
            Successfully normalized ProcessedRecord objects.
        """
        for pkt in packet_stream:
            record, _ = self.process_packet(pkt)
            if record is not None:
                yield record
