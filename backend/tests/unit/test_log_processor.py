"""Unit tests for E1 Log Processor Module."""

from datetime import datetime
import pytest

from src.engines.e1_log_processing.log_parser import ParsedPacket
from src.engines.e1_log_processing.log_processor import (
    LogProcessor,
    ProcessedRecord,
    ProcessingErrorRecord,
)


def test_process_packet_normalization() -> None:
    """Tests normalisation of timestamp, MAC format, and Traffic_Log fields."""
    processor = LogProcessor(batch_id="test-batch-001")

    parsed = ParsedPacket(
        packet_index=1,
        timestamp=1700000000.5,
        packet_length=74,
        captured_length=74,
        link_layer_type="Ethernet",
        protocol="TCP",
        source_address="192.168.1.50",
        destination_address="10.0.0.1",
        source_mac="00-11-22-33-44-55",  # Dashed MAC input
        destination_mac="66:77:88:99:AA:BB",  # Uppercase MAC input
        source_port=8080,
        destination_port=443,
        tcp_flags={"SYN": True, "ACK": False},
    )

    rec, err = processor.process_packet(parsed)

    assert err is None
    assert isinstance(rec, ProcessedRecord)
    assert rec.batch_id == "test-batch-001"
    assert rec.log_id is not None
    # Verify ISO timestamp
    assert rec.timestamp.startswith("2023-11-14T")
    # Verify MAC normalization to lowercase colon-separated
    assert rec.source_mac == "00:11:22:33:44:55"
    assert rec.destination_mac == "66:77:88:99:aa:bb"
    assert rec.protocol == "TCP"

    # Verify Traffic_Log dictionary schema compliance
    log_dict = rec.to_dict()
    required_keys = {
        "log_id",
        "batch_id",
        "timestamp",
        "source_address",
        "destination_address",
        "source_mac",
        "destination_mac",
        "protocol",
        "log_details",
    }
    assert set(log_dict.keys()) == required_keys

    # Check rich attributes inside log_details
    details = log_dict["log_details"]
    assert details["source_port"] == 8080
    assert details["destination_port"] == 443
    assert details["tcp_flags"]["SYN"] is True


def test_process_missing_fields_null_handling() -> None:
    """Tests that missing protocol layers and addresses are preserved as None."""
    processor = LogProcessor(batch_id="test-batch-002")

    # Packet with only wireless MAC, no IP or transport layer
    parsed = ParsedPacket(
        packet_index=2,
        timestamp=1700000001.0,
        packet_length=42,
        captured_length=42,
        link_layer_type="IEEE 802.11",
        protocol="802.11_MGMT",
        source_address=None,
        destination_address=None,
        source_mac="11:22:33:44:55:66",
        destination_mac="ff:ff:ff:ff:ff:ff",
        source_port=None,
        destination_port=None,
    )

    rec, err = processor.process_packet(parsed)

    assert err is None
    assert rec is not None
    assert rec.source_address is None
    assert rec.destination_address is None
    assert rec.log_details["source_port"] is None
    assert rec.log_details["destination_port"] is None


def test_process_corrupt_packet_generates_error() -> None:
    """Tests that corrupt packet records generate ProcessingErrorRecord and increment failure counter."""
    processor = LogProcessor(batch_id="test-batch-003")

    corrupt_pkt = ParsedPacket(
        packet_index=3,
        timestamp=0.0,
        packet_length=0,
        captured_length=0,
        is_corrupt=True,
        parsing_error="Truncated frame payload exception",
    )

    rec, err = processor.process_packet(corrupt_pkt)

    assert rec is None
    assert isinstance(err, ProcessingErrorRecord)
    assert err.error_type == "PacketParsingCorruption"
    assert "Truncated" in err.error_message
    assert processor.counters.failed_packets == 1
    assert processor.counters.total_packets == 1
    assert processor.counters.processed_packets == 0

