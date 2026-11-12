"""Integration tests for the complete E1 Processing Pipeline."""

from pathlib import Path
import pytest

from src.common.constants import ProcessingStatus, ValidationStatus
from src.engines.e1_log_processing.processing_pipeline import (
    E1DetectionOutput,
    E1ProcessingPipeline,
    E1StorageOutput,
)


def test_pipeline_single_valid_file(valid_ethernet_pcap: Path) -> None:
    """Tests complete end-to-end execution on a valid Ethernet capture."""
    pipeline = E1ProcessingPipeline()
    detection_out, storage_out = pipeline.process_file(
        valid_ethernet_pcap, user_id="admin-01"
    )

    # 1. Verify E1DetectionOutput for E2
    assert isinstance(detection_out, E1DetectionOutput)
    assert len(detection_out.records) == 5
    assert detection_out.summary.processing_status == ProcessingStatus.SUCCESS
    assert detection_out.summary.successfully_processed_packets == 5
    assert detection_out.summary.failed_packets == 0
    assert detection_out.summary.duration_seconds > 0
    assert detection_out.summary.packets_per_second > 0

    # 2. Verify E1StorageOutput for E3
    assert isinstance(storage_out, E1StorageOutput)
    assert storage_out.batch_metadata["file_name"] == "valid_ethernet.pcap"
    assert storage_out.batch_metadata["user_id"] == "admin-01"
    assert storage_out.batch_metadata["total_records"] == 5
    assert storage_out.batch_metadata["processed_records"] == 5
    assert storage_out.batch_metadata["processing_status"] == ProcessingStatus.SUCCESS.value

    # Verify Traffic_Log records structure
    assert len(storage_out.traffic_logs) == 5
    first_log = storage_out.traffic_logs[0]
    assert first_log["protocol"] == "TCP"
    assert first_log["source_address"] == "192.168.1.100"
    assert first_log["destination_address"] == "192.168.1.1"
    assert "packet_length" in first_log["log_details"]


def test_pipeline_wireless_file(valid_wireless_pcap: Path) -> None:
    """Tests end-to-end processing of wireless 802.11 management frames."""
    pipeline = E1ProcessingPipeline()
    detection_out, storage_out = pipeline.process_file(valid_wireless_pcap)

    assert detection_out.summary.processing_status == ProcessingStatus.SUCCESS
    assert len(detection_out.records) == 1

    rec = detection_out.records[0]
    assert rec.protocol == "802.11_MGMT"
    assert rec.log_details["wireless"]["ssid"] == "SecureLabWiFi"
    assert rec.log_details["wireless"]["bssid"] == "00:14:22:01:23:45"
    assert rec.log_details["wireless"]["signal_strength"] == -65


def test_pipeline_truncated_file(truncated_pcap: Path) -> None:
    """Tests pipeline handling of partially readable truncated PCAP files."""
    pipeline = E1ProcessingPipeline()
    detection_out, storage_out = pipeline.process_file(truncated_pcap)

    # Partial success status expected because capture was cut off mid-packet
    assert detection_out.summary.validation_status == ValidationStatus.PARTIALLY_READABLE
    assert detection_out.summary.successfully_processed_packets > 0


def test_pipeline_empty_file(empty_file: Path) -> None:
    """Tests that an empty file produces a controlled failure output without crashing."""
    pipeline = E1ProcessingPipeline()
    detection_out, storage_out = pipeline.process_file(empty_file)

    assert detection_out.summary.processing_status == ProcessingStatus.FAILED
    assert detection_out.summary.validation_status == ValidationStatus.INVALID
    assert len(detection_out.records) == 0
    assert len(storage_out.traffic_logs) == 0
    assert len(storage_out.errors) > 0


def test_pipeline_multiple_files_with_fault_tolerance(
    valid_ethernet_pcap: Path,
    valid_wireless_pcap: Path,
    corrupted_header_pcap: Path,
) -> None:
    """Tests concurrent multi-file batch execution with error isolation."""
    pipeline = E1ProcessingPipeline(max_workers=3)

    files = [valid_ethernet_pcap, corrupted_header_pcap, valid_wireless_pcap]
    results = pipeline.process_multiple_files(files)

    assert len(results) == 3

    # Check results by file name
    res_map = {res[0].summary.file_name: res for res in results}

    # Valid files must succeed
    assert res_map["valid_ethernet.pcap"][0].summary.processing_status == ProcessingStatus.SUCCESS
    assert res_map["valid_ethernet.pcap"][0].summary.successfully_processed_packets == 5

    assert res_map["valid_wireless.pcap"][0].summary.processing_status == ProcessingStatus.SUCCESS
    assert res_map["valid_wireless.pcap"][0].summary.successfully_processed_packets == 1

    # Corrupted file must fail without terminating other files
    assert res_map["corrupted_magic.pcap"][0].summary.processing_status == ProcessingStatus.FAILED
    assert res_map["corrupted_magic.pcap"][0].summary.successfully_processed_packets == 0

