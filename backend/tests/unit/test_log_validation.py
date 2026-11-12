"""Unit tests for E1 Log Validation Module."""

from pathlib import Path
import pytest

from src.common.constants import ValidationStatus
from src.engines.e1_log_processing.log_validation import LogValidator


def test_validate_valid_pcap(valid_ethernet_pcap: Path) -> None:
    """Tests validation of a structurally sound PCAP file."""
    validator = LogValidator()
    result = validator.validate(valid_ethernet_pcap)

    assert result.is_valid is True
    assert result.status == ValidationStatus.VALID
    assert result.link_type == 1  # LINKTYPE_ETHERNET
    assert result.packet_count_estimate == 5
    assert len(result.errors) == 0


def test_validate_empty_file(empty_file: Path) -> None:
    """Tests that an empty file is flagged as INVALID with an error message."""
    validator = LogValidator()
    result = validator.validate(empty_file)

    assert result.is_valid is False
    assert result.status == ValidationStatus.INVALID
    assert any("empty" in err.lower() for err in result.errors)


def test_validate_unsupported_format(temp_dir: Path) -> None:
    """Tests that non-pcap files are flagged as UNSUPPORTED_FORMAT."""
    csv_file = temp_dir / "logs.csv"
    csv_file.write_text("timestamp,ip,port\n")

    validator = LogValidator()
    result = validator.validate(csv_file)

    assert result.is_valid is False
    assert result.status == ValidationStatus.UNSUPPORTED_FORMAT
    assert any("unsupported" in err.lower() for err in result.errors)


def test_validate_corrupted_magic_header(corrupted_header_pcap: Path) -> None:
    """Tests that unrecognized magic numbers are flagged as unsupported/invalid."""
    validator = LogValidator()
    result = validator.validate(corrupted_header_pcap)

    assert result.is_valid is False
    assert result.status in (
        ValidationStatus.UNSUPPORTED_FORMAT,
        ValidationStatus.INVALID,
    )
    assert len(result.errors) > 0


def test_validate_truncated_global_header(temp_dir: Path) -> None:
    """Tests that a file smaller than the 24-byte PCAP header is flagged as INVALID."""
    truncated_hdr = temp_dir / "truncated_hdr.pcap"
    truncated_hdr.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00")  # Only 6 bytes

    validator = LogValidator()
    result = validator.validate(truncated_hdr)

    assert result.is_valid is False
    assert result.status == ValidationStatus.INVALID
    assert any("truncated" in err.lower() for err in result.errors)


def test_validate_truncated_packet_stream(truncated_pcap: Path) -> None:
    """Tests that a capture file cut off mid-packet is classified as PARTIALLY_READABLE."""
    validator = LogValidator(check_packet_integrity=True)
    result = validator.validate(truncated_pcap)

    # File has complete packets before truncation point
    assert result.is_valid is True
    assert result.is_partially_readable is True
    assert result.status == ValidationStatus.PARTIALLY_READABLE
    assert any("truncated" in w.lower() for w in result.warnings)

