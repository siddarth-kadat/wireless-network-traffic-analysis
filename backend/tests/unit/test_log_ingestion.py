"""Unit tests for E1 Log Ingestion Module."""

from pathlib import Path
import pytest

from src.common.exceptions import (
    FileAccessError,
    FileSizeLimitExceededError,
    PathTraversalSecurityError,
)
from src.engines.e1_log_processing.log_ingestion import (
    IngestedFileMetadata,
    IngestionBatch,
    LogIngestion,
)


def test_ingest_valid_pcap(valid_ethernet_pcap: Path) -> None:
    """Tests ingestion of a valid, existing PCAP file."""
    ingestion = LogIngestion()
    meta = ingestion.ingest_file(valid_ethernet_pcap)

    assert isinstance(meta, IngestedFileMetadata)
    assert meta.file_name == "valid_ethernet.pcap"
    assert meta.file_format == "pcap"
    assert meta.file_size_bytes > 0
    assert len(meta.sha256_hash) == 64
    assert meta.batch_id is not None


def test_ingest_nonexistent_file(temp_dir: Path) -> None:
    """Tests that ingesting a non-existent file raises FileAccessError."""
    ingestion = LogIngestion()
    non_existent = temp_dir / "does_not_exist.pcap"

    with pytest.raises(FileAccessError):
        ingestion.ingest_file(non_existent)


def test_ingest_multiple_pcaps(
    valid_ethernet_pcap: Path, valid_wireless_pcap: Path
) -> None:
    """Tests batch ingestion of multiple PCAP files."""
    ingestion = LogIngestion()
    batch = ingestion.ingest_batch([valid_ethernet_pcap, valid_wireless_pcap])

    assert isinstance(batch, IngestionBatch)
    assert batch.total_files == 2
    assert len(batch.files) == 2
    assert batch.total_bytes > 0
    # Both files share the same batch_id
    assert batch.files[0].batch_id == batch.batch_id
    assert batch.files[1].batch_id == batch.batch_id


def test_ingest_file_size_limit_exceeded(valid_ethernet_pcap: Path) -> None:
    """Tests that a file exceeding configured max size raises FileSizeLimitExceededError."""
    # Restrict max file size to 10 bytes
    ingestion = LogIngestion(max_file_size_bytes=10)

    with pytest.raises(FileSizeLimitExceededError):
        ingestion.ingest_file(valid_ethernet_pcap)


def test_ingest_path_traversal_protection(temp_dir: Path) -> None:
    """Tests that paths outside the allowed base directory are rejected."""
    allowed_dir = temp_dir / "allowed"
    allowed_dir.mkdir()
    outside_file = temp_dir / "outside.pcap"
    outside_file.touch()

    ingestion = LogIngestion(allowed_base_dir=allowed_dir)

    with pytest.raises(PathTraversalSecurityError):
        ingestion.ingest_file(outside_file)


def test_ingest_unsupported_extension(temp_dir: Path) -> None:
    """Tests metadata format classification for unsupported file extensions."""
    txt_file = temp_dir / "traffic.txt"
    txt_file.write_text("dummy traffic log")

    ingestion = LogIngestion()
    meta = ingestion.ingest_file(txt_file)

    assert meta.file_format == "unknown"
    assert meta.file_name == "traffic.txt"

