"""Unit tests for Zero-Copy Memory Management Utilities."""

from pathlib import Path
import pytest

from src.common.exceptions import EmptyFileError, UnsupportedFormatError
from src.common.zero_copy_utils import inspect_pcap_header_zero_copy, open_mmap_reader


def test_zero_copy_mmap_and_header_inspection(valid_ethernet_pcap: Path) -> None:
    """Tests zero-copy memory-mapped file access and header inspection."""
    with open_mmap_reader(str(valid_ethernet_pcap)) as mapped:
        assert len(mapped) > 0
        fmt, is_le, ver_maj, ver_min, link_type = inspect_pcap_header_zero_copy(mapped)

        assert fmt == "pcap"
        assert isinstance(is_le, bool)
        assert ver_maj == 2
        assert ver_min == 4
        assert link_type == 1  # Ethernet link type


def test_zero_copy_empty_file(empty_file: Path) -> None:
    """Tests that memory-mapping an empty 0-byte file raises EmptyFileError."""
    with pytest.raises(EmptyFileError):
        with open_mmap_reader(str(empty_file)):
            pass


def test_zero_copy_unsupported_magic(corrupted_header_pcap: Path) -> None:
    """Tests that inspecting invalid magic bytes raises UnsupportedFormatError."""
    with open_mmap_reader(str(corrupted_header_pcap)) as mapped:
        with pytest.raises(UnsupportedFormatError):
            inspect_pcap_header_zero_copy(mapped)

