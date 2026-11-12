"""E1: Log Validation Module.

Performs robust pre-parsing and structural validation of PCAP and PCAPNG files,
detecting empty files, corrupt headers, truncated captures, and unsupported link types.
"""

import os
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Union

from ...common.constants import (
    PCAP_GLOBAL_HEADER_LENGTH,
    PCAP_MAGIC_MICROSECONDS_SWAPPED,
    PCAP_MAGIC_NANOSECONDS_SWAPPED,
    PCAP_PACKET_HEADER_LENGTH,
    PCAPNG_MAGIC_SECTION_HEADER,
    SUPPORTED_EXTENSIONS,
    SUPPORTED_LINK_TYPES,
    VALID_PCAP_MAGICS,
    ValidationStatus,
)
from ...common.logger import get_logger
from ...common.zero_copy_utils import open_mmap_reader
from .log_ingestion import IngestedFileMetadata

logger = get_logger(__name__)


@dataclass
class ValidationResult:
    """Detailed result of a file validation inspection."""

    file_path: str
    file_name: str
    file_format: str
    status: ValidationStatus
    is_valid: bool
    is_partially_readable: bool = False
    link_type: Optional[int] = None
    link_type_name: Optional[str] = None
    is_little_endian: Optional[bool] = None
    snaplen: Optional[int] = None
    packet_count_estimate: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class LogValidator:
    """Validates PCAP/PCAPNG capture files before full parsing."""

    def __init__(self, check_packet_integrity: bool = True) -> None:
        """Initializes the validator.

        Args:
            check_packet_integrity: Whether to perform packet-level walk for truncation detection.
        """
        self.check_packet_integrity = check_packet_integrity

    def validate(self, target: Union[str, Path, IngestedFileMetadata]) -> ValidationResult:
        """Validates a PCAP file against existence, format, headers, and truncation.

        Args:
            target: File path or IngestedFileMetadata record.

        Returns:
            ValidationResult with detailed status and diagnostics.
        """
        if isinstance(target, IngestedFileMetadata):
            file_path = Path(target.file_path)
            file_name = target.file_name
        else:
            file_path = Path(target).resolve()
            file_name = file_path.name

        ext = file_path.suffix.lower()
        file_format = ext.lstrip(".") if ext in SUPPORTED_EXTENSIONS else "unknown"

        result = ValidationResult(
            file_path=str(file_path),
            file_name=file_name,
            file_format=file_format,
            status=ValidationStatus.INVALID,
            is_valid=False,
        )

        # 1. Existence and basic readability
        if not file_path.exists():
            result.errors.append(f"File not found: {file_path}")
            return result

        if not os.access(file_path, os.R_OK):
            result.errors.append(f"File exists but read permission is denied: {file_path}")
            return result

        # 2. Extension check
        if ext not in SUPPORTED_EXTENSIONS:
            result.status = ValidationStatus.UNSUPPORTED_FORMAT
            result.errors.append(
                f"Unsupported file extension '{ext}'. Expected one of {SUPPORTED_EXTENSIONS}."
            )
            return result

        # 3. Size check (empty file check)
        file_size = file_path.stat().st_size
        if file_size == 0:
            result.status = ValidationStatus.INVALID
            result.errors.append("File is empty (0 bytes).")
            return result

        # 4. Zero-copy header inspection using mmap and memoryview
        try:
            with open_mmap_reader(str(file_path)) as mapped:
                view = memoryview(mapped)
                try:
                    total_len = len(view)

                    if total_len < 4:
                        result.status = ValidationStatus.INVALID
                        result.errors.append(
                            f"File is smaller than minimum 4-byte header ({total_len} bytes)."
                        )
                        return result

                    magic = bytes(view[:4])

                    # Check PCAPNG Section Header Block magic
                    if magic == PCAPNG_MAGIC_SECTION_HEADER:
                        result.file_format = "pcapng"
                        result.is_valid = True
                        result.status = ValidationStatus.VALID
                        result.link_type_name = "PCAPNG Section Header"
                        logger.info("Validated PCAPNG file '%s' successfully.", file_name)
                        return result

                    # Check Standard PCAP magic
                    if magic not in VALID_PCAP_MAGICS:
                        result.status = ValidationStatus.UNSUPPORTED_FORMAT
                        result.errors.append(
                            f"Invalid or unrecognized capture magic number: 0x{magic.hex()}."
                        )
                        return result

                    # Standard PCAP Global Header validation
                    if total_len < PCAP_GLOBAL_HEADER_LENGTH:
                        result.status = ValidationStatus.INVALID
                        result.errors.append(
                            f"Truncated PCAP header: file is {total_len} bytes, minimum header is {PCAP_GLOBAL_HEADER_LENGTH} bytes."
                        )
                        return result

                    is_little_endian = magic in (
                        PCAP_MAGIC_MICROSECONDS_SWAPPED,
                        PCAP_MAGIC_NANOSECONDS_SWAPPED,
                    )
                    endian_fmt = "<" if is_little_endian else ">"

                    global_hdr = bytes(view[:PCAP_GLOBAL_HEADER_LENGTH])
                    _, ver_major, ver_minor, _, _, snaplen, link_type = struct.unpack(
                        f"{endian_fmt}4sHHIIII", global_hdr
                    )

                    result.is_little_endian = is_little_endian
                    result.link_type = link_type
                    result.snaplen = snaplen
                    result.link_type_name = SUPPORTED_LINK_TYPES.get(
                        link_type, f"Unknown/Vendor DLT ({link_type})"
                    )

                    if link_type not in SUPPORTED_LINK_TYPES:
                        result.warnings.append(
                            f"Link-layer type {link_type} ({result.link_type_name}) is non-standard or unsupported."
                        )

                    # 5. Fast packet-record walk for truncation and corruption detection
                    if self.check_packet_integrity:
                        offset = PCAP_GLOBAL_HEADER_LENGTH
                        packet_count = 0
                        truncated = False

                        while offset < total_len:
                            if offset + PCAP_PACKET_HEADER_LENGTH > total_len:
                                truncated = True
                                break

                            pkt_hdr = bytes(view[offset : offset + PCAP_PACKET_HEADER_LENGTH])
                            _, _, incl_len, orig_len = struct.unpack(
                                f"{endian_fmt}IIII", pkt_hdr
                            )

                            # Sanity check on captured packet length
                            if incl_len > 1000000 or (snaplen > 0 and incl_len > snaplen * 2):
                                result.warnings.append(
                                    f"Packet {packet_count + 1} has anomalous captured length: {incl_len} bytes."
                                )

                            next_offset = offset + PCAP_PACKET_HEADER_LENGTH + incl_len
                            if next_offset > total_len:
                                truncated = True
                                break

                            offset = next_offset
                            packet_count += 1

                        result.packet_count_estimate = packet_count

                        if truncated:
                            if packet_count > 0:
                                result.status = ValidationStatus.PARTIALLY_READABLE
                                result.is_valid = True
                                result.is_partially_readable = True
                                result.warnings.append(
                                    f"PCAP is truncated: {packet_count} complete packets verified before unexpected EOF."
                                )
                                logger.warning(
                                    "File '%s' is partially readable (%d packets before truncation).",
                                    file_name,
                                    packet_count,
                                )
                                return result
                            else:
                                result.status = ValidationStatus.INVALID
                                result.errors.append(
                                    "PCAP truncated before the first packet payload could be completed."
                                )
                                return result

                    result.is_valid = True
                    result.status = ValidationStatus.VALID
                    logger.info(
                        "Validated PCAP '%s': DLT=%s, Endianness=%s, Packets~=%d",
                        file_name,
                        result.link_type_name,
                        "Little" if is_little_endian else "Big",
                        result.packet_count_estimate,
                    )
                    return result
                finally:
                    view.release()

        except Exception as exc:
            result.status = ValidationStatus.INVALID
            result.errors.append(f"Validation error: {str(exc)}")
            logger.error("Validation failed for file '%s': %s", file_name, exc)
            return result
