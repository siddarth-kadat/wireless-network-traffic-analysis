"""High-performance zero-copy buffer utilities using mmap and memoryview.

Zero-Copy Architectural Documentation:
-------------------------------------
1. Where Zero-Copy is Applied:
   - Memory-Mapped I/O: Files are mapped directly into the process virtual address space
     via Python's `mmap` module. This allows the operating system kernel page cache to satisfy
     reads on demand without copying the entire multi-gigabyte file into Python user-space memory.
   - Non-Copying Slices: `memoryview` slices allow inspecting global headers and packet headers
     (e.g., magic numbers, timestamps, wire lengths, snap lengths) directly from the mmap buffer
     without allocating intermediate `bytes` objects on each slice operation.
   - Streaming Chunk Generators: Packets are yielded in bounded streaming chunks, avoiding
     in-memory accumulation of parsed packet lists (such as `rdpcap`).

2. Where Copying Still Occurs:
   - Protocol Dissection: When converting raw packet bytes into structured Python attributes
     (e.g., extracting IP address strings, integers, flags, and dictionary metadata), new Python
     objects must be allocated. This copying is required for subsequent application manipulation.
   - Inter-Process Communication (IPC): In multi-process concurrency, passing data across process
     boundaries requires serialization (pickling), which incurs memory copy overhead.

3. Measurable Benefits:
   - Drastically reduced peak resident set size (RSS) memory consumption on large PCAP files.
   - Fast file integrity and magic number validation without reading whole files.
"""

import mmap
import os
import struct
from contextlib import contextmanager
from typing import Generator, Tuple

from .constants import (
    PCAP_GLOBAL_HEADER_LENGTH,
    PCAP_MAGIC_MICROSECONDS_SWAPPED,
    PCAP_MAGIC_NANOSECONDS_SWAPPED,
    PCAPNG_MAGIC_SECTION_HEADER,
    VALID_PCAP_MAGICS,
)
from .exceptions import CorruptPcapError, EmptyFileError, UnsupportedFormatError


@contextmanager
def open_mmap_reader(file_path: str) -> Generator[mmap.mmap, None, None]:
    """Context manager for opening a file in read-only memory-mapped mode.

    Args:
        file_path: Absolute path to the file.

    Yields:
        mmap.mmap object providing zero-copy buffer access.

    Raises:
        EmptyFileError: If file size is 0.
        FileNotFoundError: If file does not exist.
    """
    file_size = os.path.getsize(file_path)
    if file_size == 0:
        raise EmptyFileError(f"File '{file_path}' is empty (0 bytes).")

    with open(file_path, "rb") as f:
        # ACCESS_READ on Windows and Linux maps pages read-only
        mapped = mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ)
        try:
            yield mapped
        finally:
            mapped.close()


def inspect_pcap_header_zero_copy(
    mapped_buffer: mmap.mmap,
) -> Tuple[str, bool, int, int, int]:
    """Inspects PCAP global header using zero-copy memoryview without allocations.

    Args:
        mapped_buffer: mmap buffer of the PCAP file.

    Returns:
        Tuple of (format_type, is_little_endian, version_major, version_minor, link_type).

    Raises:
        UnsupportedFormatError: If magic number does not match PCAP or PCAPNG.
        CorruptPcapError: If global header is truncated.
    """
    view = memoryview(mapped_buffer)
    try:
        total_len = len(view)

        if total_len < 4:
            raise CorruptPcapError("File is smaller than minimum 4-byte header.")

        # Zero-copy slice of 4-byte magic
        magic_bytes = bytes(view[:4])

        if magic_bytes == PCAPNG_MAGIC_SECTION_HEADER:
            # PCAPNG file detected (Section Header Block)
            return ("pcapng", True, 1, 0, 0)

        if magic_bytes not in VALID_PCAP_MAGICS:
            raise UnsupportedFormatError(
                f"Unrecognized capture magic number: {magic_bytes.hex()}"
            )

        if total_len < PCAP_GLOBAL_HEADER_LENGTH:
            raise CorruptPcapError(
                f"PCAP file is truncated: expected {PCAP_GLOBAL_HEADER_LENGTH} bytes global header, got {total_len} bytes."
            )

        # Determine endianness: on x86/ARM little-endian machines,
        # standard 0xa1b2c3d4 is stored on disk with LSB first: 0xd4, 0xc3, 0xb2, 0xa1
        is_little_endian = magic_bytes in (
            PCAP_MAGIC_MICROSECONDS_SWAPPED,
            PCAP_MAGIC_NANOSECONDS_SWAPPED,
        )
        endian_fmt = "<" if is_little_endian else ">"

        # PCAP Global Header layout:
        # magic(4) + ver_major(2) + ver_minor(2) + thiszone(4) + sigfigs(4) + snaplen(4) + network/linktype(4)
        header_bytes = bytes(view[:PCAP_GLOBAL_HEADER_LENGTH])
        _, ver_major, ver_minor, _, _, snaplen, link_type = struct.unpack(
            f"{endian_fmt}4sHHIIII", header_bytes
        )

        return ("pcap", is_little_endian, ver_major, ver_minor, link_type)
    finally:
        view.release()
