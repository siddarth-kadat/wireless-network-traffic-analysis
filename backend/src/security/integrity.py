"""Payload integrity and checksum utilities."""

import hashlib
from typing import Union


def compute_file_sha256(file_path: Union[str, bytes]) -> str:
    """Computes SHA-256 hash of a file or byte buffer."""
    sha256 = hashlib.sha256()
    if isinstance(file_path, (bytes, bytearray)):
        sha256.update(file_path)
    else:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
    return sha256.hexdigest()
