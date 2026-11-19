"""Input sanitization and validation utilities."""

import re
from pathlib import Path


def sanitize_filename(filename: str) -> str:
    """Removes path traversal characters and normalizes file basename."""
    base = Path(filename).name
    # Strip any characters outside alphanumerics, dots, hyphens, and underscores
    sanitized = re.sub(r"[^\w\.\-]", "_", base)
    return sanitized or "capture.pcap"


def sanitize_text(text: str) -> str:
    """Sanitizes text inputs by removing potentially dangerous HTML/script injection tokens."""
    if not text:
        return ""
    clean = re.sub(r"<[^>]*?>", "", str(text))
    return clean.strip()
