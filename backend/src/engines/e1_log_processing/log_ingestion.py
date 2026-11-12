"""E1: Log Ingestion Module.

Accepts, inspects, validates paths, collects file metadata, and prepares batches
for the Wireless Network Traffic Analysis and Alerting System.
"""

import hashlib
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Union

from ...common.configuration import settings
from ...common.constants import SUPPORTED_EXTENSIONS
from ...common.exceptions import (
    FileAccessError,
    FileSizeLimitExceededError,
    PathTraversalSecurityError,
)
from ...common.logger import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class IngestedFileMetadata:
    """Metadata representing an ingested PCAP file."""

    batch_id: str
    file_name: str
    file_path: str
    file_format: str
    file_size_bytes: int
    sha256_hash: str
    ingested_at: str
    modified_time: str


@dataclass
class IngestionBatch:
    """Batch container representing a collection of ingested files."""

    batch_id: str
    files: List[IngestedFileMetadata] = field(default_factory=list)
    total_files: int = 0
    total_bytes: int = 0
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class LogIngestion:
    """Handles ingestion of PCAP/PCAPNG network traffic files."""

    def __init__(
        self,
        max_file_size_bytes: Optional[int] = None,
        allowed_base_dir: Optional[Union[str, Path]] = None,
    ) -> None:
        """Initializes the ingestion handler.

        Args:
            max_file_size_bytes: Maximum allowed file size in bytes (defaults to settings).
            allowed_base_dir: Optional root directory to enforce path containment.
        """
        self.max_file_size_bytes = (
            max_file_size_bytes
            if max_file_size_bytes is not None
            else settings.max_file_size_bytes
        )
        self.allowed_base_dir = (
            Path(allowed_base_dir).resolve() if allowed_base_dir else None
        )

    def _sanitize_and_validate_path(self, file_path: Union[str, Path]) -> Path:
        """Validates path existence, accessibility, and path traversal security.

        Args:
            file_path: Raw input path.

        Returns:
            Resolved Path object.

        Raises:
            FileAccessError: If file does not exist or cannot be read.
            PathTraversalSecurityError: If path escapes the allowed base directory.
        """
        try:
            path_obj = Path(file_path).resolve()
        except Exception as exc:
            raise FileAccessError(f"Invalid path representation: {file_path}", {"error": str(exc)})

        # Check path traversal if a restricted base directory was configured
        if self.allowed_base_dir:
            try:
                path_obj.relative_to(self.allowed_base_dir)
            except ValueError:
                raise PathTraversalSecurityError(
                    f"Path '{path_obj}' traverses outside allowed directory '{self.allowed_base_dir}'."
                )

        if not path_obj.exists():
            raise FileAccessError(f"File not found: {path_obj}")

        if not path_obj.is_file():
            raise FileAccessError(f"Path is not a regular file: {path_obj}")

        if not os.access(path_obj, os.R_OK):
            raise FileAccessError(f"File exists but is not readable: {path_obj}")

        return path_obj

    def _compute_sha256(self, file_path: Path) -> str:
        """Computes SHA-256 checksum of a file using buffered streaming reads."""
        sha = hashlib.sha256()
        buffer_size = 64 * 1024  # 64 KB buffer
        with open(file_path, "rb") as f:
            while chunk := f.read(buffer_size):
                sha.update(chunk)
        return sha.hexdigest()

    def ingest_file(
        self, file_path: Union[str, Path], batch_id: Optional[str] = None
    ) -> IngestedFileMetadata:
        """Ingests a single PCAP file, validates metadata, and preserves the original file.

        Args:
            file_path: File system path to the PCAP file.
            batch_id: Optional batch ID string. Generates new UUID if not provided.

        Returns:
            IngestedFileMetadata record.

        Raises:
            FileAccessError: If file cannot be read or accessed.
            FileSizeLimitExceededError: If file exceeds maximum size.
        """
        valid_path = self._sanitize_and_validate_path(file_path)
        file_size = valid_path.stat().st_size

        if file_size > self.max_file_size_bytes:
            raise FileSizeLimitExceededError(
                f"File '{valid_path.name}' size ({file_size} bytes) exceeds limit ({self.max_file_size_bytes} bytes)."
            )

        batch_uuid = batch_id or str(uuid.uuid4())
        ext = valid_path.suffix.lower()
        file_format = ext.lstrip(".") if ext in SUPPORTED_EXTENSIONS else "unknown"

        sha256_hash = self._compute_sha256(valid_path)
        modified_time = datetime.fromtimestamp(
            valid_path.stat().st_mtime, tz=timezone.utc
        ).isoformat()
        ingested_at = datetime.now(timezone.utc).isoformat()

        metadata = IngestedFileMetadata(
            batch_id=batch_uuid,
            file_name=valid_path.name,
            file_path=str(valid_path),
            file_format=file_format,
            file_size_bytes=file_size,
            sha256_hash=sha256_hash,
            ingested_at=ingested_at,
            modified_time=modified_time,
        )

        logger.info(
            "Ingested file '%s' (Format: %s, Size: %d bytes, Batch: %s)",
            metadata.file_name,
            metadata.file_format,
            metadata.file_size_bytes,
            metadata.batch_id,
        )
        return metadata

    def ingest_batch(
        self, file_paths: Sequence[Union[str, Path]], batch_id: Optional[str] = None
    ) -> IngestionBatch:
        """Ingests multiple PCAP files into a unified processing batch.

        Args:
            file_paths: Collection of file paths.
            batch_id: Optional shared batch ID.

        Returns:
            IngestionBatch containing all successfully ingested files.
        """
        shared_batch_id = batch_id or str(uuid.uuid4())
        batch = IngestionBatch(batch_id=shared_batch_id)

        for path in file_paths:
            try:
                meta = self.ingest_file(path, batch_id=shared_batch_id)
                batch.files.append(meta)
                batch.total_bytes += meta.file_size_bytes
            except Exception as exc:
                logger.error("Failed to ingest file '%s': %s", path, exc)
                raise

        batch.total_files = len(batch.files)
        logger.info(
            "Prepared ingestion batch %s with %d files (%d bytes)",
            batch.batch_id,
            batch.total_files,
            batch.total_bytes,
        )
        return batch
