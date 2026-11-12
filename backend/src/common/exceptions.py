"""Custom domain exceptions for the Wireless Network Traffic Analysis and Alerting System."""

from typing import Any, Optional


class NetworkTrafficAnalysisError(Exception):
    """Base exception for all system domain errors."""

    def __init__(self, message: str, details: Optional[dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} | Details: {self.details}"
        return self.message


# Ingestion Errors
class IngestionError(NetworkTrafficAnalysisError):
    """Raised when log or PCAP ingestion fails."""
    pass


class FileAccessError(IngestionError):
    """Raised when a file cannot be found or accessed due to permissions or missing path."""
    pass


class PathTraversalSecurityError(IngestionError):
    """Raised when an untrusted path attempts directory traversal outside allowed boundaries."""
    pass


class FileSizeLimitExceededError(IngestionError):
    """Raised when an ingested file exceeds the configured maximum allowable size."""
    pass


# Validation Errors
class ValidationError(NetworkTrafficAnalysisError):
    """Raised when file or packet validation fails."""
    pass


class EmptyFileError(ValidationError):
    """Raised when an ingested file is empty (0 bytes)."""
    pass


class UnsupportedFormatError(ValidationError):
    """Raised when a file format or magic header is unsupported."""
    pass


class CorruptPcapError(ValidationError):
    """Raised when a PCAP file header or structure is corrupted."""
    pass


class TruncatedPcapError(ValidationError):
    """Raised when a PCAP file ends prematurely with incomplete packet records."""
    pass


class UnsupportedLinkTypeError(ValidationError):
    """Raised when a PCAP link-layer DLT value is not supported by the parser."""
    pass


# Parsing Errors
class ParsingError(NetworkTrafficAnalysisError):
    """Raised when packet dissection or byte parsing fails."""
    pass


class MalformedPacketError(ParsingError):
    """Raised when an individual packet has unparseable or contradictory headers."""
    pass


# Processing Errors
class ProcessingError(NetworkTrafficAnalysisError):
    """Raised during normalization, record building, or pipeline execution."""
    pass


# Concurrency Errors
class ConcurrencyError(NetworkTrafficAnalysisError):
    """Raised when concurrent worker pools encounter fatal execution or synchronization errors."""
    pass
