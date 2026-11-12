"""E1: Log Processing Engine Package.

Provides packet capture ingestion, structural validation, Scapy-based streaming parsing,
record normalization, bounded concurrency, and pipeline orchestration.
"""

from .concurrent_processor import ConcurrentProcessor, ConcurrencyStats
from .log_ingestion import IngestedFileMetadata, IngestionBatch, LogIngestion
from .log_parser import ParsedPacket, PcapParser
from .log_processor import (
    LogProcessor,
    ProcessedRecord,
    ProcessingCounters,
    ProcessingErrorRecord,
)
from .log_validation import LogValidator, ValidationResult
from .processing_pipeline import (
    E1DetectionOutput,
    E1ProcessingPipeline,
    E1StorageOutput,
    ProcessingSummary,
)

__all__ = [
    "LogIngestion",
    "IngestedFileMetadata",
    "IngestionBatch",
    "LogValidator",
    "ValidationResult",
    "PcapParser",
    "ParsedPacket",
    "LogProcessor",
    "ProcessedRecord",
    "ProcessingErrorRecord",
    "ProcessingCounters",
    "ConcurrentProcessor",
    "ConcurrencyStats",
    "E1ProcessingPipeline",
    "ProcessingSummary",
    "E1DetectionOutput",
    "E1StorageOutput",
]
