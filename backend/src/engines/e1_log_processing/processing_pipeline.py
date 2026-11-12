"""E1: Processing Pipeline Module.

Coordinates the end-to-end execution of Ingestion, Validation, Parsing,
Processing, and Concurrency, packaging structured outputs for E2 and E3.
"""

import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from ...common.constants import ProcessingStatus, ValidationStatus
from ...common.logger import get_logger
from .concurrent_processor import ConcurrentProcessor
from .log_ingestion import IngestedFileMetadata, LogIngestion
from .log_parser import PcapParser
from .log_processor import LogProcessor, ProcessedRecord, ProcessingErrorRecord
from .log_validation import LogValidator, ValidationResult

logger = get_logger(__name__)


@dataclass
class ProcessingSummary:
    """Summary metrics of a completed or failed PCAP file processing run."""

    batch_id: str
    file_name: str
    file_format: str
    file_size_bytes: int
    total_packets_encountered: int
    successfully_processed_packets: int
    failed_packets: int
    skipped_packets: int
    processing_start_time: str
    processing_completion_time: str
    duration_seconds: float
    packets_per_second: float
    processing_status: ProcessingStatus
    validation_status: ValidationStatus
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes summary to a plain dictionary."""
        d = asdict(self)
        d["processing_status"] = self.processing_status.value
        d["validation_status"] = self.validation_status.value
        return d


@dataclass
class E1DetectionOutput:
    """Output 1: Structured packet records prepared for E2 Suspicious Pattern Detection Engine."""

    batch_id: str
    records: List[ProcessedRecord]
    summary: ProcessingSummary


@dataclass
class E1StorageOutput:
    """Output 2: Prepared database entities for E3 Log and Alert Storage Engine."""

    batch_metadata: Dict[str, Any]  # Matches Log_Batch schema
    traffic_logs: List[Dict[str, Any]]  # Matches Traffic_Log schema
    errors: List[Dict[str, Any]]  # Matches Processing_Error schema
    summary: ProcessingSummary


class E1ProcessingPipeline:
    """Full coordinator for the E1 Log Processing Engine."""

    def __init__(
        self,
        max_workers: Optional[int] = None,
        max_file_size_bytes: Optional[int] = None,
        check_packet_integrity: bool = True,
    ) -> None:
        """Initializes pipeline components.

        Args:
            max_workers: Concurrency worker count.
            max_file_size_bytes: Configurable ingestion file size limit.
            check_packet_integrity: Whether to run deep truncation pre-checks in validator.
        """
        self.ingestion = LogIngestion(max_file_size_bytes=max_file_size_bytes)
        self.validator = LogValidator(check_packet_integrity=check_packet_integrity)
        self.parser = PcapParser()
        self.concurrent_processor = ConcurrentProcessor(max_workers=max_workers)

    def process_file(
        self,
        file_path: Union[str, Path],
        batch_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> Tuple[E1DetectionOutput, E1StorageOutput]:
        """Runs the complete E1 pipeline on a single PCAP file.

        Args:
            file_path: Path to the target PCAP/PCAPNG file.
            batch_id: Optional batch identifier.
            user_id: Optional submitting user identifier for batch attribution.

        Returns:
            Tuple of (E1DetectionOutput for E2, E1StorageOutput for E3).
        """
        start_wall = time.time()
        start_iso = datetime.now(timezone.utc).isoformat()
        assigned_batch_id = batch_id or str(uuid.uuid4())
        file_path_obj = Path(file_path)
        file_name = file_path_obj.name
        file_format = file_path_obj.suffix.lstrip(".").lower()
        file_size = 0
        errors: List[str] = []
        warnings: List[str] = []
        processing_errors: List[ProcessingErrorRecord] = []
        processed_records: List[ProcessedRecord] = []
        validation_status = ValidationStatus.INVALID
        processing_status = ProcessingStatus.FAILED

        # Step 1: Ingestion
        try:
            metadata = self.ingestion.ingest_file(file_path, batch_id=assigned_batch_id)
            file_size = metadata.file_size_bytes
            file_format = metadata.file_format
        except Exception as exc:
            err_msg = f"Ingestion error: {str(exc)}"
            errors.append(err_msg)
            logger.error("File '%s' failed ingestion: %s", file_name, exc)
            return self._build_failure_outputs(
                assigned_batch_id,
                file_name,
                file_format,
                file_size,
                start_iso,
                start_wall,
                validation_status,
                errors,
                warnings,
                user_id,
            )

        # Step 2: Validation
        val_res = self.validator.validate(metadata)
        validation_status = val_res.status
        errors.extend(val_res.errors)
        warnings.extend(val_res.warnings)

        if not val_res.is_valid:
            logger.error("File '%s' failed validation: %s", file_name, val_res.errors)
            return self._build_failure_outputs(
                assigned_batch_id,
                file_name,
                file_format,
                file_size,
                start_iso,
                start_wall,
                validation_status,
                errors,
                warnings,
                user_id,
            )

        # Step 3 & 4: Parsing and Processing
        processor = LogProcessor(batch_id=assigned_batch_id)

        try:
            packet_stream = self.parser.parse_file(metadata.file_path)
            for parsed_pkt in packet_stream:
                rec, err = processor.process_packet(parsed_pkt)
                if rec:
                    processed_records.append(rec)
                if err:
                    processing_errors.append(err)

        except Exception as exc:
            err_msg = f"Parsing pipeline interrupted: {str(exc)}"
            errors.append(err_msg)
            logger.error("Parsing failure on file '%s': %s", file_name, exc)

        end_wall = time.time()
        end_iso = datetime.now(timezone.utc).isoformat()
        duration = max(end_wall - start_wall, 0.0001)

        total_pkts = processor.counters.total_packets
        proc_pkts = processor.counters.processed_packets
        failed_pkts = processor.counters.failed_packets
        skipped_pkts = processor.counters.skipped_packets
        pps = round(total_pkts / duration, 2)

        if total_pkts == 0 and not errors:
            errors.append("No packets found in capture file.")
            processing_status = ProcessingStatus.FAILED
        elif failed_pkts == 0 and not errors:
            processing_status = ProcessingStatus.SUCCESS
        elif proc_pkts > 0:
            processing_status = ProcessingStatus.PARTIAL_SUCCESS
        else:
            processing_status = ProcessingStatus.FAILED

        summary = ProcessingSummary(
            batch_id=assigned_batch_id,
            file_name=file_name,
            file_format=file_format,
            file_size_bytes=file_size,
            total_packets_encountered=total_pkts,
            successfully_processed_packets=proc_pkts,
            failed_packets=failed_pkts,
            skipped_packets=skipped_pkts,
            processing_start_time=start_iso,
            processing_completion_time=end_iso,
            duration_seconds=round(duration, 4),
            packets_per_second=pps,
            processing_status=processing_status,
            validation_status=validation_status,
            errors=errors,
            warnings=warnings,
        )

        # Build Output 1 (E2)
        detection_output = E1DetectionOutput(
            batch_id=assigned_batch_id,
            records=processed_records,
            summary=summary,
        )

        # Build Output 2 (E3)
        batch_meta = {
            "batch_id": assigned_batch_id,
            "user_id": user_id,
            "file_name": file_name,
            "file_format": file_format,
            "submitted_at": start_iso,
            "processing_status": processing_status.value,
            "total_records": total_pkts,
            "processed_records": proc_pkts,
            "failed_records": failed_pkts,
        }

        traffic_logs = [r.to_dict() for r in processed_records]
        error_dicts = [e.to_dict() for e in processing_errors]

        storage_output = E1StorageOutput(
            batch_metadata=batch_meta,
            traffic_logs=traffic_logs,
            errors=error_dicts,
            summary=summary,
        )

        logger.info(
            "Completed E1 pipeline for '%s': Status=%s, Processed=%d/%d packets, Time=%.2fs",
            file_name,
            processing_status.value,
            proc_pkts,
            total_pkts,
            duration,
        )

        return detection_output, storage_output

    def process_multiple_files(
        self,
        file_paths: Sequence[Union[str, Path]],
        batch_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> List[Tuple[E1DetectionOutput, E1StorageOutput]]:
        """Processes multiple PCAP files concurrently.

        Ensures that failures in one file do not abort execution of other valid files.

        Args:
            file_paths: Sequence of file paths to process.
            batch_id: Optional shared batch ID.
            user_id: Optional user identifier.

        Returns:
            List of (E1DetectionOutput, E1StorageOutput) tuples.
        """
        def _safe_process(path: Union[str, Path]) -> Tuple[E1DetectionOutput, E1StorageOutput]:
            try:
                return self.process_file(path, batch_id=batch_id, user_id=user_id)
            except Exception as exc:
                logger.error("Unhandled error processing '%s': %s", path, exc)
                # Return failure output instead of raising to protect other files
                p_obj = Path(path)
                return self._build_failure_outputs(
                    batch_id or str(uuid.uuid4()),
                    p_obj.name,
                    p_obj.suffix.lstrip("."),
                    0,
                    datetime.now(timezone.utc).isoformat(),
                    time.time(),
                    ValidationStatus.INVALID,
                    [f"Unhandled pipeline error: {str(exc)}"],
                    [],
                    user_id,
                )

        return self.concurrent_processor.process_items_concurrently(
            items=file_paths,
            task_fn=_safe_process,
            task_description="PCAP files",
        )

    def _build_failure_outputs(
        self,
        batch_id: str,
        file_name: str,
        file_format: str,
        file_size: int,
        start_iso: str,
        start_wall: float,
        validation_status: ValidationStatus,
        errors: List[str],
        warnings: List[str],
        user_id: Optional[str] = None,
    ) -> Tuple[E1DetectionOutput, E1StorageOutput]:
        """Helper to construct structured failure outputs for E2 and E3."""
        end_wall = time.time()
        end_iso = datetime.now(timezone.utc).isoformat()
        duration = max(end_wall - start_wall, 0.0001)

        summary = ProcessingSummary(
            batch_id=batch_id,
            file_name=file_name,
            file_format=file_format,
            file_size_bytes=file_size,
            total_packets_encountered=0,
            successfully_processed_packets=0,
            failed_packets=0,
            skipped_packets=0,
            processing_start_time=start_iso,
            processing_completion_time=end_iso,
            duration_seconds=round(duration, 4),
            packets_per_second=0.0,
            processing_status=ProcessingStatus.FAILED,
            validation_status=validation_status,
            errors=errors,
            warnings=warnings,
        )

        detection_output = E1DetectionOutput(
            batch_id=batch_id,
            records=[],
            summary=summary,
        )

        batch_meta = {
            "batch_id": batch_id,
            "user_id": user_id,
            "file_name": file_name,
            "file_format": file_format,
            "submitted_at": start_iso,
            "processing_status": ProcessingStatus.FAILED.value,
            "total_records": 0,
            "processed_records": 0,
            "failed_records": 0,
        }

        storage_output = E1StorageOutput(
            batch_metadata=batch_meta,
            traffic_logs=[],
            errors=[
                {
                    "error_id": str(uuid.uuid4()),
                    "batch_id": batch_id,
                    "log_id": None,
                    "error_type": "PipelineFailure",
                    "error_message": "; ".join(errors),
                    "error_timestamp": end_iso,
                }
            ],
            summary=summary,
        )

        return detection_output, storage_output
