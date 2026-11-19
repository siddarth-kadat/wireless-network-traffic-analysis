"""Coordination: End-to-End Engine Coordinator.

Coordinates the complete data processing pipeline across all four specialized engines:
1. E1 Log Processing Engine: Ingestion, validation, parsing, concurrency.
2. E3 Log & Alert Storage Engine: Primary SQLite/PostgreSQL persistence gateway.
3. E2 Suspicious Pattern Detection Engine: Deterministic rule evaluation against active DB rules.
4. E4 Alert Generation Engine: Validation, enrichment, deduplication, and alert dispatch.
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Union

from backend.src.common.logger import get_logger
from backend.src.database.connection import SessionLocal
from backend.src.engines.e1_log_processing.processing_pipeline import (
    E1DetectionOutput,
    E1ProcessingPipeline,
    E1StorageOutput,
)
from backend.src.engines.e2_suspicious_pattern_detection.detection_engine import (
    SuspiciousPatternDetectionEngine,
)
from backend.src.engines.e2_suspicious_pattern_detection.models import (
    DetectionBatchResult,
)
from backend.src.engines.e3_log_alert_storage.storage_engine import StorageEngine
from backend.src.engines.e3_log_alert_storage.user_repository import UserRepository
from backend.src.engines.e4_alert_generation.e4_engine import E4AlertEngine
from .message_handler import EventType, MessageHandler, default_message_handler

logger = get_logger(__name__)


def resolve_user_id(user_identifier: Optional[Union[int, str]] = None) -> int:
    """Resolve an incoming user identifier (string username, custom ID, or int) to an internal int PK."""
    if isinstance(user_identifier, int) and user_identifier > 0:
        return user_identifier

    if isinstance(user_identifier, str) and user_identifier.strip().isdigit():
        return int(user_identifier.strip())

    try:
        with SessionLocal() as session:
            repo = UserRepository(session)
            if isinstance(user_identifier, str) and user_identifier.strip():
                clean_name = user_identifier.strip()
                # Check direct username match
                user = repo.get_by_username(clean_name)
                if user:
                    return user.user_id
                # Check if it was formatted like 'usr-admin-01' -> fallback to 'admin'
                if "admin" in clean_name.lower():
                    admin_user = repo.get_by_username("admin")
                    if admin_user:
                        return admin_user.user_id
                if "analyst" in clean_name.lower():
                    analyst_user = repo.get_by_username("analyst")
                    if analyst_user:
                        return analyst_user.user_id

            # Fallback to default admin
            admin = repo.get_by_username("admin")
            if admin:
                return admin.user_id

            # Fallback to any user
            all_users = repo.list_all(limit=1)
            if all_users:
                return all_users[0].user_id
    except Exception as exc:
        logger.warning("Could not resolve user_id via database: %s. Using default 1.", exc)

    return 1


class EngineCoordinator:
    """Coordinates workflows across E1, E2, E3, and E4 engines."""

    def __init__(
        self,
        storage_engine: Optional[StorageEngine] = None,
        alert_engine: Optional[E4AlertEngine] = None,
        detection_engine: Optional[SuspiciousPatternDetectionEngine] = None,
        e1_pipeline: Optional[E1ProcessingPipeline] = None,
        message_handler: Optional[MessageHandler] = None,
    ) -> None:
        """Initializes and wires together all four engines."""
        # 1. E3 Storage Engine
        self.storage_engine = storage_engine or StorageEngine()

        # 2. E4 Alert Generation Engine (wired with E3 storage sink)
        self.alert_engine = alert_engine or E4AlertEngine(
            storage_sink=self.storage_engine.store_alert
        )

        # 3. E2 Suspicious Pattern Detection Engine (wired with E3 and E4)
        self.detection_engine = detection_engine or SuspiciousPatternDetectionEngine(
            storage_engine=self.storage_engine,
            alert_engine=self.alert_engine,
        )

        # 4. E1 Processing Pipeline
        self.e1_pipeline = e1_pipeline or E1ProcessingPipeline()

        # 5. Message & Event Broker
        self.message_handler = message_handler or default_message_handler

        logger.info("EngineCoordinator successfully initialized and all 4 engines wired.")

    def process_pcap_file(
        self,
        file_path: Union[str, Path],
        user_id: Optional[Union[int, str]] = None,
        batch_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Executes the complete PCAP ingestion, detection, and alerting lifecycle.

        Workflow sequence:
        1. Validates and parses capture file via E1 (produces detection & storage payloads).
        2. Persists batch metadata, traffic logs, and parser errors into DB via E3.
        3. Dispatches structured records to E2 to evaluate against active detection rules.
        4. E2 evaluates records and persists detection results (matched and unmatched) to E3.
        5. E2 forwards suspicious breaches to E4.
        6. E4 deduplicates and dispatches validated alerts directly to DB via E3.

        Args:
            file_path: Absolute or relative path to PCAP or PCAPNG capture file.
            user_id: Submitting user identifier (string or int).
            batch_id: Optional client-specified batch UUID.

        Returns:
            Dictionary containing comprehensive workflow summary metrics.
        """
        start_time = time.time()
        file_path_obj = Path(file_path).resolve()

        if not file_path_obj.exists():
            raise FileNotFoundError(f"Capture file not found: {file_path_obj}")

        resolved_user_id = resolve_user_id(user_id)
        assigned_batch_uuid = batch_id or str(uuid.uuid4())

        logger.info(
            "Starting coordinated pipeline for file: %s (batch_uuid=%s, user_id=%d)",
            file_path_obj.name,
            assigned_batch_uuid,
            resolved_user_id,
        )

        self.message_handler.publish(
            EventType.PCAP_INGESTION_STARTED,
            batch_id=assigned_batch_uuid,
            payload={"file_path": str(file_path_obj), "user_id": resolved_user_id},
            message=f"PCAP ingestion started for {file_path_obj.name}",
        )

        try:
            # ------------------------------------------------------------------
            # Phase 1: E1 Log Processing Engine
            # ------------------------------------------------------------------
            e1_detection_out, e1_storage_out = self.e1_pipeline.process_file(
                file_path=file_path_obj,
                batch_id=assigned_batch_uuid,
                user_id=str(resolved_user_id),
            )

            self.message_handler.publish(
                EventType.PCAP_INGESTION_COMPLETED,
                batch_id=assigned_batch_uuid,
                payload=e1_detection_out.summary.to_dict(),
                message=f"E1 processed {len(e1_detection_out.records)} records.",
            )

            # ------------------------------------------------------------------
            # Phase 2: E3 Batch & Log Storage
            # ------------------------------------------------------------------
            storage_res = self.storage_engine.store_e1_batch(
                e1_storage_out,
                user_id=resolved_user_id,
            )

            internal_batch_id = storage_res["batch_id"]

            self.message_handler.publish(
                EventType.LOGS_STORED,
                batch_id=assigned_batch_uuid,
                payload=storage_res,
                message=f"E3 stored {storage_res['logs_stored']} logs for batch {internal_batch_id}.",
            )

            # ------------------------------------------------------------------
            # Phase 3 & 4: E2 Pattern Detection & E4 Alert Generation
            # ------------------------------------------------------------------
            self.message_handler.publish(
                EventType.DETECTION_STARTED,
                batch_id=assigned_batch_uuid,
                payload={"records_to_evaluate": len(e1_detection_out.records)},
                message="E2 detection started.",
            )

            detection_batch_result: DetectionBatchResult = (
                self.detection_engine.process_batch(
                    batch_input=e1_detection_out,
                    persist_results=True,
                    forward_alerts=True,
                )
            )

            total_evaluated = detection_batch_result.metrics.rules_evaluated_count
            total_matched = detection_batch_result.metrics.matched_results_count
            alerts_triggered = len(detection_batch_result.matched_outcomes)

            self.message_handler.publish(
                EventType.DETECTION_COMPLETED,
                batch_id=assigned_batch_uuid,
                payload={
                    "total_evaluated": total_evaluated,
                    "total_matched": total_matched,
                    "matched_results_count": alerts_triggered,
                },
                message=f"E2 evaluation complete. {total_matched} matches found.",
            )

            # ------------------------------------------------------------------
            # Phase 5: Workflow Summary Compilation
            # ------------------------------------------------------------------
            elapsed = time.time() - start_time
            summary_dict = {
                "batch_id": internal_batch_id,
                "batch_uuid": assigned_batch_uuid,
                "user_id": resolved_user_id,
                "file_name": file_path_obj.name,
                "file_format": e1_storage_out.batch_metadata.get("file_format", "pcap"),
                "processing_status": str(
                    e1_storage_out.batch_metadata.get("processing_status", "SUCCESS")
                ),
                "total_records": e1_detection_out.summary.total_packets_encountered,
                "processed_records": e1_detection_out.summary.successfully_processed_packets,
                "failed_records": e1_detection_out.summary.failed_packets,
                "logs_stored": storage_res["logs_stored"],
                "errors_stored": storage_res["errors_stored"],
                "rules_evaluated": total_evaluated,
                "suspicious_matches": total_matched,
                "alerts_generated": alerts_triggered,
                "duration_seconds": round(elapsed, 3),
            }

            self.message_handler.publish(
                EventType.PIPELINE_COMPLETED,
                batch_id=assigned_batch_uuid,
                payload=summary_dict,
                message=f"Pipeline completed successfully in {elapsed:.2f}s.",
            )

            logger.info(
                "Coordinated processing complete for batch %s in %.3fs: %d logs, %d matches.",
                assigned_batch_uuid,
                elapsed,
                storage_res["logs_stored"],
                total_matched,
            )

            return summary_dict

        except Exception as exc:
            logger.error(
                "Coordinated pipeline failed for file %s: %s",
                file_path_obj.name,
                exc,
                exc_info=True,
            )
            self.message_handler.publish(
                EventType.PIPELINE_FAILED,
                batch_id=assigned_batch_uuid,
                payload={"error": str(exc)},
                message=f"Pipeline execution failed: {exc}",
            )
            raise


# Shared default coordinator instance
default_engine_coordinator = EngineCoordinator()
