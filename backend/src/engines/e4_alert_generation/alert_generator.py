"""E4: Alert Generator Module.

Coordinates the end-to-end alert generation workflow from receiving E2 detection results
through validation, severity resolution, deduplication, formatting, building, and dispatch to E3.
"""

import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from ...common.logger import get_logger
from .alert_builder import AlertBuilder, AlertPayload
from .alert_deduplicator import AlertDeduplicator
from .alert_dispatcher import AlertDispatcher, DispatchResult
from .alert_receiver import AlertReceiver, DetectionResultPayload
from .alert_validator import AlertValidator
from .severity_manager import SeverityManager

logger = get_logger(__name__)


@dataclass
class AlertGenerationSummary:
    """Operational summary metrics for an alert generation batch run."""

    total_results_received: int = 0
    suspicious_results_identified: int = 0
    normal_results_skipped: int = 0
    invalid_results_rejected: int = 0
    duplicate_results_skipped: int = 0
    alerts_generated: int = 0
    alerts_dispatched: int = 0
    dispatch_failures: int = 0
    start_time: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    completion_time: str = ""
    duration_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Converts summary to dictionary representation."""
        return asdict(self)


class AlertGenerator:
    """Orchestrates the complete E4 alert generation pipeline."""

    def __init__(
        self,
        receiver: Optional[AlertReceiver] = None,
        validator: Optional[AlertValidator] = None,
        severity_manager: Optional[SeverityManager] = None,
        builder: Optional[AlertBuilder] = None,
        deduplicator: Optional[AlertDeduplicator] = None,
        dispatcher: Optional[AlertDispatcher] = None,
        storage_sink: Optional[Callable[[Dict[str, Any]], Any]] = None,
    ) -> None:
        """Initializes all sub-components of the alert generation engine.

        Args:
            receiver: Custom AlertReceiver or default.
            validator: Custom AlertValidator or default.
            severity_manager: Custom SeverityManager or default.
            builder: Custom AlertBuilder or default.
            deduplicator: Custom AlertDeduplicator or default.
            dispatcher: Custom AlertDispatcher or default.
            storage_sink: Optional E3 alert storage sink callable.
        """
        self.receiver = receiver or AlertReceiver()
        self.validator = validator or AlertValidator()
        self.severity_manager = severity_manager or SeverityManager()
        self.builder = builder or AlertBuilder()
        self.deduplicator = deduplicator or AlertDeduplicator()
        self.dispatcher = dispatcher or AlertDispatcher(storage_sink=storage_sink)

    def generate_alert_from_result(
        self,
        raw_result: Union[Dict[str, Any], DetectionResultPayload, Any],
        dispatch_to_storage: bool = True,
    ) -> Tuple[Optional[AlertPayload], Optional[str]]:
        """Processes a single detection result and generates an alert if suspicious and non-duplicate.

        Args:
            raw_result: Detection result from E2.
            dispatch_to_storage: If True, immediately dispatches the generated alert to E3.

        Returns:
            Tuple of (AlertPayload or None, error_or_skip_reason or None).
        """
        # Step 1: Receive
        recv_outcome = self.receiver.receive_result(raw_result)
        if not recv_outcome.is_accepted or not recv_outcome.payload:
            err = recv_outcome.rejection_reason or "Payload rejected by receiver."
            logger.warning("Alert generation aborted: %s", err)
            return None, err

        payload = recv_outcome.payload

        # Step 2: Validate
        val_res = self.validator.validate(payload)
        if not val_res.is_valid:
            err = val_res.rejection_reason or "Payload failed validation."
            logger.warning("Alert validation failed for result '%s': %s", payload.result_id, err)
            return None, err

        # Step 3: Check suspiciousness (only confirmed matches generate alerts)
        if not val_res.should_generate_alert:
            reason = val_res.rejection_reason or "Detection result indicates normal/benign traffic."
            logger.debug(
                "No alert generated for result '%s': %s", payload.result_id, reason
            )
            return None, reason

        # Step 4: Check deduplication
        if self.deduplicator.is_duplicate(payload.result_id):
            reason = f"Duplicate detection result '{payload.result_id}' already processed."
            logger.info(reason)
            return None, reason

        # Step 5: Resolve severity from rule or result
        severity = self.severity_manager.resolve_severity(
            payload.severity, context_id=payload.result_id
        )

        # Step 6: Build alert entity
        alert = self.builder.build_alert(payload, severity)

        # Step 7: Mark processed in deduplicator
        self.deduplicator.mark_processed(payload.result_id)

        # Step 8: Dispatch to E3 if requested
        if dispatch_to_storage:
            disp_res = self.dispatcher.dispatch_alert(alert)
            if not disp_res.is_successful:
                logger.error(
                    "Alert '%s' generated but dispatch failed: %s",
                    alert.alert_id,
                    disp_res.error_message,
                )
                return alert, f"Dispatch warning: {disp_res.error_message}"

        return alert, None

    def process_batch(
        self,
        raw_results: Sequence[Union[Dict[str, Any], DetectionResultPayload, Any]],
        dispatch_to_storage: bool = True,
    ) -> Tuple[List[AlertPayload], AlertGenerationSummary]:
        """Processes a batch of detection results from E2 and coordinates E3 dispatch.

        Args:
            raw_results: Sequence of detection result dictionaries or payloads.
            dispatch_to_storage: Whether to forward alerts to E3 immediately.

        Returns:
            Tuple of (List of successfully generated AlertPayloads, AlertGenerationSummary).
        """
        start_wall = time.time()
        start_iso = datetime.now(timezone.utc).isoformat()

        summary = AlertGenerationSummary(
            total_results_received=len(raw_results),
            start_time=start_iso,
        )

        alerts: List[AlertPayload] = []

        for idx, item in enumerate(raw_results):
            # Check receiver outcome first
            recv = self.receiver.receive_result(item)
            if not recv.is_accepted or not recv.payload:
                summary.invalid_results_rejected += 1
                summary.errors.append(
                    f"Item {idx}: {recv.rejection_reason or 'Receiver rejection'}"
                )
                continue

            payload = recv.payload

            # Validate
            val = self.validator.validate(payload)
            if not val.is_valid:
                summary.invalid_results_rejected += 1
                summary.errors.append(
                    f"Result '{payload.result_id}': {val.rejection_reason}"
                )
                continue

            if not val.should_generate_alert:
                summary.normal_results_skipped += 1
                continue

            # Check deduplication
            if self.deduplicator.is_duplicate(payload.result_id):
                summary.duplicate_results_skipped += 1
                continue

            summary.suspicious_results_identified += 1

            # Resolve severity
            try:
                severity = self.severity_manager.resolve_severity(
                    payload.severity, context_id=payload.result_id
                )
            except Exception as exc:
                summary.errors.append(
                    f"Result '{payload.result_id}' severity error: {str(exc)}"
                )
                continue

            # Build alert
            alert = self.builder.build_alert(payload, severity)
            self.deduplicator.mark_processed(payload.result_id)
            alerts.append(alert)
            summary.alerts_generated += 1

            # Dispatch
            if dispatch_to_storage:
                disp_res = self.dispatcher.dispatch_alert(alert)
                if disp_res.is_successful:
                    summary.alerts_dispatched += 1
                else:
                    summary.dispatch_failures += 1
                    summary.errors.append(
                        f"Alert '{alert.alert_id}' dispatch failed: {disp_res.error_message}"
                    )

        end_wall = time.time()
        summary.completion_time = datetime.now(timezone.utc).isoformat()
        summary.duration_seconds = round(max(end_wall - start_wall, 0.0001), 4)

        logger.info(
            "Completed Alert Generation batch: Received=%d, Alerts=%d, Dispatched=%d, Duration=%.4fs",
            summary.total_results_received,
            summary.alerts_generated,
            summary.alerts_dispatched,
            summary.duration_seconds,
        )

        return alerts, summary

