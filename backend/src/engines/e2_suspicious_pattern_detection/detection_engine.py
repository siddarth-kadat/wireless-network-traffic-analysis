"""E2: Core Detection Engine Orchestrator Module.

Coordinates:
- Ingestion of structured processed records from E1
- Loading and caching of enabled detection rules from E3
- Dispatching records to deterministic detection algorithms (A04-A11)
- Persisting both matched and unmatched detection results through E3
- Forwarding suspicious results to E4 for alert generation
- Measuring detection performance metrics
"""

import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union
import uuid
from datetime import datetime, timezone

from backend.src.common.logger import get_logger
from backend.src.engines.e1_log_processing.log_processor import ProcessedRecord
from backend.src.engines.e1_log_processing.processing_pipeline import E1DetectionOutput
from .exceptions import InvalidRecordError, StorageIntegrationError
from .models import (
    DetectionAlgorithm,
    DetectionBatchResult,
    DetectionOutcome,
    DetectionPerformanceMetrics,
    DetectionRuleDefinition,
)
from .pattern_identifier import PatternIdentifier
from .rule_evaluator import RuleEvaluator, extract_record_field
from .rule_loader import RuleLoader
from .signature_detector import SignatureDetector
from .statistical_detector import StatisticalDetector
from .threshold_detector import ThresholdDetector

logger = get_logger(__name__)


class SuspiciousPatternDetectionEngine:
    """Primary engine coordinator for E2 Suspicious Pattern Detection."""

    def __init__(
        self,
        storage_engine: Optional[Any] = None,
        alert_engine: Optional[Any] = None,
        rule_loader: Optional[RuleLoader] = None,
        rule_evaluator: Optional[RuleEvaluator] = None,
        threshold_detector: Optional[ThresholdDetector] = None,
        statistical_detector: Optional[StatisticalDetector] = None,
        signature_detector: Optional[SignatureDetector] = None,
        pattern_identifier: Optional[PatternIdentifier] = None,
    ) -> None:
        """Initializes the detection engine and all sub-detector components.

        Args:
            storage_engine: Optional E3 StorageEngine instance for persistence.
            alert_engine: Optional E4 E4AlertEngine instance for alert generation.
            rule_loader: Custom or default RuleLoader.
            rule_evaluator: Custom or default RuleEvaluator.
            threshold_detector: Custom or default ThresholdDetector (A05, A06, A07).
            statistical_detector: Custom or default StatisticalDetector (A09).
            signature_detector: Custom or default SignatureDetector (A04, A10).
            pattern_identifier: Custom or default PatternIdentifier (A08, A11).
        """
        self.storage_engine = storage_engine
        self.alert_engine = alert_engine

        self.evaluator = rule_evaluator or RuleEvaluator()
        self.rule_loader = rule_loader or RuleLoader(evaluator=self.evaluator)

        self.threshold_detector = threshold_detector or ThresholdDetector()
        self.statistical_detector = statistical_detector or StatisticalDetector()
        self.signature_detector = signature_detector or SignatureDetector(evaluator=self.evaluator)
        self.pattern_identifier = pattern_identifier or PatternIdentifier(evaluator=self.evaluator)

        logger.info("Initialized SuspiciousPatternDetectionEngine (E2).")

    def set_storage_engine(self, storage_engine: Any) -> None:
        """Configures or updates E3 storage engine gateway."""
        self.storage_engine = storage_engine

    def set_alert_engine(self, alert_engine: Any) -> None:
        """Configures or updates E4 alert generation engine."""
        self.alert_engine = alert_engine

    def reset(self) -> None:
        """Resets state in all internal detectors (useful between test runs)."""
        self.threshold_detector.reset()
        self.statistical_detector.reset()
        self.pattern_identifier.reset()

    # -----------------------------------------------------------------------
    # Rule Evaluation Dispatcher
    # -----------------------------------------------------------------------

    def evaluate_record_against_rule(
        self,
        record: Union[ProcessedRecord, Dict[str, Any]],
        rule: DetectionRuleDefinition,
    ) -> DetectionOutcome:
        """Evaluates a single traffic record against a single rule using its assigned algorithm.

        Args:
            record: Processed traffic log record from E1.
            rule: Validated DetectionRuleDefinition from E3.

        Returns:
            DetectionOutcome representing the evaluation result.
        """
        # Extract mandatory log UUID
        log_uuid: Optional[str] = getattr(record, "log_id", None)
        if log_uuid is None and isinstance(record, dict):
            log_uuid = record.get("log_id")

        if not log_uuid or not str(log_uuid).strip():
            raise InvalidRecordError("Traffic log record is missing required 'log_id' UUID.")

        result_uuid = str(uuid.uuid4())
        detection_time = datetime.now(timezone.utc).isoformat()

        # Contextual metadata from record
        if isinstance(record, ProcessedRecord):
            rec_dict = record.to_dict()
        elif isinstance(record, dict):
            rec_dict = record
        else:
            rec_dict = vars(record)

        src_addr = rec_dict.get("source_address")
        dst_addr = rec_dict.get("destination_address")
        src_mac = rec_dict.get("source_mac")
        dst_mac = rec_dict.get("destination_mac")
        protocol = rec_dict.get("protocol")
        log_details = rec_dict.get("log_details")

        algo = rule.algorithm
        matched = False
        observed_val: Optional[float] = None
        threshold_val: Optional[float] = rule.threshold_value
        evidence: Dict[str, Any] = {}

        try:
            # ---------------------------------------------------------------
            # A04: Rule-Based Pattern Matching
            # ---------------------------------------------------------------
            if algo == DetectionAlgorithm.A04_PATTERN_MATCHING:
                matched, evidence = self.signature_detector.evaluate_pattern(
                    record=record,
                    rule_protocol=rule.protocol,
                    condition=rule.parsed_condition or rule.detection_condition,
                )

            # ---------------------------------------------------------------
            # A05: Sliding Window Threshold Detection
            # ---------------------------------------------------------------
            elif algo == DetectionAlgorithm.A05_SLIDING_WINDOW:
                threshold = rule.threshold_value or 30.0
                window_sec = rule.time_window_seconds or 60
                group_field = rule.parsed_condition.get("group_by", "source_address")
                matched, obs, thresh, evidence = (
                    self.threshold_detector.evaluate_sliding_window_threshold(
                        record=record,
                        threshold=threshold,
                        window_seconds=window_sec,
                        group_by_field=group_field,
                        rule_id=rule.rule_id,
                    )
                )
                observed_val = obs
                threshold_val = thresh

            # ---------------------------------------------------------------
            # A06: Rate and Ratio Analysis
            # ---------------------------------------------------------------
            elif algo == DetectionAlgorithm.A06_RATE_RATIO:
                threshold = rule.threshold_value or 10.0
                window_sec = rule.time_window_seconds or 60
                analysis_type = rule.parsed_condition.get("analysis_type", "rate")
                group_field = rule.parsed_condition.get("group_by", "source_address")
                tgt_field = rule.parsed_condition.get("target_field")
                tgt_val = rule.parsed_condition.get("target_value")

                matched, obs, thresh, evidence = (
                    self.threshold_detector.evaluate_rate_and_ratio(
                        record=record,
                        threshold=threshold,
                        window_seconds=window_sec,
                        analysis_type=analysis_type,
                        group_by_field=group_field,
                        target_condition_field=tgt_field,
                        target_condition_value=tgt_val,
                        rule_id=rule.rule_id,
                    )
                )
                observed_val = obs
                threshold_val = thresh

            # ---------------------------------------------------------------
            # A07: Distinct Count and Cardinality Analysis
            # ---------------------------------------------------------------
            elif algo == DetectionAlgorithm.A07_DISTINCT_COUNT:
                threshold = rule.threshold_value or 15.0
                window_sec = rule.time_window_seconds or 60
                target_field = (
                    rule.parsed_condition.get("target_field")
                    or rule.parsed_condition.get("distinct_field")
                    or "destination_port"
                )
                group_field = rule.parsed_condition.get("group_by", "source_address")

                matched, obs, thresh, evidence = (
                    self.threshold_detector.evaluate_distinct_count(
                        record=record,
                        target_field=target_field,
                        threshold=threshold,
                        window_seconds=window_sec,
                        group_by_field=group_field,
                        rule_id=rule.rule_id,
                    )
                )
                observed_val = obs
                threshold_val = thresh

            # ---------------------------------------------------------------
            # A08: Sequence and State-Based Detection
            # ---------------------------------------------------------------
            elif algo == DetectionAlgorithm.A08_SEQUENCE_STATE:
                group_field = rule.parsed_condition.get("group_by", "source_mac")
                event_field = rule.parsed_condition.get("event_field", "frame_subtype")
                exp_seq = rule.parsed_condition.get("expected_sequence")
                disallowed = rule.parsed_condition.get("disallowed_transitions")

                # If disallowed provided as list of dicts or lists
                parsed_disallowed = None
                if disallowed and isinstance(disallowed, list):
                    parsed_disallowed = [
                        (item[0], item[1]) for item in disallowed if len(item) >= 2
                    ]

                matched, evidence = self.pattern_identifier.evaluate_sequence_state(
                    record=record,
                    group_by_field=group_field,
                    event_field=event_field,
                    expected_sequence=exp_seq,
                    disallowed_transitions=parsed_disallowed,
                    rule_id=rule.rule_id,
                )

            # ---------------------------------------------------------------
            # A09: Baseline Deviation Detection
            # ---------------------------------------------------------------
            elif algo == DetectionAlgorithm.A09_BASELINE_DEVIATION:
                metric_field = (
                    rule.parsed_condition.get("metric_field")
                    or rule.parsed_condition.get("baseline_metric")
                    or "packet_length"
                )
                threshold_z = rule.threshold_value or 3.0
                min_samples = rule.parsed_condition.get("min_baseline_samples", 5)
                group_field = rule.parsed_condition.get("group_by", "source_address")

                matched, obs_z, thresh_z, evidence = (
                    self.statistical_detector.evaluate_baseline_deviation(
                        record=record,
                        metric_field=metric_field,
                        threshold_z_score=threshold_z,
                        min_baseline_samples=min_samples,
                        group_by_field=group_field,
                        rule_id=rule.rule_id,
                    )
                )
                observed_val = obs_z
                threshold_val = thresh_z

            # ---------------------------------------------------------------
            # A10: Allowlist and Policy Comparison
            # ---------------------------------------------------------------
            elif algo == DetectionAlgorithm.A10_ALLOWLIST_POLICY:
                field_to_check = (
                    rule.parsed_condition.get("field_to_check")
                    or rule.parsed_condition.get("field")
                    or "source_address"
                )
                allowlist = rule.parsed_condition.get("allowlist")
                policy_name = rule.parsed_condition.get("policy_name", rule.rule_name)

                matched, evidence = self.signature_detector.evaluate_allowlist_policy(
                    record=record,
                    field_to_check=field_to_check,
                    allowlist=allowlist,
                    policy_name=policy_name,
                )

            # ---------------------------------------------------------------
            # A11: Multi-Condition Correlation
            # ---------------------------------------------------------------
            elif algo == DetectionAlgorithm.A11_MULTI_CONDITION:
                conditions = rule.parsed_condition.get("conditions", [])
                corr_op = rule.parsed_condition.get("logical_operator", "AND")

                matched, evidence = (
                    self.pattern_identifier.evaluate_multi_condition_correlation(
                        record=record,
                        conditions=conditions,
                        correlation_operator=corr_op,
                    )
                )

            else:
                matched, evidence = self.signature_detector.evaluate_pattern(
                    record=record,
                    rule_protocol=rule.protocol,
                    condition=rule.parsed_condition or rule.detection_condition,
                )

        except Exception as exc:
            logger.error("Error evaluating rule '%s' (ID: %d): %s", rule.rule_name, rule.rule_id, exc)
            matched = False
            evidence = {
                "error": str(exc),
                "rule_name": rule.rule_name,
                "rule_id": rule.rule_id,
                "matched": False,
            }

        return DetectionOutcome(
            result_uuid=result_uuid,
            log_uuid=str(log_uuid).strip(),
            rule_id=rule.rule_id,
            rule_match_status=matched,
            detection_time=detection_time,
            observed_value=observed_val,
            threshold_value=threshold_val,
            detection_evidence=evidence,
            rule_name=rule.rule_name,
            suspicious_activity=rule.suspicious_activity,
            severity=rule.severity,
            source_address=src_addr,
            destination_address=dst_addr,
            source_mac=src_mac,
            destination_mac=dst_mac,
            protocol=protocol,
            log_details=log_details,
        )

    # -----------------------------------------------------------------------
    # Batch and Record Processing Orchestration
    # -----------------------------------------------------------------------

    def process_record(
        self,
        record: Union[ProcessedRecord, Dict[str, Any]],
        rules: Optional[List[DetectionRuleDefinition]] = None,
        persist_results: bool = True,
        forward_alerts: bool = True,
    ) -> List[DetectionOutcome]:
        """Processes a single record against rules, persisting results and forwarding alerts.

        Args:
            record: Processed traffic log record from E1.
            rules: Optional rule definitions (loads enabled rules from E3 if None).
            persist_results: Whether to store results into E3.
            forward_alerts: Whether to dispatch suspicious results to E4.

        Returns:
            List of DetectionOutcome instances for each evaluated rule.
        """
        active_rules = rules
        if active_rules is None:
            active_rules = self.rule_loader.load_rules_from_e3(self.storage_engine)

        if not active_rules:
            logger.warning("No enabled detection rules available for evaluation.")
            return []

        outcomes: List[DetectionOutcome] = []
        for rule in active_rules:
            try:
                outcome = self.evaluate_record_against_rule(record, rule)
                outcomes.append(outcome)

                e3_persisted = True
                # Persist to E3 (both matched and unmatched)
                if persist_results and self.storage_engine is not None:
                    try:
                        res = self.storage_engine.store_detection_result(**outcome.to_e3_kwargs())
                        if res is None:
                            e3_persisted = False
                    except Exception as exc:
                        e3_persisted = False
                        logger.error(
                            "Failed to store detection result %s in E3: %s",
                            outcome.result_uuid,
                            exc,
                        )

                # Forward suspicious match to E4 only if rule matched AND E3 persistence succeeded
                can_forward = outcome.rule_match_status and forward_alerts and self.alert_engine is not None
                if persist_results and self.storage_engine is not None:
                    can_forward = can_forward and e3_persisted

                if can_forward:
                    try:
                        payload = outcome.to_e4_payload()
                        self.alert_engine.process_result(payload, dispatch_to_storage=True)
                    except Exception as exc:
                        logger.error(
                            "Failed to forward suspicious result %s to E4: %s",
                            outcome.result_uuid,
                            exc,
                        )

            except InvalidRecordError as err:
                logger.warning("Skipping invalid record: %s", err)
                break
            except Exception as exc:
                logger.error("Unexpected error evaluating record against rule %d: %s", rule.rule_id, exc)

        return outcomes

    def process_batch(
        self,
        batch_input: Union[
            E1DetectionOutput,
            Sequence[ProcessedRecord],
            Sequence[Dict[str, Any]],
        ],
        rules: Optional[List[DetectionRuleDefinition]] = None,
        persist_results: bool = True,
        forward_alerts: bool = True,
    ) -> DetectionBatchResult:
        """Processes a collection or stream of log records from E1 through the detection pipeline.

        Args:
            batch_input: E1DetectionOutput dataclass, or sequence of ProcessedRecord / dicts.
            rules: Optional list of rules (fetches from E3 if None).
            persist_results: Whether to store matched and unmatched results via E3.
            forward_alerts: Whether to forward suspicious results to E4.

        Returns:
            DetectionBatchResult containing outcomes, matched results, and performance metrics.
        """
        start_wall = time.time()
        metrics = DetectionPerformanceMetrics()

        # Unpack batch input
        batch_id: Optional[str] = None
        records: Sequence[Union[ProcessedRecord, Dict[str, Any]]] = []

        if isinstance(batch_input, E1DetectionOutput):
            batch_id = batch_input.batch_id
            records = batch_input.records
        elif isinstance(batch_input, (list, tuple)):
            records = batch_input
            if records and isinstance(records[0], (ProcessedRecord, dict)):
                r0 = records[0]
                batch_id = getattr(r0, "batch_id", None) or (
                    r0.get("batch_id") if isinstance(r0, dict) else None
                )

        metrics.total_records_received = len(records)

        # Retrieve enabled rules if not passed explicitly
        active_rules = rules
        if active_rules is None:
            active_rules = self.rule_loader.load_rules_from_e3(self.storage_engine)

        all_outcomes: List[DetectionOutcome] = []
        matched_outcomes: List[DetectionOutcome] = []
        unmatched_outcomes: List[DetectionOutcome] = []

        for record in records:
            # Validate record presence and required log_id
            rec_log_id = getattr(record, "log_id", None) or (
                record.get("log_id") if isinstance(record, dict) else None
            )
            if not rec_log_id or not str(rec_log_id).strip():
                metrics.records_invalid += 1
                metrics.errors.append("Encountered record missing mandatory log_id.")
                continue

            metrics.records_processed += 1

            for rule in active_rules:
                metrics.rules_evaluated_count += 1
                try:
                    outcome = self.evaluate_record_against_rule(record, rule)
                    all_outcomes.append(outcome)

                    if outcome.rule_match_status:
                        metrics.matched_results_count += 1
                        matched_outcomes.append(outcome)
                    else:
                        metrics.unmatched_results_count += 1
                        unmatched_outcomes.append(outcome)

                    e3_persisted = True
                    # Persist to E3 (both matched and unmatched)
                    if persist_results and self.storage_engine is not None:
                        try:
                            res = self.storage_engine.store_detection_result(**outcome.to_e3_kwargs())
                            if res is None:
                                e3_persisted = False
                                metrics.e3_storage_failures += 1
                                metrics.errors.append(
                                    f"E3 storage returned empty response for result {outcome.result_uuid}"
                                )
                            else:
                                metrics.results_stored_e3 += 1
                        except Exception as exc:
                            e3_persisted = False
                            metrics.e3_storage_failures += 1
                            metrics.errors.append(
                                f"Failed to persist detection result {outcome.result_uuid} to E3: {str(exc)}"
                            )
                            logger.error(
                                "Failed to persist detection result %s to E3: %s",
                                outcome.result_uuid,
                                exc,
                            )

                    # Forward suspicious result to E4 only when rule_match_status is True
                    # AND E3 successfully persisted that exact detection result (when storage is enabled)
                    can_forward = outcome.rule_match_status and forward_alerts and self.alert_engine is not None
                    if persist_results and self.storage_engine is not None:
                        can_forward = can_forward and e3_persisted

                    if can_forward:
                        try:
                            payload = outcome.to_e4_payload()
                            self.alert_engine.process_result(payload, dispatch_to_storage=True)
                            metrics.alerts_forwarded_e4 += 1
                        except Exception as exc:
                            metrics.e4_forward_failures += 1
                            metrics.errors.append(
                                f"Failed to forward suspicious result {outcome.result_uuid} to E4: {str(exc)}"
                            )
                            logger.error(
                                "Failed to forward suspicious result %s to E4: %s",
                                outcome.result_uuid,
                                exc,
                            )

                except Exception as exc:
                    metrics.errors.append(
                        f"Record {rec_log_id} failed evaluation on rule {rule.rule_id}: {str(exc)}"
                    )
                    logger.error(
                        "Error evaluating record %s on rule %d: %s",
                        rec_log_id,
                        rule.rule_id,
                        exc,
                    )

        end_wall = time.time()
        metrics.complete(start_wall, end_wall)

        logger.info(
            "Batch %s completed: %d records processed, %d rules evaluated, "
            "%d matches, %d unmatched, duration=%.4fs (%.1f rec/s).",
            batch_id or "unknown",
            metrics.records_processed,
            metrics.rules_evaluated_count,
            metrics.matched_results_count,
            metrics.unmatched_results_count,
            metrics.duration_seconds,
            metrics.records_per_second,
        )

        return DetectionBatchResult(
            batch_id=batch_id,
            total_records=metrics.total_records_received,
            outcomes=all_outcomes,
            matched_outcomes=matched_outcomes,
            unmatched_outcomes=unmatched_outcomes,
            metrics=metrics,
        )


# Canonical alias
DetectionEngine = SuspiciousPatternDetectionEngine
