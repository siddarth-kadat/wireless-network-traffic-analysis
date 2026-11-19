"""E2: Domain Models and Data Structures for Suspicious Pattern Detection Engine."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
import uuid


class DetectionAlgorithm(str, Enum):
    """The 8 approved deterministic detection algorithms for E2."""

    A04_PATTERN_MATCHING = "A04"
    A05_SLIDING_WINDOW = "A05"
    A06_RATE_RATIO = "A06"
    A07_DISTINCT_COUNT = "A07"
    A08_SEQUENCE_STATE = "A08"
    A09_BASELINE_DEVIATION = "A09"
    A10_ALLOWLIST_POLICY = "A10"
    A11_MULTI_CONDITION = "A11"


@dataclass
class DetectionRuleDefinition:
    """Validated in-memory representation of a Detection_Rule from E3."""

    rule_id: int
    rule_name: str
    suspicious_activity: str
    protocol: str
    detection_condition: str
    severity: str
    threshold_value: Optional[float] = None
    time_window_seconds: Optional[int] = None
    is_enabled: bool = True
    algorithm: DetectionAlgorithm = DetectionAlgorithm.A04_PATTERN_MATCHING
    parsed_condition: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert rule definition to dictionary."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "suspicious_activity": self.suspicious_activity,
            "protocol": self.protocol,
            "detection_condition": self.detection_condition,
            "threshold_value": self.threshold_value,
            "time_window_seconds": self.time_window_seconds,
            "severity": self.severity,
            "is_enabled": self.is_enabled,
            "algorithm": self.algorithm.value,
            "parsed_condition": self.parsed_condition,
        }


@dataclass
class DetectionOutcome:
    """Individual rule evaluation result produced by E2."""

    result_uuid: str
    log_uuid: str
    rule_id: int
    rule_match_status: bool
    detection_time: str
    observed_value: Optional[float] = None
    threshold_value: Optional[float] = None
    detection_evidence: Optional[Dict[str, Any]] = None

    # Contextual metadata from rule
    rule_name: Optional[str] = None
    suspicious_activity: Optional[str] = None
    severity: Optional[str] = None

    # Contextual metadata from traffic log
    source_address: Optional[str] = None
    destination_address: Optional[str] = None
    source_mac: Optional[str] = None
    destination_mac: Optional[str] = None
    protocol: Optional[str] = None
    log_details: Optional[Dict[str, Any]] = None

    def to_e3_kwargs(self) -> Dict[str, Any]:
        """Arguments matching StorageEngine.store_detection_result signature."""
        return {
            "result_uuid": self.result_uuid,
            "log_uuid": self.log_uuid,
            "rule_id": self.rule_id,
            "rule_match_status": self.rule_match_status,
            "detection_time": self.detection_time,
            "observed_value": self.observed_value,
            "threshold_value": self.threshold_value,
            "detection_evidence": self.detection_evidence,
        }

    def to_e4_payload(self) -> Dict[str, Any]:
        """Dictionary matching E4 DetectionResultPayload input contract."""
        return {
            "result_id": self.result_uuid,
            "rule_match_status": self.rule_match_status,
            "log_id": self.log_uuid,
            "rule_id": str(self.rule_id),
            "rule_name": self.rule_name,
            "suspicious_activity": self.suspicious_activity,
            "severity": self.severity,
            "observed_value": self.observed_value,
            "threshold_value": self.threshold_value,
            "detection_evidence": self.detection_evidence,
            "detection_time": self.detection_time,
            "source_address": self.source_address,
            "destination_address": self.destination_address,
            "source_mac": self.source_mac,
            "destination_mac": self.destination_mac,
            "protocol": self.protocol,
            "log_details": self.log_details,
            "raw_payload": {
                "result_uuid": self.result_uuid,
                "log_uuid": self.log_uuid,
                "rule_id": self.rule_id,
            },
        }

    def to_dict(self) -> Dict[str, Any]:
        """Full dictionary representation."""
        return asdict(self)


@dataclass
class DetectionPerformanceMetrics:
    """Measurable execution metrics for E2 processing operations."""

    total_records_received: int = 0
    records_processed: int = 0
    records_invalid: int = 0
    rules_evaluated_count: int = 0
    matched_results_count: int = 0
    unmatched_results_count: int = 0
    results_stored_e3: int = 0
    e3_storage_failures: int = 0
    alerts_forwarded_e4: int = 0
    e4_forward_failures: int = 0
    processing_start_time: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    processing_end_time: str = ""
    duration_seconds: float = 0.0
    records_per_second: float = 0.0
    evaluations_per_second: float = 0.0
    errors: List[str] = field(default_factory=list)

    def complete(self, start_wall_time: float, end_wall_time: float) -> None:
        """Finalize calculated duration and rates."""
        self.processing_end_time = datetime.now(timezone.utc).isoformat()
        self.duration_seconds = max(end_wall_time - start_wall_time, 0.000001)
        self.records_per_second = round(
            self.records_processed / self.duration_seconds, 2
        )
        self.evaluations_per_second = round(
            self.rules_evaluated_count / self.duration_seconds, 2
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return asdict(self)


@dataclass
class DetectionBatchResult:
    """Overall outcome of processing a batch of records through E2."""

    batch_id: Optional[str]
    total_records: int
    outcomes: List[DetectionOutcome]
    matched_outcomes: List[DetectionOutcome]
    unmatched_outcomes: List[DetectionOutcome]
    metrics: DetectionPerformanceMetrics

    def to_dict(self) -> Dict[str, Any]:
        """Convert batch result to summary dictionary."""
        return {
            "batch_id": self.batch_id,
            "total_records": self.total_records,
            "total_outcomes": len(self.outcomes),
            "matched_count": len(self.matched_outcomes),
            "unmatched_count": len(self.unmatched_outcomes),
            "metrics": self.metrics.to_dict(),
        }
