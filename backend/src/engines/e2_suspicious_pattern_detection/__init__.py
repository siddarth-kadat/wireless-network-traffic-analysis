"""E2: Suspicious Pattern Detection Engine Module.

Provides deterministic, rule-based detection for wireless network traffic
using the eight approved algorithms (A04-A11).
"""

from .detection_engine import DetectionEngine, SuspiciousPatternDetectionEngine
from .exceptions import (
    AlertForwardingError,
    ConditionEvaluationError,
    DetectionError,
    InsufficientBaselineError,
    InvalidRecordError,
    RuleValidationError,
    StorageIntegrationError,
)
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

__all__ = [
    "DetectionEngine",
    "SuspiciousPatternDetectionEngine",
    "DetectionAlgorithm",
    "DetectionBatchResult",
    "DetectionOutcome",
    "DetectionPerformanceMetrics",
    "DetectionRuleDefinition",
    "RuleLoader",
    "RuleEvaluator",
    "SignatureDetector",
    "ThresholdDetector",
    "StatisticalDetector",
    "PatternIdentifier",
    "extract_record_field",
    "DetectionError",
    "RuleValidationError",
    "ConditionEvaluationError",
    "InvalidRecordError",
    "StorageIntegrationError",
    "AlertForwardingError",
    "InsufficientBaselineError",
]
