"""E2: Domain Exceptions for Suspicious Pattern Detection Engine.

Custom exception hierarchy for rule evaluation, pattern matching,
and detection engine orchestration.
"""

from typing import Any, Dict, Optional
from backend.src.common.exceptions import NetworkTrafficAnalysisError


class DetectionError(NetworkTrafficAnalysisError):
    """Base exception for all E2 Suspicious Pattern Detection Engine errors."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, details)


class RuleValidationError(DetectionError):
    """Raised when a detection rule definition is malformed, invalid, or missing required fields."""
    pass


class ConditionEvaluationError(DetectionError):
    """Raised when evaluation of a detection condition fails due to unsupported operators or syntax."""
    pass


class InvalidRecordError(DetectionError):
    """Raised when an incoming processed record from E1 fails structural or schema validation."""
    pass


class StorageIntegrationError(DetectionError):
    """Raised when communicating with E3 storage engine fails."""
    pass


class AlertForwardingError(DetectionError):
    """Raised when forwarding suspicious results to E4 alert generation fails."""
    pass


class InsufficientBaselineError(DetectionError):
    """Raised when baseline deviation detection cannot be evaluated due to insufficient data."""
    pass
