"""E4: Alert Generation Engine Package.

Receives suspicious activity detection results from E2, validates criteria,
resolves and preserves severity, constructs structured security alerts conforming
to the Alert entity, and forwards alerts to E3 for storage.
"""

from .alert_builder import AlertBuilder, AlertPayload
from .alert_deduplicator import AlertDeduplicator
from .alert_dispatcher import AlertDispatcher, DispatchResult
from .alert_formatter import AlertFormatter
from .alert_generator import AlertGenerationSummary, AlertGenerator
from .alert_receiver import AlertReceiver, DetectionResultPayload, ReceiverOutcome
from .alert_validator import AlertValidationResult, AlertValidator
from .e4_engine import E4AlertEngine
from .severity_manager import SEVERITY_MAP, SeverityManager

__all__ = [
    "E4AlertEngine",
    "AlertGenerator",
    "AlertGenerationSummary",
    "AlertReceiver",
    "DetectionResultPayload",
    "ReceiverOutcome",
    "AlertValidator",
    "AlertValidationResult",
    "SeverityManager",
    "SEVERITY_MAP",
    "AlertBuilder",
    "AlertPayload",
    "AlertFormatter",
    "AlertDeduplicator",
    "AlertDispatcher",
    "DispatchResult",
]
