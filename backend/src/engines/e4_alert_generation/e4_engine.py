"""E4: Main Engine Entry Point Module (E4AlertEngine).

Integrates all E4 modules into a unified service entry point for inter-engine coordination,
batch processing, and FastAPI service hooks.
"""

from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from ...common.logger import get_logger
from .alert_builder import AlertBuilder, AlertPayload
from .alert_deduplicator import AlertDeduplicator
from .alert_dispatcher import AlertDispatcher
from .alert_generator import AlertGenerationSummary, AlertGenerator
from .alert_receiver import AlertReceiver, DetectionResultPayload
from .alert_validator import AlertValidator
from .severity_manager import SeverityManager

logger = get_logger(__name__)


class E4AlertEngine:
    """Primary engine coordinator for the E4 Alert Generation Engine."""

    def __init__(
        self,
        storage_sink: Optional[Callable[[Dict[str, Any]], Any]] = None,
        max_retries: Optional[int] = None,
        default_severity_fallback: str = "MEDIUM",
        dedup_cache_size: Optional[int] = None,
    ) -> None:
        """Initializes the E4 Alert Generation Engine.

        Args:
            storage_sink: Optional E3 storage hook (callable accepting alert dictionary).
            max_retries: Maximum dispatch retry attempts on transient failure.
            default_severity_fallback: Fallback severity if input is missing/invalid.
            dedup_cache_size: Capacity of deduplication cache.
        """
        self.receiver = AlertReceiver()
        self.validator = AlertValidator()
        self.severity_manager = SeverityManager()
        self.builder = AlertBuilder()
        self.deduplicator = AlertDeduplicator(max_size=dedup_cache_size)
        self.dispatcher = AlertDispatcher(
            storage_sink=storage_sink, max_retries=max_retries
        )

        self.generator = AlertGenerator(
            receiver=self.receiver,
            validator=self.validator,
            severity_manager=self.severity_manager,
            builder=self.builder,
            deduplicator=self.deduplicator,
            dispatcher=self.dispatcher,
        )
        logger.info("Initialized E4AlertEngine.")

    def set_storage_sink(self, sink: Callable[[Dict[str, Any]], Any]) -> None:
        """Configures or updates E3 storage sink callable."""
        self.dispatcher.set_storage_sink(sink)

    def process_result(
        self,
        detection_result: Union[Dict[str, Any], DetectionResultPayload, Any],
        dispatch_to_storage: bool = True,
    ) -> Tuple[Optional[AlertPayload], Optional[str]]:
        """Processes an individual detection result from E2.

        Args:
            detection_result: Dictionary or DetectionResultPayload from E2.
            dispatch_to_storage: Whether to immediately forward generated alert to E3.

        Returns:
            Tuple of (AlertPayload or None, error_or_skip_reason or None).
        """
        return self.generator.generate_alert_from_result(
            detection_result, dispatch_to_storage=dispatch_to_storage
        )

    def process_batch(
        self,
        detection_results: Sequence[Union[Dict[str, Any], DetectionResultPayload, Any]],
        dispatch_to_storage: bool = True,
    ) -> Tuple[List[AlertPayload], AlertGenerationSummary]:
        """Processes a collection of detection results from E2.

        Args:
            detection_results: Sequence of detection result dictionaries or payloads.
            dispatch_to_storage: Whether to dispatch alerts to E3 immediately.

        Returns:
            Tuple of (List of generated AlertPayloads, AlertGenerationSummary).
        """
        return self.generator.process_batch(
            detection_results, dispatch_to_storage=dispatch_to_storage
        )

    def reset_deduplication(self) -> None:
        """Clears the deduplication cache (useful for testing and batch resets)."""
        self.deduplicator.clear()

