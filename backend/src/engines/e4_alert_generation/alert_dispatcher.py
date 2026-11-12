"""E4: Alert Dispatcher Module.

Forwards generated alerts to E3 (Log and Alert Storage Engine) with bounded exponential
retries, failure logging, and duplicate prevention, without directly accessing the database.
"""

import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Set

from ...common.configuration import settings
from ...common.exceptions import AlertDispatchError
from ...common.logger import get_logger
from .alert_builder import AlertPayload

logger = get_logger(__name__)


@dataclass
class DispatchResult:
    """Outcome of attempting to dispatch an alert to E3 storage."""

    alert_id: str
    result_id: str
    is_successful: bool
    attempts: int
    error_message: Optional[str] = None


class AlertDispatcher:
    """Dispatches generated alerts to E3 storage with bounded retries."""

    def __init__(
        self,
        storage_sink: Optional[Callable[[Dict[str, Any]], Any]] = None,
        max_retries: Optional[int] = None,
        initial_delay: Optional[float] = None,
        backoff_factor: float = 2.0,
    ) -> None:
        """Initializes the dispatcher.

        Args:
            storage_sink: Optional callable representing E3's alert storage interface.
                          Accepts an alert dictionary and returns truthy or raises on failure.
            max_retries: Maximum delivery attempts (defaults to settings.max_alert_retries).
            initial_delay: Initial delay in seconds before first retry (defaults to settings).
            backoff_factor: Multiplier for exponential backoff on retry.
        """
        self.storage_sink = storage_sink
        self.max_retries = (
            max_retries if max_retries is not None else settings.max_alert_retries
        )
        self.initial_delay = (
            initial_delay
            if initial_delay is not None
            else settings.alert_retry_delay_seconds
        )
        self.backoff_factor = backoff_factor
        self._dispatched_alert_ids: Set[str] = set()

    def set_storage_sink(self, sink: Callable[[Dict[str, Any]], Any]) -> None:
        """Configures or updates the target E3 storage sink callable."""
        self.storage_sink = sink

    def dispatch_alert(self, alert: AlertPayload) -> DispatchResult:
        """Dispatches a single alert to E3 with bounded retries.

        Args:
            alert: AlertPayload to forward to E3.

        Returns:
            DispatchResult detailing delivery status and retry attempts.
        """
        if not alert or not alert.alert_id:
            return DispatchResult(
                alert_id="unknown",
                result_id="unknown",
                is_successful=False,
                attempts=0,
                error_message="Alert is None or lacks alert_id.",
            )

        # Avoid re-dispatching already confirmed delivered alert
        if alert.alert_id in self._dispatched_alert_ids:
            logger.info("Alert '%s' was already successfully dispatched to E3.", alert.alert_id)
            return DispatchResult(
                alert_id=alert.alert_id,
                result_id=alert.result_id,
                is_successful=True,
                attempts=1,
                error_message=None,
            )

        alert_dict = alert.to_dict()
        attempts = 0
        current_delay = self.initial_delay
        last_error = None

        while attempts < self.max_retries:
            attempts += 1
            try:
                if self.storage_sink:
                    # Invoke E3 storage sink
                    self.storage_sink(alert_dict)
                else:
                    # Default simulated / pass-through E3 sink (for decoupled operation)
                    logger.debug(
                        "Default E3 sink received alert '%s' for result '%s'.",
                        alert.alert_id,
                        alert.result_id,
                    )

                self._dispatched_alert_ids.add(alert.alert_id)
                logger.info(
                    "Successfully dispatched Alert '%s' to E3 (Attempts: %d).",
                    alert.alert_id,
                    attempts,
                )
                return DispatchResult(
                    alert_id=alert.alert_id,
                    result_id=alert.result_id,
                    is_successful=True,
                    attempts=attempts,
                    error_message=None,
                )

            except Exception as exc:
                last_error = str(exc)
                logger.warning(
                    "E3 dispatch attempt %d/%d failed for Alert '%s': %s",
                    attempts,
                    self.max_retries,
                    alert.alert_id,
                    last_error,
                )
                if attempts < self.max_retries:
                    time.sleep(current_delay)
                    current_delay *= self.backoff_factor

        err_msg = f"Failed to dispatch Alert '{alert.alert_id}' after {attempts} attempts. Last error: {last_error}"
        logger.error(err_msg)
        return DispatchResult(
            alert_id=alert.alert_id,
            result_id=alert.result_id,
            is_successful=False,
            attempts=attempts,
            error_message=err_msg,
        )

    def dispatch_batch(
        self, alerts: Sequence[AlertPayload]
    ) -> List[DispatchResult]:
        """Dispatches a collection of alerts sequentially.

        Args:
            alerts: Sequence of AlertPayload items.

        Returns:
            List of DispatchResult records.
        """
        results: List[DispatchResult] = []
        for alert in alerts:
            res = self.dispatch_alert(alert)
            results.append(res)
        return results

