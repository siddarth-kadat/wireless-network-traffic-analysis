"""E2: Threshold Detector Module.

Implements:
- A05: Sliding Window Threshold Detection
- A06: Rate and Ratio Analysis
- A07: Distinct Count and Cardinality Analysis

Maintains bounded in-memory sliding windows with automatic expiration
to prevent uncontrolled memory growth.
"""

from collections import OrderedDict, deque
from datetime import datetime, timezone
import math
from typing import Any, Deque, Dict, List, Optional, Set, Tuple, Union

from backend.src.common.logger import get_logger
from backend.src.engines.e1_log_processing.log_processor import ProcessedRecord
from .rule_evaluator import extract_record_field

logger = get_logger(__name__)


def parse_timestamp_epoch(ts: Optional[Union[str, float, int]]) -> float:
    """Parses timestamp into float epoch seconds.

    Args:
        ts: ISO 8601 string or numeric timestamp.

    Returns:
        Float epoch seconds.
    """
    if ts is None:
        return datetime.now(timezone.utc).timestamp()
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, str):
        try:
            # Handle ISO string
            norm = ts.strip().replace("Z", "+00:00")
            dt = datetime.fromisoformat(norm)
            return dt.timestamp()
        except (ValueError, TypeError):
            try:
                return float(ts)
            except ValueError:
                return datetime.now(timezone.utc).timestamp()
    return datetime.now(timezone.utc).timestamp()


class BoundedSlidingWindowTracker:
    """Thread-safe, bounded-capacity sliding window tracker with LRU key eviction."""

    def __init__(self, max_keys: int = 5000, max_events_per_key: int = 1000) -> None:
        self.max_keys = max_keys
        self.max_events_per_key = max_events_per_key
        # key -> deque of (timestamp_epoch, event_payload)
        self._windows: OrderedDict[str, Deque[Tuple[float, Any]]] = OrderedDict()

    def add_event(
        self,
        key: str,
        timestamp_epoch: float,
        payload: Any = None,
        window_seconds: float = 60.0,
    ) -> Deque[Tuple[float, Any]]:
        """Adds an event and purges expired events for the key."""
        if key in self._windows:
            self._windows.move_to_end(key)
            window = self._windows[key]
        else:
            if len(self._windows) >= self.max_keys:
                self._windows.popitem(last=False)  # Evict oldest key
            window = deque(maxlen=self.max_events_per_key)
            self._windows[key] = window

        window.append((timestamp_epoch, payload))

        # Evict expired events
        cutoff = timestamp_epoch - max(window_seconds, 0.001)
        while window and window[0][0] < cutoff:
            window.popleft()

        return window

    def get_events(
        self, key: str, current_time_epoch: float, window_seconds: float
    ) -> List[Tuple[float, Any]]:
        """Returns non-expired events in window for a given key."""
        if key not in self._windows:
            return []
        cutoff = current_time_epoch - max(window_seconds, 0.001)
        window = self._windows[key]
        # Clean expired
        while window and window[0][0] < cutoff:
            window.popleft()
        return list(window)

    def clear(self) -> None:
        """Clears all sliding windows."""
        self._windows.clear()


class ThresholdDetector:
    """Executes volume, rate, ratio, and cardinality anomaly detection."""

    def __init__(self, max_tracker_keys: int = 5000) -> None:
        self.window_tracker = BoundedSlidingWindowTracker(max_keys=max_tracker_keys)
        self.cardinality_tracker = BoundedSlidingWindowTracker(max_keys=max_tracker_keys)
        self.ratio_tracker = BoundedSlidingWindowTracker(max_keys=max_tracker_keys)

    def reset(self) -> None:
        """Reset internal trackers (useful for testing)."""
        self.window_tracker.clear()
        self.cardinality_tracker.clear()
        self.ratio_tracker.clear()

    # -----------------------------------------------------------------------
    # A05 – Sliding Window Threshold Detection
    # -----------------------------------------------------------------------

    def evaluate_sliding_window_threshold(
        self,
        record: Union[ProcessedRecord, Dict[str, Any]],
        threshold: float,
        window_seconds: int = 60,
        group_by_field: Optional[str] = "source_address",
        rule_id: Optional[int] = None,
    ) -> Tuple[bool, float, float, Dict[str, Any]]:
        """Detects whether event count exceeds threshold within a sliding time window.

        Args:
            record: Processed traffic log record.
            threshold: Numeric event count threshold.
            window_seconds: Observation window in seconds.
            group_by_field: Field to partition window by (e.g. source_address, source_mac).
            rule_id: Rule ID for key scoping.

        Returns:
            Tuple of (matched: bool, observed_count: float, threshold: float, evidence: Dict).
        """
        # Determine tracking key
        key_val = "global"
        if group_by_field:
            found, val = extract_record_field(record, group_by_field)
            if found and val:
                key_val = str(val).strip()

        tracking_key = f"r{rule_id or 0}_{group_by_field or 'global'}_{key_val}"

        # Extract record timestamp
        ts_val = getattr(record, "timestamp", None)
        if ts_val is None and isinstance(record, dict):
            ts_val = record.get("timestamp")
        ts_epoch = parse_timestamp_epoch(ts_val)

        # Record event in sliding window
        window = self.window_tracker.add_event(
            key=tracking_key,
            timestamp_epoch=ts_epoch,
            payload=None,
            window_seconds=float(window_seconds),
        )

        observed_count = float(len(window))
        is_matched = observed_count >= threshold

        evidence = {
            "algorithm": "A05_SLIDING_WINDOW",
            "tracking_key": tracking_key,
            "group_by_field": group_by_field,
            "group_by_value": key_val,
            "observed_count": observed_count,
            "threshold": threshold,
            "window_seconds": window_seconds,
            "matched": is_matched,
            "description": (
                f"Observed {observed_count} events in {window_seconds}s window "
                f"(threshold: {threshold})"
            ),
        }

        return is_matched, observed_count, threshold, evidence

    # -----------------------------------------------------------------------
    # A06 – Rate and Ratio Analysis
    # -----------------------------------------------------------------------

    def evaluate_rate_and_ratio(
        self,
        record: Union[ProcessedRecord, Dict[str, Any]],
        threshold: float,
        window_seconds: int = 60,
        analysis_type: str = "rate",  # "rate" or "ratio"
        group_by_field: Optional[str] = "source_address",
        target_condition_field: Optional[str] = None,
        target_condition_value: Optional[Any] = None,
        rule_id: Optional[int] = None,
    ) -> Tuple[bool, float, float, Dict[str, Any]]:
        """Evaluates event rates (events/sec) or ratios (specific/total) in a window.

        Args:
            record: Processed traffic log record.
            threshold: Rate or ratio threshold to exceed.
            window_seconds: Observation window in seconds.
            analysis_type: 'rate' (events per sec) or 'ratio' (fraction 0.0 - 1.0).
            group_by_field: Entity partition field.
            target_condition_field: For ratio analysis, field identifying target event.
            target_condition_value: For ratio analysis, target value indicating positive event.
            rule_id: Rule identifier.

        Returns:
            Tuple of (matched: bool, observed_value: float, threshold: float, evidence: Dict).
        """
        key_val = "global"
        if group_by_field:
            found, val = extract_record_field(record, group_by_field)
            if found and val:
                key_val = str(val).strip()

        tracking_key = f"r{rule_id or 0}_{analysis_type}_{key_val}"

        ts_val = getattr(record, "timestamp", None)
        if ts_val is None and isinstance(record, dict):
            ts_val = record.get("timestamp")
        ts_epoch = parse_timestamp_epoch(ts_val)

        # Determine if this record matches the target condition (for ratio)
        is_target_event = True
        if analysis_type == "ratio" and target_condition_field:
            found, obs_val = extract_record_field(record, target_condition_field)
            if found and target_condition_value is not None:
                is_target_event = (
                    str(obs_val).strip().lower()
                    == str(target_condition_value).strip().lower()
                )
            else:
                is_target_event = False

        # Add event with payload = is_target_event
        window = self.ratio_tracker.add_event(
            key=tracking_key,
            timestamp_epoch=ts_epoch,
            payload=is_target_event,
            window_seconds=float(window_seconds),
        )

        total_events = len(window)
        win_duration = max(float(window_seconds), 1.0)

        if analysis_type == "rate":
            # Events per second
            observed_val = round(total_events / win_duration, 4)
            is_matched = observed_val >= threshold
            evidence = {
                "algorithm": "A06_RATE_ANALYSIS",
                "tracking_key": tracking_key,
                "analysis_type": "rate",
                "observed_rate_pps": observed_val,
                "threshold_rate_pps": threshold,
                "total_events": total_events,
                "window_seconds": window_seconds,
                "matched": is_matched,
            }
        else:
            # Ratio analysis: count of target events / total events
            target_count = sum(1 for _, payload in window if payload is True)
            observed_val = (
                round(target_count / total_events, 4) if total_events > 0 else 0.0
            )
            is_matched = observed_val >= threshold
            evidence = {
                "algorithm": "A06_RATIO_ANALYSIS",
                "tracking_key": tracking_key,
                "analysis_type": "ratio",
                "observed_ratio": observed_val,
                "threshold_ratio": threshold,
                "target_events": target_count,
                "total_events": total_events,
                "window_seconds": window_seconds,
                "matched": is_matched,
            }

        return is_matched, observed_val, threshold, evidence

    # -----------------------------------------------------------------------
    # A07 – Distinct Count and Cardinality Analysis
    # -----------------------------------------------------------------------

    def evaluate_distinct_count(
        self,
        record: Union[ProcessedRecord, Dict[str, Any]],
        target_field: str,
        threshold: float,
        window_seconds: int = 60,
        group_by_field: Optional[str] = "source_address",
        rule_id: Optional[int] = None,
    ) -> Tuple[bool, float, float, Dict[str, Any]]:
        """Identifies suspicious cardinality (e.g. port scan, host scan).

        Args:
            record: Processed traffic log record.
            target_field: Field whose distinct values are counted (e.g. destination_port, destination_address).
            threshold: Minimum distinct count to trigger match.
            window_seconds: Observation window in seconds.
            group_by_field: Entity whose cardinality is monitored (e.g. source_address).
            rule_id: Rule identifier.

        Returns:
            Tuple of (matched: bool, observed_distinct_count: float, threshold: float, evidence: Dict).
        """
        # Extract target field value
        found_target, target_val = extract_record_field(record, target_field)
        if not found_target or target_val is None:
            # Field is unavailable: do not invent values, do not trigger
            return (
                False,
                0.0,
                threshold,
                {
                    "algorithm": "A07_DISTINCT_COUNT",
                    "target_field": target_field,
                    "reason": f"Required target field '{target_field}' not available in record.",
                    "matched": False,
                },
            )

        key_val = "global"
        if group_by_field:
            found, val = extract_record_field(record, group_by_field)
            if found and val:
                key_val = str(val).strip()

        tracking_key = f"r{rule_id or 0}_distinct_{target_field}_{key_val}"

        ts_val = getattr(record, "timestamp", None)
        if ts_val is None and isinstance(record, dict):
            ts_val = record.get("timestamp")
        ts_epoch = parse_timestamp_epoch(ts_val)

        # Store the target field value in sliding window
        window = self.cardinality_tracker.add_event(
            key=tracking_key,
            timestamp_epoch=ts_epoch,
            payload=target_val,
            window_seconds=float(window_seconds),
        )

        # Compute unique distinct items
        distinct_items: Set[Any] = {payload for _, payload in window if payload is not None}
        distinct_count = float(len(distinct_items))
        is_matched = distinct_count >= threshold

        sample_items = [str(x) for x in list(distinct_items)[:10]]

        evidence = {
            "algorithm": "A07_DISTINCT_COUNT",
            "tracking_key": tracking_key,
            "target_field": target_field,
            "group_by_field": group_by_field,
            "group_by_value": key_val,
            "distinct_count": distinct_count,
            "threshold": threshold,
            "window_seconds": window_seconds,
            "sample_distinct_values": sample_items,
            "matched": is_matched,
        }

        return is_matched, distinct_count, threshold, evidence
