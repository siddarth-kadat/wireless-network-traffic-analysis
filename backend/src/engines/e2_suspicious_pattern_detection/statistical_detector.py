"""E2: Statistical Detector Module.

Implements:
- A09: Baseline Deviation Detection

Calculates deterministic statistical measures (mean, sample variance, standard deviation,
and Z-scores) against observed metric histories without using Machine Learning or AI models.
"""

from collections import OrderedDict, deque
import math
from typing import Any, Deque, Dict, List, Optional, Tuple, Union

from backend.src.common.logger import get_logger
from backend.src.engines.e1_log_processing.log_processor import ProcessedRecord
from .rule_evaluator import extract_record_field

logger = get_logger(__name__)


class StatisticalDetector:
    """Performs deterministic baseline calculation and deviation detection."""

    def __init__(self, max_entities: int = 5000, max_samples_per_entity: int = 1000) -> None:
        """Initializes detector with bounded history storage.

        Args:
            max_entities: Maximum tracked entities in LRU cache.
            max_samples_per_entity: Maximum baseline samples per entity.
        """
        self.max_entities = max_entities
        self.max_samples_per_entity = max_samples_per_entity
        # key -> deque of float values
        self._history: OrderedDict[str, Deque[float]] = OrderedDict()

    def reset(self) -> None:
        """Clears all accumulated baseline observations."""
        self._history.clear()

    def add_observation(self, key: str, value: float) -> Deque[float]:
        """Appends a numeric observation to the baseline history."""
        if key in self._history:
            self._history.move_to_end(key)
            history = self._history[key]
        else:
            if len(self._history) >= self.max_entities:
                self._history.popitem(last=False)
            history = deque(maxlen=self.max_samples_per_entity)
            self._history[key] = history

        history.append(float(value))
        return history

    def calculate_stats(self, values: List[float]) -> Tuple[float, float]:
        """Calculates arithmetic mean and standard deviation deterministically.

        Args:
            values: List of numeric values.

        Returns:
            Tuple of (mean, standard_deviation).
        """
        n = len(values)
        if n == 0:
            return 0.0, 0.0
        if n == 1:
            return values[0], 0.0

        mean = sum(values) / n
        # Deterministic sample variance: sum((x - mean)^2) / (n - 1)
        variance = sum((x - mean) ** 2 for x in values) / (n - 1)
        std_dev = math.sqrt(max(variance, 0.0))
        return mean, std_dev

    def evaluate_baseline_deviation(
        self,
        record: Union[ProcessedRecord, Dict[str, Any]],
        metric_field: str,
        threshold_z_score: float,
        min_baseline_samples: int = 5,
        group_by_field: Optional[str] = "source_address",
        rule_id: Optional[int] = None,
    ) -> Tuple[bool, Optional[float], float, Dict[str, Any]]:
        """Evaluates whether an observed metric significantly deviates from historical baseline.

        Args:
            record: Processed traffic log record.
            metric_field: Field name to measure (e.g. packet_length, payload_size).
            threshold_z_score: Z-score threshold (e.g. 2.5 or 3.0 standard deviations).
            min_baseline_samples: Minimum observations required before deviation can trigger.
            group_by_field: Entity partition field.
            rule_id: Rule identifier for key scoping.

        Returns:
            Tuple of (matched: bool, observed_z_score: float or None, threshold: float, evidence: Dict).
        """
        # 1. Extract the metric value
        found, val = extract_record_field(record, metric_field)
        if not found or val is None:
            return (
                False,
                None,
                threshold_z_score,
                {
                    "algorithm": "A09_BASELINE_DEVIATION",
                    "metric_field": metric_field,
                    "reason": f"Required metric field '{metric_field}' unavailable in record.",
                    "matched": False,
                },
            )

        try:
            current_value = float(val)
        except (ValueError, TypeError):
            return (
                False,
                None,
                threshold_z_score,
                {
                    "algorithm": "A09_BASELINE_DEVIATION",
                    "metric_field": metric_field,
                    "reason": f"Field '{metric_field}' value '{val}' is not numeric.",
                    "matched": False,
                },
            )

        # 2. Determine tracking key
        key_val = "global"
        if group_by_field:
            found_key, grp_val = extract_record_field(record, group_by_field)
            if found_key and grp_val:
                key_val = str(grp_val).strip()

        tracking_key = f"r{rule_id or 0}_base_{metric_field}_{key_val}"

        # 3. Retrieve existing baseline before adding current value
        existing_history = list(self._history.get(tracking_key, []))

        # 4. Check if baseline has enough observations
        if len(existing_history) < min_baseline_samples:
            # Not enough observations to establish statistically sound baseline
            self.add_observation(tracking_key, current_value)
            return (
                False,
                0.0,
                threshold_z_score,
                {
                    "algorithm": "A09_BASELINE_DEVIATION",
                    "tracking_key": tracking_key,
                    "metric_field": metric_field,
                    "observed_value": current_value,
                    "current_sample_count": len(existing_history) + 1,
                    "min_required_samples": min_baseline_samples,
                    "reason": "Insufficient baseline observations for deviation calculation.",
                    "matched": False,
                },
            )

        # 5. Calculate baseline statistics
        mean, std_dev = self.calculate_stats(existing_history)

        # Compute Z-score: |x - mean| / std_dev
        if std_dev > 0.000001:
            z_score = abs(current_value - mean) / std_dev
        else:
            # Zero variance in baseline
            if abs(current_value - mean) > 0.000001:
                # Value differs from constant baseline
                z_score = 999.0  # Infinite deviation
            else:
                z_score = 0.0

        is_matched = z_score >= threshold_z_score

        # Add current observation to history
        self.add_observation(tracking_key, current_value)

        evidence = {
            "algorithm": "A09_BASELINE_DEVIATION",
            "tracking_key": tracking_key,
            "metric_field": metric_field,
            "observed_value": current_value,
            "baseline_mean": round(mean, 4),
            "baseline_std_dev": round(std_dev, 4),
            "baseline_sample_count": len(existing_history),
            "observed_z_score": round(z_score, 4),
            "threshold_z_score": threshold_z_score,
            "matched": is_matched,
            "description": (
                f"Observed value {current_value} has Z-score {round(z_score, 2)} "
                f"against baseline mean {round(mean, 2)} +/- {round(std_dev, 2)} (threshold: {threshold_z_score})"
            ),
        }

        return is_matched, round(z_score, 4), threshold_z_score, evidence
