"""E2: Rule Loader Module.

Loads, validates, and categorizes detection rules from E3 storage.
Maps rules deterministically to their corresponding detection algorithms (A04-A11).
"""

from typing import Any, Dict, List, Optional, Union

from backend.src.common.logger import get_logger
from .exceptions import RuleValidationError
from .models import DetectionAlgorithm, DetectionRuleDefinition
from .rule_evaluator import RuleEvaluator

logger = get_logger(__name__)


class RuleLoader:
    """Retrieves and validates Detection_Rules from E3 storage gateway."""

    def __init__(self, evaluator: Optional[RuleEvaluator] = None) -> None:
        self.evaluator = evaluator or RuleEvaluator()
        self._cached_rules: List[DetectionRuleDefinition] = []

    def _infer_algorithm(
        self,
        raw_rule: Dict[str, Any],
        parsed_condition: Dict[str, Any],
    ) -> DetectionAlgorithm:
        """Determines the appropriate detection algorithm for a rule configuration.

        Args:
            raw_rule: Raw rule dictionary from E3.
            parsed_condition: Structured condition dictionary.

        Returns:
            DetectionAlgorithm enum member.
        """
        # 1. Check explicit algorithm declaration
        explicit_algo = parsed_condition.get("algorithm")
        if explicit_algo:
            clean_algo = str(explicit_algo).strip().upper()
            for member in DetectionAlgorithm:
                if member.value == clean_algo or member.name.upper() == clean_algo:
                    return member
            # Name mappings
            if "PATTERN" in clean_algo:
                return DetectionAlgorithm.A04_PATTERN_MATCHING
            if "WINDOW" in clean_algo:
                return DetectionAlgorithm.A05_SLIDING_WINDOW
            if "RATE" in clean_algo or "RATIO" in clean_algo:
                return DetectionAlgorithm.A06_RATE_RATIO
            if "DISTINCT" in clean_algo or "CARDINALITY" in clean_algo:
                return DetectionAlgorithm.A07_DISTINCT_COUNT
            if "SEQUENCE" in clean_algo or "STATE" in clean_algo:
                return DetectionAlgorithm.A08_SEQUENCE_STATE
            if "BASELINE" in clean_algo or "DEVIATION" in clean_algo or "STATISTICAL" in clean_algo:
                return DetectionAlgorithm.A09_BASELINE_DEVIATION
            if "ALLOWLIST" in clean_algo or "POLICY" in clean_algo or "WHITELIST" in clean_algo:
                return DetectionAlgorithm.A10_ALLOWLIST_POLICY
            if "MULTI" in clean_algo or "CORRELATION" in clean_algo:
                return DetectionAlgorithm.A11_MULTI_CONDITION

        # 2. Check for Multi-condition indicators
        if "conditions" in parsed_condition and isinstance(parsed_condition["conditions"], list):
            if len(parsed_condition["conditions"]) > 1:
                return DetectionAlgorithm.A11_MULTI_CONDITION

        # 3. Check for Allowlist / Policy indicators
        if "allowlist" in parsed_condition or "policy_name" in parsed_condition:
            return DetectionAlgorithm.A10_ALLOWLIST_POLICY

        # 4. Check for Sequence / State indicators
        if "expected_sequence" in parsed_condition or "disallowed_transitions" in parsed_condition:
            return DetectionAlgorithm.A08_SEQUENCE_STATE

        # 5. Check for Baseline Deviation indicators
        if "metric_field" in parsed_condition or "baseline_metric" in parsed_condition or "z_score" in parsed_condition:
            return DetectionAlgorithm.A09_BASELINE_DEVIATION

        # 6. Check for Distinct Count indicators
        if "distinct_field" in parsed_condition or "cardinality_field" in parsed_condition or "target_distinct" in parsed_condition:
            return DetectionAlgorithm.A07_DISTINCT_COUNT

        # 7. Check for Rate / Ratio indicators
        if "analysis_type" in parsed_condition:
            atype = str(parsed_condition["analysis_type"]).lower()
            if atype in ("rate", "ratio"):
                return DetectionAlgorithm.A06_RATE_RATIO

        # 8. Check for Threshold and Time Window (A05 Sliding Window default)
        threshold_val = raw_rule.get("threshold_value")
        window_sec = raw_rule.get("time_window_seconds")
        if threshold_val is not None and window_sec is not None and window_sec > 0:
            # Check if condition mentions rate or ratio in text
            raw_cond_str = str(raw_rule.get("detection_condition", "")).lower()
            if "rate" in raw_cond_str or "pps" in raw_cond_str:
                return DetectionAlgorithm.A06_RATE_RATIO
            if "ratio" in raw_cond_str:
                return DetectionAlgorithm.A06_RATE_RATIO
            if "distinct" in raw_cond_str:
                return DetectionAlgorithm.A07_DISTINCT_COUNT
            return DetectionAlgorithm.A05_SLIDING_WINDOW

        # 9. Default to A04 Rule-Based Pattern Matching
        return DetectionAlgorithm.A04_PATTERN_MATCHING

    def validate_and_parse_rule(
        self, raw_rule: Dict[str, Any]
    ) -> DetectionRuleDefinition:
        """Validates a single rule dictionary and constructs a DetectionRuleDefinition.

        Args:
            raw_rule: Dictionary containing Detection_Rule attributes from E3.

        Returns:
            Validated DetectionRuleDefinition instance.

        Raises:
            RuleValidationError: If mandatory fields are missing or invalid.
        """
        if not isinstance(raw_rule, dict):
            raise RuleValidationError(
                f"Rule definition must be a dictionary, got {type(raw_rule).__name__}"
            )

        # Check required fields
        rule_id = raw_rule.get("rule_id")
        if rule_id is None or not isinstance(rule_id, int):
            raise RuleValidationError(f"Invalid or missing 'rule_id': {rule_id}")

        rule_name = raw_rule.get("rule_name")
        if not rule_name or not str(rule_name).strip():
            raise RuleValidationError(f"Rule {rule_id}: 'rule_name' is missing or empty.")

        suspicious_activity = raw_rule.get("suspicious_activity")
        if not suspicious_activity or not str(suspicious_activity).strip():
            raise RuleValidationError(
                f"Rule '{rule_name}': 'suspicious_activity' is missing or empty."
            )

        condition_str = raw_rule.get("detection_condition")
        if not condition_str or not str(condition_str).strip():
            raise RuleValidationError(
                f"Rule '{rule_name}': 'detection_condition' is missing or empty."
            )

        protocol = str(raw_rule.get("protocol", "ANY")).strip()
        severity = str(raw_rule.get("severity", "MEDIUM")).strip().upper()
        is_enabled = bool(raw_rule.get("is_enabled", True))

        threshold_val: Optional[float] = None
        if raw_rule.get("threshold_value") is not None:
            try:
                threshold_val = float(raw_rule["threshold_value"])
            except (ValueError, TypeError):
                logger.warning(
                    "Rule '%s': invalid threshold_value '%s'",
                    rule_name,
                    raw_rule["threshold_value"],
                )

        window_sec: Optional[int] = None
        if raw_rule.get("time_window_seconds") is not None:
            try:
                window_sec = int(raw_rule["time_window_seconds"])
            except (ValueError, TypeError):
                logger.warning(
                    "Rule '%s': invalid time_window_seconds '%s'",
                    rule_name,
                    raw_rule["time_window_seconds"],
                )

        # Safely parse the condition
        parsed_cond = self.evaluator.parse_condition_string(condition_str)

        # Map to algorithm
        algorithm = self._infer_algorithm(raw_rule, parsed_cond)

        rule_def = DetectionRuleDefinition(
            rule_id=rule_id,
            rule_name=str(rule_name).strip(),
            suspicious_activity=str(suspicious_activity).strip(),
            protocol=protocol,
            detection_condition=condition_str,
            severity=severity,
            threshold_value=threshold_val,
            time_window_seconds=window_sec,
            is_enabled=is_enabled,
            algorithm=algorithm,
            parsed_condition=parsed_cond,
        )

        return rule_def

    def load_rules_from_e3(
        self, storage_engine: Any, refresh_cache: bool = True
    ) -> List[DetectionRuleDefinition]:
        """Fetches enabled rules from E3 StorageEngine.get_enabled_rules().

        Args:
            storage_engine: E3 StorageEngine instance.
            refresh_cache: If True, updates internal rule cache.

        Returns:
            List of validated DetectionRuleDefinition objects.
        """
        if storage_engine is None:
            logger.warning("No storage engine provided to RuleLoader.")
            return list(self._cached_rules)

        try:
            raw_rules = storage_engine.get_enabled_rules()
        except Exception as exc:
            logger.error("Failed to retrieve enabled rules from E3: %s", exc)
            return list(self._cached_rules)

        validated_rules: List[DetectionRuleDefinition] = []
        for raw in raw_rules:
            try:
                rule_def = self.validate_and_parse_rule(raw)
                validated_rules.append(rule_def)
            except RuleValidationError as err:
                logger.warning("Skipping invalid detection rule from E3: %s", err)

        if refresh_cache:
            self._cached_rules = validated_rules

        logger.info(
            "RuleLoader loaded %d validated enabled rules from E3.", len(validated_rules)
        )
        return validated_rules

    def get_cached_rules(self) -> List[DetectionRuleDefinition]:
        """Returns currently cached rule definitions."""
        return list(self._cached_rules)
