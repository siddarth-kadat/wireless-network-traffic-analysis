"""E4: Alert Validator Module.

Validates detection result records prior to alert generation, determining whether
the payload represents confirmed suspicious activity according to the E2 contract.
"""

from dataclasses import dataclass
from typing import Optional, Set

from ...common.logger import get_logger
from .alert_receiver import DetectionResultPayload

logger = get_logger(__name__)

# Truthy representations of confirmed suspicious rule matches from E2
CONFIRMED_MATCH_STATUSES: Set[str] = {
    "true",
    "1",
    "matched",
    "suspicious",
    "confirmed",
    "alert",
    "detected",
}

# Explicitly benign / clean representations that should NOT trigger alerts
BENIGN_STATUSES: Set[str] = {
    "false",
    "0",
    "normal",
    "clean",
    "no_match",
    "unmatched",
    "benign",
}


@dataclass
class AlertValidationResult:
    """Outcome of validating a detection result for alert generation."""

    is_valid: bool
    is_suspicious: bool
    should_generate_alert: bool
    rejection_reason: Optional[str] = None
    payload: Optional[DetectionResultPayload] = None


class AlertValidator:
    """Validates detection results against E2 contracts and alert generation criteria."""

    def is_confirmed_suspicious(self, match_status: object) -> bool:
        """Determines if the rule_match_status represents confirmed suspicious activity.

        Args:
            match_status: The rule_match_status value (bool, str, int, etc.).

        Returns:
            True if confirmed suspicious; False otherwise.
        """
        if match_status is None:
            return False

        if isinstance(match_status, bool):
            return match_status

        if isinstance(match_status, (int, float)):
            return match_status == 1

        status_str = str(match_status).strip().lower()
        return status_str in CONFIRMED_MATCH_STATUSES

    def validate(
        self, payload: Optional[DetectionResultPayload]
    ) -> AlertValidationResult:
        """Validates a detection result payload for alert generation eligibility.

        Args:
            payload: DetectionResultPayload object.

        Returns:
            AlertValidationResult indicating whether an alert should be synthesized.
        """
        if payload is None:
            return AlertValidationResult(
                is_valid=False,
                is_suspicious=False,
                should_generate_alert=False,
                rejection_reason="Detection payload is None.",
            )

        # 1. Result identifier check
        if not payload.result_id or not str(payload.result_id).strip():
            return AlertValidationResult(
                is_valid=False,
                is_suspicious=False,
                should_generate_alert=False,
                rejection_reason="Missing or empty 'result_id'.",
                payload=payload,
            )

        # 2. Check for explicit error flags or incomplete detection outcomes
        raw = payload.raw_payload or {}
        if raw.get("is_complete") is False or raw.get("has_error") is True:
            logger.info(
                "Skipping incomplete or errored detection result '%s'.",
                payload.result_id,
            )
            return AlertValidationResult(
                is_valid=True,
                is_suspicious=False,
                should_generate_alert=False,
                rejection_reason="Detection result is incomplete or flagged with error.",
                payload=payload,
            )

        # 3. Check rule match status
        is_suspicious = self.is_confirmed_suspicious(payload.rule_match_status)
        if not is_suspicious:
            logger.debug(
                "Result '%s' indicates normal traffic (status: %s). No alert generated.",
                payload.result_id,
                payload.rule_match_status,
            )
            return AlertValidationResult(
                is_valid=True,
                is_suspicious=False,
                should_generate_alert=False,
                rejection_reason="Normal traffic (rule_match_status did not confirm suspicious activity).",
                payload=payload,
            )

        # Valid confirmed suspicious detection result
        logger.info(
            "Validated confirmed suspicious detection result '%s' (Rule: %s, Activity: %s).",
            payload.result_id,
            payload.rule_id or "unknown",
            payload.suspicious_activity or "unspecified",
        )
        return AlertValidationResult(
            is_valid=True,
            is_suspicious=True,
            should_generate_alert=True,
            rejection_reason=None,
            payload=payload,
        )

