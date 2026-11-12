"""E4: Alert Formatter Module.

Sanitizes alert descriptions and evidence payloads to prevent XSS/injection,
and structures rich contextual metadata for security analysts and downstream storage.
"""

import html
import re
from typing import Any, Dict, Optional

from ...common.logger import get_logger
from .alert_receiver import DetectionResultPayload

logger = get_logger(__name__)

# Pattern to strip dangerous unprintable control characters (preserving tab, newline, CR)
CONTROL_CHAR_REGEX = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class AlertFormatter:
    """Sanitizes text and formats alert context payloads."""

    def sanitize_text(self, text: Optional[str]) -> Optional[str]:
        """Sanitizes input strings by escaping HTML entities and stripping control characters.

        Args:
            text: Raw input string.

        Returns:
            Sanitized string or None if text is None.
        """
        if text is None:
            return None
        stripped = CONTROL_CHAR_REGEX.sub("", str(text).strip())
        return html.escape(stripped, quote=True)

    def sanitize_evidence(self, evidence: Any) -> Any:
        """Recursively sanitizes evidence dictionaries or strings.

        Args:
            evidence: Dictionary, string, or primitive evidence payload.

        Returns:
            Sanitized evidence structure.
        """
        if evidence is None:
            return None
        if isinstance(evidence, str):
            return self.sanitize_text(evidence)
        if isinstance(evidence, dict):
            return {
                self.sanitize_text(str(k)): self.sanitize_evidence(v)
                for k, v in evidence.items()
            }
        if isinstance(evidence, (list, tuple)):
            return [self.sanitize_evidence(item) for item in evidence]
        return evidence

    def format_alert_details(
        self, payload: DetectionResultPayload, severity: str
    ) -> Dict[str, Any]:
        """Constructs sanitized alert_details dictionary adhering to the project schema.

        Args:
            payload: DetectionResultPayload from E2.
            severity: Normalized severity rating.

        Returns:
            Dictionary containing structured alert details.
        """
        activity_sanitized = self.sanitize_text(
            payload.suspicious_activity or "Unspecified Suspicious Activity"
        )
        rule_name_sanitized = self.sanitize_text(payload.rule_name or "Custom Detection Rule")
        evidence_sanitized = self.sanitize_evidence(payload.detection_evidence)

        # Extract wireless info from log_details if present without inventing values
        wireless_info = None
        if isinstance(payload.log_details, dict):
            wireless_info = payload.log_details.get("wireless")

        network_context = {
            "source_address": payload.source_address,
            "destination_address": payload.destination_address,
            "source_mac": payload.source_mac,
            "destination_mac": payload.destination_mac,
            "protocol": payload.protocol,
            "wireless": wireless_info,
        }

        # Build clean summary narrative
        observed = payload.observed_value
        threshold = payload.threshold_value
        metrics_desc = ""
        if observed is not None and threshold is not None:
            metrics_desc = f" (Observed: {observed} | Threshold: {threshold})"
        elif observed is not None:
            metrics_desc = f" (Observed: {observed})"

        src_desc = payload.source_address or payload.source_mac or "Unknown Source"
        dst_desc = payload.destination_address or payload.destination_mac or "Unknown Destination"

        summary_desc = (
            f"[{severity}] {activity_sanitized} detected by rule '{rule_name_sanitized}' "
            f"from {src_desc} to {dst_desc}{metrics_desc}."
        )

        return {
            "suspicious_activity": activity_sanitized,
            "rule_id": payload.rule_id,
            "rule_name": rule_name_sanitized,
            "log_id": payload.log_id,
            "network_context": network_context,
            "metrics": {
                "observed_value": observed,
                "threshold_value": threshold,
            },
            "detection_evidence": evidence_sanitized,
            "summary_description": summary_desc,
        }
