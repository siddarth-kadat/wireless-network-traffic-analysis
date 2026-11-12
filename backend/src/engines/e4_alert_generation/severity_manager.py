"""E4: Severity Manager Module.

Normalizes, validates, and preserves the severity level assigned by E2 detection rules
or results, ensuring conformity with approved SeverityLevel standards without altering classifications.
"""

from typing import Optional, Union

from ...common.constants import SeverityLevel
from ...common.exceptions import InvalidSeverityError
from ...common.logger import get_logger

logger = get_logger(__name__)

# Valid standardized severity mappings
SEVERITY_MAP = {
    "low": SeverityLevel.LOW.value,
    "1": SeverityLevel.LOW.value,
    "medium": SeverityLevel.MEDIUM.value,
    "med": SeverityLevel.MEDIUM.value,
    "2": SeverityLevel.MEDIUM.value,
    "high": SeverityLevel.HIGH.value,
    "3": SeverityLevel.HIGH.value,
    "critical": SeverityLevel.CRITICAL.value,
    "crit": SeverityLevel.CRITICAL.value,
    "4": SeverityLevel.CRITICAL.value,
}


class SeverityManager:
    """Manages alert severity resolution, normalization, and preservation."""

    def __init__(
        self,
        default_severity: SeverityLevel = SeverityLevel.MEDIUM,
        strict_mode: bool = False,
    ) -> None:
        """Initializes the severity manager.

        Args:
            default_severity: Fallback severity when input is absent or invalid (defaults to MEDIUM).
            strict_mode: If True, raises InvalidSeverityError on unknown values instead of falling back.
        """
        self.default_severity = default_severity
        self.strict_mode = strict_mode

    def resolve_severity(
        self,
        severity_value: Optional[Union[str, int, float]],
        context_id: Optional[str] = None,
    ) -> str:
        """Normalizes and validates incoming severity while preserving its classification.

        Args:
            severity_value: Severity assigned by E2 detection rule or result.
            context_id: Optional result_id for logging diagnostics.

        Returns:
            Normalized uppercase severity string ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').

        Raises:
            InvalidSeverityError: If strict_mode is True and severity cannot be mapped.
        """
        if severity_value is None:
            if self.strict_mode:
                raise InvalidSeverityError(
                    f"Missing severity value for detection result '{context_id}'."
                )
            logger.warning(
                "Result '%s' has missing severity; defaulting to '%s'.",
                context_id or "unknown",
                self.default_severity.value,
            )
            return self.default_severity.value

        clean_str = str(severity_value).strip().lower()
        if clean_str in SEVERITY_MAP:
            normalized = SEVERITY_MAP[clean_str]
            logger.debug(
                "Preserved severity '%s' -> '%s' for context '%s'.",
                severity_value,
                normalized,
                context_id,
            )
            return normalized

        if self.strict_mode:
            raise InvalidSeverityError(
                f"Invalid severity value '{severity_value}' for context '{context_id}'."
            )

        logger.warning(
            "Unknown severity '%s' for result '%s'; applying fallback '%s'.",
            severity_value,
            context_id or "unknown",
            self.default_severity.value,
        )
        return self.default_severity.value

