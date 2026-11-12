"""E4: Alert Builder Module.

Constructs structured, schema-compliant security alert records conforming to the
approved Alert database entity.
"""

import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from ...common.constants import AlertStatus
from ...common.logger import get_logger
from .alert_formatter import AlertFormatter
from .alert_receiver import DetectionResultPayload

logger = get_logger(__name__)


@dataclass
class AlertPayload:
    """Security alert matching the approved Alert database entity schema."""

    alert_id: str
    result_id: str
    alert_details: Dict[str, Any]
    alert_timestamp: str
    severity: str
    alert_status: str = AlertStatus.NEW.value

    def to_dict(self) -> Dict[str, Any]:
        """Serializes alert to dictionary matching the Alert database table schema."""
        return {
            "alert_id": self.alert_id,
            "result_id": self.result_id,
            "alert_details": self.alert_details,
            "alert_timestamp": self.alert_timestamp,
            "severity": self.severity,
            "alert_status": self.alert_status,
        }


class AlertBuilder:
    """Builds structured AlertPayload records from validated detection results."""

    def __init__(self, formatter: Optional[AlertFormatter] = None) -> None:
        """Initializes the builder.

        Args:
            formatter: Optional AlertFormatter instance (creates default if None).
        """
        self.formatter = formatter or AlertFormatter()

    def build_alert(
        self,
        payload: DetectionResultPayload,
        severity: str,
        alert_id: Optional[str] = None,
        custom_status: Optional[str] = None,
    ) -> AlertPayload:
        """Constructs an AlertPayload conforming to the approved Alert entity schema.

        Args:
            payload: Validated DetectionResultPayload.
            severity: Normalized severity level string.
            alert_id: Optional predetermined alert ID (generates UUID4 if omitted).
            custom_status: Optional initial status override (defaults to AlertStatus.NEW).

        Returns:
            Structured AlertPayload object.
        """
        assigned_alert_id = alert_id or str(uuid.uuid4())
        alert_timestamp = datetime.now(timezone.utc).isoformat()
        initial_status = custom_status or AlertStatus.NEW.value

        formatted_details = self.formatter.format_alert_details(payload, severity)

        alert = AlertPayload(
            alert_id=assigned_alert_id,
            result_id=payload.result_id,
            alert_details=formatted_details,
            alert_timestamp=alert_timestamp,
            severity=severity,
            alert_status=initial_status,
        )

        logger.info(
            "Constructed Alert '%s' for Result '%s' (Severity: %s, Status: %s).",
            alert.alert_id,
            alert.result_id,
            alert.severity,
            alert.alert_status,
        )
        return alert
