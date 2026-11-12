"""E4: Alert Receiver Module.

Receives, unpacks, and performs initial structural ingestion of detection results
delivered by E2 (Suspicious Pattern Detection Engine).
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Union

from ...common.exceptions import AlertValidationError
from ...common.logger import get_logger

logger = get_logger(__name__)


@dataclass
class DetectionResultPayload:
    """Standardized representation of a detection result received from E2."""

    result_id: str
    rule_match_status: Union[bool, str, int]
    log_id: Optional[str] = None
    rule_id: Optional[str] = None
    observed_value: Optional[Union[float, int, str]] = None
    threshold_value: Optional[Union[float, int, str]] = None
    detection_evidence: Optional[Union[Dict[str, Any], str]] = None
    detection_time: Optional[str] = None

    # Contextual metadata from detection rule
    rule_name: Optional[str] = None
    suspicious_activity: Optional[str] = None
    severity: Optional[str] = None

    # Contextual metadata from traffic log
    source_address: Optional[str] = None
    destination_address: Optional[str] = None
    source_mac: Optional[str] = None
    destination_mac: Optional[str] = None
    protocol: Optional[str] = None
    log_details: Optional[Dict[str, Any]] = None

    # Diagnostic metadata
    raw_payload: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReceiverOutcome:
    """Outcome of receiving and parsing an incoming detection payload."""

    is_accepted: bool
    payload: Optional[DetectionResultPayload] = None
    rejection_reason: Optional[str] = None


class AlertReceiver:
    """Receives and parses detection results from E2."""

    def receive_result(
        self, raw_input: Union[Dict[str, Any], DetectionResultPayload, Any]
    ) -> ReceiverOutcome:
        """Parses and validates the incoming detection result structure.

        Args:
            raw_input: Raw detection result dictionary or payload object.

        Returns:
            ReceiverOutcome indicating acceptance or rejection with details.
        """
        if raw_input is None:
            return ReceiverOutcome(
                is_accepted=False,
                rejection_reason="Detection result payload is None.",
            )

        if isinstance(raw_input, DetectionResultPayload):
            if not raw_input.result_id or not str(raw_input.result_id).strip():
                return ReceiverOutcome(
                    is_accepted=False,
                    rejection_reason="Missing or empty 'result_id'.",
                )
            return ReceiverOutcome(is_accepted=True, payload=raw_input)

        if not isinstance(raw_input, dict):
            # Try to convert object attributes to dict if possible
            if hasattr(raw_input, "__dict__"):
                raw_dict = vars(raw_input)
            else:
                return ReceiverOutcome(
                    is_accepted=False,
                    rejection_reason=f"Unsupported payload type '{type(raw_input).__name__}'. Expected dict or DetectionResultPayload.",
                )
        else:
            raw_dict = raw_input

        # Check required fields
        result_id = raw_dict.get("result_id")
        if result_id is None or not str(result_id).strip():
            return ReceiverOutcome(
                is_accepted=False,
                rejection_reason="Missing or empty required field 'result_id'.",
            )

        if "rule_match_status" not in raw_dict:
            return ReceiverOutcome(
                is_accepted=False,
                rejection_reason="Missing required field 'rule_match_status'.",
            )

        result_id_str = str(result_id).strip()
        rule_match_status = raw_dict["rule_match_status"]

        # Parse associated fields without fabricating missing information
        log_id = str(raw_dict["log_id"]) if raw_dict.get("log_id") is not None else None
        rule_id = str(raw_dict["rule_id"]) if raw_dict.get("rule_id") is not None else None
        observed_val = raw_dict.get("observed_value")
        threshold_val = raw_dict.get("threshold_value")
        evidence = raw_dict.get("detection_evidence")
        det_time = (
            str(raw_dict["detection_time"])
            if raw_dict.get("detection_time")
            else datetime.now(timezone.utc).isoformat()
        )

        rule_name = raw_dict.get("rule_name")
        suspicious_act = raw_dict.get("suspicious_activity")
        severity = raw_dict.get("severity")

        src_addr = raw_dict.get("source_address")
        dst_addr = raw_dict.get("destination_address")
        src_mac = raw_dict.get("source_mac")
        dst_mac = raw_dict.get("destination_mac")
        protocol = raw_dict.get("protocol")
        log_details = raw_dict.get("log_details")

        payload = DetectionResultPayload(
            result_id=result_id_str,
            rule_match_status=rule_match_status,
            log_id=log_id,
            rule_id=rule_id,
            observed_value=observed_val,
            threshold_value=threshold_val,
            detection_evidence=evidence,
            detection_time=det_time,
            rule_name=rule_name,
            suspicious_activity=suspicious_act,
            severity=severity,
            source_address=src_addr,
            destination_address=dst_addr,
            source_mac=src_mac,
            destination_mac=dst_mac,
            protocol=protocol,
            log_details=log_details,
            raw_payload=raw_dict,
        )

        return ReceiverOutcome(is_accepted=True, payload=payload)

    def receive_batch(
        self, raw_items: Sequence[Union[Dict[str, Any], DetectionResultPayload, Any]]
    ) -> List[ReceiverOutcome]:
        """Receives a batch of detection results.

        Args:
            raw_items: Sequence of raw detection result dictionaries or payloads.

        Returns:
            List of ReceiverOutcome objects.
        """
        if not raw_items:
            logger.debug("Received empty detection batch.")
            return []

        outcomes: List[ReceiverOutcome] = []
        for idx, item in enumerate(raw_items):
            outcome = self.receive_result(item)
            if not outcome.is_accepted:
                logger.warning(
                    "Detection result at index %d rejected by receiver: %s",
                    idx,
                    outcome.rejection_reason,
                )
            outcomes.append(outcome)

        return outcomes

