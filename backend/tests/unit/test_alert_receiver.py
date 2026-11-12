"""Unit tests for E4 Alert Receiver Module."""

import pytest

from src.engines.e4_alert_generation.alert_receiver import (
    AlertReceiver,
    DetectionResultPayload,
    ReceiverOutcome,
)


def test_receive_valid_dict_payload() -> None:
    """Tests receiving a well-formed detection result dictionary."""
    receiver = AlertReceiver()
    raw = {
        "result_id": "res-101",
        "log_id": "log-500",
        "rule_id": "rule-deauth-01",
        "rule_match_status": True,
        "observed_value": 150,
        "threshold_value": 50,
        "detection_evidence": {"frame_count": 150, "subtype": "Deauthentication"},
        "severity": "HIGH",
        "suspicious_activity": "Deauthentication Flood",
        "source_mac": "00:11:22:33:44:55",
        "destination_mac": "ff:ff:ff:ff:ff:ff",
        "protocol": "802.11_MGMT",
    }

    outcome = receiver.receive_result(raw)

    assert outcome.is_accepted is True
    assert outcome.payload is not None
    assert outcome.payload.result_id == "res-101"
    assert outcome.payload.log_id == "log-500"
    assert outcome.payload.rule_id == "rule-deauth-01"
    assert outcome.payload.rule_match_status is True
    assert outcome.payload.severity == "HIGH"
    assert outcome.payload.source_mac == "00:11:22:33:44:55"


def test_receive_dataclass_payload() -> None:
    """Tests receiving a DetectionResultPayload object directly."""
    receiver = AlertReceiver()
    payload = DetectionResultPayload(
        result_id="res-102",
        rule_match_status="MATCHED",
        severity="CRITICAL",
    )

    outcome = receiver.receive_result(payload)

    assert outcome.is_accepted is True
    assert outcome.payload.result_id == "res-102"
    assert outcome.payload.rule_match_status == "MATCHED"


def test_receive_missing_result_id_rejected() -> None:
    """Tests that payloads lacking result_id are rejected."""
    receiver = AlertReceiver()
    raw = {
        "rule_match_status": True,
        "severity": "MEDIUM",
    }

    outcome = receiver.receive_result(raw)

    assert outcome.is_accepted is False
    assert "result_id" in outcome.rejection_reason.lower()


def test_receive_missing_match_status_rejected() -> None:
    """Tests that payloads lacking rule_match_status are rejected."""
    receiver = AlertReceiver()
    raw = {
        "result_id": "res-103",
    }

    outcome = receiver.receive_result(raw)

    assert outcome.is_accepted is False
    assert "rule_match_status" in outcome.rejection_reason.lower()


def test_receive_none_payload_rejected() -> None:
    """Tests that None payload is handled safely and rejected."""
    receiver = AlertReceiver()
    outcome = receiver.receive_result(None)

    assert outcome.is_accepted is False
    assert "none" in outcome.rejection_reason.lower()


def test_receive_batch_with_mixed_records() -> None:
    """Tests receiving a batch containing valid and invalid items."""
    receiver = AlertReceiver()
    batch = [
        {"result_id": "res-1", "rule_match_status": True},
        {"invalid_field": "no result id"},
        {"result_id": "res-2", "rule_match_status": False},
    ]

    outcomes = receiver.receive_batch(batch)

    assert len(outcomes) == 3
    assert outcomes[0].is_accepted is True
    assert outcomes[1].is_accepted is False
    assert outcomes[2].is_accepted is True

