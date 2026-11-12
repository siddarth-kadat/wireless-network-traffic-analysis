"""Unit tests for E4 Alert Validator Module."""

import pytest

from src.engines.e4_alert_generation.alert_receiver import DetectionResultPayload
from src.engines.e4_alert_generation.alert_validator import AlertValidator


def test_validator_confirmed_suspicious_statuses() -> None:
    """Tests that confirmed match statuses trigger alert generation."""
    validator = AlertValidator()

    for status in [True, 1, "MATCHED", "SUSPICIOUS", "confirmed", "TRUE"]:
        payload = DetectionResultPayload(
            result_id="res-suspicious",
            rule_match_status=status,
            severity="HIGH",
        )
        res = validator.validate(payload)
        assert res.is_valid is True
        assert res.is_suspicious is True
        assert res.should_generate_alert is True


def test_validator_normal_traffic_skipped() -> None:
    """Tests that benign/clean detection results do not trigger alert generation."""
    validator = AlertValidator()

    for status in [False, 0, "NORMAL", "CLEAN", "NO_MATCH", "unmatched"]:
        payload = DetectionResultPayload(
            result_id="res-benign",
            rule_match_status=status,
            severity="LOW",
        )
        res = validator.validate(payload)
        assert res.is_valid is True
        assert res.is_suspicious is False
        assert res.should_generate_alert is False
        assert "normal" in res.rejection_reason.lower()


def test_validator_incomplete_or_errored_results_skipped() -> None:
    """Tests that incomplete detection results do not generate alerts."""
    validator = AlertValidator()

    payload = DetectionResultPayload(
        result_id="res-incomplete",
        rule_match_status=True,
        raw_payload={"is_complete": False},
    )
    res = validator.validate(payload)
    assert res.should_generate_alert is False
    assert "incomplete" in res.rejection_reason.lower()

    payload_err = DetectionResultPayload(
        result_id="res-error",
        rule_match_status=True,
        raw_payload={"has_error": True},
    )
    res_err = validator.validate(payload_err)
    assert res_err.should_generate_alert is False


def test_validator_missing_result_id_invalid() -> None:
    """Tests that empty result_id fails validation."""
    validator = AlertValidator()

    payload = DetectionResultPayload(
        result_id="",
        rule_match_status=True,
    )
    res = validator.validate(payload)
    assert res.is_valid is False
    assert res.should_generate_alert is False


def test_validator_none_payload_invalid() -> None:
    """Tests that None payload fails validation."""
    validator = AlertValidator()
    res = validator.validate(None)
    assert res.is_valid is False
    assert res.should_generate_alert is False

