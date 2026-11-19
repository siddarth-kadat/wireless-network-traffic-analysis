"""Unit tests for E2 RuleEvaluator and RuleLoader components."""

import pytest
from unittest.mock import MagicMock

from backend.src.engines.e1_log_processing.log_processor import ProcessedRecord
from backend.src.engines.e2_suspicious_pattern_detection.exceptions import (
    ConditionEvaluationError,
    RuleValidationError,
)
from backend.src.engines.e2_suspicious_pattern_detection.models import DetectionAlgorithm
from backend.src.engines.e2_suspicious_pattern_detection.rule_evaluator import (
    RuleEvaluator,
    extract_record_field,
)
from backend.src.engines.e2_suspicious_pattern_detection.rule_loader import RuleLoader


class TestRuleEvaluator:
    def setup_method(self):
        self.evaluator = RuleEvaluator()
        self.sample_record = ProcessedRecord(
            log_id="11111111-1111-1111-1111-111111111111",
            batch_id="22222222-2222-2222-2222-222222222222",
            timestamp="2026-11-12T17:00:00+00:00",
            source_address="192.168.1.100",
            destination_address="192.168.1.1",
            source_mac="00:11:22:33:44:55",
            destination_mac="66:77:88:99:aa:bb",
            protocol="TCP",
            log_details={
                "packet_index": 42,
                "packet_length": 512,
                "destination_port": 80,
                "source_port": 54321,
                "wireless": {
                    "bssid": "00:14:22:01:23:45",
                    "ssid": "SecureWiFi",
                    "frame_type": "Management",
                    "frame_subtype": "Deauthentication",
                    "channel": 11,
                    "signal_strength": -70,
                },
            },
        )

    def test_extract_record_field_direct_and_aliased(self):
        found, val = extract_record_field(self.sample_record, "protocol")
        assert found is True and val == "TCP"

        found, val = extract_record_field(self.sample_record, "dst_port")
        assert found is True and val == 80

        found, val = extract_record_field(self.sample_record, "frame_subtype")
        assert found is True and val == "Deauthentication"

        found, val = extract_record_field(self.sample_record, "bssid")
        assert found is True and val == "00:14:22:01:23:45"

        found, val = extract_record_field(self.sample_record, "non_existent")
        assert found is False and val is None

    def test_parse_condition_string_json(self):
        json_str = '{"field": "dst_port", "operator": "<", "value": 1024}'
        parsed = self.evaluator.parse_condition_string(json_str)
        assert parsed["field"] == "dst_port"
        assert parsed["operator"] == "<"
        assert parsed["value"] == 1024

    def test_parse_condition_string_expression(self):
        expr = "dst_port < 1024"
        parsed = self.evaluator.parse_condition_string(expr)
        assert parsed["field"] == "dst_port"
        assert parsed["operator"] == "<"
        assert parsed["value"] == 1024

    def test_parse_condition_conjunction_and(self):
        expr = "protocol == 'TCP' and dst_port == 80"
        parsed = self.evaluator.parse_condition_string(expr)
        assert "conditions" in parsed
        assert parsed["logical_operator"] == "AND"
        assert len(parsed["conditions"]) == 2

    def test_evaluate_condition_success(self):
        cond = {"field": "dst_port", "operator": "==", "value": 80}
        matched, ev = self.evaluator.evaluate_condition(self.sample_record, cond)
        assert matched is True
        assert ev["observed_value"] == 80

    def test_evaluate_condition_unsupported_operator(self):
        cond = {"field": "dst_port", "operator": "unsupported_op", "value": 80}
        matched, ev = self.evaluator.evaluate_condition(self.sample_record, cond)
        assert matched is False
        assert "error" in ev


class TestRuleLoader:
    def setup_method(self):
        self.loader = RuleLoader()

    def test_validate_and_parse_valid_rule(self):
        raw = {
            "rule_id": 1,
            "rule_name": "Deauth_Attack_Detection",
            "suspicious_activity": "Deauthentication Flood",
            "protocol": "802.11_MGMT",
            "detection_condition": '{"field": "frame_subtype", "operator": "eq", "value": "Deauthentication"}',
            "threshold_value": 30.0,
            "time_window_seconds": 5,
            "severity": "CRITICAL",
            "is_enabled": True,
        }
        rule_def = self.loader.validate_and_parse_rule(raw)
        assert rule_def.rule_id == 1
        assert rule_def.rule_name == "Deauth_Attack_Detection"
        assert rule_def.algorithm == DetectionAlgorithm.A05_SLIDING_WINDOW
        assert rule_def.threshold_value == 30.0

    def test_algorithm_inference_for_all_types(self):
        # A04
        r4 = self.loader.validate_and_parse_rule({
            "rule_id": 4, "rule_name": "R4", "suspicious_activity": "A",
            "protocol": "TCP", "detection_condition": "dst_port == 23",
            "severity": "HIGH"
        })
        assert r4.algorithm == DetectionAlgorithm.A04_PATTERN_MATCHING

        # A05
        r5 = self.loader.validate_and_parse_rule({
            "rule_id": 5, "rule_name": "R5", "suspicious_activity": "A",
            "protocol": "TCP", "detection_condition": "dst_port == 80",
            "threshold_value": 10.0, "time_window_seconds": 60, "severity": "HIGH"
        })
        assert r5.algorithm == DetectionAlgorithm.A05_SLIDING_WINDOW

        # A06
        r6 = self.loader.validate_and_parse_rule({
            "rule_id": 6, "rule_name": "R6", "suspicious_activity": "A",
            "protocol": "TCP", "detection_condition": '{"analysis_type": "rate"}',
            "threshold_value": 5.0, "time_window_seconds": 10, "severity": "HIGH"
        })
        assert r6.algorithm == DetectionAlgorithm.A06_RATE_RATIO

        # A07
        r7 = self.loader.validate_and_parse_rule({
            "rule_id": 7, "rule_name": "R7", "suspicious_activity": "A",
            "protocol": "TCP", "detection_condition": '{"distinct_field": "dst_port"}',
            "severity": "HIGH"
        })
        assert r7.algorithm == DetectionAlgorithm.A07_DISTINCT_COUNT

        # A08
        r8 = self.loader.validate_and_parse_rule({
            "rule_id": 8, "rule_name": "R8", "suspicious_activity": "A",
            "protocol": "802.11", "detection_condition": '{"expected_sequence": ["AUTH", "ASSOC"]}',
            "severity": "HIGH"
        })
        assert r8.algorithm == DetectionAlgorithm.A08_SEQUENCE_STATE

        # A09
        r9 = self.loader.validate_and_parse_rule({
            "rule_id": 9, "rule_name": "R9", "suspicious_activity": "A",
            "protocol": "TCP", "detection_condition": '{"metric_field": "packet_length", "z_score": 3.0}',
            "severity": "HIGH"
        })
        assert r9.algorithm == DetectionAlgorithm.A09_BASELINE_DEVIATION

        # A10
        r10 = self.loader.validate_and_parse_rule({
            "rule_id": 10, "rule_name": "R10", "suspicious_activity": "A",
            "protocol": "TCP", "detection_condition": '{"allowlist": ["192.168.1.1"]}',
            "severity": "HIGH"
        })
        assert r10.algorithm == DetectionAlgorithm.A10_ALLOWLIST_POLICY

        # A11
        r11 = self.loader.validate_and_parse_rule({
            "rule_id": 11, "rule_name": "R11", "suspicious_activity": "A",
            "protocol": "TCP", "detection_condition": '{"conditions": [{"field": "a"}, {"field": "b"}]}',
            "severity": "HIGH"
        })
        assert r11.algorithm == DetectionAlgorithm.A11_MULTI_CONDITION

    def test_validate_rule_missing_fields_raises(self):
        with pytest.raises(RuleValidationError):
            self.loader.validate_and_parse_rule({"rule_name": "MissingID"})

        with pytest.raises(RuleValidationError):
            self.loader.validate_and_parse_rule({"rule_id": 1, "rule_name": ""})

        with pytest.raises(RuleValidationError):
            self.loader.validate_and_parse_rule({"rule_id": 1, "rule_name": "R", "suspicious_activity": ""})

    def test_load_rules_from_e3_handles_failure(self):
        mock_e3 = MagicMock()
        mock_e3.get_enabled_rules.side_effect = RuntimeError("Database connection down")
        # Should catch error, log, and return cached rules (empty) without crashing
        rules = self.loader.load_rules_from_e3(mock_e3)
        assert rules == []
