"""E2: Signature Detector Module.

Implements:
- A04: Rule-Based Pattern Matching (known attack signatures and malformed frames)
- A10: Allowlist and Policy Comparison (approved addresses, protocols, and policies)
"""

from typing import Any, Dict, List, Optional, Set, Tuple, Union

from backend.src.common.logger import get_logger
from backend.src.engines.e1_log_processing.log_processor import ProcessedRecord
from .rule_evaluator import RuleEvaluator, extract_record_field

logger = get_logger(__name__)


class SignatureDetector:
    """Executes rule-based signature matching and policy allowlist verification."""

    def __init__(self, evaluator: Optional[RuleEvaluator] = None) -> None:
        self.evaluator = evaluator or RuleEvaluator()

    # -----------------------------------------------------------------------
    # A04 – Rule-Based Pattern Matching
    # -----------------------------------------------------------------------

    def evaluate_pattern(
        self,
        record: Union[ProcessedRecord, Dict[str, Any]],
        rule_protocol: str,
        condition: Union[str, Dict[str, Any]],
    ) -> Tuple[bool, Dict[str, Any]]:
        """Matches a traffic record against a protocol filter and condition.

        Args:
            record: Processed traffic log record.
            rule_protocol: Expected protocol ('TCP', '802.11_MGMT', 'ANY', 'ALL', etc.).
            condition: Condition string or parsed dictionary.

        Returns:
            Tuple of (matched: bool, evidence: Dict).
        """
        # 1. Protocol check
        rec_protocol = getattr(record, "protocol", None)
        if rec_protocol is None and isinstance(record, dict):
            rec_protocol = record.get("protocol")

        clean_rule_proto = (rule_protocol or "ANY").strip().upper()
        clean_rec_proto = str(rec_protocol or "UNKNOWN").strip().upper()

        if clean_rule_proto not in ("ANY", "ALL", "*"):
            # Check for protocol compatibility
            # Allow 802.11 to match 802.11_MGMT, 802.11_DATA, 802.11_CTRL
            proto_match = (
                clean_rec_proto == clean_rule_proto
                or (clean_rule_proto == "802.11" and clean_rec_proto.startswith("802.11"))
                or (clean_rec_proto == "802.11" and clean_rule_proto.startswith("802.11"))
            )
            if not proto_match:
                return False, {
                    "algorithm": "A04_PATTERN_MATCHING",
                    "protocol_matched": False,
                    "expected_protocol": clean_rule_proto,
                    "observed_protocol": clean_rec_proto,
                    "reason": f"Protocol mismatch: expected '{clean_rule_proto}', observed '{clean_rec_proto}'",
                    "matched": False,
                }

        # 2. Evaluate condition
        matched, cond_evidence = self.evaluator.evaluate_condition(record, condition)

        evidence = {
            "algorithm": "A04_PATTERN_MATCHING",
            "protocol_matched": True,
            "rule_protocol": clean_rule_proto,
            "observed_protocol": clean_rec_proto,
            "condition_evidence": cond_evidence,
            "matched": matched,
        }

        return matched, evidence

    # -----------------------------------------------------------------------
    # A10 – Allowlist and Policy Comparison
    # -----------------------------------------------------------------------

    def evaluate_allowlist_policy(
        self,
        record: Union[ProcessedRecord, Dict[str, Any]],
        field_to_check: str,
        allowlist: Optional[List[Any]] = None,
        policy_name: str = "default_policy",
        strict_mode: bool = True,
    ) -> Tuple[bool, Dict[str, Any]]:
        """Compares observed network attributes against an approved allowlist.

        A violation occurs when the observed value is NOT present in the allowlist.
        Crucial requirement: A missing policy (empty allowlist or missing field)
        must NOT automatically be treated as suspicious.

        Args:
            record: Processed traffic log record.
            field_to_check: Attribute path (e.g. 'source_address', 'source_mac', 'protocol', 'bssid').
            allowlist: Collection of approved values. If None or empty, policy is considered missing/inactive.
            policy_name: Human-readable policy label.
            strict_mode: If True, unknown values trigger a policy violation match.

        Returns:
            Tuple of (matched: bool, evidence: Dict). Note: matched=True means a violation occurred!
        """
        # Rule constraint: A missing policy must not automatically be treated as suspicious.
        if not allowlist:
            return False, {
                "algorithm": "A10_ALLOWLIST_POLICY",
                "policy_name": policy_name,
                "field_checked": field_to_check,
                "reason": "Policy or allowlist is not defined/empty; benign by default.",
                "matched": False,
            }

        # Extract field value from record
        found, val = extract_record_field(record, field_to_check)
        if not found or val is None:
            # Attribute not present in record (e.g. non-IP frame has no source IP)
            # Cannot violate an IP policy if it is not an IP frame
            return False, {
                "algorithm": "A10_ALLOWLIST_POLICY",
                "policy_name": policy_name,
                "field_checked": field_to_check,
                "reason": f"Field '{field_to_check}' is not present in traffic record; cannot evaluate policy.",
                "matched": False,
            }

        # Normalize allowlist for comparison
        clean_obs = str(val).strip().lower()
        normalized_allowlist: Set[str] = {str(item).strip().lower() for item in allowlist}

        is_allowed = clean_obs in normalized_allowlist

        # If not allowed, it is a policy violation (suspicious match = True)
        is_violation = not is_allowed

        evidence = {
            "algorithm": "A10_ALLOWLIST_POLICY",
            "policy_name": policy_name,
            "field_checked": field_to_check,
            "observed_value": str(val),
            "allowlist": list(allowlist),
            "is_allowed": is_allowed,
            "matched": is_violation,
            "description": (
                f"Policy '{policy_name}' violation: observed '{val}' is not in approved allowlist."
                if is_violation
                else f"Observed '{val}' conforms to policy '{policy_name}'."
            ),
        }

        return is_violation, evidence
