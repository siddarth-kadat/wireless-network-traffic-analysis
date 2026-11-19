"""E2: Rule Evaluator Module.

Safe, deterministic evaluation of individual detection conditions against
incoming traffic log records. Strictly avoids python eval() or exec().
"""

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from backend.src.common.logger import get_logger
from backend.src.engines.e1_log_processing.log_processor import ProcessedRecord
from .exceptions import ConditionEvaluationError

logger = get_logger(__name__)

# Supported relational and comparison operators
SUPPORTED_OPERATORS: Set[str] = {
    "==",
    "=",
    "eq",
    "!=",
    "neq",
    "<",
    "lt",
    "<=",
    "lte",
    ">",
    "gt",
    ">=",
    "gte",
    "in",
    "not in",
    "not_in",
    "contains",
    "startswith",
    "endswith",
    "regex",
}

# Alias map for standard network field names
FIELD_ALIASES: Dict[str, str] = {
    "dst_port": "log_details.destination_port",
    "destination_port": "log_details.destination_port",
    "src_port": "log_details.source_port",
    "source_port": "log_details.source_port",
    "packet_length": "log_details.packet_length",
    "frame_type": "log_details.wireless.frame_type",
    "frame_subtype": "log_details.wireless.frame_subtype",
    "bssid": "log_details.wireless.bssid",
    "ssid": "log_details.wireless.ssid",
    "channel": "log_details.wireless.channel",
    "signal_strength": "log_details.wireless.signal_strength",
    "ip_ttl": "log_details.ip_ttl",
    "payload_size": "log_details.payload_size",
    "tcp_flags": "log_details.tcp_flags",
}


def extract_record_field(
    record: Union[ProcessedRecord, Dict[str, Any]], field_path: str
) -> Tuple[bool, Any]:
    """Safely extracts a nested or aliased attribute from a ProcessedRecord or dictionary.

    Args:
        record: ProcessedRecord instance or plain dictionary.
        field_path: Dot-notated or aliased path (e.g. 'protocol', 'dst_port', 'log_details.wireless.bssid').

    Returns:
        Tuple of (field_found: bool, field_value: Any).
    """
    if record is None:
        return False, None

    # Resolve alias if present
    normalized_path = FIELD_ALIASES.get(field_path, field_path)

    # Convert ProcessedRecord to dict if needed
    if isinstance(record, ProcessedRecord):
        rec_dict = record.to_dict()
    elif isinstance(record, dict):
        rec_dict = record
    elif hasattr(record, "__dict__"):
        rec_dict = vars(record)
    else:
        return False, None

    parts = normalized_path.split(".")
    curr: Any = rec_dict

    for part in parts:
        if isinstance(curr, dict):
            if part in curr:
                curr = curr[part]
            else:
                return False, None
        elif hasattr(curr, part):
            curr = getattr(curr, part)
        else:
            return False, None

    return True, curr


def _compare_values(observed: Any, operator: str, target: Any) -> bool:
    """Deterministically compares observed value with target using approved operators.

    Args:
        observed: Value extracted from the traffic record.
        operator: Comparison operator string.
        target: Target value specified in rule.

    Returns:
        Boolean comparison result.
    """
    op = operator.lower().strip()

    if op in ("==", "=", "eq"):
        # Handle string comparisons case-insensitively when strings
        if isinstance(observed, str) and isinstance(target, str):
            return observed.strip().lower() == target.strip().lower()
        # Coerce numeric types if compatible
        if isinstance(observed, (int, float)) and isinstance(target, (int, float, str)):
            try:
                return float(observed) == float(target)
            except (ValueError, TypeError):
                pass
        return observed == target

    if op in ("!=", "neq"):
        if isinstance(observed, str) and isinstance(target, str):
            return observed.strip().lower() != target.strip().lower()
        if isinstance(observed, (int, float)) and isinstance(target, (int, float, str)):
            try:
                return float(observed) != float(target)
            except (ValueError, TypeError):
                pass
        return observed != target

    # Numeric relational operators
    if op in ("<", "lt", "<=", "lte", ">", "gt", ">=", "gte"):
        if observed is None or target is None:
            return False
        try:
            obs_num = float(observed)
            tgt_num = float(target)
            if op in ("<", "lt"):
                return obs_num < tgt_num
            if op in ("<=", "lte"):
                return obs_num <= tgt_num
            if op in (">", "gt"):
                return obs_num > tgt_num
            if op in (">=", "gte"):
                return obs_num >= tgt_num
        except (ValueError, TypeError):
            # Fall back to lexicographical for strings if both are strings
            if isinstance(observed, str) and isinstance(target, str):
                if op in ("<", "lt"):
                    return observed < target
                if op in ("<=", "lte"):
                    return observed <= target
                if op in (">", "gt"):
                    return observed > target
                if op in (">=", "gte"):
                    return observed >= target
            return False

    # Membership operators
    if op == "in":
        if observed is None:
            return False
        if isinstance(target, (list, tuple, set)):
            # Case-insensitive string matching in collections
            if isinstance(observed, str):
                target_strs = {str(item).lower() for item in target}
                return observed.lower() in target_strs
            return observed in target
        if isinstance(target, str):
            return str(observed).lower() in target.lower()
        return False

    if op in ("not in", "not_in"):
        if observed is None:
            return True
        if isinstance(target, (list, tuple, set)):
            if isinstance(observed, str):
                target_strs = {str(item).lower() for item in target}
                return observed.lower() not in target_strs
            return observed not in target
        if isinstance(target, str):
            return str(observed).lower() not in target.lower()
        return True

    # String containment / prefix operators
    if op == "contains":
        if observed is None or target is None:
            return False
        return str(target).lower() in str(observed).lower()

    if op == "startswith":
        if observed is None or target is None:
            return False
        return str(observed).lower().startswith(str(target).lower())

    if op == "endswith":
        if observed is None or target is None:
            return False
        return str(observed).lower().endswith(str(target).lower())

    if op == "regex":
        if observed is None or target is None:
            return False
        try:
            pattern = re.compile(str(target), re.IGNORECASE)
            return bool(pattern.search(str(observed)))
        except re.error:
            logger.warning("Invalid regex pattern in rule condition: %s", target)
            return False

    raise ConditionEvaluationError(f"Unsupported operator '{operator}'")


class RuleEvaluator:
    """Evaluates rule conditions against traffic log records deterministically."""

    @staticmethod
    def parse_condition_string(condition_str: str) -> Dict[str, Any]:
        """Safely parses a condition string into a structured condition representation.

        Supports:
        1. JSON strings: e.g. {"field": "dst_port", "operator": "<", "value": 1024}
        2. Simple comparisons: e.g. "dst_port < 1024" or "frame_subtype == Deauthentication"
        3. Conjunctions of simple comparisons: e.g. "protocol == TCP and dst_port < 1024"

        Args:
            condition_str: Raw detection_condition text.

        Returns:
            Structured dictionary representation of condition.
        """
        raw = condition_str.strip()
        if not raw:
            return {}

        # 1. Try parsing as JSON first
        if (raw.startswith("{") and raw.endswith("}")) or (
            raw.startswith("[") and raw.endswith("]")
        ):
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    return parsed
                if isinstance(parsed, list):
                    return {"conditions": parsed, "logical_operator": "AND"}
            except json.JSONDecodeError:
                pass

        # 2. Check for conjunctions (e.g. 'cond1 and cond2')
        and_parts = re.split(r"\s+and\s+", raw, flags=re.IGNORECASE)
        if len(and_parts) > 1:
            sub_conds = [
                RuleEvaluator.parse_condition_string(p.strip()) for p in and_parts
            ]
            return {"conditions": sub_conds, "logical_operator": "AND"}

        or_parts = re.split(r"\s+or\s+", raw, flags=re.IGNORECASE)
        if len(or_parts) > 1:
            sub_conds = [
                RuleEvaluator.parse_condition_string(p.strip()) for p in or_parts
            ]
            return {"conditions": sub_conds, "logical_operator": "OR"}

        # 3. Parse single comparison: <field> <op> <value>
        # Match operators: ==, !=, <=, >=, <, >, in, not in, contains, startswith, endswith
        comp_pattern = re.compile(
            r"^([a-zA-Z0-9_.]+)\s*(==|!=|<=|>=|<|>|not\s+in|in|contains|startswith|endswith)\s*(.+)$",
            re.IGNORECASE,
        )
        match = comp_pattern.match(raw)
        if match:
            field_name = match.group(1).strip()
            operator = match.group(2).strip().lower()
            val_str = match.group(3).strip()

            # Clean quotes from string values
            if (val_str.startswith('"') and val_str.endswith('"')) or (
                val_str.startswith("'") and val_str.endswith("'")
            ):
                val: Any = val_str[1:-1]
            elif val_str.lower() == "true":
                val = True
            elif val_str.lower() == "false":
                val = False
            elif val_str.lower() == "none" or val_str.lower() == "null":
                val = None
            else:
                try:
                    if "." in val_str:
                        val = float(val_str)
                    else:
                        val = int(val_str)
                except ValueError:
                    val = val_str

            return {"field": field_name, "operator": operator, "value": val}

        # Fallback: treat as raw text condition
        return {"raw_condition": raw}

    def evaluate_condition(
        self,
        record: Union[ProcessedRecord, Dict[str, Any]],
        condition: Union[str, Dict[str, Any]],
    ) -> Tuple[bool, Dict[str, Any]]:
        """Evaluates a condition structure against a traffic record.

        Args:
            record: ProcessedRecord or dictionary.
            condition: Condition string or parsed dictionary.

        Returns:
            Tuple of (matched: bool, evidence: Dict[str, Any]).
        """
        if isinstance(condition, str):
            cond_dict = self.parse_condition_string(condition)
        elif isinstance(condition, dict):
            cond_dict = condition
        else:
            return False, {"error": "Invalid condition type", "condition": str(condition)}

        # Handle compound conditions
        if "conditions" in cond_dict:
            logical_op = cond_dict.get("logical_operator", "AND").upper()
            sub_results: List[Dict[str, Any]] = []
            for sub_cond in cond_dict["conditions"]:
                matched, sub_ev = self.evaluate_condition(record, sub_cond)
                sub_results.append(
                    {"matched": matched, "evidence": sub_ev, "condition": sub_cond}
                )

            if logical_op == "OR":
                matched = any(r["matched"] for r in sub_results)
            else:
                matched = all(r["matched"] for r in sub_results)

            return matched, {
                "logical_operator": logical_op,
                "matched": matched,
                "sub_conditions": sub_results,
            }

        # Handle explicit single field comparison
        if "field" in cond_dict and "operator" in cond_dict:
            field_name = cond_dict["field"]
            operator = cond_dict["operator"]
            target_val = cond_dict.get("value")

            found, observed = extract_record_field(record, field_name)
            if not found:
                return False, {
                    "field": field_name,
                    "field_found": False,
                    "observed_value": None,
                    "reason": f"Required field '{field_name}' not available in record.",
                }

            try:
                matched = _compare_values(observed, operator, target_val)
                return matched, {
                    "field": field_name,
                    "operator": operator,
                    "target_value": target_val,
                    "observed_value": observed,
                    "matched": matched,
                }
            except ConditionEvaluationError as err:
                logger.warning("Condition evaluation error: %s", err)
                return False, {
                    "field": field_name,
                    "operator": operator,
                    "error": str(err),
                    "matched": False,
                }

        # Handle simple key-value dictionary equality conditions
        # e.g. {"frame_type": "Management", "frame_subtype": "Deauthentication"}
        if cond_dict and not cond_dict.get("raw_condition"):
            sub_matches: List[Dict[str, Any]] = []
            all_match = True
            for k, expected in cond_dict.items():
                if k in ("algorithm", "description", "threshold", "time_window_seconds"):
                    continue
                found, observed = extract_record_field(record, k)
                if not found:
                    all_match = False
                    sub_matches.append(
                        {
                            "field": k,
                            "field_found": False,
                            "matched": False,
                            "reason": f"Field '{k}' missing",
                        }
                    )
                    continue
                field_matched = _compare_values(observed, "==", expected)
                if not field_matched:
                    all_match = False
                sub_matches.append(
                    {
                        "field": k,
                        "observed": observed,
                        "expected": expected,
                        "matched": field_matched,
                    }
                )

            if sub_matches:
                return all_match, {
                    "key_value_matches": sub_matches,
                    "matched": all_match,
                }

        # Fallback raw condition evaluation
        raw = cond_dict.get("raw_condition", "")
        return False, {
            "raw_condition": raw,
            "matched": False,
            "reason": "Unsupported or unstructured condition format",
        }
