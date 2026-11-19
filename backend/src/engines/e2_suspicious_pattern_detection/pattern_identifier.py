"""E2: Pattern Identifier Module.

Implements:
- A08: Sequence and State-Based Detection (deterministic state transitions)
- A11: Multi-Condition Correlation (combining multiple indicators and sub-rules)
"""

from collections import OrderedDict, deque
from typing import Any, Deque, Dict, List, Optional, Set, Tuple, Union

from backend.src.common.logger import get_logger
from backend.src.engines.e1_log_processing.log_processor import ProcessedRecord
from .rule_evaluator import RuleEvaluator, extract_record_field

logger = get_logger(__name__)

# Standard 802.11 State Transitions
# Normal lifecycle: UNASSOCIATED -> PROBE -> AUTHENTICATED -> ASSOCIATED -> DATA
STANDARD_ALLOWED_TRANSITIONS: Dict[str, Set[str]] = {
    "START": {"PROBE", "AUTH", "BEACON", "DATA", "OTHER"},
    "PROBE": {"AUTH", "PROBE", "ASSOC", "OTHER"},
    "AUTH": {"ASSOC", "AUTH", "DEAUTH", "DISASSOC", "OTHER"},
    "ASSOC": {"DATA", "ASSOC", "DEAUTH", "DISASSOC", "OTHER"},
    "DATA": {"DATA", "DEAUTH", "DISASSOC", "AUTH", "OTHER"},
    "DEAUTH": {"AUTH", "PROBE", "START", "OTHER"},
    "DISASSOC": {"ASSOC", "AUTH", "PROBE", "START", "OTHER"},
}

SUSPICIOUS_TRANSITIONS: Set[Tuple[str, str]] = {
    # Jumping directly to Association or Data without Prior Auth
    ("START", "ASSOC"),
    ("PROBE", "DATA"),
    # Rapid Deauth loop from unexpected state
    ("START", "DEAUTH"),
}


class PatternIdentifier:
    """Executes sequence state machines and multi-condition correlation detection."""

    def __init__(
        self,
        max_entities: int = 5000,
        evaluator: Optional[RuleEvaluator] = None,
    ) -> None:
        self.max_entities = max_entities
        self.evaluator = evaluator or RuleEvaluator()
        # entity_key -> current state string
        self._states: OrderedDict[str, str] = OrderedDict()
        # entity_key -> deque of recent transition history
        self._state_history: OrderedDict[str, Deque[Dict[str, Any]]] = OrderedDict()

    def reset(self) -> None:
        """Clears all tracking states and sequence histories."""
        self._states.clear()
        self._state_history.clear()

    # -----------------------------------------------------------------------
    # A08 – Sequence and State-Based Detection
    # -----------------------------------------------------------------------

    def _determine_event_label(
        self, record: Union[ProcessedRecord, Dict[str, Any]], event_field: Optional[str] = None
    ) -> str:
        """Extracts normalized event state label from a traffic record."""
        raw_val = None
        if event_field:
            found, val = extract_record_field(record, event_field)
            if found and val:
                raw_val = str(val).strip()

        if raw_val is None:
            found_st, subtype = extract_record_field(record, "frame_subtype")
            if found_st and subtype:
                raw_val = str(subtype).strip()

        if raw_val is not None:
            clean_st = raw_val.lower()
            if "probe" in clean_st:
                return "PROBE"
            if "beacon" in clean_st:
                return "BEACON"
            if "deauth" in clean_st:
                return "DEAUTH"
            if "disassoc" in clean_st:
                return "DISASSOC"
            if "auth" in clean_st:
                return "AUTH"
            if "assoc" in clean_st:
                return "ASSOC"
            if "data" in clean_st:
                return "DATA"
            return raw_val.upper()
            if "disassoc" in clean_st:
                return "DISASSOC"
            if "auth" in clean_st:
                return "AUTH"
            if "assoc" in clean_st:
                return "ASSOC"
            if "data" in clean_st:
                return "DATA"

        # Check protocol or TCP flags
        proto = getattr(record, "protocol", None) or (
            record.get("protocol") if isinstance(record, dict) else None
        )
        if proto:
            clean_proto = str(proto).upper()
            if "MGMT" in clean_proto:
                return "MGMT"
            if "DATA" in clean_proto or clean_proto in ("TCP", "UDP"):
                return "DATA"

        return "OTHER"

    def evaluate_sequence_state(
        self,
        record: Union[ProcessedRecord, Dict[str, Any]],
        group_by_field: str = "source_mac",
        event_field: Optional[str] = "frame_subtype",
        expected_sequence: Optional[List[str]] = None,
        disallowed_transitions: Optional[List[Tuple[str, str]]] = None,
        rule_id: Optional[int] = None,
    ) -> Tuple[bool, Dict[str, Any]]:
        """Evaluates state machine transitions for sequence violations.

        Args:
            record: Processed traffic log record.
            group_by_field: Entity whose state is tracked (e.g. source_mac, source_address).
            event_field: Field defining the state/event label.
            expected_sequence: Optional strict sequence of states that must not be broken.
            disallowed_transitions: Optional list of (from_state, to_state) forbidden transitions.
            rule_id: Rule identifier.

        Returns:
            Tuple of (matched: bool, evidence: Dict).
        """
        # 1. Determine entity key
        found_key, entity_val = extract_record_field(record, group_by_field)
        if not found_key or not entity_val:
            return False, {
                "algorithm": "A08_SEQUENCE_STATE",
                "reason": f"Required entity field '{group_by_field}' not present in record.",
                "matched": False,
            }

        tracking_key = f"r{rule_id or 0}_{str(entity_val).strip()}"

        # 2. Determine current event label
        current_event = self._determine_event_label(record, event_field)

        # 3. Retrieve previous state
        if tracking_key in self._states:
            self._states.move_to_end(tracking_key)
            prev_state = self._states[tracking_key]
        else:
            if len(self._states) >= self.max_entities:
                self._states.popitem(last=False)
            prev_state = "START"

        # 4. Check for sequence/transition violation
        is_suspicious = False
        violation_reason = ""

        # Check explicit disallowed transitions
        active_disallowed = set(disallowed_transitions) if disallowed_transitions else SUSPICIOUS_TRANSITIONS
        if (prev_state, current_event) in active_disallowed:
            is_suspicious = True
            violation_reason = f"Disallowed state transition observed: {prev_state} -> {current_event}"

        # Check explicit sequence order if supplied
        if expected_sequence and not is_suspicious:
            # History tracking
            history = self._state_history.get(tracking_key)
            if history:
                prev_events = [item["event"] for item in history]
                # If current event does not follow expected progression
                if prev_state != "START" and current_event in expected_sequence:
                    try:
                        exp_idx = expected_sequence.index(prev_state)
                        cur_idx = expected_sequence.index(current_event)
                        if cur_idx < exp_idx or cur_idx > exp_idx + 1:
                            is_suspicious = True
                            violation_reason = (
                                f"Sequence order violation: observed '{current_event}' "
                                f"after '{prev_state}' (expected ordered progression in {expected_sequence})"
                            )
                    except ValueError:
                        pass

        # 5. Update state and history
        self._states[tracking_key] = current_event

        if tracking_key not in self._state_history:
            if len(self._state_history) >= self.max_entities:
                self._state_history.popitem(last=False)
            self._state_history[tracking_key] = deque(maxlen=20)

        hist_item = {
            "from_state": prev_state,
            "event": current_event,
            "is_suspicious": is_suspicious,
        }
        self._state_history[tracking_key].append(hist_item)

        evidence = {
            "algorithm": "A08_SEQUENCE_STATE",
            "tracking_key": tracking_key,
            "entity_value": str(entity_val),
            "previous_state": prev_state,
            "current_event": current_event,
            "new_state": current_event,
            "matched": is_suspicious,
            "violation_reason": violation_reason if is_suspicious else "Valid sequence progression",
            "recent_sequence": list(self._state_history[tracking_key]),
        }

        return is_suspicious, evidence

    # -----------------------------------------------------------------------
    # A11 – Multi-Condition Correlation
    # -----------------------------------------------------------------------

    def evaluate_multi_condition_correlation(
        self,
        record: Union[ProcessedRecord, Dict[str, Any]],
        conditions: List[Dict[str, Any]],
        correlation_operator: str = "AND",
    ) -> Tuple[bool, Dict[str, Any]]:
        """Correlates multiple conditions deterministically using boolean logic.

        Args:
            record: Processed traffic log record.
            conditions: List of sub-condition definitions.
            correlation_operator: 'AND' (all must match) or 'OR' (any must match).

        Returns:
            Tuple of (matched: bool, evidence: Dict).
        """
        if not conditions:
            return False, {
                "algorithm": "A11_MULTI_CONDITION",
                "reason": "No correlation conditions supplied.",
                "matched": False,
            }

        sub_evaluations: List[Dict[str, Any]] = []

        for idx, sub_cond in enumerate(conditions):
            matched, ev = self.evaluator.evaluate_condition(record, sub_cond)
            sub_evaluations.append(
                {
                    "condition_index": idx,
                    "condition": sub_cond,
                    "matched": matched,
                    "evidence": ev,
                }
            )

        clean_op = correlation_operator.upper().strip()
        if clean_op == "OR":
            is_matched = any(res["matched"] for res in sub_evaluations)
        else:
            is_matched = all(res["matched"] for res in sub_evaluations)

        evidence = {
            "algorithm": "A11_MULTI_CONDITION",
            "correlation_operator": clean_op,
            "total_conditions": len(conditions),
            "matched_conditions_count": sum(1 for res in sub_evaluations if res["matched"]),
            "sub_condition_results": sub_evaluations,
            "matched": is_matched,
            "description": (
                f"Multi-condition correlation ({clean_op}): "
                f"{sum(1 for res in sub_evaluations if res['matched'])}/{len(conditions)} matched."
            ),
        }

        return is_matched, evidence
