"""Unit tests for E4 Severity Manager Module."""

import pytest

from src.common.constants import SeverityLevel
from src.common.exceptions import InvalidSeverityError
from src.engines.e4_alert_generation.severity_manager import SeverityManager


def test_severity_preservation() -> None:
    """Tests that standard severity levels are preserved and normalized."""
    manager = SeverityManager()

    assert manager.resolve_severity("LOW") == SeverityLevel.LOW.value
    assert manager.resolve_severity("low") == SeverityLevel.LOW.value
    assert manager.resolve_severity("MEDIUM") == SeverityLevel.MEDIUM.value
    assert manager.resolve_severity("medium") == SeverityLevel.MEDIUM.value
    assert manager.resolve_severity("HIGH") == SeverityLevel.HIGH.value
    assert manager.resolve_severity("high") == SeverityLevel.HIGH.value
    assert manager.resolve_severity("CRITICAL") == SeverityLevel.CRITICAL.value
    assert manager.resolve_severity("critical") == SeverityLevel.CRITICAL.value


def test_severity_numeric_mappings() -> None:
    """Tests that numeric severity values are mapped correctly."""
    manager = SeverityManager()

    assert manager.resolve_severity(1) == SeverityLevel.LOW.value
    assert manager.resolve_severity(2) == SeverityLevel.MEDIUM.value
    assert manager.resolve_severity(3) == SeverityLevel.HIGH.value
    assert manager.resolve_severity(4) == SeverityLevel.CRITICAL.value


def test_severity_missing_fallback() -> None:
    """Tests fallback behavior when severity is None in standard mode."""
    manager = SeverityManager(default_severity=SeverityLevel.MEDIUM, strict_mode=False)

    assert manager.resolve_severity(None, context_id="res-001") == SeverityLevel.MEDIUM.value


def test_severity_unknown_value_fallback() -> None:
    """Tests fallback behavior when severity is an unrecognized string."""
    manager = SeverityManager(default_severity=SeverityLevel.MEDIUM, strict_mode=False)

    assert manager.resolve_severity("UNRECOGNIZED_LEVEL") == SeverityLevel.MEDIUM.value


def test_severity_strict_mode_raises() -> None:
    """Tests that strict mode raises InvalidSeverityError on missing or invalid severity."""
    manager = SeverityManager(strict_mode=True)

    with pytest.raises(InvalidSeverityError):
        manager.resolve_severity(None)

    with pytest.raises(InvalidSeverityError):
        manager.resolve_severity("INVALID_SEVERITY")

