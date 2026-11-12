"""Unit tests for E4 Alert Deduplicator Module."""

import pytest

from src.engines.e4_alert_generation.alert_deduplicator import AlertDeduplicator


def test_deduplicator_prevents_duplicate_processing() -> None:
    """Tests that the deduplicator marks new IDs and detects repeats."""
    dedup = AlertDeduplicator()

    # First time: not duplicate, mark succeeds
    assert dedup.is_duplicate("res-001") is False
    assert dedup.mark_processed("res-001") is True

    # Second time: detected as duplicate, mark returns False
    assert dedup.is_duplicate("res-001") is True
    assert dedup.mark_processed("res-001") is False


def test_deduplicator_cache_clearing() -> None:
    """Tests that clear() resets the deduplication cache."""
    dedup = AlertDeduplicator()
    dedup.mark_processed("res-002")
    assert dedup.is_duplicate("res-002") is True

    dedup.clear()
    assert dedup.is_duplicate("res-002") is False


def test_deduplicator_capacity_eviction() -> None:
    """Tests bounded capacity eviction to prevent memory expansion."""
    # Small cache capacity of 3 items
    dedup = AlertDeduplicator(max_size=3)

    dedup.mark_processed("id-1")
    dedup.mark_processed("id-2")
    dedup.mark_processed("id-3")
    assert len(dedup) == 3

    # Adding 4th item evicts the oldest (id-1)
    dedup.mark_processed("id-4")
    assert len(dedup) == 3
    assert dedup.is_duplicate("id-1") is False
    assert dedup.is_duplicate("id-4") is True

