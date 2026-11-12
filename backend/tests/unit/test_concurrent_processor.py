"""Unit tests for E1 Concurrent Processor Module."""

import time
import pytest

from src.engines.e1_log_processing.concurrent_processor import ConcurrentProcessor


def test_concurrent_processing_multiple_workers() -> None:
    """Tests execution of independent work items across multiple workers."""
    processor = ConcurrentProcessor(max_workers=4)

    items = list(range(10))

    def work(x: int) -> int:
        return x * 2

    results = processor.process_items_concurrently(items, work, "test work")

    # Verify all results accounted for without duplicates or loss
    assert len(results) == 10
    assert sorted(results) == [x * 2 for x in items]
    assert processor.stats.completed_tasks == 10
    assert processor.stats.failed_tasks == 0


def test_concurrent_processing_consistency() -> None:
    """Verifies that multi-worker execution yields consistent counts with single worker."""
    items = [f"item_{i}" for i in range(25)]

    def work(s: str) -> str:
        return s.upper()

    proc_single = ConcurrentProcessor(max_workers=1)
    res_single = proc_single.process_items_concurrently(items, work)

    proc_multi = ConcurrentProcessor(max_workers=4)
    res_multi = proc_multi.process_items_concurrently(items, work)

    assert sorted(res_single) == sorted(res_multi)
    assert len(res_multi) == 25


def test_chunk_stream_bounded_memory() -> None:
    """Tests chunking of packet streams into bounded batches."""
    processor = ConcurrentProcessor(chunk_size=10)
    stream = range(25)

    chunks = list(processor.chunk_stream(stream, chunk_size=10))

    assert len(chunks) == 3
    assert len(chunks[0]) == 10
    assert len(chunks[1]) == 10
    assert len(chunks[2]) == 5

    # Verify all items preserved in exact order
    flattened = [item for ch in chunks for item in ch]
    assert flattened == list(range(25))

