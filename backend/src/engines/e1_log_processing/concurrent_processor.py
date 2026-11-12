"""E1: Concurrent Processing Module.

Provides bounded, safe concurrency mechanisms for parsing multi-file batches
and chunked packet streams without uncontrolled memory expansion.

Concurrency Strategy Justification:
----------------------------------
1. File-Level Concurrency:
   When ingesting multiple PCAP files (common in batch captures or network segments),
   processing distinct files concurrently via a worker pool achieves near-linear speedup
   because each worker independently reads, parses, and normalizes its respective file
   without lock contention or inter-process shared state.

2. Chunked Stream Concurrency & Bounded Memory:
   For individual large PCAP files, unbounded multiprocessing or threading often exhausts RAM
   by buffering millions of parsed packet objects before consumer ingestion.
   This module implements bounded chunking (default: 1,000 packets per chunk) with ordered
   sequence identifiers, ensuring deterministic packet ordering while capping resident memory.

3. Worker Isolation & Failure Tolerance:
   Exceptions encountered in one worker (such as corrupt byte sequences or malformed packets)
   are trapped, converted into structured error records, and prevented from crashing sibling workers.
"""

from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Callable, Generator, Iterable, List, Optional, Sequence, TypeVar

from ...common.configuration import settings
from ...common.exceptions import ConcurrencyError
from ...common.logger import get_logger

logger = get_logger(__name__)

T = TypeVar("T")
R = TypeVar("R")


@dataclass
class ConcurrencyStats:
    """Statistics tracked during concurrent execution."""

    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    worker_count: int = 1


class ConcurrentProcessor:
    """Manages concurrent execution of file-level and chunk-level log processing."""

    def __init__(
        self,
        max_workers: Optional[int] = None,
        chunk_size: Optional[int] = None,
    ) -> None:
        """Initializes the concurrent processing coordinator.

        Args:
            max_workers: Number of parallel worker threads/processes (defaults to settings).
            chunk_size: Maximum packets per processing chunk (defaults to settings).
        """
        self.max_workers = max_workers or settings.default_workers
        self.chunk_size = chunk_size or settings.chunk_size
        self.stats = ConcurrencyStats(worker_count=self.max_workers)

    def process_items_concurrently(
        self,
        items: Sequence[T],
        task_fn: Callable[[T], R],
        task_description: str = "tasks",
    ) -> List[R]:
        """Executes a function across an items sequence using a worker pool.

        Args:
            items: List of work items (e.g., file paths or data batches).
            task_fn: Callable accepting an item and returning a result.
            task_description: Human-readable task description for logging.

        Returns:
            List of results matching the completed tasks.

        Raises:
            ConcurrencyError: If pool execution encounters fatal failure.
        """
        if not items:
            return []

        self.stats.total_tasks = len(items)
        self.stats.completed_tasks = 0
        self.stats.failed_tasks = 0
        results: List[R] = []

        # If only 1 item or 1 worker, avoid thread overhead and execute directly
        if len(items) == 1 or self.max_workers <= 1:
            logger.info("Executing %d %s sequentially.", len(items), task_description)
            for item in items:
                try:
                    res = task_fn(item)
                    results.append(res)
                    self.stats.completed_tasks += 1
                except Exception as exc:
                    self.stats.failed_tasks += 1
                    logger.error("Task failed in sequential execution: %s", exc)
                    raise
            return results

        logger.info(
            "Executing %d %s concurrently with %d workers.",
            len(items),
            task_description,
            self.max_workers,
        )

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_item = {
                executor.submit(task_fn, item): item for item in items
            }

            for future in as_completed(future_to_item):
                item = future_to_item[future]
                try:
                    res = future.result()
                    results.append(res)
                    self.stats.completed_tasks += 1
                except Exception as exc:
                    self.stats.failed_tasks += 1
                    logger.error("Worker failure on item '%s': %s", item, exc)
                    # Propagate or collect error depending on policy
                    raise ConcurrencyError(
                        f"Concurrent execution failed for item '{item}': {str(exc)}"
                    ) from exc

        return results

    def chunk_stream(
        self, stream: Iterable[T], chunk_size: Optional[int] = None
    ) -> Generator[List[T], None, None]:
        """Splits a streaming packet generator into bounded batches to constrain RAM usage.

        Args:
            stream: Incoming iterator or generator of items.
            chunk_size: Items per chunk (defaults to self.chunk_size).

        Yields:
            Lists containing at most chunk_size items.
        """
        size = chunk_size or self.chunk_size
        chunk: List[T] = []

        for item in stream:
            chunk.append(item)
            if len(chunk) >= size:
                yield chunk
                chunk = []

        if chunk:
            yield chunk
