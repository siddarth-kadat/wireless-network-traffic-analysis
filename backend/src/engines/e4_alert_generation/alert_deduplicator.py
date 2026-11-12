"""E4: Alert Deduplicator Module.

Provides memory-bounded, thread-safe deduplication to prevent generating
or dispatching duplicate security alerts for the same detection result.
"""

from collections import OrderedDict
import threading
from typing import Optional

from ...common.configuration import settings
from ...common.logger import get_logger

logger = get_logger(__name__)


class AlertDeduplicator:
    """Thread-safe LRU-based deduplicator for detection result identifiers."""

    def __init__(self, max_size: Optional[int] = None) -> None:
        """Initializes the deduplicator with a bounded capacity.

        Args:
            max_size: Maximum entries in the deduplication cache (defaults to settings).
        """
        self.max_size = max_size or settings.alert_dedup_cache_size
        self._cache: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def is_duplicate(self, result_id: str) -> bool:
        """Checks if a result_id has already been processed without modifying state.

        Args:
            result_id: Detection result identifier.

        Returns:
            True if result_id is in the cache, False otherwise.
        """
        if not result_id:
            return False
        with self._lock:
            return result_id in self._cache

    def mark_processed(self, result_id: str) -> bool:
        """Registers a result_id as processed.

        Args:
            result_id: Detection result identifier.

        Returns:
            True if newly registered; False if already processed (duplicate).
        """
        if not result_id:
            return False

        with self._lock:
            if result_id in self._cache:
                # Move to end to denote recent access
                self._cache.move_to_end(result_id)
                logger.debug("Duplicate detection result identified: '%s'.", result_id)
                return False

            self._cache[result_id] = 1.0

            # Evict oldest entry if capacity is exceeded
            if len(self._cache) > self.max_size:
                evicted_id, _ = self._cache.popitem(last=False)
                logger.debug("Evicted oldest result_id from dedup cache: '%s'.", evicted_id)

            return True

    def clear(self) -> None:
        """Clears all entries from the deduplicator cache."""
        with self._lock:
            self._cache.clear()

    def __len__(self) -> int:
        """Returns current number of cached entries."""
        with self._lock:
            return len(self._cache)
