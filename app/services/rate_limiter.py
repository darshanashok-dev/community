"""Privacy-aware in-memory sliding-window rate limiter.

Uses a per-process ephemeral salt to hash client addresses in memory so raw IP
addresses are never persisted or logged.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from collections import deque


class InMemoryRateLimiter:
    """Thread-safe sliding-window rate limiter keyed by salted client hash."""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60) -> None:
        self.max_requests = max(1, max_requests)
        self.window_seconds = max(1, window_seconds)
        self._salt = os.urandom(16)
        self._buckets: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _hash_key(self, raw_identifier: str) -> str:
        digest = hashlib.sha256(self._salt + raw_identifier.encode("utf-8", errors="ignore"))
        return digest.hexdigest()[:16]

    def allow(self, raw_identifier: str, now: float | None = None) -> tuple[bool, int]:
        """Return (is_allowed, retry_after_seconds) for the given request source."""
        current = now if now is not None else time.monotonic()
        cutoff = current - self.window_seconds
        key = self._hash_key(raw_identifier or "anonymous")

        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = deque()
                self._buckets[key] = bucket

            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= self.max_requests:
                retry_after = max(1, int(self.window_seconds - (current - bucket[0])) + 1)
                return False, retry_after

            bucket.append(current)

            # Bound memory growth by pruning stale empty buckets periodically
            if len(self._buckets) > 2048:
                stale_keys = [
                    k for k, dq in self._buckets.items() if not dq or dq[-1] <= cutoff
                ]
                for k in stale_keys:
                    del self._buckets[k]

            return True, 0

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()
