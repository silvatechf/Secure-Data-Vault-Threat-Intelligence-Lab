"""
app/security/rate_limiter.py
===============================

EX-09: two different rate-limiting algorithms, because they solve
slightly different problems, and understanding both -- not just picking
one -- is the actual point of this exercise.

SLIDING WINDOW: "AT MOST N REQUESTS IN THE LAST T SECONDS"
------------------------------------------------------------------
Tracks the exact timestamp of every request in a rolling window. Precise
and fair (no burst-at-the-boundary problem that a naive fixed-window
counter has, where a client could send N requests at 0:59 and another N
at 1:01 -- 2N requests in 2 seconds, technically "within limits" each
window). Used here for LOGIN attempts, where precision matters and
traffic is low-volume enough that tracking individual timestamps is cheap.

TOKEN BUCKET: "A REFILLABLE ALLOWANCE THAT SMOOTHS BURSTS"
------------------------------------------------------------------
A bucket holds up to `capacity` tokens, refilling at a steady rate. Each
request consumes one token; if the bucket's empty, the request is
rejected. Unlike sliding window, token bucket naturally ALLOWS brief
bursts (spend your whole saved-up allowance at once) while still capping
sustained throughput -- a better fit for a higher-volume, authenticated
route where occasional bursts (a user uploading several files in a row)
shouldn't be punished the way they would under a strict window.

EXPONENTIAL BACKOFF FOR REPEAT VIOLATORS
---------------------------------------------
A single rate-limit hit gets a normal, short block. Someone who keeps
hitting the limit repeatedly is behaving like an automated attack, not a
person who made one mistake -- each consecutive violation roughly doubles
the block duration, quickly turning a brute-force script's request rate
toward zero without permanently banning a legitimate user who just needs
to slow down.
"""

import time
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass
class RateLimitResult:
    allowed: bool
    retry_after_seconds: float = 0.0


class SlidingWindowLimiter:
    """At most `max_requests` per `window_seconds`, per key (e.g. an IP address)."""

    def __init__(self, max_requests: int, window_seconds: float):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, deque] = defaultdict(deque)

    def check(self, key: str) -> RateLimitResult:
        now = time.monotonic()
        window = self._requests[key]

        # Drop timestamps that have aged out of the window.
        while window and window[0] <= now - self.window_seconds:
            window.popleft()

        if len(window) >= self.max_requests:
            retry_after = self.window_seconds - (now - window[0])
            return RateLimitResult(allowed=False, retry_after_seconds=max(retry_after, 0))

        window.append(now)
        return RateLimitResult(allowed=True)

    def reset(self) -> None:
        """Clears all tracked request history for every key. Mainly useful for test isolation."""
        self._requests.clear()


class TokenBucketLimiter:
    """A refillable allowance of `capacity` tokens, replenishing at `refill_rate` tokens/second, per key."""

    def __init__(self, capacity: float, refill_rate: float):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self._buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_refill_time)

    def check(self, key: str) -> RateLimitResult:
        now = time.monotonic()
        tokens, last_refill = self._buckets.get(key, (self.capacity, now))

        elapsed = now - last_refill
        tokens = min(self.capacity, tokens + elapsed * self.refill_rate)

        if tokens < 1:
            deficit = 1 - tokens
            retry_after = deficit / self.refill_rate
            self._buckets[key] = (tokens, now)
            return RateLimitResult(allowed=False, retry_after_seconds=retry_after)

        tokens -= 1
        self._buckets[key] = (tokens, now)
        return RateLimitResult(allowed=True)


class ExponentialBackoffTracker:
    """
    Tracks consecutive rate-limit violations per key and computes a
    growing block duration: base_seconds * (2 ** violation_count),
    capped at max_seconds so a long-idle attacker doesn't end up
    permanently blocked by an ever-doubling number.
    """

    def __init__(self, base_seconds: float = 1.0, max_seconds: float = 300.0):
        self.base_seconds = base_seconds
        self.max_seconds = max_seconds
        self._violations: dict[str, int] = defaultdict(int)
        self._blocked_until: dict[str, float] = {}

    def is_blocked(self, key: str) -> RateLimitResult:
        blocked_until = self._blocked_until.get(key, 0)
        now = time.monotonic()
        if now < blocked_until:
            return RateLimitResult(allowed=False, retry_after_seconds=blocked_until - now)
        return RateLimitResult(allowed=True)

    def record_violation(self, key: str) -> float:
        """Call this each time the underlying limiter rejects a request. Returns the new block duration in seconds."""
        self._violations[key] += 1
        block_seconds = min(self.base_seconds * (2 ** self._violations[key]), self.max_seconds)
        self._blocked_until[key] = time.monotonic() + block_seconds
        return block_seconds

    def reset(self, key: str) -> None:
        """Call this on a SUCCESSFUL request -- a legitimate user who eventually gets it right shouldn't carry a growing penalty forever."""
        self._violations.pop(key, None)
        self._blocked_until.pop(key, None)

    def reset_all(self) -> None:
        """Clears every tracked key. Mainly useful for test isolation."""
        self._violations.clear()
        self._blocked_until.clear()


# Shared instances used by the login endpoint -- 5 attempts per 60 seconds
# per IP address, with exponential backoff for repeat offenders.
login_limiter = SlidingWindowLimiter(max_requests=5, window_seconds=60)
login_backoff = ExponentialBackoffTracker(base_seconds=2.0, max_seconds=300.0)
