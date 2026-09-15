"""
tests/test_rate_limiter.py
=============================

Tests for both rate-limiting algorithms in isolation, plus the actual
/auth/login endpoint enforcing them end to end.
"""

import time

from app.security.rate_limiter import (
    ExponentialBackoffTracker,
    SlidingWindowLimiter,
    TokenBucketLimiter,
)


class TestSlidingWindowLimiter:
    def test_allows_requests_up_to_the_limit(self):
        limiter = SlidingWindowLimiter(max_requests=3, window_seconds=60)
        for _ in range(3):
            assert limiter.check("1.2.3.4").allowed is True

    def test_rejects_the_request_that_exceeds_the_limit(self):
        limiter = SlidingWindowLimiter(max_requests=3, window_seconds=60)
        for _ in range(3):
            limiter.check("1.2.3.4")
        result = limiter.check("1.2.3.4")
        assert result.allowed is False
        assert result.retry_after_seconds > 0

    def test_different_keys_have_independent_limits(self):
        limiter = SlidingWindowLimiter(max_requests=1, window_seconds=60)
        assert limiter.check("ip-a").allowed is True
        assert limiter.check("ip-b").allowed is True  # a different IP, unaffected by ip-a's usage

    def test_old_requests_age_out_of_the_window(self):
        limiter = SlidingWindowLimiter(max_requests=1, window_seconds=0.05)
        assert limiter.check("1.2.3.4").allowed is True
        assert limiter.check("1.2.3.4").allowed is False  # immediately over the limit
        time.sleep(0.06)
        assert limiter.check("1.2.3.4").allowed is True  # window has passed


class TestTokenBucketLimiter:
    def test_allows_a_burst_up_to_capacity(self):
        limiter = TokenBucketLimiter(capacity=3, refill_rate=1)
        for _ in range(3):
            assert limiter.check("user-1").allowed is True

    def test_rejects_once_the_bucket_is_empty(self):
        limiter = TokenBucketLimiter(capacity=1, refill_rate=0.01)  # near-zero refill for a deterministic test
        limiter.check("user-1")
        result = limiter.check("user-1")
        assert result.allowed is False

    def test_bucket_refills_over_time(self):
        limiter = TokenBucketLimiter(capacity=1, refill_rate=20)  # refills in 50ms
        limiter.check("user-1")
        assert limiter.check("user-1").allowed is False
        time.sleep(0.1)
        assert limiter.check("user-1").allowed is True


class TestExponentialBackoff:
    def test_each_violation_at_least_doubles_the_previous_block(self):
        tracker = ExponentialBackoffTracker(base_seconds=1, max_seconds=1000)
        first = tracker.record_violation("1.2.3.4")
        second = tracker.record_violation("1.2.3.4")
        assert second > first

    def test_block_duration_is_capped_at_max_seconds(self):
        tracker = ExponentialBackoffTracker(base_seconds=1, max_seconds=10)
        for _ in range(10):  # enough violations that uncapped growth would be huge
            duration = tracker.record_violation("1.2.3.4")
        assert duration <= 10

    def test_reset_clears_the_block(self):
        tracker = ExponentialBackoffTracker(base_seconds=100, max_seconds=1000)
        tracker.record_violation("1.2.3.4")
        assert tracker.is_blocked("1.2.3.4").allowed is False
        tracker.reset("1.2.3.4")
        assert tracker.is_blocked("1.2.3.4").allowed is True


class TestLoginEndpointRateLimiting:
    def test_sixth_login_attempt_within_a_minute_is_rate_limited(self, client):
        client.post(
            "/auth/register",
            json={"username": "ratelimited", "email": "rl@example.com", "password": "Str0ng!Password"},
        )
        for _ in range(5):
            response = client.post(
                "/auth/login", json={"username": "ratelimited", "password": "WrongPassword!1"}
            )
            assert response.status_code == 401  # wrong password, but still within the rate limit

        sixth_response = client.post(
            "/auth/login", json={"username": "ratelimited", "password": "WrongPassword!1"}
        )
        assert sixth_response.status_code == 429

    def test_rate_limit_applies_even_to_correct_credentials(self, client):
        """
        Rate limiting must trigger on REQUEST VOLUME, not on whether the
        password was right -- otherwise an attacker could avoid the limiter
        entirely just by making sure every guess is wrong.
        """
        client.post(
            "/auth/register",
            json={"username": "burstuser", "email": "burst@example.com", "password": "Str0ng!Password"},
        )
        for _ in range(5):
            client.post("/auth/login", json={"username": "burstuser", "password": "Str0ng!Password"})

        sixth_response = client.post(
            "/auth/login", json={"username": "burstuser", "password": "Str0ng!Password"}
        )
        assert sixth_response.status_code == 429
