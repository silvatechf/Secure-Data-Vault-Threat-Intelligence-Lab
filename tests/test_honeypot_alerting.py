"""
tests/test_honeypot_alerting.py
==================================
"""

import os
from unittest.mock import MagicMock, patch

from app.honeypot.alerting import maybe_alert, send_alert


class TestSendAlert:
    def test_no_webhook_configured_returns_false(self, monkeypatch):
        monkeypatch.delenv("HONEYPOT_WEBHOOK_URL", raising=False)
        result = send_alert("SQLi", 0.9, "1.2.3.4", "/admin")
        assert result is False

    def test_successful_webhook_post_returns_true(self, monkeypatch):
        monkeypatch.setenv("HONEYPOT_WEBHOOK_URL", "https://example.com/webhook")
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        with patch("app.honeypot.alerting.requests.post", return_value=mock_response) as mock_post:
            result = send_alert("SQLi", 0.9, "1.2.3.4", "/admin")

        assert result is True
        mock_post.assert_called_once()

    def test_webhook_failure_is_caught_and_returns_false(self, monkeypatch):
        """
        THE CORE DESIGN PROPERTY: a broken webhook must never raise an
        exception out of this function -- see the module docstring for
        why alerting failures are swallowed rather than propagated.
        """
        monkeypatch.setenv("HONEYPOT_WEBHOOK_URL", "https://example.com/webhook")
        import requests

        with patch(
            "app.honeypot.alerting.requests.post",
            side_effect=requests.ConnectionError("connection refused"),
        ):
            result = send_alert("SQLi", 0.9, "1.2.3.4", "/admin")  # must not raise

        assert result is False


class TestMaybeAlert:
    def test_high_confidence_triggers_alert(self, monkeypatch):
        monkeypatch.setenv("HONEYPOT_WEBHOOK_URL", "https://example.com/webhook")
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        with patch("app.honeypot.alerting.requests.post", return_value=mock_response) as mock_post:
            result = maybe_alert("RCE", 0.95, "1.2.3.4", "/admin")

        assert result is True
        mock_post.assert_called_once()

    def test_low_confidence_never_calls_the_webhook_at_all(self, monkeypatch):
        monkeypatch.setenv("HONEYPOT_WEBHOOK_URL", "https://example.com/webhook")
        with patch("app.honeypot.alerting.requests.post") as mock_post:
            result = maybe_alert("XSS", 0.5, "1.2.3.4", "/admin")

        assert result is False
        mock_post.assert_not_called()
