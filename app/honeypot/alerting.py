"""
app/honeypot/alerting.py
===========================

Sends a webhook notification when the honeypot catches a high-confidence
attack. Kept deliberately separate from the honeypot server itself
(app/honeypot/server.py) so it can be tested without any real network
call, and so a broken or unreachable webhook endpoint can never crash
request handling in the honeypot.

DESIGN DECISION: FAILURES HERE ARE SWALLOWED, NOT RAISED
--------------------------------------------------------------
This is a deliberate exception to this project's general "don't hide
errors" philosophy (see app/vault/vault_engine.py, app/security/rate_limiter.py
for examples where errors are NEVER swallowed). Alerting is different: a
webhook failing to send should reduce visibility into an attack, not
compound the problem by taking down the honeypot's ability to keep
logging that attack. The honeypot's job (capture and log) must keep
working even if the notification pipeline is degraded.
"""

import logging
import os

import requests

logger = logging.getLogger(__name__)

CONFIDENCE_ALERT_THRESHOLD = 0.80


def send_alert(attack_type: str, confidence: float, source_ip: str, path: str) -> bool:
    """
    Posts a JSON payload to the webhook URL configured in
    HONEYPOT_WEBHOOK_URL. Returns True if the alert was sent
    successfully, False otherwise (including when no webhook is
    configured at all -- a portfolio deployment with no webhook
    integration is a valid, expected state, not an error).
    """
    webhook_url = os.environ.get("HONEYPOT_WEBHOOK_URL")
    if not webhook_url:
        logger.info(
            "Alert suppressed (no HONEYPOT_WEBHOOK_URL configured): "
            "%s attack, confidence %.2f, from %s on %s",
            attack_type, confidence, source_ip, path,
        )
        return False

    payload = {
        "text": (
            f"[Honeypot Alert] {attack_type} attack detected "
            f"(confidence {confidence:.0%}) from {source_ip} on {path}"
        ),
        "attack_type": attack_type,
        "confidence": confidence,
        "source_ip": source_ip,
        "path": path,
    }

    try:
        response = requests.post(webhook_url, json=payload, timeout=5)
        response.raise_for_status()
        return True
    except requests.RequestException as exc:
        logger.warning("Failed to send honeypot alert webhook: %s", exc)
        return False


def maybe_alert(attack_type: str, confidence: float, source_ip: str, path: str) -> bool:
    """Only sends an alert if confidence clears the threshold — the honeypot's actual entry point."""
    if confidence < CONFIDENCE_ALERT_THRESHOLD:
        return False
    return send_alert(attack_type, confidence, source_ip, path)
