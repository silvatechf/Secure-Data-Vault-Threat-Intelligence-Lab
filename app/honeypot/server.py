"""
app/honeypot/server.py
=========================

EX-12: the honeypot itself. A SEPARATE Flask app (not part of the main
FastAPI application) that mimics a vulnerable /admin panel, catches
everything sent to it, classifies the attempt, and stores it as threat
intelligence.

WHY A SEPARATE SERVER, ON A SEPARATE PORT, IN A SEPARATE FRAMEWORK
------------------------------------------------------------------------
Three deliberate isolation choices, each for a different reason:

1. **Separate port (8080, not the main app's port)** -- so the honeypot
   can be exposed to the internet independently of the real application.
   A honeypot's entire value is LOOKING like a real, separately-reachable
   target.
2. **Separate logging (`honeypot_logs` / `threat_intel` tables, not
   `audit_logs`)** -- audit_logs records events about YOUR real users and
   YOUR real system; honeypot data is entirely about attackers probing a
   fake one. Mixing them would make audit_logs a worse audit trail and
   threat_intel a worse threat feed.
3. **Separate framework (Flask, not FastAPI)** -- this is honestly more
   "the blueprint specified it, and it's a reasonable real-world pattern"
   than a deep technical necessity: running the decoy on a genuinely
   different stack means a vulnerability specific to one framework
   doesn't automatically expose the other, and it makes the decoy
   trivially distinguishable in your own infrastructure inventory from
   the real API.

WHAT THIS ACTUALLY CATCHES
--------------------------------
Every request to any path under this Flask app (a catch-all route) is
logged in full -- method, path, headers, body, source IP -- and run through
the classifier (app/honeypot/classifier.py). If the classifier's
confidence is high enough, an alert fires (app/honeypot/alerting.py).
Nothing here requires an attacker to hit a SPECIFIC known-vulnerable path;
the whole app IS the trap.
"""

from datetime import datetime, timezone

from flask import Flask, request

from app.database import Base, SessionLocal, engine
from app.honeypot.alerting import maybe_alert
from app.honeypot.classifier import AttackType, classify_request
from app.honeypot.persistence import persist_event

# This server is meant to run as its OWN standalone process -- a real
# deployment starts it independently of the main FastAPI app (see the
# module docstring above: separate port, separate process, by design).
# Without this line, running `python -m app.honeypot.server` on a machine
# that has never started the main app first would try to INSERT into
# tables that don't exist yet, and every single request would fail with a
# database error. This exact bug slipped past the test suite, because
# tests always import app.main first (which creates the tables as a side
# effect) -- it only showed up when the honeypot was run as its own
# process, the way it's actually meant to be deployed.
Base.metadata.create_all(bind=engine)

app = Flask(__name__)

# In-memory store for captured events -- kept alongside the database
# write (not instead of it) because it makes tests fast and simple to
# assert against without a DB round-trip, while persist_event() below
# still gives this data the durability a real deployment needs.
captured_events: list[dict] = []


def _record_event(method: str, path: str, headers: dict, body: str, source_ip: str) -> dict:
    classification = classify_request(path=path, body=body, headers=headers)

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "method": method,
        "path": path,
        "headers": dict(headers),
        "body": body,
        "attack_type": classification.attack_type.value,
        "confidence": classification.confidence,
        "matched_patterns": classification.matched_patterns,
    }
    captured_events.append(event)

    db = SessionLocal()
    try:
        persist_event(db, event)
    finally:
        db.close()

    if classification.attack_type != AttackType.NONE:
        maybe_alert(
            attack_type=classification.attack_type.value,
            confidence=classification.confidence,
            source_ip=source_ip,
            path=path,
        )

    return event


@app.route(
    "/",
    defaults={"path": ""},
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
)
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def catch_all(path: str):
    """
    Every single request, to every single path, lands here. This is what
    makes it a honeypot rather than a single decoy endpoint: there's no
    "correct" URL an attacker needs to find -- anything they try gets
    captured.

    IMPORTANT: the query string is deliberately folded into the path used
    for classification and logging. Flask's routed `path` and
    `request.path` never include it -- and query parameters are exactly
    where a huge share of real LFI and SQLi payloads live (e.g.
    `?file=../../etc/passwd`, `?id=1' OR '1'='1`). The first version of
    this honeypot only classified the bare path and body, which meant a
    classic query-string LFI attempt was silently invisible to it --
    caught during manual end-to-end testing with curl, not by the
    original test suite (which happened not to exercise a query-string
    attack). tests/test_honeypot_server.py now has a regression test for
    exactly this.
    """
    query_string = request.query_string.decode("utf-8", errors="replace")
    full_path = f"/{path}" + (f"?{query_string}" if query_string else "")

    body = request.get_data(as_text=True) or ""
    _record_event(
        method=request.method,
        path=full_path,
        headers=dict(request.headers),
        body=body,
        source_ip=request.remote_addr or "unknown",
    )

    # Deliberately looks like a plausible, boring admin panel response --
    # not an error page that might tip off an attacker they've been
    # logged, and not real functionality that could ever be exploited.
    return {"status": "unauthorized", "message": "Admin access requires authentication."}, 401


def create_app() -> Flask:
    """Factory function, used by tests to get a fresh app instance."""
    return app
