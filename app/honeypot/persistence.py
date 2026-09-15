"""
app/honeypot/persistence.py
==============================

Writes captured honeypot events to the real database tables --
`honeypot_logs` for every single request, `threat_intel` only for the
ones the classifier flagged as an actual attack. Split out from
app/honeypot/server.py so the Flask route stays about HTTP handling and
this stays about storage -- the same separation-of-concerns pattern used
throughout this project (e.g. vault_engine.py vs. key_cache.py).
"""

import json

from sqlalchemy.orm import Session

from app.models import HoneypotLog, ThreatIntel


def persist_event(db: Session, event: dict) -> None:
    """
    Every captured request becomes a HoneypotLog row, unconditionally --
    this is the raw, complete record. A ThreatIntel row is added ONLY
    when the classifier found a real attack signature, because
    threat_intel is meant to be a curated feed of actual threats, not a
    duplicate of the raw log.
    """
    honeypot_log = HoneypotLog(
        source_ip=event["source_ip"],
        method=event["method"],
        path=event["path"],
        headers=json.dumps(event["headers"]),
        body=event["body"],
    )
    db.add(honeypot_log)

    if event["attack_type"] != "none":
        db.add(
            ThreatIntel(
                source_ip=event["source_ip"],
                attack_type=event["attack_type"],
                confidence=event["confidence"],
                payload=event["body"] or event["path"],
            )
        )

    db.commit()
