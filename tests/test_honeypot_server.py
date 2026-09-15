"""
tests/test_honeypot_server.py
================================

End-to-end tests through the actual Flask test client -- proves the
catch-all route, classification, and database persistence all work
together, not just each piece in isolation.
"""

import os

os.environ["SKIP_PERMISSION_CHECK"] = "1"

from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models import HoneypotLog, ThreatIntel

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def honeypot_client(monkeypatch):
    """
    Sets up an isolated in-memory database and points the honeypot
    server's SessionLocal at it, then returns a Flask test client plus
    the session factory so tests can query what got persisted.
    """
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestSessionLocal = sessionmaker(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)

    import app.honeypot.server as server_module

    monkeypatch.setattr(server_module, "SessionLocal", TestSessionLocal)
    server_module.captured_events.clear()

    server_module.app.config["TESTING"] = True
    client = server_module.app.test_client()

    yield client, TestSessionLocal

    Base.metadata.drop_all(bind=test_engine)


class TestCatchAllRoute:
    def test_any_path_is_caught_and_returns_401(self, honeypot_client):
        client, _ = honeypot_client
        response = client.get("/wp-admin/setup-config.php")
        assert response.status_code == 401

    def test_request_is_recorded_in_memory(self, honeypot_client):
        client, _ = honeypot_client
        client.get("/admin/login")
        import app.honeypot.server as server_module

        assert len(server_module.captured_events) == 1
        assert server_module.captured_events[0]["path"] == "/admin/login"

    def test_benign_request_is_classified_as_none(self, honeypot_client):
        client, _ = honeypot_client
        client.get("/admin")
        import app.honeypot.server as server_module

        assert server_module.captured_events[0]["attack_type"] == "none"

    def test_sqli_payload_is_classified_and_flagged(self, honeypot_client):
        client, _ = honeypot_client
        client.post("/login", data="username=admin' OR '1'='1")
        import app.honeypot.server as server_module

        assert server_module.captured_events[0]["attack_type"] == "SQLi"

    def test_lfi_via_query_string_is_classified_and_flagged(self, honeypot_client):
        """
        REGRESSION TEST: found through real, manual end-to-end testing
        with curl against a running honeypot process -- an LFI attempt in
        the query string (`?file=../../etc/passwd`, the classic delivery
        mechanism for this attack) was silently invisible to the original
        version of this route, which only classified request.path and the
        body, never the query string. This must never regress silently.
        """
        client, _ = honeypot_client
        client.get("/download?file=../../../../etc/passwd")
        import app.honeypot.server as server_module

        assert server_module.captured_events[0]["attack_type"] == "LFI"


class TestStandaloneDeployment:
    """
    Runs in a genuinely SEPARATE Python process, importing ONLY
    app.honeypot.server -- never app.main. This is deliberate: within a
    single pytest process, Python's module cache means re-importing
    app.honeypot.server after app.main has already run elsewhere would
    NOT reproduce the real bug this guards against (tables already exist
    by then). A fresh subprocess is the only way to faithfully test what
    actually happens when the honeypot is deployed and started on its
    own, the way the module docstring describes it should be.
    """

    def test_honeypot_creates_its_own_tables_when_run_standalone(self, tmp_path):
        import sqlite3
        import subprocess
        import sys

        db_path = tmp_path / "standalone_test.db"
        script = (
            "import os\n"
            f"os.environ['DATABASE_URL'] = 'sqlite:///{db_path}'\n"
            "import app.honeypot.server\n"  # import ONLY this -- never app.main
            "print('OK')\n"
        )

        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            cwd=str(_PROJECT_ROOT),
            timeout=30,
        )

        assert result.returncode == 0, f"subprocess failed:\n{result.stderr}"
        assert "OK" in result.stdout

        # THE ACTUAL PROOF: query the fresh sqlite file directly and
        # confirm honeypot_logs exists -- not the more common
        # `app.main`-created database, since app.main was never imported.
        connection = sqlite3.connect(str(db_path))
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        connection.close()

        assert "honeypot_logs" in tables
        assert "threat_intel" in tables


class TestPersistence:
    def test_every_request_creates_a_honeypot_log_row(self, honeypot_client):
        client, SessionLocal = honeypot_client
        client.get("/admin")

        db = SessionLocal()
        try:
            logs = db.query(HoneypotLog).all()
            assert len(logs) == 1
            assert logs[0].path == "/admin"
        finally:
            db.close()

    def test_attack_creates_a_threat_intel_row_but_benign_does_not(self, honeypot_client):
        client, SessionLocal = honeypot_client
        client.get("/admin")  # benign
        client.post("/login", data="username=admin' OR '1'='1")  # attack

        db = SessionLocal()
        try:
            honeypot_logs = db.query(HoneypotLog).all()
            threat_intel_rows = db.query(ThreatIntel).all()
            assert len(honeypot_logs) == 2  # both requests logged
            assert len(threat_intel_rows) == 1  # only the attack is threat intel
            assert threat_intel_rows[0].attack_type == "SQLi"
        finally:
            db.close()
