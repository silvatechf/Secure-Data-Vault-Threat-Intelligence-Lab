"""
tests/test_sql_injection.py
==============================

The most important test file in this project. It doesn't just check that
code "works" -- it PROVES, with a real classic attack string, that the
vulnerable version in app/insecure/ is exploitable, and that the fixed
version in app/vault/ is not. Read this alongside
docs/week-01-02-foundation.md for the full explanation.
"""

import sqlite3
import tempfile
from pathlib import Path

import pytest

from app.insecure.sql_injection_demo import find_user_by_username_VULNERABLE
from app.vault.secure_queries import find_user_by_username

# The classic authentication-bypass injection string. If this ever
# matches every row instead of zero, the query is vulnerable.
CLASSIC_INJECTION_STRING = "' OR '1'='1"


@pytest.fixture
def seeded_db():
    """A raw SQLite file (not the app's ORM) seeded with 3 users, so both
    the vulnerable and secure query functions -- which use raw sqlite3,
    not SQLAlchemy -- can run against it."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = str(Path(tmp_dir) / "test.db")
        conn = sqlite3.connect(db_path)
        conn.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)"
        )
        conn.executemany(
            "INSERT INTO users (username, email) VALUES (?, ?)",
            [
                ("alice", "alice@example.com"),
                ("bob", "bob@example.com"),
                ("carol", "carol@example.com"),
            ],
        )
        conn.commit()
        conn.close()
        yield db_path


class TestVulnerableVersionIsActuallyExploitable:
    """
    These tests exist to prove the vulnerability is real, not theoretical
    -- if someone "fixes" the insecure demo by accident while refactoring,
    this test starts failing and flags it immediately.
    """

    def test_normal_lookup_returns_exactly_one_user(self, seeded_db):
        results = find_user_by_username_VULNERABLE(seeded_db, "alice")
        assert len(results) == 1
        assert results[0][1] == "alice"

    def test_injection_string_returns_every_user_not_zero(self, seeded_db):
        """
        THE PROOF: searching for a username that doesn't exist should
        return zero rows. Instead, the injection string manipulates the
        WHERE clause into matching every row in the table.
        """
        results = find_user_by_username_VULNERABLE(seeded_db, CLASSIC_INJECTION_STRING)
        assert len(results) == 3  # every user in the table, not the 0 you'd expect


class TestSecureVersionResistsTheSameAttack:
    def test_normal_lookup_returns_exactly_one_user(self, seeded_db):
        results = find_user_by_username(seeded_db, "alice")
        assert len(results) == 1
        assert results[0][1] == "alice"

    def test_injection_string_returns_zero_users_not_every_user(self, seeded_db):
        """
        THE FIX, PROVEN: the exact same attack string that broke the
        vulnerable version returns zero rows here, because the database
        treats it as literal data -- a username that doesn't exist --
        rather than as part of the query's logic.
        """
        results = find_user_by_username(seeded_db, CLASSIC_INJECTION_STRING)
        assert len(results) == 0
