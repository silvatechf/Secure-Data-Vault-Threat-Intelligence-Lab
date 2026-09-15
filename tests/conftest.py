"""
tests/conftest.py
===================

Shared pytest fixtures. The key idea: every test gets a FRESH, ISOLATED,
IN-MEMORY database -- tests never touch vault.db on disk, and never leak
state between each other.
"""

import os
import tempfile
from pathlib import Path

os.environ["SKIP_PERMISSION_CHECK"] = "1"  # tests don't depend on file modes
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
# Without this, every test run would append to the real logs/access.log on
# disk, forever -- see app/middleware/access_log.py's module docstring.
os.environ["ACCESS_LOG_PATH"] = str(Path(tempfile.mkdtemp(prefix="secure_vault_test_logs_")) / "access.log")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth.jwt_manager import jwt_manager
from app.database import Base, get_db
from app.main import app
from app.security.rate_limiter import login_backoff, login_limiter

# StaticPool is required for an in-memory SQLite database in tests: without
# it, every new connection SQLAlchemy opens gets its OWN separate
# in-memory database (they don't share state), so tables created in one
# connection are invisible to the next. StaticPool forces every session in
# this test run to reuse the same single connection.
TEST_ENGINE = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=TEST_ENGINE)


@pytest.fixture
def client():
    Base.metadata.create_all(bind=TEST_ENGINE)

    def override_get_db():
        db = TestSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    # The rate limiter and JWT blacklist are process-wide singletons (see
    # app/security/rate_limiter.py and app/auth/jwt_manager.py) -- without
    # resetting them, tests would leak state into each other, since every
    # TestClient request appears to come from the same IP.
    login_limiter.reset()
    login_backoff.reset_all()
    jwt_manager.blacklist._revoked.clear()

    yield TestClient(app)
    Base.metadata.drop_all(bind=TEST_ENGINE)
    app.dependency_overrides.clear()


@pytest.fixture
def db_session_for_role_promotion():
    """
    Test-only helper: promotes a user's role directly via the database,
    simulating what a real admin-provisioning process (a CLI command, a
    manual DB operation, a dedicated internal endpoint) would do -- this
    project has no public "become an admin" API on purpose.
    """
    from app.models import User

    def _promote(username: str, new_role: str) -> None:
        db = TestSessionLocal()
        try:
            user = db.query(User).filter(User.username == username).first()
            user.role = new_role
            db.commit()
        finally:
            db.close()

    return _promote
