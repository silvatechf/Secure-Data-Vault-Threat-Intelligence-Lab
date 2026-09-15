"""
app/main.py
============

Application entrypoint. Run with:
    uvicorn app.main:app --reload

STARTUP ORDER MATTERS
-----------------------
1. The file permission scan runs FIRST, before anything else -- including
   before the database is touched. If a secret is exposed, we want the
   app to refuse to start, not accept one request first.
2. Database tables are created if they don't exist yet.
3. Routers are registered.

This ordering is not arbitrary: it reflects "fail closed" -- when in
doubt, refuse to run rather than run in a known-insecure state.
"""

from pathlib import Path

from fastapi import FastAPI

from app.admin.routes import router as admin_router
from app.auth.routes import router as auth_router
from app.database import Base, engine
from app.middleware.access_log import AccessLogMiddleware
from app.security.file_permissions import enforce_secure_permissions
from app.vault.routes import router as vault_router
from app.zkp.routes import router as zkp_router
from app.privacy.routes import router as privacy_router

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Step 1: abort startup if any critical file has insecure permissions.
# In a test environment this is normally skipped (see tests/conftest.py)
# so test runs don't depend on the filesystem permissions of whoever
# checked out the repo.
import os  # noqa: E402

if os.environ.get("SKIP_PERMISSION_CHECK") != "1":
    enforce_secure_permissions(PROJECT_ROOT)

# Step 2: create tables if they don't exist. A real production deployment
# would use Alembic migrations instead of create_all -- this is the
# pragmatic choice for a project at this stage, and is called out
# explicitly in docs/week-01-02-foundation.md as a known simplification.
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Secure Data Vault & Threat Intelligence Platform",
    description="A hands-on security engineering portfolio project.",
    version="0.1.0",
)

# Step 3: middleware and routers.
app.add_middleware(AccessLogMiddleware)
app.include_router(auth_router)
app.include_router(vault_router)
app.include_router(admin_router)
app.include_router(zkp_router)
app.include_router(privacy_router)


@app.get("/health")
def health_check():
    """Simple liveness check -- not a security feature, just useful."""
    return {"status": "ok"}
