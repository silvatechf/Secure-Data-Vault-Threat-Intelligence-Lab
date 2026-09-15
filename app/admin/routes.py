"""
app/admin/routes.py
=====================

A minimal admin-only surface that exists specifically to exercise RBAC
end to end -- the honeypot config and threat intel management endpoints
the blueprint describes as "admin-protected" land in Week 7-8, once those
features exist. This gives `require_role("admin")` something real to
protect right now, rather than leaving RBAC untested until later phases.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.auth.rbac import require_role
from app.database import get_db
from app.models import AuditLog, User

router = APIRouter(prefix="/admin", tags=["admin"])


class UserSummary(BaseModel):
    id: int
    username: str
    email: str
    role: str
    model_config = ConfigDict(from_attributes=True)


class AuditLogSummary(BaseModel):
    id: int
    event_type: str
    user_id: int | None
    ip_address: str | None
    severity: str
    details: str | None
    model_config = ConfigDict(from_attributes=True)


@router.get("/users", response_model=list[UserSummary])
def list_users(db: Session = Depends(get_db), _admin: dict = Depends(require_role("admin"))):
    """Admin-only. A 'user' or 'analyst' token gets a 403 here, tested explicitly in tests/test_rbac.py."""
    return db.query(User).all()


@router.get("/audit-logs", response_model=list[AuditLogSummary])
def list_audit_logs(
    db: Session = Depends(get_db),
    _admin: dict = Depends(require_role("admin", "analyst")),
):
    """
    Admin OR analyst -- a two-role example, since a real security team
    usually wants analysts to review logs without needing full admin
    rights over the user base (see list_users above, admin-only).
    """
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(100).all()
