"""
app/privacy/routes.py
========================

The admin-only endpoint the blueprint describes: `/reports/aggregated`,
protected the same way every other admin route in this project is (Week
5-6's `require_role`), returning a differentially private view of user
statistics -- never raw, individually-identifiable data.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.auth.rbac import require_role
from app.database import get_db
from app.models import User
from app.privacy.differential_privacy import generate_private_report

router = APIRouter(prefix="/reports", tags=["privacy"])


@router.get("/aggregated")
def get_aggregated_report(
    epsilon: float = 1.0,
    _admin=Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """
    Reports a NOISY total user count (never the exact figure) and checks
    k-anonymity on role/username-length as a stand-in quasi-identifier
    pair -- a real deployment would choose quasi-identifiers based on its
    actual schema's sensitive-adjacent fields.
    """
    users = db.query(User).all()
    records = [{"role": user.role, "username_length_bucket": len(user.username) // 5} for user in users]

    report = generate_private_report(
        records, quasi_identifiers=["role", "username_length_bucket"], epsilon=epsilon, k=5
    )

    return {
        "noisy_user_count": round(report.noisy_count, 2),
        "epsilon": report.epsilon,
        "k_anonymity_violations": len(report.k_anonymity_violations),
        "note": "noisy_user_count is randomized for privacy -- it will differ slightly on every call, by design.",
    }
