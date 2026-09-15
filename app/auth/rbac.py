"""
app/auth/rbac.py
==================

RBAC (Role-Based Access Control) enforcement.

A NOTE ON "DECORATORS" VS. FASTAPI DEPENDENCIES
------------------------------------------------------
The blueprint describes this as `@require_role('admin')` decorators.
FastAPI's idiomatic equivalent is a DEPENDENCY, not a Python decorator --
FastAPI resolves dependencies through its `Depends()` system so it can
also generate correct OpenAPI docs, handle errors consistently, and let
dependencies build on each other (require_role depends on
get_current_user, which depends on the token). This file gives you the
exact same DEVELOPER EXPERIENCE as a decorator -- write
`Depends(require_role("admin"))` on a route and it just works -- using the
pattern FastAPI is actually built around.

WHY get_current_user IS ITS OWN DEPENDENCY, SEPARATE FROM require_role
------------------------------------------------------------------------------
Plenty of endpoints need to know WHO is calling without restricting WHICH
role can call it (e.g. "list my own vault entries" -- any logged-in user,
not just admins). Splitting "who is this" from "are they allowed" means
every endpoint picks exactly the check it needs, instead of every route
implicitly requiring a specific role.
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.auth.jwt_manager import TokenError, jwt_manager

# HTTPBearer expects an `Authorization: Bearer <token>` header and extracts
# the token for us -- FastAPI also uses this to generate the "Authorize"
# button in the /docs UI automatically.
bearer_scheme = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> dict:
    """
    Decodes and validates the access token from the Authorization header.
    Returns a dict with user_id, username, and role -- every protected
    route gets this via `Depends(get_current_user)` instead of trusting a
    client-supplied user_id in the request body (the gap this phase
    closes -- see app/vault/routes.py).
    """
    token = credentials.credentials
    try:
        payload = jwt_manager.decode_token(token, expected_type="access")
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {
        "user_id": int(payload["sub"]),
        "username": payload["username"],
        "role": payload["role"],
    }


def require_role(*allowed_roles: str):
    """
    Returns a dependency that ensures the current user's role is one of
    `allowed_roles`. Usage on a route:

        @router.post("/admin/config")
        def admin_only(user: dict = Depends(require_role("admin"))):
            ...

    Stacking with get_current_user (rather than duplicating the token
    check) means role-restricted routes get identical 401-vs-403 behavior
    to every other authenticated route -- 401 if there's no valid token at
    all, 403 if there IS a valid token but the wrong role.
    """

    def dependency(user: dict = Depends(get_current_user)) -> dict:
        if user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires one of these roles: {', '.join(allowed_roles)}.",
            )
        return user

    return dependency
