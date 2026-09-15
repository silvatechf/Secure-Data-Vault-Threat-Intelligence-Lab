"""
app/auth/routes.py
====================

Registration and login endpoints. This is where EX-04 (hashing) and EX-01
(validation) meet: registration validates input BEFORE it ever touches the
hashing function, and the hashing function never sees a password that
hasn't already passed the strength checks.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.auth.hashing import hash_password, verify_password
from app.auth.jwt_manager import TokenError, TokenPair, jwt_manager
from app.auth.rbac import get_current_user
from app.database import get_db
from app.middleware.validation import validate_registration_input
from app.models import AuditLog, User
from app.security.rate_limiter import login_backoff, login_limiter

router = APIRouter(prefix="/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: int
    username: str
    email: str

    model_config = ConfigDict(from_attributes=True)


def _log_event(db: Session, event_type: str, user_id: int | None, ip: str, severity: str, details: str) -> None:
    db.add(AuditLog(event_type=event_type, user_id=user_id, ip_address=ip, severity=severity, details=details))
    db.commit()


def _client_ip(request: Request) -> str:
    # request.client is None in some test contexts (e.g. certain ASGI
    # transports) -- fall back to a placeholder rather than crashing on
    # something that isn't security-critical to get exactly right here.
    return request.client.host if request.client else "unknown"


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    errors = validate_registration_input(payload.username, payload.email, payload.password)
    if errors:
        # 422 with the full list of problems -- see app/middleware/validation.py's
        # docstring for why we collect every error instead of stopping at the first.
        raise HTTPException(status_code=422, detail=errors)

    existing = (
        db.query(User)
        .filter((User.username == payload.username) | (User.email == payload.email))
        .first()
    )
    if existing:
        # Deliberately vague: doesn't say WHICH of username/email is taken.
        # Confirming "this exact email already has an account" is a small
        # but real account-enumeration leak.
        raise HTTPException(status_code=409, detail="Username or email already registered.")

    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ip = _client_ip(request)

    # --- Rate limiting: check the exponential backoff block FIRST, before
    # even touching the sliding window -- a client currently serving a
    # backoff penalty shouldn't get a fresh sliding-window slot consumed.
    backoff_check = login_backoff.is_blocked(ip)
    if not backoff_check.allowed:
        _log_event(db, "login_blocked", None, ip, "HIGH", "IP blocked by exponential backoff.")
        raise HTTPException(
            status_code=429,
            detail=f"Too many attempts. Try again in {backoff_check.retry_after_seconds:.0f} seconds.",
        )

    window_check = login_limiter.check(ip)
    if not window_check.allowed:
        block_seconds = login_backoff.record_violation(ip)
        _log_event(
            db, "login_rate_limited", None, ip, "MEDIUM",
            f"Rate limit exceeded; backing off for {block_seconds:.0f}s.",
        )
        raise HTTPException(
            status_code=429,
            detail=f"Too many attempts. Try again in {window_check.retry_after_seconds:.0f} seconds.",
        )

    # --- Actual credential check.
    user = db.query(User).filter(User.username == payload.username).first()
    invalid_credentials = HTTPException(status_code=401, detail="Invalid username or password.")

    if not user or not verify_password(payload.password, user.password_hash):
        _log_event(db, "login_failed", user.id if user else None, ip, "MEDIUM", "Invalid credentials.")
        raise invalid_credentials

    # A real login resets the backoff penalty -- a legitimate user who
    # mistyped a few times shouldn't carry a growing block after finally
    # succeeding.
    login_backoff.reset(ip)
    _log_event(db, "login_success", user.id, ip, "LOW", "Successful login.")

    tokens = jwt_manager.create_token_pair(user_id=user.id, username=user.username, role=user.role)
    return TokenResponse(access_token=tokens.access_token, refresh_token=tokens.refresh_token)


@router.post("/refresh", response_model=TokenResponse)
def refresh(payload: RefreshRequest):
    try:
        tokens: TokenPair = jwt_manager.refresh_access_token(payload.refresh_token)
    except TokenError as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    return TokenResponse(access_token=tokens.access_token, refresh_token=tokens.refresh_token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, user: dict = Depends(get_current_user)):
    """
    Requires a valid access token (proves you're logged in), and
    blacklists it immediately -- this token can't be used again even
    though it hasn't naturally expired yet. The refresh token is a
    separate credential; a real client should discard it locally, but
    this endpoint only receives the access token via the Authorization
    header, so that's the one it can revoke directly.
    """
    # get_current_user already validated the token; re-extract it to
    # revoke rather than decode a second time.
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.removeprefix("Bearer ").strip()
    jwt_manager.revoke_token(token)
