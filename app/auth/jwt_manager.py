"""
app/auth/jwt_manager.py
=========================

EX-08: JWT (JSON Web Token) issuance and validation, signed with RS256.

WHAT A JWT ACTUALLY IS, IN THREE PARTS
------------------------------------------
A JWT is three base64-encoded pieces joined by dots:
`header.payload.signature`
- **header**: which algorithm was used to sign it (RS256, here).
- **payload**: the actual claims -- user_id, role, expiry, etc. Anyone
  can decode and READ this without any key -- a JWT is not encrypted,
  it's signed. Never put a secret inside a JWT payload.
- **signature**: proves the payload hasn't been tampered with. This is
  the part that requires the private key to produce, and the public key
  to verify.

WHY EXPIRY IS NON-NEGOTIABLE
---------------------------------
A JWT is a bearer token -- whoever holds it is treated as authenticated,
full stop, until it expires or is blacklisted. A token with no expiry, or
a very long one, is a permanent credential if it ever leaks. This module
uses SHORT-lived access tokens (15 minutes) and a LONGER-lived refresh
token (7 days) whose only job is to get a new access token -- limiting how
long a stolen access token remains useful, without forcing a full
re-login every 15 minutes.

WHY BLACKLIST AT ALL, IF TOKENS EXPIRE ANYWAY?
-------------------------------------------------------
Expiry handles the normal case. Blacklisting handles the abnormal one:
what if a user logs out, or their refresh token is rotated, before natural
expiry? Without a blacklist, a token that's supposed to be "dead" (logged
out, rotated away) would still verify successfully as long as it hasn't
technically expired yet. The blacklist closes that gap.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt

from app.auth.keys import load_or_generate_keys

ALGORITHM = "RS256"
ACCESS_TOKEN_TTL_MINUTES = 15
REFRESH_TOKEN_TTL_DAYS = 7


class TokenError(Exception):
    """Raised for any invalid, expired, or blacklisted token -- callers
    never need to know WHICH specific failure occurred, only that the
    token isn't usable. Revealing the specific reason (expired vs.
    tampered vs. blacklisted) to a client is an unnecessary information
    leak, same principle as the login endpoint's uniform error message."""


@dataclass
class TokenPair:
    access_token: str
    refresh_token: str


class TokenBlacklist:
    """
    Tracks revoked token IDs (the JWT's `jti` claim) until their original
    expiry passes -- after that, the token would fail validation on
    expiry alone, so there's no need to remember it forever.

    IN-MEMORY FOR THIS PHASE, ON PURPOSE: the blueprint's original design
    calls for Redis, which is the right choice the moment this API runs
    as more than one process (an in-memory set isn't shared across
    instances). A single-process portfolio deployment doesn't need that
    yet -- this class is written so swapping the storage backend later
    means implementing the same three methods against Redis, not
    redesigning the calling code.
    """

    def __init__(self):
        self._revoked: dict[str, datetime] = {}  # jti -> original expiry

    def revoke(self, jti: str, expires_at: datetime) -> None:
        self._revoked[jti] = expires_at

    def is_revoked(self, jti: str) -> bool:
        return jti in self._revoked

    def purge_expired(self) -> None:
        """Drops entries whose original token has already expired naturally -- housekeeping, not a correctness requirement."""
        now = datetime.now(timezone.utc)
        expired_jtis = [jti for jti, exp in self._revoked.items() if exp < now]
        for jti in expired_jtis:
            del self._revoked[jti]


class JWTManager:
    def __init__(self, keys_dir: Path | None = None):
        private_pem, public_pem = load_or_generate_keys(keys_dir) if keys_dir else load_or_generate_keys()
        self._private_key = private_pem
        self._public_key = public_pem
        self.blacklist = TokenBlacklist()

    def _create_token(self, user_id: int, username: str, role: str, ttl: timedelta, token_type: str) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "sub": str(user_id),
            "username": username,
            "role": role,
            "type": token_type,  # "access" or "refresh" -- see why this matters below
            "iat": now,
            "exp": now + ttl,
            "jti": str(uuid.uuid4()),  # unique ID, what the blacklist tracks
        }
        return jwt.encode(payload, self._private_key, algorithm=ALGORITHM)

    def create_token_pair(self, user_id: int, username: str, role: str) -> TokenPair:
        access = self._create_token(
            user_id, username, role, timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES), "access"
        )
        refresh = self._create_token(
            user_id, username, role, timedelta(days=REFRESH_TOKEN_TTL_DAYS), "refresh"
        )
        return TokenPair(access_token=access, refresh_token=refresh)

    def decode_token(self, token: str, expected_type: str = "access") -> dict:
        """
        Verifies signature and expiry (both handled by PyJWT internally),
        then checks two things PyJWT doesn't know about: the blacklist,
        and that this token is the TYPE the caller expects.

        WHY CHECK `type`? Without it, a REFRESH token -- which is only
        supposed to be exchanged for a new access token -- could be used
        directly as if it were an access token to call any protected
        endpoint. Refresh tokens should only ever flow through
        refresh_access_token() below.
        """
        try:
            payload = jwt.decode(token, self._public_key, algorithms=[ALGORITHM])
        except jwt.ExpiredSignatureError:
            raise TokenError("Token has expired.")
        except jwt.InvalidTokenError:
            raise TokenError("Token is invalid.")

        if self.blacklist.is_revoked(payload["jti"]):
            raise TokenError("Token has been revoked.")

        if payload.get("type") != expected_type:
            raise TokenError(f"Expected a {expected_type} token.")

        return payload

    def refresh_access_token(self, refresh_token: str) -> TokenPair:
        """
        Exchanges a valid, non-revoked refresh token for a brand new
        token pair, and immediately blacklists the OLD refresh token.

        WHY ROTATE THE REFRESH TOKEN TOO, NOT JUST ISSUE A NEW ACCESS
        TOKEN? If a refresh token is ever stolen, rotation limits it to a
        SINGLE use before it's dead -- an attacker who steals a refresh
        token gets at most one refresh cycle out of it, not indefinite
        re-use for its entire 7-day lifetime.
        """
        payload = self.decode_token(refresh_token, expected_type="refresh")

        expires_at = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        self.blacklist.revoke(payload["jti"], expires_at)

        return self.create_token_pair(
            user_id=int(payload["sub"]), username=payload["username"], role=payload["role"]
        )

    def revoke_token(self, token: str) -> None:
        """Used by /auth/logout -- blacklists whatever token is presented, regardless of type."""
        try:
            # Decode without type-checking or blacklist-checking here --
            # logout should work even on a token that's technically the
            # "wrong type," since the goal is just "make sure this can
            # never be used again."
            payload = jwt.decode(token, self._public_key, algorithms=[ALGORITHM])
        except jwt.InvalidTokenError:
            return  # already invalid/expired -- nothing to revoke
        expires_at = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        self.blacklist.revoke(payload["jti"], expires_at)


# One shared instance for the running application -- same pattern as
# app/vault/key_cache.py's shared `key_cache`.
jwt_manager = JWTManager()
