"""
app/vault/key_cache.py
========================

Master keys are NEVER stored, anywhere, ever -- not on disk, not in the
database, not in a config file. This module derives an encryption key
on-the-fly from a user's password, every time it's needed, and caches the
DERIVED key in memory for a short time so repeated operations (uploading
several files in one session) don't pay the full key-derivation cost every
single time.

WHY DERIVE THE KEY FROM A PASSWORD AT ALL?
----------------------------------------------
AES needs a fixed-length key (32 bytes for AES-256) -- a raw password like
"Str0ng!Password" isn't the right shape or randomness for that. PBKDF2
(Password-Based Key Derivation Function 2) takes a password + a salt and
stretches them through many rounds of hashing to produce exactly the right
number of bytes, in a way that's deliberately slow -- same "make brute
force expensive" logic as bcrypt for password hashing (see
app/auth/hashing.py), applied here to key derivation instead.

WHY CACHE THE DERIVED KEY, AND WHY ONLY BRIEFLY?
------------------------------------------------------
PBKDF2 with a high round count takes real time (that's the point). Making
a user's password "unlock" their vault key on every single file operation
in a session would be a slow, frustrating experience. Caching the DERIVED
key (never the password itself) for a short TTL (time-to-live) is the
practical middle ground: fast enough for a real session, short-lived
enough that a key doesn't sit in memory indefinitely if the process is
compromised or the session goes idle.
"""

import hashlib
import os
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# NIST currently recommends at least 600,000 iterations for PBKDF2-HMAC-SHA256
# (2023 OWASP guidance, still the right ballpark as of 2026). Like bcrypt's
# cost factor, higher = slower to brute-force, at the cost of taking longer
# for a legitimate user too.
PBKDF2_ITERATIONS = 600_000
AES_256_KEY_LENGTH_BYTES = 32  # 256 bits
DEFAULT_CACHE_TTL_SECONDS = 300  # 5 minutes


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a 32-byte AES-256 key from a password and salt. Deterministic:
    the same password + salt always produces the same key, which is
    exactly what's needed -- the vault needs to re-derive the same key
    later to decrypt, not a random one each time.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_256_KEY_LENGTH_BYTES,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


class KeyCache:
    """
    An in-memory, per-process cache of derived keys, keyed by
    (user_id, password fingerprint), with a TTL. Not a database table --
    restarting the process clears it entirely, which is the correct
    behavior for something that must never persist.
    """

    def __init__(self, ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS):
        self._ttl_seconds = ttl_seconds
        self._store: dict[tuple[int, str], tuple[bytes, float]] = {}  # (user_id, fingerprint) -> (key, expires_at)

    @staticmethod
    def _fingerprint(password: str, salt: bytes) -> str:
        """
        A cache-key fingerprint of the password -- NOT the AES key itself,
        and never used for anything security-sensitive. Its only job is
        to make sure a DIFFERENT password for the same user_id can never
        collide with (and silently reuse) a previously cached key for a
        correct password. Without this, caching purely by user_id would
        mean: derive once with the right password, and every SUBSEQUENT
        call within the TTL -- even with a wrong password -- would
        silently return the old, still-correct key instead of failing.
        That's a real bug this fingerprint exists specifically to close.
        """
        return hashlib.sha256(password.encode("utf-8") + salt).hexdigest()

    def get_or_derive(self, user_id: int, password: str, salt: bytes) -> bytes:
        cache_key = (user_id, self._fingerprint(password, salt))
        cached = self._store.get(cache_key)
        if cached is not None:
            key, expires_at = cached
            if time.monotonic() < expires_at:
                return key
            # expired -- fall through and re-derive

        key = derive_key(password, salt)
        self._store[cache_key] = (key, time.monotonic() + self._ttl_seconds)
        return key

    def invalidate(self, user_id: int) -> None:
        """Called on logout or password change -- drops every cached key for this user, regardless of which password produced it."""
        stale_keys = [k for k in self._store if k[0] == user_id]
        for k in stale_keys:
            del self._store[k]

    def size(self) -> int:
        """Mostly useful for tests -- how many keys are currently cached."""
        return len(self._store)


def generate_salt() -> bytes:
    """
    A fresh random salt for a new user's vault. Stored alongside the user
    (not secret -- salts are meant to be public), unlike the derived key,
    which is never stored.
    """
    return os.urandom(16)


# One shared cache instance for the running application.
key_cache = KeyCache()
