"""
app/auth/hashing.py
=====================

EX-04: Password hashing -- the single most important file in this project
to get right, because getting it wrong is how "Have I Been Pwned" gets new
entries.

THE RULE THAT MATTERS MOST: NEVER STORE PASSWORDS. STORE HASHES.
--------------------------------------------------------------------
A hash is a one-way function: easy to compute forward (password -> hash),
computationally infeasible to reverse (hash -> password). If this
database ever leaks, an attacker gets hashes, not passwords -- and a
*properly chosen* hashing algorithm makes cracking those hashes
prohibitively slow, even at scale.

WHY BCRYPT, NOT MD5 OR SHA-256?
-----------------------------------
MD5 and SHA-256 are FAST. That's exactly the wrong property for password
hashing -- fast means an attacker with a GPU can try billions of guesses
per second against a leaked hash dump. bcrypt (and argon2, its more modern
sibling) are deliberately SLOW and tunable via a "cost factor": each
increment roughly doubles the time it takes to compute one hash. That's a
minor inconvenience for your login endpoint (bcrypt at cost 12 takes
~250ms) and a massive obstacle for an attacker trying billions of guesses.

WHY A SALT?
--------------
Without a salt, two users with the password "password123" would have the
IDENTICAL hash in the database -- which lets an attacker use precomputed
"rainbow tables" to crack many accounts at once instead of one at a time.
bcrypt generates and embeds a random salt automatically every time you
hash a password, so this module doesn't manage salts manually -- but it's
worth knowing bcrypt is doing it for you, not assuming there's no salt
just because you don't see one.
"""

import bcrypt

# Cost factor: each +1 roughly doubles hashing time. 12 is bcrypt's
# widely-recommended minimum in 2026 -- high enough to slow down offline
# cracking attempts, low enough that a real login endpoint still responds
# in a few hundred milliseconds instead of several seconds.
BCRYPT_COST_FACTOR = 12


def hash_password(plain_password: str) -> str:
    """
    Hash a plaintext password for storage. Returns a string safe to store
    directly in the `password_hash` column -- it already contains the
    algorithm identifier, cost factor, and salt, all encoded together.
    """
    salt = bcrypt.gensalt(rounds=BCRYPT_COST_FACTOR)
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """
    Check a login attempt's plaintext password against the stored hash.

    Note there is no "decrypt the hash and compare" -- that's impossible
    by design. Instead, bcrypt re-hashes the provided password using the
    SAME salt and cost factor embedded in `stored_hash`, and compares the
    two hashes. This is why bcrypt.checkpw needs both values, not just the
    plaintext password.
    """
    return bcrypt.checkpw(plain_password.encode("utf-8"), stored_hash.encode("utf-8"))
