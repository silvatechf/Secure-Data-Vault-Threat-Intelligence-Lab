# API Security: A Guided Walkthrough

Same format as [Week 1-2](./week-01-02-foundation.md) and
[Week 3-4](./week-03-04-vault-engine.md): the *why* first, then the file
that implements it. This phase closes the biggest gap flagged as a known
simplification in both earlier phases: real session security.

## Table of contents

1. [JWT: what it is, and why RS256](#1-jwt-what-it-is-and-why-rs256)
2. [Access + refresh tokens, and why rotation matters](#2-access--refresh-tokens-and-why-rotation-matters)
3. [RBAC as a dependency, not a decorator](#3-rbac-as-a-dependency-not-a-decorator)
4. [Rate limiting: two algorithms, two different jobs](#4-rate-limiting-two-algorithms-two-different-jobs)
5. [The password manager: reusing the vault, not rebuilding it](#5-the-password-manager-reusing-the-vault-not-rebuilding-it)
6. [A real bug this phase found and fixed](#6-a-real-bug-this-phase-found-and-fixed)
7. [Design decisions worth defending in an interview](#7-design-decisions-worth-defending-in-an-interview)
8. [Known simplifications in this phase](#8-known-simplifications-in-this-phase)

---

## 1. JWT: what it is, and why RS256

A JWT (JSON Web Token) is three pieces joined by dots:
`header.payload.signature`. The payload holds claims — who this token
represents (`sub`), their role, when it expires (`exp`) — and it is
**signed, not encrypted**. Anyone can decode and read a JWT's payload
without any key at all; what the signature guarantees is that the payload
hasn't been tampered with since it was issued. (This is why nothing
secret ever goes inside a JWT payload.)

There are two ways to sign a JWT, and the choice matters:

- **HS256** (symmetric): one secret both signs and verifies. Anything that
  can check a token is valid can also forge new ones.
- **RS256** (asymmetric, used here): a **private key** signs, a separate
  **public key** verifies. A service that only needs to verify tokens
  (say, a future microservice checking who's calling) only needs the
  public key — it can confirm a token is genuine without ever being able
  to create one. For a single-service project this distinction is mostly
  academic; it's the right habit for a system that might ever grow past
  one service, and it's what `app/auth/keys.py` and
  `app/auth/jwt_manager.py` implement.

## 2. Access + refresh tokens, and why rotation matters

Two tokens exist for a reason: the **access token** (15 minutes) is what
gets sent with every request — short-lived on purpose, so a leaked one is
only useful briefly. The **refresh token** (7 days) does exactly one job:
trade itself for a new token pair, via `POST /auth/refresh`. It's never
sent with ordinary API calls, which limits how often it's exposed at all.

**Rotation** is the detail that makes refresh tokens meaningfully safer
than "just make the access token last longer": every time a refresh token
is used, it's immediately blacklisted and a brand new refresh token is
issued alongside the new access token.

```python
def test_old_refresh_token_is_blacklisted_after_use(self, ...):
    ...
```

Why this matters: if a refresh token is ever stolen, an attacker gets
**at most one refresh cycle** out of it — the moment the legitimate user
refreshes next (which they will, routinely, as their access token
expires), the stolen copy stops working. Without rotation, a stolen
refresh token would remain valid for its entire 7-day lifetime.

## 3. RBAC as a dependency, not a decorator

The project blueprint sketches `@require_role('admin')` as a decorator.
`app/auth/rbac.py` implements the same developer experience —
`Depends(require_role("admin"))` on a route — as a **FastAPI dependency**
instead. This isn't a cosmetic difference: FastAPI dependencies compose
(`require_role` is built ON TOP of `get_current_user`, not duplicating its
token-checking logic), integrate with the auto-generated `/docs` UI (which
shows an "Authorize" button), and give consistent error handling across
every protected route in the app.

`get_current_user` and `require_role` are deliberately separate:

```python
@router.get("/my-files")
def list_my_files(user: dict = Depends(get_current_user)):
    ...  # any logged-in user, no role restriction

@router.get("/admin/users")
def list_users(_admin: dict = Depends(require_role("admin"))):
    ...  # admin only
```

Splitting "who is calling" from "are they allowed to do THIS" means every
endpoint asks for exactly the check it needs.

**A genuinely important property, worth understanding, not just knowing
it's tested:** a role change doesn't retroactively affect tokens already
issued. `tests/test_rbac.py` proves this directly —

```python
def test_old_token_still_reflects_old_role_after_promotion(...):
    old_token = _register_login_get_token(client, "laterpromoted")
    db_session_for_role_promotion("laterpromoted", "admin")
    # The token issued BEFORE promotion still claims role=user.
    response = client.get("/admin/users", headers={"Authorization": f"Bearer {old_token}"})
    assert response.status_code == 403
```

A promoted user's *existing* token keeps behaving as if they're still a
regular user until it naturally expires (at most 15 minutes) or they log
in again. This is a real, deliberate trade-off of using JWTs at all — the
alternative (checking the database on every single request) would defeat
the point of a stateless token in the first place.

## 4. Rate limiting: two algorithms, two different jobs

`app/security/rate_limiter.py` implements two different algorithms
because they solve genuinely different problems, not because variety is
inherently good:

- **Sliding window** (`SlidingWindowLimiter`) tracks exact request
  timestamps and asks "how many happened in the last N seconds?" — precise
  and fair, no boundary trick where a client sends a burst right at the
  edge of two windows to double their effective rate. Used for
  **login attempts**, where precision matters more than raw throughput.
- **Token bucket** (`TokenBucketLimiter`) holds a refillable allowance —
  naturally permits short bursts (spend your saved-up allowance) while
  still capping sustained throughput over time. Better suited to a
  higher-volume, authenticated route where occasional bursts (uploading
  several files back to back) shouldn't be punished the way a strict
  window would.

**Exponential backoff** sits on top of either limiter: a single rate-limit
hit gets a short penalty, but each *consecutive* violation roughly doubles
the block duration. This is wired into `/auth/login` directly — five
failed attempts in 60 seconds trigger a block, and repeat offenders get
locked out for exponentially longer:

```python
def test_sixth_login_attempt_within_a_minute_is_rate_limited(self, client):
    ...
```

Every block is also written to `audit_logs` (the table Week 1-2 defined,
now actually populated) — this is the first real consumer of that schema,
ahead of the full SIEM-style analysis coming in Week 7-8.

## 5. The password manager: reusing the vault, not rebuilding it

`app/cli/password_manager.py` (B-01) is deliberately built on components
this project already has — `VaultEngine` for AES-256-GCM encryption,
`key_cache` for PBKDF2 key derivation — rather than inventing a second
encryption scheme for a second use case. Site credentials are encrypted
with the exact same master vault password that protects uploaded files:
one strong password protects everything, the same design real password
managers (Bitwarden, 1Password) use.

Two details worth understanding:

- **Passwords are generated with `secrets`, never `random`.** Python's
  `random` module is a general-purpose, statistically predictable PRNG —
  fine for a game or a simulation, never for anything security-sensitive.
  `secrets` is specifically built for tokens, passwords, and similar
  values, and is what Python's own documentation recommends.
- **Clipboard auto-clear degrades gracefully.** In a headless environment
  (CI, SSH, a server with no display), there's no clipboard to copy to at
  all — `_copy_to_clipboard_with_auto_clear()` catches that and falls back
  to printing the password directly, rather than crashing. When a
  clipboard IS available, it clears itself after 10 seconds — but *only*
  if the clipboard still holds what this tool put there, so it never wipes
  out something the user copied in the meantime.

## 6. A real bug this phase found and fixed

Worth being completely direct about this one, because it's a better
interview story than pretending everything was perfect the first time:

Week 3-4's `KeyCache` cached a derived AES key **by `user_id` alone**.
That has a real, exploitable consequence: if a user unlocks their vault
correctly once, the correct key sits cached for 5 minutes — during which
a call with the **wrong** password would still silently receive the
**correct**, previously-cached key back, because the cache lookup never
checked whether the newly-supplied password actually matched what
produced the cached key.

The fix, in this phase's version of `app/vault/key_cache.py`, caches by
`(user_id, sha256(password + salt))` instead of `user_id` alone —
a wrong password produces a different fingerprint, misses the cache
entirely, and correctly derives a *different* (wrong) key from PBKDF2,
which then fails AES-GCM's integrity check exactly as it should.

```python
def test_wrong_password_never_returns_a_previously_cached_correct_key(self, ...):
    ...
```

This is a good example of why revisiting earlier phases as a project
grows isn't optional — a design that looked reasonable in isolation
(Week 3-4, before any authentication flow existed to attack it through)
turned out to have a real gap once a more complete threat model applied.

**A second, unrelated bug from the same end-to-end testing pass**: Week
1-2's file permission scanner (`app/security/file_permissions.py`) flags
any `*.pem` file that's readable by group/others — which is correct for a
private key, but wrong for a *public* key, whose entire purpose is to be
freely readable. The first time this project's real startup path ran
(rather than the test suite, which skips the permission check), it
refused to boot because `jwt_signing_key.pub.pem` was sitting at the
normal, expected mode 644. Fixed by excluding `*.pub.pem` (and similar
public-key naming patterns) from the scanner's critical-file list — see
`tests/test_file_permissions.py` for the regression test, including one
that confirms the *private* half of the same key pair is still correctly
flagged if it's ever insecure. Worth citing directly if asked "how do you
find bugs like this" — testing the actual startup path, not just the unit
tests, is what surfaced it.

## 7. Design decisions worth defending in an interview

- **The JWT proves identity; the vault password unlocks encryption — kept
  as two separate concerns on purpose.** `app/vault/routes.py`'s docstring
  explains this directly: a stolen JWT alone is not enough to decrypt
  anyone's files, because the AES key is derived from a password that
  never appears in the token.
- **`client.user_id` is no longer trusted from the request body anywhere**
  — every protected route gets the user from the validated token instead.
  `tests/test_vault_routes.py::test_user_b_cannot_use_a_forged_user_id_anymore`
  proves the exact vulnerability this closes, compared to Week 3-4's
  version of these same endpoints.
- **The in-memory blacklist and rate limiter are explicitly documented as
  single-process only** — not hidden as if they were production-ready.
  Naming a real limitation clearly is more credible than pretending it
  doesn't exist.

## 8. Known simplifications in this phase

- **JWT blacklist and rate limiter state are in-memory**, not Redis. This
  is fine for a single-process deployment (this project's current
  target); it stops being fine the moment more than one instance of the
  app runs behind a load balancer, since neither structure is shared
  across processes. The classes are written so swapping in Redis later
  means implementing the same handful of methods against a different
  backend, not a redesign.
- **There is no public "become an admin" endpoint.** Role promotion in
  this phase happens by direct database access — the same way a real
  admin-provisioning process might work early on, before a proper admin
  console exists. `tests/conftest.py`'s `db_session_for_role_promotion`
  fixture exists specifically because there's no API to test through.
- **The password manager CLI has no `delete` or `update` command yet** —
  `add`, `get`, `list`, and `generate` cover the exercise's core
  requirements; credential rotation/deletion is a natural, small addition
  rather than a gap in the underlying design.
- **The RSA signing key pair itself is never rotated** — it's generated
  once and reused indefinitely. This is a different thing from the
  refresh-token rotation in section 2 above (which happens on every
  `/auth/refresh` call and is implemented): the blueprint's security
  checklist calls for rotating the *signing key* every 30 days, which
  would need a key-versioning scheme (so tokens signed by the previous
  key still verify during a rollover window) that this phase doesn't
  build yet.
