# Foundation: A Guided Walkthrough

This document explains the *why* behind every decision in Phase 1, not
just the *what*. If you're newer to security or Python, read this before
you read the code — each section builds the mental model first, then
points you at the exact file that implements it.

## Table of contents

1. [Why passwords are hashed, not encrypted](#1-why-passwords-are-hashed-not-encrypted)
2. [What a salt actually does](#2-what-a-salt-actually-does)
3. [Validation vs. parameterization — two different jobs](#3-validation-vs-parameterization--two-different-jobs)
4. [The file permission scanner, and why it aborts instead of warns](#4-the-file-permission-scanner)
5. [SQL injection, from first principles, with a real attack](#5-sql-injection-from-first-principles)
6. [Design decisions worth defending in an interview](#6-design-decisions-worth-defending-in-an-interview)
7. [Known simplifications in this phase](#7-known-simplifications-in-this-phase)

---

## 1. Why passwords are hashed, not encrypted

These two words get used interchangeably in casual conversation, and
that's exactly the mistake that leads to real breaches.

**Encryption is reversible.** If you encrypt something, there's a key that
decrypts it back to the original. That's the correct tool when *you* need
to read the data back later — a file in the vault (Phase 2), for example.

**Hashing is one-way by design.** There is no key that turns a hash back
into the original password. `hash_password("hunter2")` always produces
some fixed-length gibberish, and there is no `unhash()` function — not
because nobody's built one, but because the math doesn't allow it.

So why does that matter for passwords specifically? Because **the
application never needs to know your actual password** — it only ever
needs to check "does this login attempt match what I have on file?" That's
exactly what `verify_password()` in `app/auth/hashing.py` does: it hashes
the login attempt the same way, and compares the two hashes. If your
database of hashes ever leaks (and across the industry, this happens
constantly — it's not a hypothetical), an attacker gets a pile of gibberish
they cannot reverse into passwords, not a spreadsheet of your users' actual
passwords.

**Try it yourself:**
```python
from app.auth.hashing import hash_password
print(hash_password("hunter2"))
# $2b$12$K3n... (a completely different string every time you run this)
```

## 2. What a salt actually does

Here's a scenario that shows why hashing *alone* isn't enough: imagine two
users both pick the password `password123`. If you hash it with a plain
SHA-256 and no salt, their two hashes in the database would be **identical**
— because hashing the same input always produces the same output.

That's a problem because attackers maintain massive precomputed tables
("rainbow tables") mapping common passwords to their hashes. If your hash
matches a rainbow table entry, the attacker instantly knows your password —
no cracking required, just a lookup.

**A salt is random data mixed into the password before hashing**, unique
per user. Now `password123` hashed with salt `a1b2c3` produces a totally
different result than `password123` hashed with salt `x9y8z7` — even
though the underlying password is identical. Rainbow tables become useless,
because they'd need a separate table for every possible salt value, which
defeats the purpose of precomputing anything.

bcrypt (used in this project) generates and manages the salt for you
automatically — it's baked into the string `hash_password()` returns. You
don't see a separate "salt" field in the database because it's already
embedded in that one string.

**Proof this is working**, straight from `tests/test_auth.py`:
```python
def test_same_password_hashed_twice_produces_different_hashes(self):
    hash_one = hash_password("SamePassword1!")
    hash_two = hash_password("SamePassword1!")
    assert hash_one != hash_two          # different salts → different output
    assert verify_password("SamePassword1!", hash_one) is True   # but both still verify
    assert verify_password("SamePassword1!", hash_two) is True
```

## 3. Validation vs. parameterization — two different jobs

It's tempting to think "if my database queries are safe, my input is
safe" — but these solve genuinely different problems, and this project
deliberately implements both.

| | **Validation** (`app/middleware/validation.py`) | **Parameterization** (`app/vault/secure_queries.py`) |
|---|---|---|
| Question it answers | "Is this data well-formed and what I expect?" | "Can this data execute as code?" |
| Example failure it catches | Email `"not-an-email"` | Username `' OR '1'='1` |
| Where it runs | Before data touches the database | At the moment the database runs a query |

A validated, well-formed username can *still* be a SQL injection attack —
`admin' --` looks like a plausible username string, passes basic length and
character checks if you're not careful, and is a real, working attack
payload. Conversely, parameterized queries don't care whether an email
address is well-formed; they only guarantee that whatever string you pass
in is treated as inert data, never as part of the query's logic.

**You need both, and they run at different layers of the request.**

## 4. The file permission scanner

Quick primer on Unix file permissions, if this is new to you: every file
has three permission groups — **owner**, **group**, and **others** — each
with read/write/execute bits. A file mode of `644` breaks down as:
- `6` (owner: read + write)
- `4` (group: read only)
- `4` (others: read only)

The "others" category means **every other user account on that machine** —
not just you, not just your team. If your `.env` file (holding database
credentials, API keys, secrets) has any read permission for "others," any
other process or user on a shared host, a misconfigured container, or a
compromised low-privilege account can read it directly, no exploit
required.

`app/security/file_permissions.py` scans for `.env`, `.pem`, and `.key`
files on every startup and checks: `mode & 0o077`. That bitwise AND
isolates exactly the group/others permission bits — if the result is
non-zero, something beyond the owner has access, and the app refuses to
start.

**Why abort instead of just logging a warning?** A warning buried in
startup logs that nobody reads doesn't fix anything. Refusing to boot is
the only way to *guarantee* the misconfiguration gets noticed and fixed
before the application is exposed to real traffic.

**Try it yourself** (don't do this on a real `.env` with real secrets):
```bash
touch fake.env
chmod 644 fake.env
python -c "from pathlib import Path; from app.security.file_permissions import scan_for_insecure_permissions; print(scan_for_insecure_permissions(Path('.')))"
rm fake.env
```

## 5. SQL injection, from first principles

This is the concept worth understanding most deeply in Phase 1, because
it's still one of the most common real-world vulnerabilities — and once
you've seen it work, you'll never write a raw f-string SQL query again.

**The vulnerable version** (`app/insecure/sql_injection_demo.py`):
```python
query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
cursor.execute(query)
```

This looks harmless if you only ever test it with normal usernames like
`"alice"`. The problem appears the moment `username` contains a single
quote — because a single quote in SQL means "end of string." Watch what
happens with the input `' OR '1'='1`:

```
Before substitution:
  SELECT id, username, email FROM users WHERE username = '{username}'

After substitution:
  SELECT id, username, email FROM users WHERE username = '' OR '1'='1'
```

Read that final query as the database reads it: "find rows where username
equals empty string, **OR** where `1 equals 1`." Since `1=1` is always
true, this condition matches **every single row in the table** — the
attacker didn't need to know any real username, they turned the WHERE
clause itself into something that always matches.

This is proven, not just described, in `tests/test_sql_injection.py`:
```python
def test_injection_string_returns_every_user_not_zero(self, seeded_db):
    results = find_user_by_username_VULNERABLE(seeded_db, "' OR '1'='1")
    assert len(results) == 3   # every user in the table
```

**The fix** (`app/vault/secure_queries.py`):
```python
query = "SELECT id, username, email FROM users WHERE username = ?"
cursor.execute(query, (username,))
```

The `?` is a placeholder. Critically, the query text and the data are sent
to SQLite **separately** — the database compiles the query structure first
(with a placeholder, not a value, in that slot), and only afterward
substitutes in the actual value as pure data. There is no step where the
attacker's string gets parsed as part of the query's grammar, because by
the time substitution happens, the grammar is already fixed.

Run the exact same attack string against the fixed version:
```python
def test_injection_string_returns_zero_users_not_every_user(self, seeded_db):
    results = find_user_by_username(seeded_db, "' OR '1'='1")
    assert len(results) == 0   # treated as a literal (nonexistent) username
```

Zero rows — because the database now searches for a user whose username is
literally the 11-character string `' OR '1'='1`, which doesn't exist.

**A common misconception worth addressing directly**: "couldn't you just
escape the quotes yourself, or block dangerous keywords like `OR`?" You
could try — and security history is full of people who tried exactly that,
and full of attackers who found bypasses for every hand-rolled escaping or
blocklist scheme (alternate encodings, comment tricks, keyword case
variations, and more). Parameterized queries aren't "one good defense
among several" — they close the vulnerability at the protocol level,
structurally, rather than trying to filter for "bad-looking" input.

## 6. Design decisions worth defending in an interview

A few choices in this phase that weren't accidental, and are good talking
points:

- **Login and registration validation errors are asymmetric on purpose.**
  Registration tells you exactly what's wrong with your password ("needs a
  number"). Login never does — a wrong password and a nonexistent username
  return the *identical* `401` with the *identical* message. Detailed
  errors help a legitimate user fix a typo; detailed errors on a login
  endpoint help an attacker enumerate which usernames are real accounts.
- **Registration collects every validation error at once**, not just the
  first one it finds — a user fixing one problem only to hit the next on
  resubmit is a bad, and easily avoidable, experience.
- **The permission scanner skips `.venv`, `.git`, and `node_modules`** —
  without that, the scan would flag files that aren't secrets this project
  manages, generating false positives that train you to ignore its output.

## 7. Known simplifications in this phase

Being upfront about what's *not* done yet, on purpose, at this stage:

- **`Base.metadata.create_all()` instead of real migrations.** This
  creates tables if they don't exist, but has no concept of *changing* a
  table that already exists. A production system would use Alembic
  migrations from day one; this project defers that until the schema is
  less likely to change on every phase.
- **No session/token security yet.** `/auth/login` returns a plain success
  message with a user ID — there's no JWT, no session cookie, nothing an
  attacker could steal and reuse. That's intentional: Week 5-6 (EX-08)
  replaces this with real RS256-signed JWTs. Phase 1's job was proving the
  *authentication* logic (hashing, verification) works correctly, not
  building session management twice.
- **`SKIP_PERMISSION_CHECK=1` exists for tests and some dev environments.**
  This is a deliberate, narrow escape hatch — it must never be set in a
  real deployment, and it's called out explicitly here so it's never
  mistaken for a security feature rather than a testing convenience.
