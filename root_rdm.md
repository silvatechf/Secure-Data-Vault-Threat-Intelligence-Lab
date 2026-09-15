# 🔐 Security Engineering & Threat Intelligence Laboratory

A production-shaped security engineering project built one deliberate phase at a time: hardened authentication, encrypted file storage, JWT-based API security, an active honeypot with a SIEM-style analyzer, end-to-end encrypted messaging, zero-knowledge proof auth, differential privacy, and a self-audit scanner — all in one connected FastAPI application, not disconnected scripts.

**All 5 phases complete — 244 tests passing, self-audit scanner reports zero findings, `bandit`/`pip-audit` clean.**

**Every secure module has a vulnerable twin.** `app/insecure/` holds intentionally broken code next to its fixed version, so the fix is provable, not just asserted.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Running It](#running-it)
3. [Phase 1 — Foundation (Weeks 1-2)](#phase-1--foundation-weeks-1-2)
4. [Phase 2 — Vault Engine (Weeks 3-4)](#phase-2--vault-engine-weeks-3-4)
5. [Phase 3 — API Security (Weeks 5-6)](#phase-3--api-security-weeks-5-6)
6. [Phase 4 — Threat Intelligence (Weeks 7-8)](#phase-4--threat-intelligence-weeks-7-8)
7. [Phase 5 — Advanced Crypto & Audit (Weeks 9-10)](#phase-5--advanced-crypto--audit-weeks-9-10)
8. [Real Bugs Found by Actually Running the System](#real-bugs-found-by-actually-running-the-system)
9. [Testing](#testing)
10. [Security Controls Summary](#security-controls-summary)
11. [Known Limitations](#known-limitations)
12. [Project Structure](#project-structure)

---

## Architecture

```
Main application (uvicorn app.main:app)         Honeypot (separate process, port 8080)
  │                                                │
  │  /auth/*, /vault/*, /admin/*, /auth/zkp/*,     │  ANY path, ANY method
  │  /reports/aggregated                           │
  ▼                                                ▼
FastAPI app                                    Flask catch-all
  │                                                │
  ├── AccessLogMiddleware ──► logs/access.log      ├── classifier.py (XSS/LFI/RCE/SQLi)
  │        │                                       │        │
  │        ▼                                       │        ▼
  │  app/analysis/log_analyzer.py                  │  app/honeypot/alerting.py ── webhook if confidence > 80%
  │  (brute-force, bad UA, traversal, spikes)       │        │
  │                                                 │        ▼
  ├── app/auth/ (hashing, JWT RS256, RBAC)          └──► honeypot_logs + threat_intel tables
  ├── app/vault/ (AES-256-GCM, PII redaction)
  ├── app/security/ (permission scan, rate limiter)
  ├── app/zkp/ (Schnorr non-interactive proof)
  ├── app/privacy/ (differential privacy + charts)
  ├── app/messenger/ (RSA-4096 E2E encryption)
  ├── app/audit/ (AST self-audit scanner, SARIF output)
  ├── app/cli/ (password manager, messenger CLI)
  │
  └── app/models.py ── users, vault_entries, audit_logs, threat_intel,
                        honeypot_logs, site_credentials

app/forensics/ (standalone tools)
  ├── packet_sniffer.py    ── pcap analysis: HTTP/DNS/TLS-SNI, port scan detection
  └── string_extractor.py  ── printable strings + IoCs + YARA rule generation
```

## Running It

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env              # edit if needed

uvicorn app.main:app --reload
```

Open `http://localhost:8000/docs` for the interactive API docs.

**The honeypot is a separate process, by design** (see Phase 4):
```bash
python -m flask --app app.honeypot.server run --port 8080
```

**Docker** (main app + honeypot as two services):
```bash
docker compose up --build
```
*(Authored and hand-checked; not built against a live daemon in this environment — run `docker compose up --build` yourself before relying on it. See [Known Limitations](#known-limitations).)*

**Password manager CLI:**
```bash
python -m app.cli.password_manager add <site> --username <user>
python -m app.cli.password_manager get <site>
```

**E2E messenger CLI:**
```bash
python -m app.cli.messenger keygen alice
python -m app.cli.messenger send alice bob "message" --out msg.json
python -m app.cli.messenger receive bob msg.json
```

**Self-audit scanner:**
```bash
python -c "
from pathlib import Path
from app.audit.security_scan import scan_directory, has_critical_findings
findings = scan_directory(Path('app'))
print(f'{len(findings)} findings, critical: {has_critical_findings(findings)}')
"
```

---

## Phase 1 — Foundation (Weeks 1-2)

**Deliverable:** working auth system, hardened database, permission scanner.

### Password hashing (EX-04) — `app/auth/hashing.py`
bcrypt, cost factor 12, salt generated and embedded automatically. Hashing is one-way by design — there is no `unhash()`, unlike encryption. bcrypt (deliberately *slow*) is used instead of fast hashes like MD5/SHA-256, which is exactly the wrong property for passwords: fast means an attacker can try billions of guesses per second against a leaked dump.

### Input validation (EX-01) — `app/middleware/validation.py`
Regex-based checks for email/username/password strength, collecting *every* error at once rather than stopping at the first. Validation (data quality) and parameterized queries (execution safety) solve different problems — a well-formed username can still be a SQL injection payload.

### File permission scanner (EX-03) — `app/security/file_permissions.py`
Scans `.env`/`.pem`/`.key` on every startup; **aborts boot** (not just warns) if any are group/other-readable. Public keys (`*.pub.pem`) are explicitly excluded — they're *meant* to be world-readable (see [Real Bugs](#real-bugs-found-by-actually-running-the-system)).

### SQL injection (EX-07) — `app/insecure/sql_injection_demo.py` vs `app/vault/secure_queries.py`
The vulnerable version builds a query with an f-string; `' OR '1'='1` returns every row. The fixed version uses a `?` placeholder — the database treats the exact same string as inert data, returning zero rows. Proven directly in `tests/test_sql_injection.py` against both versions with the identical attack string.

---

## Phase 2 — Vault Engine (Weeks 3-4)

**Deliverable:** end-to-end encrypted file vault with PII-safe metadata.

### AES-256-GCM (EX-06) — `app/vault/vault_engine.py`
GCM is an AEAD mode: it provides confidentiality *and* an authentication tag, so a single tampered ciphertext byte makes decryption fail loudly rather than silently returning corrupted data. A fresh random 12-byte IV is generated on **every** encryption call — reusing an IV with GCM can catastrophically leak the authentication key.

### Key derivation (`app/vault/key_cache.py`)
PBKDF2 (600,000 rounds) derives the AES key from the user's password on demand — no master key is ever stored. A short-TTL cache avoids re-deriving on every operation in a session, fingerprinted on `(user_id, hash(password+salt))` — not just `user_id` (see [Real Bugs](#real-bugs-found-by-actually-running-the-system)).

### PII redaction (EX-05) — `app/vault/pii_redaction.py`
Filenames/descriptions are redacted (email/SSN/credit-card patterns) **before** database insertion — encryption protects file contents, not metadata, which stays plaintext and searchable otherwise.

### Caesar cipher (EX-02) — `app/vault/caesar_cipher.py`
The deliberate *insecure* exception: only 25 possible shifts, so `brute_force_crack()` recovers plaintext from ciphertext alone using English letter-frequency scoring — no key needed. Exists purely as a "legacy import" feature and a contrast to AES-256's 2^256 key space.

---

## Phase 3 — API Security (Weeks 5-6)

**Deliverable:** JWT auth, RBAC, rate limiting, CLI password manager.

### JWT RS256 (EX-08) — `app/auth/jwt_manager.py`, `app/auth/keys.py`
Asymmetric signing: a private key signs, a public key verifies — a service that only verifies tokens can never forge one. 15-min access tokens; refresh tokens **rotate on every use** (old one blacklisted immediately) so a stolen refresh token is useful for at most one cycle.

### RBAC (`app/auth/rbac.py`)
`require_role("admin")` as a FastAPI dependency, built on `get_current_user`. A promoted user's *existing* token still reflects their old role until reissued — a real, deliberate trade-off of stateless tokens, not a bug.

### Rate limiting (EX-09) — `app/security/rate_limiter.py`
Sliding window (precise, no boundary-gaming) for login attempts; token bucket (allows natural bursts) for higher-volume routes. Exponential backoff on repeat violations, logged to `audit_logs`.

### Password manager (B-01) — `app/cli/password_manager.py`
Built entirely on Phase 2's `VaultEngine`/`key_cache` — no new cryptography. Passwords generated with `secrets` (never `random`). Clipboard auto-clears after 10s, only if it still holds what this tool put there.

---

## Phase 4 — Threat Intelligence (Weeks 7-8)

**Deliverable:** honeypot, SIEM-style analyzer, forensics toolkit.

### Honeypot (EX-12) — `app/honeypot/`
A **separate** Flask app (separate port, separate database tables, separate framework) with a catch-all route — every path/method lands in the same handler. `classifier.py` pattern-matches XSS/LFI/RCE/SQLi (transparent, explainable, catches most real-world scanner traffic); `alerting.py` fires a webhook above 80% confidence, swallowing failures so a broken webhook never takes down logging.

### Log analyzer (EX-10) — `app/analysis/log_analyzer.py`
Reads `logs/access.log` (written by `app/middleware/access_log.py`) and detects: brute-force (5+ 401s/60s, sliding-window precise), suspicious user agents, directory traversal (CRITICAL — against the *real* app, not a decoy), traffic spikes (LOW — most legitimate explanations).

### Packet sniffer (B-02) — `app/forensics/packet_sniffer.py`
Analyzes `.pcap` files (not live sniffing — that needs root). Extracts HTTP requests, DNS queries, and TLS SNI (the hostname sent *in the clear* during a TLS handshake, before encryption starts). Port-scan detection: many distinct SYN destination ports from one source, correctly excluding SYN-ACK responses.

### String extractor (EX-13) — `app/forensics/string_extractor.py`
Reimplements Unix `strings`: scans raw bytes for printable runs ≥4 chars, filters for URL/email/API-key patterns, cross-references known IoCs, generates a simplified YARA rule.

---

## Phase 5 — Advanced Crypto & Audit (Weeks 9-10)

**Deliverable:** E2E messaging, ZKP auth, differential privacy, self-audit, Docker.

### E2E messenger (EX-11) — `app/messenger/e2e.py`, `app/cli/messenger.py`
RSA-4096. Encryption (OAEP, with the *recipient's* public key) and signing (PSS, with the *sender's* private key) are different operations solving different problems — confidentiality vs. authenticity. **Verify-then-decrypt** ordering: a forged/tampered message never reaches decryption. Private keys stored as password-protected PEM.

### Zero-Knowledge Proof (EX-15) — `app/zkp/schnorr.py`
Schnorr protocol, non-interactive via Fiat-Shamir (`c = H(g,y,t)`). Proves knowledge of a secret `x` to a verifier who only ever stores `y = g^x mod p` — `x` **never** travels over the network, not even once, not even encrypted. Demo endpoint: `/auth/zkp/register` + `/auth/zkp/prove`.

### Differential privacy (EX-14) — `app/privacy/differential_privacy.py`
Laplace-mechanism noise (calibrated to epsilon) added to aggregate counts before release — defends against *differencing attacks* ("aggregate-only" isn't automatically private). k-anonimity checked separately (a dataset property, not a release-time statistic property). `/reports/aggregated` is RBAC-protected.

### Self-audit scanner (B-03) — `app/audit/security_scan.py`, `app/audit/sarif.py`
AST-based (not regex) scan of the project's **own** source for hardcoded secrets, unsafe `eval`/`exec`, weak hashes, `debug=True`, bare `except`. `app/insecure/` is explicitly, documentedly excluded. Outputs SARIF (GitHub code-scanning compatible). **Result: 0 findings of any severity** on real project source, re-checked on every test run.

### Final polish
`Dockerfile` (non-root user) + `docker-compose.yml` (main app + honeypot as separate services); `SECURITY.md` audit report; `bandit` + `pip-audit` run clean (2 real findings fixed — see below).

---

## Real Bugs Found by Actually Running the System

A recurring, honest pattern across this project: **the most important bugs weren't caught by unit tests in isolation — they surfaced by actually running the system the way it's meant to run.** Good interview material, listed here in one place:

| # | Bug | Found by | Fix |
|---|---|---|---|
| 1 | `KeyCache` (Phase 2) cached a derived key by `user_id` alone — a *wrong* password within the TTL window could silently receive the previously-cached *correct* key | Re-reviewing Phase 2 while building Phase 3's auth flow | Cache key fingerprinted on `(user_id, hash(password+salt))` |
| 2 | File permission scanner (Phase 1) flagged the JWT *public* key as an insecure secret, aborting startup every time a fresh key pair was generated | Running the real app startup path (not just tests, which skip the permission check) | Excluded `*.pub.pem` and similar public-key patterns |
| 3 | Honeypot (Phase 4) never created its own database tables when run as a genuinely standalone process | Starting the honeypot as its own process and hitting it with `curl` | Added `Base.metadata.create_all()` directly to `app/honeypot/server.py`; regression test spawns a real subprocess (module caching would hide it otherwise) |
| 4 | LFI attacks via query string (`?file=../../etc/passwd`) were invisible to the honeypot classifier — Flask's `request.path` never includes the query string | Manually attacking a live honeypot with `curl` | Query string folded into the path used for classification/logging |
| 5 | Access log middleware wrote to a fixed real path, polluting `logs/access.log` on every test run forever | Noticing accumulated log noise after full suite runs | Path made configurable via `ACCESS_LOG_PATH`; tests point it at a temp dir |
| 6 | Messenger CLI (Phase 5) crashed with a raw traceback on a wrong passphrase instead of a clean error | Manually running `keygen`→`send`→`receive` with a deliberately wrong passphrase | Wrapped key-loading in `try/except ValueError`, clean message + exit code 1 |
| 7 | `differential_privacy.py` used non-cryptographic `random` for Laplace noise — a predictable PRNG could, in principle, let noise be reconstructed and the true value recovered, defeating the DP guarantee | `bandit` static analysis | Switched to `secrets.SystemRandom()` |
| 8 | Password manager's clipboard-clear thread had a bare `except Exception: pass`, hiding real failures | `bandit` static analysis | Logs the exception instead of silently discarding it |

---

## Testing

**244 tests.** Highlights, not just counts:

- **Real proof-of-exploit**: the exact `' OR '1'='1` string returns every row against the vulnerable query, zero against the fixed one
- **Real proof-of-crack**: the Caesar brute-forcer recovers plaintext from ciphertext alone, for all 25 shifts
- **AES-GCM integrity**: a single tampered ciphertext byte is proven to fail decryption
- **JWT lifecycle**: signing, expiry, tampering, refresh-token rotation, blacklist
- **RBAC token staleness**: a promoted user's old token still reflects the old role
- **Rate limiting**: both algorithms in isolation, and wired end-to-end through `/auth/login`
- **Honeypot standalone deployment**: a real subprocess test, not an in-process import
- **Query-string LFI**: the exact regression scenario found via manual `curl` testing
- **pcap parsing with real synthetic packets** (scapy-crafted, not mocked): HTTP, DNS, TLS SNI, port-scan detection correctly excluding SYN-ACK
- **E2E messenger**: tampered ciphertext and forged signatures both rejected before decryption
- **Schnorr ZKP**: wrong-secret proofs rejected; two proofs of the same secret use independent randomness
- **Self-audit against real project source**: 0 findings, checked on every run

```bash
pytest tests/ -v
```

---

## Security Controls Summary

See [`SECURITY.md`](./SECURITY.md) for the full audit report, verification commands, and every known limitation stated plainly. Quick summary:

| Control | Status |
|---|---|
| Password hashing (bcrypt-12) | ✅ |
| Parameterized queries | ✅ (proven exploit test) |
| AES-256-GCM at rest | ✅ |
| PII redaction | ✅ |
| JWT RS256 + refresh rotation | ✅ |
| RBAC | ✅ |
| Rate limiting | ✅ (login endpoint; not yet all routes) |
| Honeypot + SIEM analysis | ✅ |
| E2E encrypted messaging | ✅ |
| Zero-knowledge auth | ✅ (demo-sized group, not production) |
| Differential privacy | ✅ |
| Self-audit (AST + SARIF) | ✅ (0 findings) |
| `bandit` / `pip-audit` | ✅ (clean, 2 findings fixed) |
| Docker non-root | ✅ (authored, not build-verified — see below) |

---

## Known Limitations

Stated plainly, not buried — full detail in `SECURITY.md` and each phase's section above:

- JWT blacklist and rate limiter state are **in-memory, single-process only** — needs Redis (or similar) for multi-instance deployments.
- The E2E messenger's RSA key pair is **never rotated**.
- The ZKP module uses a **demo-sized 512-bit prime**, not a production 2048-bit+ safe prime.
- Attack classification (honeypot) and log analysis are **pattern-based, not ML-based** — a determined attacker who knows the patterns could evade them.
- **Docker was authored and hand-checked but never built against a live daemon** in this environment — run `docker compose up --build` yourself before trusting it.
- `bandit`/`pip-audit` were **run manually**, not yet wired into CI.
- RSA-OAEP in the messenger encrypts short messages **directly**, not via hybrid encryption (RSA-wraps-AES) — a real limit (~446 bytes for 4096-bit keys), not a bug.

---

## Project Structure

```
secure-data-vault/
├── README.md                          ← you are here (single technical reference)
├── ROADMAP.md                         ← all 10 weeks / 23 exercises, tracked
├── SECURITY.md                        ← full audit report + verification commands
├── Dockerfile / docker-compose.yml
├── requirements.txt / .env.example
├── app/
│   ├── main.py, database.py, models.py
│   ├── auth/          (hashing, keys, jwt_manager, rbac, routes)
│   ├── middleware/     (validation, access_log)
│   ├── security/       (file_permissions, rate_limiter)
│   ├── vault/          (key_cache, vault_engine, pii_redaction, caesar_cipher, routes, secure_queries)
│   ├── insecure/       (sql_injection_demo — intentionally vulnerable)
│   ├── admin/          (RBAC-protected example routes)
│   ├── cli/            (password_manager, messenger)
│   ├── honeypot/        (server, classifier, alerting, persistence)
│   ├── analysis/        (log_analyzer)
│   ├── forensics/       (packet_sniffer, string_extractor)
│   ├── messenger/       (e2e)
│   ├── zkp/             (schnorr, routes)
│   ├── privacy/         (differential_privacy, chart, routes)
│   └── audit/           (security_scan, sarif)
├── tests/               (28 files, 244 tests)
└── docs/                 (per-phase deep-dive walkthroughs, ultra-detailed)
    ├── week-01-02-foundation.md
    ├── week-03-04-vault-engine.md
    ├── week-05-06-api-security.md
    ├── week-07-08-threat-intelligence.md
    └── week-09-10-advanced-crypto.md
```

Each `docs/week-*.md` file goes deeper than this README on its phase — the "why," worked examples, and the full story behind each bug fix. This README is the single technical reference; those are the extended director's commentary.
