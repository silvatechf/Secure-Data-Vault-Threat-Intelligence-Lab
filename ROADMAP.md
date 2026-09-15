# 🗺️ Roadmap — Secure Data Vault & Threat Intelligence Platform

10 weeks, 23 exercises, one connected system. Each phase builds directly on
the last — nothing here is a disconnected exercise done for its own sake.

## ✅ Week 1-2: Foundation — Scaffold, Database & Authentication

**Status: done, tested, documented.**

- [x] EX: Project scaffold (`app/`, `tests/`, clean package structure)
- [x] Database schema — 5 tables: `users`, `vault_entries`, `audit_logs`,
      `threat_intel`, `honeypot_logs`
- [x] EX-04: Password hashing with bcrypt (cost factor 12), salted automatically
- [x] EX-01: Input validation middleware (email, username, password strength)
- [x] EX-03: File permission scanner — aborts startup on exposed `.env`/`.pem`/`.key`
- [x] EX-07: SQL injection hardening — vulnerable/secure pair, proven with a real attack string

**Deliverable:** working auth system + hardened database + permission
scanner. See [`docs/week-01-02-foundation.md`](./docs/week-01-02-foundation.md)
for the full walkthrough — this is the file worth reading if you're new to
any of these concepts.

## ✅ Week 3-4: Vault Engine — Encryption, Storage & Retrieval

**Status: done, tested, documented.**

- [x] EX-06: AES-256-GCM file vault (`VaultEngine` class, PBKDF2 key derivation)
- [x] EX-05: PII redaction on metadata before storage (email, SSN, credit card)
- [x] EX-02: Caesar cipher "legacy import" + brute-force cracker (educational)
- [x] Secure key derivation with TTL cache — master keys never stored

**Deliverable:** end-to-end encrypted file vault with PII-safe metadata.
See [`docs/week-03-04-vault-engine.md`](./docs/week-03-04-vault-engine.md)
for the full walkthrough.

## ✅ Week 5-6: API Security — JWT, RBAC, Rate Limiting

**Status: done, tested, documented.**

- [x] EX-08: JWT with RS256 (RSA key pair, access+refresh tokens, rotation on refresh, blacklist)
- [x] RBAC enforcement (`require_role` dependency; `/admin/users`, `/admin/audit-logs`)
- [x] EX-09: Rate limiter — sliding window (login) + token bucket, exponential backoff, wired to `/auth/login`
- [x] B-01: CLI password manager built on the vault's master key, `secrets`-based generation, clipboard auto-clear

**Deliverable:** secure API with JWT auth, RBAC, rate limiting, and an
integrated password manager. See
[`docs/week-05-06-api-security.md`](./docs/week-05-06-api-security.md) for
the full walkthrough — including a real caching bug from Week 3-4 that
this phase found and fixed.

## ✅ Week 7-8: Threat Intelligence — Honeypot, Monitoring & Forensics

**Status: done, tested, documented.**

- [x] EX-12: Honeypot HTTP server (Flask, separate port), catch-all route, attack classification (XSS/LFI/RCE/SQLi), webhook alerting above 80% confidence
- [x] EX-10: Log analyzer — brute-force/suspicious-UA/directory-traversal/traffic-spike detection, JSON severity report
- [x] B-02: Packet analyzer (pcap-based) — HTTP/DNS/TLS-SNI extraction, port scan detection, suspicious-flow export
- [x] EX-13: Forensic string extractor — printable-string extraction, IoC filtering, cross-referencing, simplified YARA rule generation

**Deliverable:** active threat detection system — honeypot, SIEM-style
analyzer, forensics toolkit. See
[`docs/week-07-08-threat-intelligence.md`](./docs/week-07-08-threat-intelligence.md)
for the full walkthrough — including three real bugs found by actually
running the system end to end, not just trusting the test suite.

## ✅ Week 9-10: Advanced Crypto — E2E Chat, ZKP, Privacy & Audit

**Status: done, tested, documented.**

- [x] EX-11: RSA-4096 end-to-end encrypted CLI messenger (OAEP + PSS)
- [x] EX-15: Zero-Knowledge Proof auth (Schnorr protocol, Fiat-Shamir)
- [x] EX-14: Differential privacy reports (Laplace noise, k-anonymity checker)
- [x] B-03: Self-audit static code scanner (AST-based, SARIF output) — 0 findings on real project source
- [x] Final polish: Dockerfile + docker-compose (non-root), `SECURITY.md` audit report

**Deliverable:** complete platform — advanced crypto, privacy engineering,
self-auditing, production docs. See
[`docs/week-09-10-advanced-crypto.md`](./docs/week-09-10-advanced-crypto.md)
and [`SECURITY.md`](./SECURITY.md).

---

## Why this order

Each phase depends on what came before it, not just thematically —
literally, in code:

- The vault (Week 3-4) needs users to own encrypted files, so auth (Week
  1-2) has to exist first.
- JWT auth (Week 5-6) replaces the simple session response from Week 1-2's
  `/auth/login` — it doesn't bolt on separately, it upgrades what's already
  there.
- The honeypot and log analyzer (Week 7-8) write to the `audit_logs` and
  `threat_intel` tables defined back in Week 1-2's schema.
- The self-audit scanner (Week 9-10) checks the ENTIRE codebase built in
  every prior week — it's the last piece specifically because it needs
  something real to audit.

## Security hardening checklist (tracked across all 10 weeks)

- [x] No hardcoded secrets in source code (`.env` + `python-dotenv`)
- [x] All database queries parameterized (zero f-string SQL — see the
      vulnerable/secure pair in `app/insecure/` vs `app/vault/`)
- [x] Passwords hashed with bcrypt (cost factor 12)
- [x] JWTs use RS256, with refresh-token rotation on every `/auth/refresh` call (a different thing from rotating the signing key pair itself, which is not yet implemented — see note below)
- [x] Rate limiting active on the login endpoint (extending to all public endpoints is a natural follow-up, not yet done for every route)
- [x] AES-256-GCM with random IV for every encryption operation
- [x] File permissions checked on startup (no world-readable secrets)
- [x] PII redacted in all logs and error messages
- [x] Honeypot running on separate port with isolated logging
- [x] All security events logged with timestamp, IP, and severity
- [x] Differential privacy applied to all aggregated user reports
- [x] Self-audit scanner passes with zero critical findings
- [x] Docker image runs as non-root user
- [x] Dependencies and code scanned with `bandit` + `pip-audit` (run manually; not yet wired into CI — see SECURITY.md)
