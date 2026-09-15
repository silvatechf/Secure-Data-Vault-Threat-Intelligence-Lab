# Advanced Crypto & Final Audit: A Guided Walkthrough

The last phase. Same format as the previous four: the *why* first, then
the file that implements it. This phase is a genuine step up in
cryptographic sophistication from everything before it — and it closes
with the project auditing itself.

## Table of contents

1. [The E2E messenger: encryption and signing are not the same job](#1-the-e2e-messenger-encryption-and-signing-are-not-the-same-job)
2. [Zero-Knowledge Proofs: proving a secret without sending it](#2-zero-knowledge-proofs-proving-a-secret-without-sending-it)
3. [Differential privacy: why aggregation alone isn't privacy](#3-differential-privacy-why-aggregation-alone-isnt-privacy)
4. [The self-audit scanner: the project grading its own homework](#4-the-self-audit-scanner-the-project-grading-its-own-homework)
5. [A real CLI bug this phase found — the same way the last two phases found theirs](#5-a-real-cli-bug-this-phase-found)
6. [Design decisions worth defending in an interview](#6-design-decisions-worth-defending-in-an-interview)
7. [Known simplifications in this phase](#7-known-simplifications-in-this-phase)
8. [Closing: what this project demonstrates end to end](#8-closing-what-this-project-demonstrates-end-to-end)

---

## 1. The E2E messenger: encryption and signing are not the same job

`app/messenger/e2e.py` gives every user an RSA-4096 key pair and does two
separate cryptographic operations to send a message — conflating them is
one of the most common real cryptography mistakes, so it's worth being
precise about why both are needed:

- **Encrypting with the recipient's public key** guarantees only the
  recipient (holder of the matching private key) can read the message.
  That's confidentiality — but it proves nothing about who sent it, since
  the recipient's public key is, by definition, not secret. Anyone could
  encrypt a message with it.
- **Signing the ciphertext with the sender's private key** lets the
  recipient verify the message really came from the claimed sender and
  wasn't altered. That's authenticity and integrity — but a signature
  alone hides nothing from anyone who intercepts the message.

Real confidentiality *and* authenticity together need both operations,
using two *different* keys — the recipient's for encryption, the
sender's own for signing.

**Order matters on receipt, and it's proven directly:**
```python
def verify_and_decrypt(encrypted, sender_public_key, recipient_private_key):
    sender_public_key.verify(encrypted.signature, encrypted.ciphertext, ...)  # FIRST
    return recipient_private_key.decrypt(encrypted.ciphertext, ...)            # SECOND
```
Verifying before decrypting means a forged or tampered message never even
reaches the (comparatively expensive) decryption step —
`test_tampered_ciphertext_fails_signature_verification` proves a single
flipped byte in the ciphertext is caught here, before decryption is ever
attempted.

**A real structural limit worth understanding, not working around
silently:** RSA-OAEP can only encrypt messages up to roughly key_size -
2×hash_size - 2 bytes directly (about 446 bytes for a 4096-bit key with
SHA-256). This isn't a bug in this module — it's how RSA encryption
works, full stop. Real chat systems handle this with *hybrid encryption*:
use RSA only to encrypt a short, random AES key, then use that AES key
(exactly the AES-256-GCM engine already built in `app/vault/vault_engine.py`)
to encrypt the actual, arbitrarily-long message. This project keeps things
direct for a single short message, and names the real limitation instead
of hiding it — see `max_message_length_bytes()` and the "known
simplifications" section below.

## 2. Zero-Knowledge Proofs: proving a secret without sending it

Every other login in this project sends a password to the server, which
hashes and compares it. The server never *stores* the plaintext, but it
*sees* it, every single time. `app/zkp/schnorr.py` proves something
fundamentally different is possible: proving "I know a secret x" to a
verifier who only ever stores `y = g^x mod p` — without x ever traveling
over the network, not once, not even encrypted.

**The interactive protocol, in one pass:**
1. Prover picks random `r`, sends commitment `t = g^r mod p`.
2. Verifier sends a random challenge `c`.
3. Prover responds with `s = (r + c·x) mod q`.
4. Verifier checks `g^s == t · y^c (mod p)`.

The magic is in why this works: producing a valid `s` for an
*unpredictable* challenge `c` is only possible if the prover actually
knows `x` — but watching the exchange teaches the verifier nothing about
`x` itself, because `t` is fresh random noise every time and `s` is a
combination of that randomness and `x` that doesn't isolate `x` alone.

**Fiat-Shamir removes the "verifier has to be online" requirement**, by
replacing the random challenge with a hash of the protocol's own public
values: `c = H(g, y, t) mod q`. The prover can't predict a hash output
before choosing `t`, so they still can't cheat — but now the entire proof
`(t, s)` is something the prover computes alone, with no interaction,
which is what makes it usable as a real non-interactive login (see
`/auth/zkp/prove`).

**A subtlety worth being precise about**, because it's easy to state
wrong: a single Fiat-Shamir proof *is* replayable — the same `(y, t, s)`
verifies every time someone checks it, and that's correct, not a flaw
(`test_replaying_a_captured_proof_still_verifies` proves this
deliberately). What actually defeats replay is that a *new login* always
requires a *fresh* commitment `t` (and therefore a fresh, unpredictable
challenge) — an old captured proof doesn't let an attacker construct a
*new*, currently-useful proof; it only re-demonstrates something already
true.

## 3. Differential privacy: why aggregation alone isn't privacy

"We only ever show aggregate numbers, never individual records" sounds
safe — but consider: if a report shows "3.2 years average account age"
today, and after one specific user deletes their account it shows "3.1
years" tomorrow, comparing those two *safe-looking, aggregate-only*
numbers reveals something about that one specific person's account age.
This is a **differencing attack**, and it's a real, well-documented
technique.

`app/privacy/differential_privacy.py` adds Laplace-distributed random
noise to any released count, calibrated so the mechanism's output barely
changes whether or not any single individual's data is included —
formally, that's what "epsilon-differential privacy" means. The trade-off
is real and irreducible, not an implementation shortcoming: smaller
epsilon (stronger privacy) mathematically requires more noise (less
accurate output). `app/privacy/chart.py` makes this trade-off visible —
plotting average noise magnitude against epsilon always slopes the same
direction, because it's guaranteed by the mechanism, not just empirically
common in this exercise.

**k-anonymity is a separate, complementary check**, and the module keeps
it that way on purpose: differential privacy protects a *released
statistic*, k-anonymity is a property of the *underlying dataset* itself
(no combination of quasi-identifying fields — zip code, birth year,
role — should single out fewer than k records). A real system needs both,
because they defend against different things.

## 4. The self-audit scanner: the project grading its own homework

`app/audit/security_scan.py` parses this project's *own* source with
Python's built-in `ast` module — not regex over raw text. That distinction
matters concretely: a regex for `eval(` would also flag a variable named
`evaluation` or the word appearing in a comment; walking the actual
Abstract Syntax Tree means every check is a structural fact ("is this
node a Call to the built-in function literally named `eval`"), immune to
that whole class of false positive —
`test_a_function_merely_named_evaluate_is_not_flagged` proves it directly.

**The result, measured, not asserted:** running the scanner against this
project's real `app/` source produces **zero findings of any severity** —
not just zero critical ones. That's checked on every test run
(`tests/test_security_scan.py::TestSelfAudit`), so it's a claim that
breaks loudly the moment it stops being true, rather than a one-time
snapshot in a document nobody re-checks.

`app/insecure/sql_injection_demo.py` is explicitly excluded from this
scan, with the reason documented directly in the scanner's own source: it
is *intentionally* vulnerable, on purpose, as a teaching artifact from
Week 1-2 — scanning it would "find" the exact vulnerability it exists to
demonstrate. That's a deliberate, justified exclusion with a paper trail,
not a coverage gap quietly swept under the rug.

## 5. A real CLI bug this phase found

Consistent with how Weeks 5-6 and 7-8 each found a real bug by actually
*running* the system, not just trusting green tests: manually running the
messenger CLI end to end (`keygen` → `send` → `receive`) with a
deliberately *wrong* passphrase caused a raw `ValueError` traceback to
crash the program instead of a clean error message and exit code.

The underlying cryptography was never wrong — `load_private_key()`
correctly refuses to load a key with the wrong passphrase, exactly as it
should. The bug was purely in the CLI layer not catching that expected
failure gracefully. Fixed by wrapping both `cmd_send()` and
`cmd_receive()`'s key-loading calls in a `try/except ValueError`, printing
a clear message, and exiting with a deliberate, non-zero status —
`test_wrong_passphrase_exits_cleanly_instead_of_crashing` locks this in
directly, checking for `SystemExit` with code `1`, not an unhandled
exception.

## 6. Design decisions worth defending in an interview

- **4096-bit RSA for the messenger, when 2048-bit is still considered
  secure today.** A deliberate, conservative margin: this key protects
  message confidentiality for however long anyone might want to read old
  messages — potentially years — unlike the JWT signing key (Week 5-6,
  2048-bit), which only protects 15-minute-lived tokens. Matching key
  size to how long the protected data needs to stay protected is the
  right way to make this trade-off, not "bigger is always better."
- **The ZKP demo uses a small (512-bit) prime, explicitly and
  documentedly not production-sized.** Naming this directly, rather than
  letting a reader assume production-readiness, is the more credible
  choice — see "Known simplifications" below.
- **The self-audit scanner explicitly excludes `app/insecure/`, with the
  reasoning written directly into the scanner's own source** — not a
  silent skip list maintained separately from the code that uses it.
- **SARIF output, not a project-specific JSON shape**, for the scanner's
  results — so findings could be uploaded directly to GitHub code
  scanning or similar tooling with zero translation step.

## 7. Known simplifications in this phase

- **RSA-OAEP encrypts short messages directly, not via hybrid encryption.**
  As discussed in section 1, a real chat system would use RSA only to
  wrap a random AES key, then AES-256-GCM (already built in this
  project) for the actual message body — removing the ~446-byte size
  limit entirely. Not built here because the exercise's own scope is a
  single short message, and the size limit is well within what
  demonstrates the underlying cryptography correctly.
- **The ZKP group parameters are a 512-bit demo prime**, generated once
  and cached to disk (`keys/zkp_group_params.txt`) — fast for tests and
  demos, explicitly not sized for real-world adversarial resistance.
  Production Diffie-Hellman-style groups use 2048-bit+ safe primes (RFC
  3526) or elliptic curve groups instead.
- **Docker was authored but never built against a live Docker daemon**
  in this environment (see `SECURITY.md` for the full, honest note) —
  every line was hand-checked, `docker-compose.yml` validated as
  syntactically correct YAML, but `docker build`/`docker compose up`
  should be run for real before trusting this in any real deployment.
- **No `bandit`/`safety` dependency scanning wired into CI yet** — the
  AST self-audit scanner checks code *patterns*, not known
  vulnerabilities in third-party packages; that's a different, valuable
  check this project doesn't yet automate.

## 8. Closing: what this project demonstrates end to end

Five phases, 244 tests, and — worth saying directly — several real bugs
found not by writing more unit tests in isolation, but by actually
*running* the system the way it's meant to run: a standalone honeypot
process, a live `curl` attack, a CLI tool exercised with a wrong
passphrase. That pattern, repeated across three separate phases, is
arguably the single strongest, most honest thing to say about this
project in an interview: it wasn't just built to pass its own tests, it
was pressure-tested against how it would actually be used, and every gap
that surfaced got fixed and locked in with a regression test, not quietly
patched over.
