# Vault Engine: A Guided Walkthrough

Same format as [Week 1-2](./week-01-02-foundation.md): the *why* first,
then the file that implements it. This phase is about protecting data at
rest — the file contents themselves, not just the login that guards them.

## Table of contents

1. [Why AES-256-GCM, not just "AES"](#1-why-aes-256-gcm-not-just-aes)
2. [Why the IV must never repeat, proven](#2-why-the-iv-must-never-repeat-proven)
3. [Deriving keys instead of storing them](#3-deriving-keys-instead-of-storing-them)
4. [PII redaction: protecting metadata, not just file contents](#4-pii-redaction)
5. [The Caesar cipher: why it's here to be broken](#5-the-caesar-cipher-why-its-here-to-be-broken)
6. [Design decisions worth defending in an interview](#6-design-decisions-worth-defending-in-an-interview)
7. [Known simplifications in this phase](#7-known-simplifications-in-this-phase)

---

## 1. Why AES-256-GCM, not just "AES"

"AES" names a cipher (a way to scramble fixed-size blocks of data with a
key) — it doesn't by itself tell you how to handle a file *larger* than
one block, or whether tampering with the encrypted data can be detected.
That's the job of a **mode of operation**, and getting this choice wrong
is one of the most common real-world cryptography mistakes.

GCM (Galois/Counter Mode) is what's called an **AEAD** mode — Authenticated
Encryption with Associated Data. It gives you two guarantees at once:

- **Confidentiality**: the data is scrambled, same as any AES mode.
- **Authenticity**: GCM produces an authentication *tag* alongside the
  ciphertext. On decryption, that tag is checked — if even one bit of the
  ciphertext was altered, decryption fails outright instead of silently
  returning corrupted data that *looks* like it worked.

Without that second guarantee, an attacker who can modify stored
ciphertext — without ever knowing the key — could flip bits and produce a
*different*, still "successfully decrypting" plaintext. That's a real,
documented class of attack against non-authenticated encryption modes.
GCM closes that door structurally, the same way parameterized queries
close SQL injection structurally (see Week 1-2, section 5) rather than
relying on a check that could be bypassed.

## 2. Why the IV must never repeat, proven

The IV (Initialization Vector, also called a nonce) isn't secret — it's
stored right alongside the ciphertext (see `EncryptedPayload` in
`app/vault/vault_engine.py`). But it has one absolute rule: **never reuse
the same IV with the same key.** For GCM specifically, reusing an IV isn't
just a weakness — it can let an attacker recover the authentication key
entirely, breaking every file ever encrypted with that key.

`VaultEngine.encrypt()` generates a fresh random 12-byte IV with
`os.urandom()` on every single call — no caching, no reuse "for
performance," no exceptions. This is proven directly in
`tests/test_vault_engine.py`:

```python
def test_encrypting_the_same_plaintext_twice_produces_different_ciphertext(self):
    payload_one = engine.encrypt(b"identical content")
    payload_two = engine.encrypt(b"identical content")
    assert payload_one.iv != payload_two.iv
    assert payload_one.ciphertext != payload_two.ciphertext
```

If the IV were reused, encrypting the exact same content twice would
produce identical ciphertext both times — which, notably, would also leak
that two files are identical without an attacker ever decrypting either
one.

**And the integrity guarantee, proven directly:**
```python
def test_tampered_ciphertext_fails_integrity_check(self):
    payload = engine.encrypt(b"original content")
    tampered_bytes = bytearray(payload.ciphertext)
    tampered_bytes[0] ^= 0xFF  # flip every bit in the first byte
    tampered_payload = EncryptedPayload(iv=payload.iv, ciphertext=bytes(tampered_bytes))
    with pytest.raises(VaultIntegrityError):
        engine.decrypt(tampered_payload)
```

One flipped byte, anywhere in the ciphertext, and decryption refuses to
proceed at all.

## 3. Deriving keys instead of storing them

There is no `master_key` column anywhere in this project's database, on
purpose. Instead, `app/vault/key_cache.py` derives a fresh 32-byte AES key
from the user's password every time it's needed, using **PBKDF2**
(Password-Based Key Derivation Function 2).

Why not just use the password directly as the key? Two reasons:
1. AES-256 needs *exactly* 32 bytes of high-entropy data. A typed password
   is neither the right length nor random enough on its own.
2. PBKDF2 runs the password through 600,000 rounds of hashing — the same
   "make brute force expensive" principle as bcrypt's cost factor (Week
   1-2, section 1), applied here to key derivation instead of login
   hashing.

**Why cache the derived key at all, even briefly?** Because 600,000 rounds
of PBKDF2 takes real, deliberately-not-instant time. Re-deriving the key
from scratch on every single file operation in a session would make the
vault feel sluggish. `KeyCache` holds the *derived key* — never the
password — in memory for a short TTL (5 minutes by default), so a user
uploading three files in a row pays the derivation cost once, not three
times. This is proven directly:

```python
def test_cache_returns_same_key_on_repeated_calls(self):
    key_one = cache.get_or_derive(user_id=1, password="pw", salt=salt)
    key_two = cache.get_or_derive(user_id=1, password="pw", salt=salt)
    assert key_one == key_two
    assert cache.size() == 1   # only derived once
```

## 4. PII redaction

Encryption protects the file *contents*. It does nothing for the
*metadata* — filename and description — which are stored as plain,
searchable text in `vault_entries` so the app can list and search files
without decrypting anything. If a user names a file
`ssn-123-45-6789-backup.pdf`, that SSN is sitting in the clear in the
database, completely outside whatever protection the encrypted file
itself has.

`app/vault/pii_redaction.py` runs three detectors (email, US SSN, credit
card number patterns) against filenames and descriptions **before** they
ever reach the database — see the redaction call happening first thing in
`app/vault/routes.py`'s `upload_file()`, ahead of the encryption step.

Two masking strategies exist because they serve different needs:
- **Full** (`[EMAIL_REDACTED]`) — when no trace should remain.
- **Partial** (`j***@example.com`) — when a user or support agent still
  needs enough context to recognize *which* piece of data was redacted,
  without the sensitive value ever being stored.

## 5. The Caesar cipher: why it's here to be broken

Every other cipher in this project (AES-256-GCM) is production-grade. The
Caesar cipher in `app/vault/caesar_cipher.py` is the deliberate exception
— included purely so the "Legacy Import" feature can read old
Caesar-encrypted files, and as a teaching contrast.

A Caesar cipher shifts every letter by a fixed amount — `shift=3` turns
'A' into 'D'. That's the *entire* algorithm. It has exactly **25 possible
keys** (shifts 1 through 25). A modern computer doesn't need a clever
attack to break it — it can just try all 25 and pick the one that looks
like real English.

`brute_force_crack()` does exactly that, scoring each of the 25 candidate
decryptions against expected English letter frequencies (E is the most
common letter in English text, then T, A, O...) and picking whichever
candidate's frequency distribution is closest to real English. No key is
provided to the cracker — only the ciphertext:

```python
def test_cracker_finds_the_correct_shift_for_english_text(self):
    ciphertext = caesar_encrypt(plaintext, shift=11)
    result = brute_force_crack(ciphertext)
    assert result.best_shift == 11
    assert result.best_plaintext == plaintext
```

Compare the key space directly: Caesar has **25** possible keys. AES-256
has **2^256** — a number so large that trying every key is physically
impossible with any amount of computing power anyone will ever build. That
gap is *the entire point* of this module existing.

## 6. Design decisions worth defending in an interview

- **The vulnerable/secure pattern from Week 1-2 continues here**, just
  inverted: instead of a broken function next to a fixed one, it's a
  broken *cipher* (Caesar) next to a real one (AES-256-GCM) — same
  teaching principle, different layer of the stack.
- **The PBKDF2 salt reuses the first 16 bytes of the user's bcrypt hash**
  rather than adding a separate salt column. The bcrypt hash already
  contains unique, per-user random data — reusing it avoids storing a
  second secret-adjacent value that would need the same protection
  reasoning applied twice.
- **VaultEngine takes a raw key, and has no idea what a password is.**
  Separating "how do we get a key" (`key_cache.py`) from "what do we do
  with a key" (`vault_engine.py`) keeps each piece small and
  independently testable — `test_vault_engine.py` never has to think
  about passwords at all.
- **PII redaction runs before database insertion, not as a cleanup job
  after.** There's no "we'll redact it later" step where unredacted PII
  sits in the database even briefly.

## 7. Known simplifications in this phase

- **Upload/download endpoints take `user_id` and `password` as request
  parameters**, not a validated session/token. This is the same
  simplification flagged in Week 1-2 — real auth (JWT) lands in Week 5-6,
  and these endpoints will be updated to read the authenticated user from
  a token instead of trusting client-supplied values.
- **Encrypted files are stored on local disk** (`encrypted_storage/`), not
  object storage like S3. The encryption approach doesn't change based on
  where the bytes end up — swapping the storage backend later is an
  infrastructure change, not a cryptography change.
- **The credit card regex is intentionally broad** (13-16 digit runs,
  loosely formatted) rather than validating against real card-issuer
  prefixes or a Luhn checksum. For redaction, over-catching a
  card-shaped number that turns out invalid is the safer failure mode
  than under-catching a real one.
