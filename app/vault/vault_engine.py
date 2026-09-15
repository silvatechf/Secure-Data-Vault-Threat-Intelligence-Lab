"""
app/vault/vault_engine.py
============================

EX-06: the AES-256-GCM file vault. This is the module that actually
encrypts and decrypts files -- everything else in this phase (key
derivation, PII redaction) exists to support this correctly and safely.

WHY AES-256-GCM SPECIFICALLY (NOT JUST "AES")?
----------------------------------------------------
"AES" names a cipher, not a complete encryption scheme -- you also have to
choose a MODE OF OPERATION, and that choice matters enormously.

GCM (Galois/Counter Mode) gives you two things a naive mode like ECB or
even plain CBC doesn't:
1. **Confidentiality** -- the actual encryption, same as any AES mode.
2. **Authenticity** -- GCM produces an authentication TAG alongside the
   ciphertext. On decryption, if a single bit of the ciphertext (or the
   tag) has been tampered with, decryption FAILS LOUDLY instead of
   silently returning corrupted-but-plausible-looking data. This is
   called an AEAD (Authenticated Encryption with Associated Data) mode.

Without authentication, an attacker who can modify stored ciphertext
(even without the key) could flip bits and produce a *different*, still
"successfully decrypting" plaintext -- a real class of attack against
non-authenticated modes. GCM closes that door.

WHY A RANDOM IV (NONCE) FOR EVERY SINGLE ENCRYPTION?
-----------------------------------------------------------
The IV (Initialization Vector, sometimes called a nonce) does NOT need to
be secret, but it must NEVER be reused with the same key. Reusing an IV
with GCM specifically is catastrophic -- it doesn't just weaken security,
it can let an attacker recover the authentication key entirely and forge
valid ciphertexts. This module generates a fresh random 12-byte IV (the
standard size for GCM) on every single encryption call, no exceptions, no
"reuse for performance" shortcuts.
"""

import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 12 bytes (96 bits) is the size GCM is specifically designed and optimized
# for. Using a different IV length is possible but not recommended -- 12
# bytes is what every major implementation and standard uses.
GCM_IV_LENGTH_BYTES = 12


class VaultIntegrityError(Exception):
    """
    Raised when decryption fails because the ciphertext or tag was
    tampered with -- NOT when the wrong key is used to decrypt someone
    else's file, which raises the same exception, because there's no way
    to distinguish "wrong key" from "tampered data" without leaking
    information an attacker could use.
    """


@dataclass
class EncryptedPayload:
    """
    Everything needed to decrypt later, bundled together. `iv` and
    `ciphertext` are NOT secret and can be stored directly -- only the
    key (never present in this dataclass) must stay protected.
    """

    iv: bytes
    ciphertext: bytes  # includes the GCM authentication tag, appended automatically


class VaultEngine:
    """
    Encrypts and decrypts file contents with AES-256-GCM. Takes an
    already-derived 32-byte key (see app/vault/key_cache.py) -- this class
    has no idea what a password is, on purpose. Separating "how do we get
    a key" from "what do we do with a key" keeps each piece simple and
    independently testable.
    """

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("VaultEngine requires a 32-byte (256-bit) AES key.")
        self._aesgcm = AESGCM(key)

    def encrypt(self, plaintext: bytes) -> EncryptedPayload:
        iv = os.urandom(GCM_IV_LENGTH_BYTES)
        # AESGCM.encrypt appends the authentication tag to the ciphertext
        # automatically -- there's no separate "tag" field to manage.
        ciphertext = self._aesgcm.encrypt(iv, plaintext, associated_data=None)
        return EncryptedPayload(iv=iv, ciphertext=ciphertext)

    def decrypt(self, payload: EncryptedPayload) -> bytes:
        """
        Decrypts and verifies integrity in one step -- GCM doesn't let you
        get plaintext back without the authentication check passing.
        Raises VaultIntegrityError (never the raw cryptography exception)
        if the tag doesn't match, whether that's because of tampering or
        the wrong key.
        """
        try:
            return self._aesgcm.decrypt(payload.iv, payload.ciphertext, associated_data=None)
        except InvalidTag as exc:
            raise VaultIntegrityError(
                "Decryption failed integrity check -- the file may have been "
                "tampered with, or the wrong key was used."
            ) from exc

    def encrypt_file(self, source_path: str, dest_path: str) -> None:
        """
        Convenience wrapper: reads a file from disk, encrypts it, and
        writes iv + ciphertext to dest_path as iv (12 bytes) followed by
        ciphertext. This simple concatenation format is enough for a
        single-file vault -- a production system storing many files might
        use a structured container format instead, but that's added
        complexity this project doesn't need yet.
        """
        with open(source_path, "rb") as f:
            plaintext = f.read()
        payload = self.encrypt(plaintext)
        with open(dest_path, "wb") as f:
            f.write(payload.iv)
            f.write(payload.ciphertext)

    def decrypt_file(self, source_path: str, dest_path: str) -> None:
        with open(source_path, "rb") as f:
            raw = f.read()
        iv, ciphertext = raw[:GCM_IV_LENGTH_BYTES], raw[GCM_IV_LENGTH_BYTES:]
        plaintext = self.decrypt(EncryptedPayload(iv=iv, ciphertext=ciphertext))
        with open(dest_path, "wb") as f:
            f.write(plaintext)
