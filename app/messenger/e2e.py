"""
app/messenger/e2e.py
=======================

EX-11: an RSA-4096 end-to-end encrypted messenger. Each user has their own
key pair; messages are encrypted with the RECIPIENT's public key and
signed with the SENDER's private key. This is the same two-step pattern
real E2E systems use (PGP, Signal's underlying principles, even if
Signal itself uses different primitives) -- encryption for
confidentiality, signing for authenticity, and they are NOT the same
operation.

WHY TWO SEPARATE OPERATIONS (ENCRYPT-THEN-SIGN), NOT ONE
------------------------------------------------------------
Encrypting with the recipient's public key means ONLY the recipient's
private key can decrypt it -- that's confidentiality. But it says nothing
about who sent it: anyone could grab the recipient's public key and send
them an encrypted message. Signing with the sender's private key means
anyone with the sender's public key can verify the message really came
from them -- that's authenticity. A message that's only encrypted can be
read exclusively by the recipient but could have been forged by anyone;
a message that's only signed proves who sent it but anyone could read it.
Real confidentiality AND authenticity together need both operations,
using two DIFFERENT keys (the recipient's for encryption, the sender's
own for signing).

WHY OAEP FOR ENCRYPTION, PSS FOR SIGNING
----------------------------------------------
Both are the modern, randomized padding schemes for RSA, replacing the
older PKCS#1 v1.5 padding, which has known weaknesses (padding oracle
attacks against encryption, and forgery vulnerabilities in some signing
scenarios). OAEP (Optimal Asymmetric Encryption Padding) is specifically
for encryption; PSS (Probabilistic Signature Scheme) is specifically for
signing -- they're not interchangeable despite both being modern RSA
padding schemes, and this project uses each for its intended purpose,
never PKCS#1 v1.5 for either.

WHY 4096 BITS, WHEN 2048 IS FASTER AND STILL CONSIDERED SECURE TODAY
------------------------------------------------------------------------
2048-bit RSA is not currently broken and remains widely deployed. 4096-bit
is a deliberately more conservative margin against future advances in
factoring (classical or, eventually, quantum) -- the trade-off is real
(4096-bit RSA operations are noticeably slower than 2048-bit), and this
project accepts that cost explicitly for a project meant to demonstrate
best-effort long-term confidentiality, matching the exercise's own
specification.

WHY PRIVATE KEYS ARE PASSWORD-PROTECTED PEM FILES
-----------------------------------------------------
A private key sitting on disk in plaintext is a single stolen file away
from total compromise. Encrypting the PEM with a password (via
`BestAvailableEncryption`) means a stolen key file alone is not enough --
the attacker also needs the password, the same defense-in-depth principle
used for the vault's PBKDF2-derived keys (Week 3-4) and the file
permission scanner protecting the JWT signing key (Week 1-2 / Week 5-6).
"""

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

RSA_KEY_SIZE_BITS = 4096
RSA_PUBLIC_EXPONENT = 65537


@dataclass
class KeyPair:
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey


@dataclass
class EncryptedMessage:
    ciphertext: bytes  # the message, encrypted with the recipient's public key
    signature: bytes   # a signature over the CIPHERTEXT, made with the sender's private key


class SignatureVerificationError(Exception):
    """Raised when a message's signature doesn't verify -- it was tampered with, or didn't come from who it claims."""


def generate_key_pair() -> KeyPair:
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT, key_size=RSA_KEY_SIZE_BITS
    )
    return KeyPair(private_key=private_key, public_key=private_key.public_key())


def serialize_private_key(private_key: rsa.RSAPrivateKey, password: str) -> bytes:
    """Password-protected PEM -- see the module docstring for why this matters."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
    )


def load_private_key(pem_data: bytes, password: str) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(pem_data, password=password.encode("utf-8"))


def serialize_public_key(public_key: rsa.RSAPublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_public_key(pem_data: bytes) -> rsa.RSAPublicKey:
    return serialization.load_pem_public_key(pem_data)


# RSA-OAEP can only encrypt a message shorter than the key size, minus
# padding overhead -- roughly 446 bytes for a 4096-bit key with SHA-256
# OAEP padding. This is a real, structural limit of RSA encryption (it is
# NOT designed to encrypt arbitrary-length data directly), not an
# arbitrary restriction added here. A real messenger sending longer
# messages would use RSA only to encrypt a random AES key (the "hybrid
# encryption" pattern), then AES-256-GCM (already built in this project's
# vault_engine.py) to encrypt the actual message body. This module keeps
# to short, direct RSA encryption because that's what the exercise
# specifies -- see "Known simplifications" in this phase's doc for the
# hybrid-encryption note.
_OAEP_PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)

_PSS_PADDING = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)


def encrypt_and_sign(
    message: bytes, recipient_public_key: rsa.RSAPublicKey, sender_private_key: rsa.RSAPrivateKey
) -> EncryptedMessage:
    """
    Encrypts `message` so only the recipient can read it, and signs the
    ciphertext so the recipient can verify who really sent it. Signing the
    CIPHERTEXT (not the plaintext) means a verifier never needs to decrypt
    first to check the signature -- verification and decryption are two
    independent steps that can happen in either order.
    """
    ciphertext = recipient_public_key.encrypt(message, _OAEP_PADDING)
    signature = sender_private_key.sign(ciphertext, _PSS_PADDING, hashes.SHA256())
    return EncryptedMessage(ciphertext=ciphertext, signature=signature)


def verify_and_decrypt(
    encrypted: EncryptedMessage,
    sender_public_key: rsa.RSAPublicKey,
    recipient_private_key: rsa.RSAPrivateKey,
) -> bytes:
    """
    Verifies the signature FIRST, decrypts only if it's valid. This order
    matters: decrypting an unverified ciphertext and only checking the
    signature afterward would mean doing real cryptographic work (and
    potentially acting on the result) before confirming the message's
    authenticity at all.
    """
    try:
        sender_public_key.verify(
            encrypted.signature, encrypted.ciphertext, _PSS_PADDING, hashes.SHA256()
        )
    except InvalidSignature as exc:
        raise SignatureVerificationError(
            "Signature verification failed -- this message may have been "
            "tampered with, or does not come from the claimed sender."
        ) from exc

    return recipient_private_key.decrypt(encrypted.ciphertext, _OAEP_PADDING)


def max_message_length_bytes(key_size_bits: int = RSA_KEY_SIZE_BITS) -> int:
    """
    The maximum plaintext size RSA-OAEP can encrypt directly for a given
    key size, with SHA-256 as both the OAEP hash and MGF1 hash:
    key_size_bytes - 2*hash_size_bytes - 2.
    """
    key_size_bytes = key_size_bits // 8
    hash_size_bytes = hashes.SHA256().digest_size
    return key_size_bytes - 2 * hash_size_bytes - 2
