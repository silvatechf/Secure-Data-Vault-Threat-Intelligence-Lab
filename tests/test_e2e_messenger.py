"""
tests/test_e2e_messenger.py
==============================

RSA-4096 key generation is deliberately slow (by design -- see the module
docstring in app/messenger/e2e.py). To keep this test file fast, key
pairs are generated ONCE per test class (module-level fixtures) and
reused across test cases, rather than generating fresh 4096-bit keys in
every single test.
"""

import pytest
from cryptography.exceptions import InvalidSignature

from app.messenger.e2e import (
    EncryptedMessage,
    SignatureVerificationError,
    encrypt_and_sign,
    generate_key_pair,
    load_private_key,
    load_public_key,
    max_message_length_bytes,
    serialize_private_key,
    serialize_public_key,
    verify_and_decrypt,
)


@pytest.fixture(scope="module")
def alice_keys():
    return generate_key_pair()


@pytest.fixture(scope="module")
def bob_keys():
    return generate_key_pair()


class TestKeySerialization:
    def test_private_key_round_trips_through_password_protected_pem(self, alice_keys):
        pem = serialize_private_key(alice_keys.private_key, password="correct-horse-battery")
        loaded = load_private_key(pem, password="correct-horse-battery")

        # Can't compare RSA key objects directly -- compare their serialized
        # public halves as a proxy for "this is really the same key."
        original_public_pem = serialize_public_key(alice_keys.public_key)
        loaded_public_pem = serialize_public_key(loaded.public_key())
        assert original_public_pem == loaded_public_pem

    def test_private_key_cannot_be_loaded_with_the_wrong_password(self, alice_keys):
        pem = serialize_private_key(alice_keys.private_key, password="correct-password")
        with pytest.raises(Exception):  # cryptography raises its own error type here
            load_private_key(pem, password="wrong-password")

    def test_public_key_round_trips_through_pem(self, alice_keys):
        pem = serialize_public_key(alice_keys.public_key)
        loaded = load_public_key(pem)
        assert serialize_public_key(loaded) == pem


class TestEncryptAndSign:
    def test_recipient_can_decrypt_and_verify_a_genuine_message(self, alice_keys, bob_keys):
        message = b"Meet at the usual place, 9pm."

        encrypted = encrypt_and_sign(message, bob_keys.public_key, alice_keys.private_key)
        decrypted = verify_and_decrypt(encrypted, alice_keys.public_key, bob_keys.private_key)

        assert decrypted == message

    def test_ciphertext_does_not_contain_the_plaintext(self, alice_keys, bob_keys):
        message = b"a very identifiable secret phrase"
        encrypted = encrypt_and_sign(message, bob_keys.public_key, alice_keys.private_key)
        assert message not in encrypted.ciphertext

    def test_wrong_recipient_cannot_decrypt(self, alice_keys, bob_keys):
        """Encrypted for Bob -- a third party's key (even a valid one) must not be able to decrypt it."""
        mallory_keys = generate_key_pair()
        message = b"for bob's eyes only"

        encrypted = encrypt_and_sign(message, bob_keys.public_key, alice_keys.private_key)

        with pytest.raises(Exception):  # RSA decryption fails outright with the wrong key
            verify_and_decrypt(encrypted, alice_keys.public_key, mallory_keys.private_key)

    def test_tampered_ciphertext_fails_signature_verification(self, alice_keys, bob_keys):
        """
        THE CORE INTEGRITY PROPERTY: altering even one byte of the
        ciphertext must be caught by signature verification, BEFORE any
        decryption is attempted.
        """
        message = b"original, untampered message"
        encrypted = encrypt_and_sign(message, bob_keys.public_key, alice_keys.private_key)

        tampered_bytes = bytearray(encrypted.ciphertext)
        tampered_bytes[0] ^= 0xFF
        tampered = EncryptedMessage(ciphertext=bytes(tampered_bytes), signature=encrypted.signature)

        with pytest.raises(SignatureVerificationError):
            verify_and_decrypt(tampered, alice_keys.public_key, bob_keys.private_key)

    def test_message_forged_with_a_different_signature_fails_verification(self, alice_keys, bob_keys):
        """
        A message encrypted correctly for Bob, but signed by someone OTHER
        than the claimed sender, must fail verification when checked
        against the claimed sender's public key.
        """
        mallory_keys = generate_key_pair()
        message = b"pretend this is from alice"

        genuine = encrypt_and_sign(message, bob_keys.public_key, alice_keys.private_key)
        forged = encrypt_and_sign(message, bob_keys.public_key, mallory_keys.private_key)
        # Take Mallory's signature but claim it's Alice's message.
        impersonated = EncryptedMessage(ciphertext=genuine.ciphertext, signature=forged.signature)

        with pytest.raises(SignatureVerificationError):
            verify_and_decrypt(impersonated, alice_keys.public_key, bob_keys.private_key)

    def test_message_too_long_for_direct_rsa_encryption_raises(self, alice_keys, bob_keys):
        """
        Documents the real, structural RSA-OAEP size limit rather than
        letting it fail with a confusing low-level error -- see
        max_message_length_bytes()'s docstring.
        """
        max_length = max_message_length_bytes()
        too_long_message = b"x" * (max_length + 1)

        with pytest.raises(Exception):
            encrypt_and_sign(too_long_message, bob_keys.public_key, alice_keys.private_key)

    def test_message_at_the_maximum_length_succeeds(self, alice_keys, bob_keys):
        max_length = max_message_length_bytes()
        message = b"x" * max_length

        encrypted = encrypt_and_sign(message, bob_keys.public_key, alice_keys.private_key)
        decrypted = verify_and_decrypt(encrypted, alice_keys.public_key, bob_keys.private_key)

        assert decrypted == message
