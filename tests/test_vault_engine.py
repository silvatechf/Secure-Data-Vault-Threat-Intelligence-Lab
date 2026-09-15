"""
tests/test_vault_engine.py
=============================

Tests for AES-256-GCM encryption/decryption and the key derivation cache.
"""

import time

import pytest

from app.vault.key_cache import KeyCache, derive_key, generate_salt
from app.vault.vault_engine import EncryptedPayload, VaultEngine, VaultIntegrityError


class TestKeyDerivation:
    def test_same_password_and_salt_produce_same_key(self):
        """Deterministic on purpose -- the vault must re-derive the identical key later."""
        salt = generate_salt()
        key_one = derive_key("MyPassword123!", salt)
        key_two = derive_key("MyPassword123!", salt)
        assert key_one == key_two

    def test_different_salts_produce_different_keys(self):
        key_one = derive_key("MyPassword123!", generate_salt())
        key_two = derive_key("MyPassword123!", generate_salt())
        assert key_one != key_two

    def test_derived_key_is_32_bytes(self):
        """AES-256 requires exactly a 32-byte (256-bit) key."""
        key = derive_key("MyPassword123!", generate_salt())
        assert len(key) == 32


class TestKeyCache:
    def test_cache_returns_same_key_on_repeated_calls(self):
        cache = KeyCache(ttl_seconds=60)
        salt = generate_salt()
        key_one = cache.get_or_derive(user_id=1, password="pw", salt=salt)
        key_two = cache.get_or_derive(user_id=1, password="pw", salt=salt)
        assert key_one == key_two
        assert cache.size() == 1  # only derived once, served from cache the second time

    def test_expired_entry_is_re_derived(self):
        cache = KeyCache(ttl_seconds=0)  # expires immediately
        salt = generate_salt()
        cache.get_or_derive(user_id=1, password="pw", salt=salt)
        time.sleep(0.01)
        # Should not raise, and should still return a valid 32-byte key --
        # proves expiry doesn't break re-derivation.
        key = cache.get_or_derive(user_id=1, password="pw", salt=salt)
        assert len(key) == 32

    def test_invalidate_removes_the_cached_key(self):
        cache = KeyCache(ttl_seconds=60)
        salt = generate_salt()
        cache.get_or_derive(user_id=1, password="pw", salt=salt)
        assert cache.size() == 1
        cache.invalidate(1)
        assert cache.size() == 0

    def test_wrong_password_never_returns_a_previously_cached_correct_key(self):
        """
        Regression test for a real bug found while building Week 5-6: the
        cache used to be keyed by user_id ALONE. That meant deriving once
        with the correct password, then calling again with a WRONG
        password for the same user_id within the TTL, would silently
        return the old correct key instead of failing -- exactly the kind
        of bug that only shows up when a user_id is reused across
        different real passwords, which is precisely what happens in
        practice.
        """
        cache = KeyCache(ttl_seconds=60)
        salt = generate_salt()

        correct_key = cache.get_or_derive(user_id=1, password="CorrectPassword1!", salt=salt)
        wrong_key = cache.get_or_derive(user_id=1, password="TotallyWrongPassword!", salt=salt)

        assert wrong_key != correct_key
        assert cache.size() == 2  # two distinct cache entries, not a collision


class TestVaultEngine:
    def test_decrypting_encrypted_data_returns_the_original(self):
        engine = VaultEngine(key=b"0" * 32)
        original = b"This is a secret file's contents."
        payload = engine.encrypt(original)
        assert engine.decrypt(payload) == original

    def test_ciphertext_does_not_contain_the_plaintext(self):
        engine = VaultEngine(key=b"0" * 32)
        original = b"a very identifiable secret string"
        payload = engine.encrypt(original)
        assert original not in payload.ciphertext

    def test_encrypting_the_same_plaintext_twice_produces_different_ciphertext(self):
        """
        Proves the IV is actually random each time -- if it weren't,
        encrypting the same plaintext twice would produce identical
        ciphertext, which leaks that two files are identical without
        needing to decrypt either.
        """
        engine = VaultEngine(key=b"0" * 32)
        payload_one = engine.encrypt(b"identical content")
        payload_two = engine.encrypt(b"identical content")
        assert payload_one.iv != payload_two.iv
        assert payload_one.ciphertext != payload_two.ciphertext

    def test_tampered_ciphertext_fails_integrity_check(self):
        """
        THE CORE SECURITY PROPERTY OF GCM: flipping a single byte in the
        ciphertext must cause decryption to fail loudly, not silently
        return corrupted data.
        """
        engine = VaultEngine(key=b"0" * 32)
        payload = engine.encrypt(b"original content")

        tampered_bytes = bytearray(payload.ciphertext)
        tampered_bytes[0] ^= 0xFF  # flip every bit in the first byte
        tampered_payload = EncryptedPayload(iv=payload.iv, ciphertext=bytes(tampered_bytes))

        with pytest.raises(VaultIntegrityError):
            engine.decrypt(tampered_payload)

    def test_wrong_key_fails_to_decrypt(self):
        engine_a = VaultEngine(key=b"0" * 32)
        engine_b = VaultEngine(key=b"1" * 32)
        payload = engine_a.encrypt(b"secret")

        with pytest.raises(VaultIntegrityError):
            engine_b.decrypt(payload)

    def test_rejects_a_key_that_is_not_32_bytes(self):
        with pytest.raises(ValueError):
            VaultEngine(key=b"too short")

    def test_encrypt_and_decrypt_file_round_trip(self, tmp_path):
        engine = VaultEngine(key=b"0" * 32)
        source = tmp_path / "original.txt"
        source.write_bytes(b"file contents to protect")

        encrypted = tmp_path / "encrypted.enc"
        engine.encrypt_file(str(source), str(encrypted))
        assert encrypted.read_bytes() != source.read_bytes()

        decrypted = tmp_path / "decrypted.txt"
        engine.decrypt_file(str(encrypted), str(decrypted))
        assert decrypted.read_bytes() == source.read_bytes()
