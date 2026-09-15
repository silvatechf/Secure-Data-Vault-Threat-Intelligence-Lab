"""
tests/test_password_manager.py
=================================

Tests the password manager's core logic directly (add_credential,
get_credential, generate_strong_password) rather than through the
interactive CLI (which reads from stdin/getpass and isn't meant to be
driven by pytest). Clipboard behavior is tested separately and mocked --
no real system clipboard is touched.
"""

from unittest.mock import patch

import pytest

from app.auth.hashing import hash_password
from app.cli.password_manager import (
    _copy_to_clipboard_with_auto_clear,
    add_credential,
    generate_strong_password,
    get_credential,
    list_sites,
)
from app.models import User
from app.vault.key_cache import derive_key
from app.vault.vault_engine import VaultEngine


@pytest.fixture
def user_and_engine(db_session_for_role_promotion):
    """
    A registered user plus a ready VaultEngine, built directly against
    the test database rather than through the FastAPI app -- the CLI
    tool doesn't go through HTTP at all, so its tests shouldn't need to
    either.
    """
    from tests.conftest import TestSessionLocal

    db = TestSessionLocal()
    password = "Str0ng!Password"
    user = User(username="clitestuser", email="cli@example.com", password_hash=hash_password(password))
    db.add(user)
    db.commit()
    db.refresh(user)

    salt = user.password_hash.encode("utf-8")[:16]
    key = derive_key(password, salt)
    engine = VaultEngine(key)

    yield db, user, engine
    db.close()


class TestPasswordGeneration:
    def test_generated_password_has_the_requested_length(self):
        assert len(generate_strong_password(length=24)) == 24

    def test_default_length_is_20(self):
        assert len(generate_strong_password()) == 20

    def test_two_generated_passwords_are_different(self):
        """Not a rigorous randomness test -- just guards against an accidental hardcoded/deterministic output."""
        assert generate_strong_password() != generate_strong_password()

    def test_generated_password_uses_a_mixed_character_set(self):
        """Loosely checks the alphabet is actually being used, not just letters."""
        password = generate_strong_password(length=200)  # long enough that all classes should appear
        assert any(c.isupper() for c in password)
        assert any(c.islower() for c in password)
        assert any(c.isdigit() for c in password)


class TestStoreAndRetrieveCredentials:
    def test_stored_credential_can_be_retrieved_and_decrypts_correctly(self, client, user_and_engine):
        db, user, engine = user_and_engine
        add_credential(db, user, engine, "github.com", "fernando", "correct-horse-battery-staple")

        result = get_credential(db, user, engine, "github.com")
        assert result == ("fernando", "correct-horse-battery-staple")

    def test_credential_for_unknown_site_returns_none(self, client, user_and_engine):
        db, user, engine = user_and_engine
        assert get_credential(db, user, engine, "nonexistent.com") is None

    def test_site_names_appear_in_list_without_decrypting(self, client, user_and_engine):
        db, user, engine = user_and_engine
        add_credential(db, user, engine, "github.com", "u1", "p1")
        add_credential(db, user, engine, "gitlab.com", "u2", "p2")

        sites = list_sites(db, user)
        assert set(sites) == {"github.com", "gitlab.com"}

    def test_stored_password_is_not_present_in_plaintext_in_the_database_blob(
        self, client, user_and_engine
    ):
        db, user, engine = user_and_engine
        secret_password = "VeryIdentifiableSecretString123!"
        add_credential(db, user, engine, "example.com", "someuser", secret_password)

        from app.models import SiteCredential

        row = db.query(SiteCredential).filter(SiteCredential.site_name == "example.com").first()
        assert secret_password.encode("utf-8") not in row.encrypted_password


class TestClipboardAutoClear:
    def test_returns_false_gracefully_when_no_clipboard_is_available(self):
        """
        Simulates a headless environment (no display, pyperclip raising)
        -- the CLI must degrade to printing the password, never crash.
        """
        with patch("pyperclip.copy", side_effect=Exception("no display")):
            result = _copy_to_clipboard_with_auto_clear("some-password", delay_seconds=1)
        assert result is False

    def test_copies_successfully_when_clipboard_is_available(self):
        with patch("pyperclip.copy") as mock_copy, patch("pyperclip.paste", return_value="some-password"):
            result = _copy_to_clipboard_with_auto_clear("some-password", delay_seconds=100)
        assert result is True
        mock_copy.assert_called_once_with("some-password")

    def test_clipboard_is_cleared_after_the_delay(self):
        with patch("pyperclip.copy") as mock_copy, patch("pyperclip.paste", return_value="my-secret"):
            _copy_to_clipboard_with_auto_clear("my-secret", delay_seconds=0.05)
            time.sleep(0.15)
        # First call copies the real password, second (from the background
        # thread) clears it -- proving the auto-clear actually fired.
        assert mock_copy.call_args_list[-1].args[0] == ""

    def test_does_not_clear_if_user_copied_something_else_in_the_meantime(self):
        """
        THE SAFETY CHECK: if the clipboard no longer holds what we put
        there, the auto-clear must NOT blindly overwrite it -- that would
        wipe out the user's own newer clipboard content.
        """
        with patch("pyperclip.copy") as mock_copy, patch(
            "pyperclip.paste", return_value="something the user copied afterward"
        ):
            _copy_to_clipboard_with_auto_clear("my-secret", delay_seconds=0.05)
            time.sleep(0.15)
        # Only the initial copy call happened -- no clearing call, because
        # paste() never matched "my-secret".
        assert mock_copy.call_count == 1


import time  # placed at end to keep the diff focused; used by the auto-clear tests above
