"""
tests/test_jwt.py
===================

Tests for the JWTManager: creation, validation, expiry, refresh rotation,
and the blacklist -- using a temporary key directory so tests never touch
the real keys/ folder used by a running app instance.
"""

import time
from datetime import timedelta

import jwt as pyjwt
import pytest

from app.auth.jwt_manager import JWTManager, TokenError


@pytest.fixture
def manager(tmp_path):
    """A fresh JWTManager with its own temporary RSA key pair per test."""
    return JWTManager(keys_dir=tmp_path)


class TestTokenCreationAndValidation:
    def test_valid_access_token_decodes_successfully(self, manager):
        tokens = manager.create_token_pair(user_id=1, username="alice", role="user")
        payload = manager.decode_token(tokens.access_token, expected_type="access")
        assert payload["sub"] == "1"
        assert payload["username"] == "alice"
        assert payload["role"] == "user"

    def test_access_and_refresh_tokens_are_different_strings(self, manager):
        tokens = manager.create_token_pair(user_id=1, username="alice", role="user")
        assert tokens.access_token != tokens.refresh_token

    def test_tampered_token_is_rejected(self, manager):
        tokens = manager.create_token_pair(user_id=1, username="alice", role="user")
        tampered = tokens.access_token[:-4] + "abcd"  # corrupt the signature
        with pytest.raises(TokenError):
            manager.decode_token(tampered, expected_type="access")

    def test_token_signed_by_a_different_key_pair_is_rejected(self, manager, tmp_path_factory):
        """
        Proves RS256 verification actually checks the signature against
        THIS manager's public key -- a token from a totally different key
        pair must never validate, even if its payload looks legitimate.
        """
        other_dir = tmp_path_factory.mktemp("other_keys")
        other_manager = JWTManager(keys_dir=other_dir)
        foreign_tokens = other_manager.create_token_pair(user_id=1, username="alice", role="user")

        with pytest.raises(TokenError):
            manager.decode_token(foreign_tokens.access_token, expected_type="access")

    def test_expired_token_is_rejected(self, manager):
        # Directly build an already-expired token using the manager's
        # internals to avoid sleeping in a test.
        expired_token = manager._create_token(
            user_id=1, username="alice", role="user",
            ttl=timedelta(seconds=-1), token_type="access",
        )
        with pytest.raises(TokenError):
            manager.decode_token(expired_token, expected_type="access")

    def test_refresh_token_cannot_be_used_as_an_access_token(self, manager):
        """
        THE KEY SECURITY PROPERTY OF THE `type` CLAIM: a refresh token --
        which should only ever be exchanged via /auth/refresh -- must be
        rejected if presented directly to an endpoint expecting an access
        token.
        """
        tokens = manager.create_token_pair(user_id=1, username="alice", role="user")
        with pytest.raises(TokenError):
            manager.decode_token(tokens.refresh_token, expected_type="access")


class TestRefreshRotation:
    def test_refreshing_issues_a_new_valid_token_pair(self, manager):
        tokens = manager.create_token_pair(user_id=1, username="alice", role="user")
        new_tokens = manager.refresh_access_token(tokens.refresh_token)

        payload = manager.decode_token(new_tokens.access_token, expected_type="access")
        assert payload["username"] == "alice"

    def test_old_refresh_token_is_blacklisted_after_use(self, manager):
        """
        THE ROTATION GUARANTEE: once a refresh token has been used, it
        cannot be used again -- proves a stolen refresh token is only
        good for a single refresh cycle, not indefinite re-use.
        """
        tokens = manager.create_token_pair(user_id=1, username="alice", role="user")
        manager.refresh_access_token(tokens.refresh_token)

        with pytest.raises(TokenError):
            manager.refresh_access_token(tokens.refresh_token)


class TestBlacklist:
    def test_revoked_access_token_is_rejected(self, manager):
        tokens = manager.create_token_pair(user_id=1, username="alice", role="user")
        manager.revoke_token(tokens.access_token)

        with pytest.raises(TokenError):
            manager.decode_token(tokens.access_token, expected_type="access")

    def test_revoking_an_already_invalid_token_does_not_raise(self, manager):
        """logout should never crash, even on a garbage or already-expired token."""
        manager.revoke_token("not-a-real-token")  # must not raise
