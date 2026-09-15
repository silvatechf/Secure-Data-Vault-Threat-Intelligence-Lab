"""
tests/test_auth.py
====================

Tests for password hashing, input validation, and the /auth endpoints.
"""
from tests.test_constants import TEST_PASSWORD, TEST_WRONG_PASSWORD

from app.auth.hashing import hash_password, verify_password
from app.middleware.validation import (
    validate_email,
    validate_password,
    validate_username,
)


class TestHashing:
    def test_hash_is_never_the_plaintext(self):
        """The whole point of hashing: the stored value must never equal the input."""
        hashed = hash_password("CorrectHorse123!")
        assert hashed != "CorrectHorse123!"

    def test_correct_password_verifies(self):
        hashed = hash_password("CorrectHorse123!")
        assert verify_password("CorrectHorse123!", hashed) is True

    def test_wrong_password_does_not_verify(self):
        hashed = hash_password("CorrectHorse123!")
        assert verify_password(TEST_WRONG_PASSWORD, hashed) is False

    def test_same_password_hashed_twice_produces_different_hashes(self):
        """
        Proves the salt is working: bcrypt generates a random salt each
        call, so hashing the identical password twice must NOT produce
        the identical hash. If this test ever fails, salting is broken.
        """
        hash_one = hash_password("SamePassword1!")
        hash_two = hash_password("SamePassword1!")
        assert hash_one != hash_two
        # but both still verify correctly against the same plaintext
        assert verify_password("SamePassword1!", hash_one) is True
        assert verify_password("SamePassword1!", hash_two) is True


class TestValidation:
    def test_valid_email_passes(self):
        assert validate_email("user@example.com").is_valid is True

    def test_email_without_at_sign_fails(self):
        assert validate_email("not-an-email").is_valid is False

    def test_valid_username_passes(self):
        assert validate_username("fernando_s").is_valid is True

    def test_username_with_spaces_fails(self):
        assert validate_username("fernando silva").is_valid is False

    def test_short_username_fails(self):
        assert validate_username("ab").is_valid is False

    def test_strong_password_passes(self):
        assert validate_password(TEST_PASSWORD).is_valid is True

    def test_password_missing_special_char_fails(self):
        assert validate_password("NoSpecialChar123").is_valid is False

    def test_short_password_fails(self):
        assert validate_password("Sh0rt!").is_valid is False


class TestAuthEndpoints:
    def test_register_with_valid_data_succeeds(self, client):
        response = client.post(
            "/auth/register",
            json={
                "username": "newuser",
                "email": "newuser@example.com",
                "password": TEST_PASSWORD,
            },
        )
        assert response.status_code == 201
        body = response.json()
        assert body["username"] == "newuser"
        # the password hash must NEVER appear in an API response
        assert "password" not in body
        assert "password_hash" not in body

    def test_register_with_weak_password_is_rejected(self, client):
        response = client.post(
            "/auth/register",
            json={"username": "someone", "email": "someone@example.com", "password": "weak"},
        )
        assert response.status_code == 422

    def test_register_duplicate_username_is_rejected(self, client):
        payload = {
            "username": "duplicate",
            "email": "first@example.com",
            "password": TEST_PASSWORD,
        }
        client.post("/auth/register", json=payload)

        payload["email"] = "second@example.com"  # different email, same username
        response = client.post("/auth/register", json=payload)
        assert response.status_code == 409

    def test_login_with_correct_credentials_succeeds(self, client):
        client.post(
            "/auth/register",
            json={
                "username": "loginuser",
                "email": "login@example.com",
                "password": TEST_PASSWORD,
            },
        )
        response = client.post(
            "/auth/login", json={"username": "loginuser", "password": TEST_PASSWORD}
        )
        assert response.status_code == 200

    def test_login_with_wrong_password_fails(self, client):
        client.post(
            "/auth/register",
            json={
                "username": "loginuser2",
                "email": "login2@example.com",
                "password": TEST_PASSWORD,
            },
        )
        response = client.post(
            "/auth/login", json={"username": "loginuser2", "password": "WrongOne!1"}
        )
        assert response.status_code == 401

    def test_login_with_nonexistent_user_gives_same_error_as_wrong_password(self, client):
        """
        Security property, not just a functional check: the error for
        "no such user" must be identical to "wrong password" -- see the
        docstring in app/auth/routes.py for why.
        """
        response = client.post(
            "/auth/login", json={"username": "ghost", "password": "Whatever1!"}
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid username or password."
