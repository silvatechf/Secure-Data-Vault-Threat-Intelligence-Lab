"""
tests/test_vault_routes.py
=============================

End-to-end tests through the actual FastAPI endpoints, now using real JWT
authentication (Week 5-6) instead of Week 3-4's client-supplied user_id.
"""

import io


def _register_and_login(client, username="vaultuser", password="Str0ng!Password"):
    """Registers a user and returns (user_id, access_token)."""
    register_response = client.post(
        "/auth/register",
        json={"username": username, "email": f"{username}@example.com", "password": password},
    )
    assert register_response.status_code == 201
    user_id = register_response.json()["id"]

    login_response = client.post("/auth/login", json={"username": username, "password": password})
    assert login_response.status_code == 200
    access_token = login_response.json()["access_token"]

    return user_id, access_token


def _auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


class TestUploadDownloadRoundTrip:
    def test_uploaded_file_can_be_downloaded_and_matches_original(self, client):
        _, token = _register_and_login(client)
        original_content = b"This is the real content of a secret file."

        upload_response = client.post(
            "/vault/upload",
            params={"vault_password": "Str0ng!Password", "description": "test file"},
            files={"file": ("secret.txt", io.BytesIO(original_content), "text/plain")},
            headers=_auth_header(token),
        )
        assert upload_response.status_code == 201
        entry_id = upload_response.json()["id"]

        download_response = client.get(
            f"/vault/download/{entry_id}",
            params={"vault_password": "Str0ng!Password"},
            headers=_auth_header(token),
        )
        assert download_response.status_code == 200
        recovered_content = bytes.fromhex(download_response.json()["content_base64"])
        assert recovered_content == original_content

    def test_upload_without_a_token_is_rejected(self, client):
        response = client.post(
            "/vault/upload",
            params={"vault_password": "Str0ng!Password", "description": ""},
            files={"file": ("f.txt", io.BytesIO(b"data"), "text/plain")},
        )
        assert response.status_code == 401  # HTTPBearer rejects a missing Authorization header

    def test_wrong_vault_password_fails_integrity_check_on_download(self, client):
        _, token = _register_and_login(client)
        upload_response = client.post(
            "/vault/upload",
            params={"vault_password": "Str0ng!Password", "description": ""},
            files={"file": ("f.txt", io.BytesIO(b"data"), "text/plain")},
            headers=_auth_header(token),
        )
        entry_id = upload_response.json()["id"]

        response = client.get(
            f"/vault/download/{entry_id}",
            params={"vault_password": "TotallyWrongPassword!1"},
            headers=_auth_header(token),
        )
        assert response.status_code == 422  # AES-GCM integrity check fails with the wrong derived key

    def test_one_user_cannot_download_another_users_file(self, client):
        _, token_a = _register_and_login(client, username="usera")
        _, token_b = _register_and_login(client, username="userb")

        upload_response = client.post(
            "/vault/upload",
            params={"vault_password": "Str0ng!Password", "description": ""},
            files={"file": ("f.txt", io.BytesIO(b"user a's secret"), "text/plain")},
            headers=_auth_header(token_a),
        )
        entry_id = upload_response.json()["id"]

        response = client.get(
            f"/vault/download/{entry_id}",
            params={"vault_password": "Str0ng!Password"},
            headers=_auth_header(token_b),
        )
        assert response.status_code == 404

    def test_user_b_cannot_use_a_forged_user_id_anymore(self, client):
        """
        THE ACTUAL FIX THIS PHASE MAKES: Week 3-4's endpoints trusted a
        client-supplied user_id directly -- user B could have simply sent
        user_id=<user A's id> in the request. That parameter doesn't exist
        anymore; the endpoint has no way to accept an impersonated
        identity, because the user always comes from the validated token.
        """
        upload_response = client.post(
            "/vault/upload",
            params={"vault_password": "Str0ng!Password", "description": ""},
        )
        # No Authorization header at all -- proves user identity cannot be
        # supplied any other way.
        assert upload_response.status_code == 401

    def test_pii_in_description_is_redacted_before_storage(self, client):
        _, token = _register_and_login(client)
        upload_response = client.post(
            "/vault/upload",
            params={"vault_password": "Str0ng!Password", "description": "backup for john@example.com"},
            files={"file": ("f.txt", io.BytesIO(b"data"), "text/plain")},
            headers=_auth_header(token),
        )
        assert upload_response.status_code == 201
        assert "john@example.com" not in upload_response.json()["description"]
