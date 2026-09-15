"""
tests/test_rbac.py
====================

Tests for role-based access control on the /admin endpoints.
"""


def _register_login_get_token(client, username, password="Str0ng!Password"):
    client.post(
        "/auth/register",
        json={"username": username, "email": f"{username}@example.com", "password": password},
    )
    response = client.post("/auth/login", json={"username": username, "password": password})
    return response.json()["access_token"]


class TestRBAC:
    def test_regular_user_cannot_access_admin_only_endpoint(self, client):
        token = _register_login_get_token(client, "regularuser")
        response = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 403

    def test_admin_can_access_admin_only_endpoint(self, client, db_session_for_role_promotion):
        """
        Registration always creates a default 'user' role (see
        app/models.py) -- there's no public "become an admin" endpoint,
        on purpose (see docs/week-05-06-api-security.md's known
        simplifications). This test promotes a user directly via the DB
        session to simulate what a real admin-provisioning process would do.
        """
        token = _register_login_get_token(client, "adminuser")
        db_session_for_role_promotion("adminuser", "admin")

        # Re-login so the new token's `role` claim reflects the promotion
        # -- the OLD token still says "user" (JWTs are immutable once
        # issued), which is itself a useful, realistic detail.
        response = client.post(
            "/auth/login", json={"username": "adminuser", "password": "Str0ng!Password"}
        )
        new_token = response.json()["access_token"]

        admin_response = client.get("/admin/users", headers={"Authorization": f"Bearer {new_token}"})
        assert admin_response.status_code == 200

    def test_old_token_still_reflects_old_role_after_promotion(
        self, client, db_session_for_role_promotion
    ):
        """
        A real, security-relevant property of JWTs worth understanding:
        they are NOT re-checked against the database on every request --
        the role is baked into the token at issuance. A promoted user's
        OLD token keeps working as a 'user' token until it naturally
        expires; only a freshly issued token reflects the new role.
        """
        old_token = _register_login_get_token(client, "laterpromoted")
        db_session_for_role_promotion("laterpromoted", "admin")

        # The token issued BEFORE promotion still claims role=user.
        response = client.get("/admin/users", headers={"Authorization": f"Bearer {old_token}"})
        assert response.status_code == 403

    def test_missing_token_is_rejected_before_role_is_even_checked(self, client):
        response = client.get("/admin/users")
        assert response.status_code == 401

    def test_analyst_role_can_access_dual_role_endpoint_but_not_admin_only(
        self, client, db_session_for_role_promotion
    ):
        _register_login_get_token(client, "analystuser")
        db_session_for_role_promotion("analystuser", "analyst")
        response = client.post(
            "/auth/login", json={"username": "analystuser", "password": "Str0ng!Password"}
        )
        token = response.json()["access_token"]

        # /admin/audit-logs allows admin OR analyst.
        logs_response = client.get("/admin/audit-logs", headers={"Authorization": f"Bearer {token}"})
        assert logs_response.status_code == 200

        # /admin/users is admin-only -- analyst is not enough.
        users_response = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
        assert users_response.status_code == 403
