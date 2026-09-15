"""
tests/test_privacy_routes.py
===============================
"""
from tests.test_constants import TEST_PASSWORD, TEST_WRONG_PASSWORD


def _register_admin(client, username="privacyadmin"):
    response = client.post(
        "/auth/register",
        json={"username": username, "email": f"{username}@example.com", "password": TEST_PASSWORD},
    )
    return response.json()["id"]


def _login(client, username, password=TEST_PASSWORD):
    response = client.post("/auth/login", json={"username": username, "password": password})
    return response.json()["access_token"]


class TestAggregatedReportEndpoint:
    def test_non_admin_cannot_access_the_report(self, client):
        client.post(
            "/auth/register",
            json={"username": "regularuser", "email": "r@example.com", "password": TEST_PASSWORD},
        )
        token = _login(client, "regularuser")

        response = client.get("/reports/aggregated", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 403

    def test_admin_can_access_the_report(self, client, db_session_for_role_promotion):
        _register_admin(client)
        db_session_for_role_promotion("privacyadmin", "admin")
        token = _login(client, "privacyadmin")

        response = client.get("/reports/aggregated", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200
        body = response.json()
        assert "noisy_user_count" in body
        assert "epsilon" in body

    def test_report_never_returns_the_exact_true_count(self, client, db_session_for_role_promotion):
        """A meaningful, if slightly unusual, assertion: the whole point of this endpoint is that the returned count is NOT the exact number."""
        _register_admin(client)
        db_session_for_role_promotion("privacyadmin", "admin")
        token = _login(client, "privacyadmin")

        from app.models import User
        from tests.conftest import TestSessionLocal

        db = TestSessionLocal()
        try:
            true_count = db.query(User).count()
        finally:
            db.close()

        response = client.get("/reports/aggregated", headers={"Authorization": f"Bearer {token}"})
        noisy_count = response.json()["noisy_user_count"]

        # Vanishingly unlikely for continuous Laplace noise to land on
        # exactly zero -- this isn't a perfect guarantee, but a
        # reasonable statistical check for a single call.
        assert noisy_count != true_count
