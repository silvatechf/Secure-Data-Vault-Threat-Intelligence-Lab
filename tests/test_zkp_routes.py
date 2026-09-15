"""
tests/test_zkp_routes.py
===========================

End-to-end test through the actual FastAPI endpoints, proving the
non-interactive ZKP flow works over real HTTP -- registration and proof
verification, with the secret itself never appearing in either request.
"""

from app.zkp.schnorr import non_interactive_prove, register


class TestZkpEndpoints:
    def test_register_then_prove_succeeds(self, client):
        secret_x = 999_888_777

        y = register(secret_x)
        register_response = client.post(
            "/auth/zkp/register", json={"identifier": "alice", "y": y}
        )
        assert register_response.status_code == 200

        _, proof = non_interactive_prove(secret_x)
        prove_response = client.post(
            "/auth/zkp/prove", json={"identifier": "alice", "t": proof.t, "s": proof.s}
        )
        assert prove_response.status_code == 200
        assert prove_response.json()["status"] == "verified"

    def test_prove_with_wrong_secret_fails(self, client):
        real_secret = 111
        wrong_secret = 222

        y = register(real_secret)
        client.post("/auth/zkp/register", json={"identifier": "bob", "y": y})

        _, forged_proof = non_interactive_prove(wrong_secret)  # proof for the WRONG secret
        response = client.post(
            "/auth/zkp/prove", json={"identifier": "bob", "t": forged_proof.t, "s": forged_proof.s}
        )
        assert response.status_code == 401

    def test_prove_for_unregistered_identifier_fails(self, client):
        _, proof = non_interactive_prove(42)
        response = client.post(
            "/auth/zkp/prove",
            json={"identifier": "nobody-registered-this-name", "t": proof.t, "s": proof.s},
        )
        assert response.status_code == 404

    def test_secret_never_appears_in_either_request_payload(self, client):
        """
        A slightly unusual but meaningful test: confirms the request
        schemas themselves have no field capable of carrying the secret
        at all -- the whole point of the protocol.
        """
        from app.zkp.routes import ProveRequest, RegisterRequest

        register_fields = set(RegisterRequest.model_fields.keys())
        prove_fields = set(ProveRequest.model_fields.keys())

        assert register_fields == {"identifier", "y"}
        assert prove_fields == {"identifier", "t", "s"}
