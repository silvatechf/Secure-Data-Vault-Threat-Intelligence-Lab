"""
tests/test_schnorr.py
========================

Tests for the core Schnorr protocol math (app/zkp/schnorr.py), separate
from tests/test_zkp_routes.py, which tests the HTTP layer built on top of
it. These tests generate ONE set of group parameters per module (via the
`params` fixture) since generating a fresh safe prime is the slow part of
this whole module -- reusing parameters across tests, the same way a real
deployment would reuse them, keeps the suite fast without weakening what
each test actually proves.
"""

import pytest

from app.zkp.schnorr import (
    Commitment,
    Proof,
    _generate_group_parameters,
    create_challenge,
    create_commitment,
    create_response,
    non_interactive_prove,
    non_interactive_verify,
    register,
    verify,
)


@pytest.fixture(scope="module")
def params():
    return _generate_group_parameters()


class TestInteractiveProtocol:
    def test_genuine_prover_is_accepted(self, params):
        secret_x = 12345
        y = register(secret_x, params)

        commitment = create_commitment(params)
        challenge = create_challenge(params)
        response = create_response(secret_x, commitment, challenge, params)

        assert verify(y, commitment.t, challenge, response, params) is True

    def test_wrong_secret_is_rejected(self, params):
        real_secret = 12345
        wrong_secret = 99999
        y = register(real_secret, params)  # the PUBLIC value is for the real secret

        commitment = create_commitment(params)
        challenge = create_challenge(params)
        # but the response is computed with the WRONG secret
        response = create_response(wrong_secret, commitment, challenge, params)

        assert verify(y, commitment.t, challenge, response, params) is False

    def test_tampered_response_is_rejected(self, params):
        secret_x = 12345
        y = register(secret_x, params)

        commitment = create_commitment(params)
        challenge = create_challenge(params)
        response = create_response(secret_x, commitment, challenge, params)

        assert verify(y, commitment.t, challenge, response + 1, params) is False

    def test_different_secrets_produce_different_public_values(self, params):
        y1 = register(111, params)
        y2 = register(222, params)
        assert y1 != y2

    def test_fresh_commitment_is_different_every_time(self, params):
        """
        The randomness in each commitment is what makes replaying an old
        proof useless -- two commitments generated back to back must not
        be identical.
        """
        commitment_1 = create_commitment(params)
        commitment_2 = create_commitment(params)
        assert commitment_1.t != commitment_2.t


class TestNonInteractiveProtocol:
    def test_genuine_proof_is_accepted(self, params):
        secret_x = 54321
        y, proof = non_interactive_prove(secret_x, params)
        assert non_interactive_verify(y, proof, params) is True

    def test_proof_for_a_different_secret_fails_against_this_y(self, params):
        y, _ = non_interactive_prove(111, params)
        _, wrong_proof = non_interactive_prove(222, params)  # a valid proof, but for a different secret
        assert non_interactive_verify(y, wrong_proof, params) is False

    def test_tampered_proof_s_value_is_rejected(self, params):
        y, proof = non_interactive_prove(777, params)
        tampered_proof = Proof(t=proof.t, s=proof.s + 1)
        assert non_interactive_verify(y, tampered_proof, params) is False

    def test_replaying_a_captured_proof_still_verifies(self, params):
        """
        An important, slightly subtle property to be explicit about: a
        Fiat-Shamir proof is deterministic given the same randomness, so
        the SAME (y, proof) pair verifies every time it's checked -- this
        isn't a weakness, it's simply what a NON-interactive proof is: a
        self-contained, replayable piece of evidence, unlike the
        interactive protocol where a NEW random challenge each round is
        what defeats replay of an old transcript. Fiat-Shamir's replay
        resistance comes from the prover needing a fresh commitment (and
        therefore a fresh, unpredictable challenge) for every new proof
        they generate, not from a single proof being single-use.
        """
        y, proof = non_interactive_prove(42, params)
        assert non_interactive_verify(y, proof, params) is True
        assert non_interactive_verify(y, proof, params) is True  # still true, not a "used up" token

    def test_two_proofs_of_the_same_secret_use_different_commitments(self, params):
        """Each call to non_interactive_prove picks a fresh random commitment, even for the identical secret."""
        _, proof_1 = non_interactive_prove(999, params)
        _, proof_2 = non_interactive_prove(999, params)
        assert proof_1.t != proof_2.t
