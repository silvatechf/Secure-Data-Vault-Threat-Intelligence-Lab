"""
app/zkp/schnorr.py
=====================

EX-15: Zero-Knowledge Proof authentication using the Schnorr protocol.
This proves someone knows a secret (their "password") WITHOUT that secret
-- or anything that reveals it -- ever being transmitted, even once, even
encrypted, even to a trusted server.

WHY THIS IS FUNDAMENTALLY DIFFERENT FROM EVERY OTHER AUTH IN THIS PROJECT
------------------------------------------------------------------------------
Every other login in this project (app/auth/hashing.py) works by sending
the password to the server, which hashes it and compares. The server
never stores the plaintext password, but it DOES see it, every single
login. A Zero-Knowledge Proof lets someone prove "I know x" to a verifier
who only ever stores y = g^x mod p (a one-way function of x, similar in
spirit to a password hash) -- the actual value of x is never sent over
the network, not even once, not even during registration after the
initial setup. This closes off an entire category of risk: a
man-in-the-middle, a compromised server process, or a logging bug can
never leak x, because x never travels anywhere to be intercepted.

THE PROTOCOL, STEP BY STEP
--------------------------------
Setup (once): a large prime p, a generator g of a subgroup of order q.
The prover picks a secret x and publishes y = g^x mod p (this is the only
thing the verifier ever stores -- like a public key, or a password hash).

1. COMMIT: the prover picks a random r, computes t = g^r mod p, and sends
   t to the verifier. `t` reveals nothing about `x` -- it's a fresh random
   value every single proof.
2. CHALLENGE: the verifier picks a random challenge c and sends it back.
   This randomness is what makes the proof "zero-knowledge" and prevents
   REPLAY -- an eavesdropper who recorded a previous (t, c, s) triple
   gains nothing, because next time the verifier will pick a different c.
3. RESPONSE: the prover computes s = (r + c*x) mod q and sends s.
4. VERIFY: the verifier checks g^s == t * y^c (mod p). If it holds, the
   prover must have known x -- the only way to produce a valid s for an
   UNPREDICTABLE c is to actually know x (this is the "soundness"
   property); and the verifier learns nothing about x itself from
   watching this exchange (this is the "zero-knowledge" property).

WHY THE FIAT-SHAMIR VARIANT REMOVES THE INTERACTION
---------------------------------------------------------
The classic protocol above needs the verifier to be online and send a
fresh random challenge. Fiat-Shamir replaces that random challenge with
c = H(g || y || t) -- a hash of the protocol's own public values. Since
the prover can't predict a hash output before choosing `t`, they still
can't cheat by picking `s` first and working backward -- but now the
ENTIRE proof (t, s) can be computed by the prover alone, with no verifier
interaction at all, which is what makes this usable as a real
non-interactive login flow (see the /auth/zkp/prove endpoint).

A NOTE ON THE GROUP SIZE USED HERE
----------------------------------------
Production Diffie-Hellman-style groups use 2048-bit (or larger) safe
primes (see RFC 3526). This module generates a smaller prime by default
for fast tests and demos -- correct enough to demonstrate every property
of the protocol, but explicitly NOT sized for real-world security
against a well-resourced attacker. See "Known simplifications" in this
phase's documentation for the honest version of this trade-off.
"""

import hashlib
import secrets
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import dh

PARAMS_DIR = Path(__file__).resolve().parent.parent.parent / "keys"
PARAMS_PATH = PARAMS_DIR / "zkp_group_params.txt"

# 512 bits is intentionally small -- fast enough that generating fresh
# parameters (a safe prime) takes a fraction of a second rather than
# several seconds, which matters for a test suite run many times. This is
# explicitly a demo/test size, not a production security parameter.
DEMO_GROUP_KEY_SIZE_BITS = 512


@dataclass
class GroupParameters:
    p: int  # the (safe) prime modulus
    q: int  # the order of the subgroup, (p - 1) // 2 for a safe prime
    g: int  # a generator of the order-q subgroup


def _generate_group_parameters(key_size_bits: int = DEMO_GROUP_KEY_SIZE_BITS) -> GroupParameters:
    dh_parameters = dh.generate_parameters(generator=2, key_size=key_size_bits)
    numbers = dh_parameters.parameter_numbers()
    p = numbers.p
    q = (p - 1) // 2  # valid because OpenSSL's DH parameter generation produces a safe prime

    # The DH generator (often 2) isn't guaranteed to generate the
    # order-q subgroup specifically -- squaring it does: for a safe prime
    # p = 2q + 1, g^2 always has order dividing q, giving us a generator
    # of exactly the subgroup this protocol's math relies on.
    g = pow(numbers.g, 2, p)

    return GroupParameters(p=p, q=q, g=g)


def _load_or_create_group_parameters() -> GroupParameters:
    """
    Generating a safe prime is the expensive part of this whole module --
    persisting it to disk and reusing it (the same pattern already used
    for the JWT signing keys in app/auth/keys.py) means the cost is paid
    once per environment, not once per process start.
    """
    if PARAMS_PATH.exists():
        p_str, q_str, g_str = PARAMS_PATH.read_text().strip().split("\n")
        return GroupParameters(p=int(p_str), q=int(q_str), g=int(g_str))

    params = _generate_group_parameters()
    PARAMS_DIR.mkdir(exist_ok=True)
    PARAMS_PATH.write_text(f"{params.p}\n{params.q}\n{params.g}\n")
    return params


@dataclass
class Commitment:
    r: int  # the prover's secret random value -- kept by the prover, never sent
    t: int  # g^r mod p -- sent to the verifier


@dataclass
class Proof:
    t: int
    s: int


def register(x: int, params: GroupParameters | None = None) -> int:
    """Computes the public value y = g^x mod p that a verifier stores -- x itself is never returned to be transmitted anywhere by this function's caller."""
    params = params or _load_or_create_group_parameters()
    return pow(params.g, x, params.p)


def create_commitment(params: GroupParameters | None = None) -> Commitment:
    """Step 1 (interactive protocol): the prover's first message."""
    params = params or _load_or_create_group_parameters()
    r = secrets.randbelow(params.q)
    t = pow(params.g, r, params.p)
    return Commitment(r=r, t=t)


def create_challenge(params: GroupParameters | None = None) -> int:
    """Step 2 (interactive protocol): the verifier's random challenge."""
    params = params or _load_or_create_group_parameters()
    return secrets.randbelow(params.q)


def create_response(x: int, commitment: Commitment, challenge: int, params: GroupParameters | None = None) -> int:
    """Step 3 (interactive protocol): the prover's response, using the secret x -- x is used in this computation but never appears in its output in a reversible way."""
    params = params or _load_or_create_group_parameters()
    return (commitment.r + challenge * x) % params.q


def verify(y: int, t: int, challenge: int, s: int, params: GroupParameters | None = None) -> bool:
    """Step 4 (interactive protocol): checks g^s == t * y^challenge (mod p)."""
    params = params or _load_or_create_group_parameters()
    left_side = pow(params.g, s, params.p)
    right_side = (t * pow(y, challenge, params.p)) % params.p
    return left_side == right_side


# --- Non-interactive variant (Fiat-Shamir) ----------------------------------

def _fiat_shamir_challenge(g: int, y: int, t: int, q: int) -> int:
    """c = H(g || y || t) mod q -- deterministic, unpredictable before t is fixed, and reproducible by any verifier who knows g, y, and t."""
    digest_input = f"{g}:{y}:{t}".encode("utf-8")
    digest = hashlib.sha256(digest_input).hexdigest()
    return int(digest, 16) % q


def non_interactive_prove(x: int, params: GroupParameters | None = None) -> tuple[int, Proof]:
    """
    Computes a complete, self-contained proof that the prover knows `x`,
    with NO verifier interaction. Returns (y, proof) -- y is the public
    value a verifier needs on record (e.g. from registration), and proof
    is (t, s), everything needed to check the proof against that y.
    """
    params = params or _load_or_create_group_parameters()
    y = pow(params.g, x, params.p)
    commitment = create_commitment(params)
    challenge = _fiat_shamir_challenge(params.g, y, commitment.t, params.q)
    s = create_response(x, commitment, challenge, params)
    return y, Proof(t=commitment.t, s=s)


def non_interactive_verify(y: int, proof: Proof, params: GroupParameters | None = None) -> bool:
    """
    Recomputes the same Fiat-Shamir challenge the prover must have used,
    then checks the same g^s == t * y^c equation as the interactive
    protocol -- the only difference from `verify()` is where the
    challenge comes from.
    """
    params = params or _load_or_create_group_parameters()
    challenge = _fiat_shamir_challenge(params.g, y, proof.t, params.q)
    return verify(y, proof.t, challenge, proof.s, params)
