"""
app/zkp/routes.py
====================

A demo endpoint showing non-interactive ZKP authentication end to end:
register a public value once, then prove knowledge of the secret on every
subsequent "login" without ever sending that secret again. This is a
standalone demonstration, separate from the main password-based
`/auth/login` flow -- it exists to show the protocol working over a real
HTTP API, not to replace the project's actual authentication system.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.zkp.schnorr import Proof, non_interactive_verify

router = APIRouter(prefix="/auth/zkp", tags=["zkp-demo"])

# In-memory registry of public values, keyed by an identifier the client
# chooses. A real system would tie this to a user account in the
# database; this stays in-memory because it's a standalone protocol demo.
_registered_public_values: dict[str, int] = {}


class RegisterRequest(BaseModel):
    identifier: str
    y: int  # the public value g^x mod p -- the secret x itself is never sent


class ProveRequest(BaseModel):
    identifier: str
    t: int
    s: int


@router.post("/register")
def register_public_value(payload: RegisterRequest):
    """
    Stores a public value for later verification. The actual secret is
    computed and used entirely on the CLIENT side (see
    app/zkp/schnorr.py's register()) -- this endpoint only ever receives
    y, never x.
    """
    _registered_public_values[payload.identifier] = payload.y
    return {"status": "registered", "identifier": payload.identifier}


@router.post("/prove")
def prove_identity(payload: ProveRequest):
    """
    Verifies a non-interactive proof against a previously registered
    public value. Note what's NEVER present anywhere in this request: the
    secret itself. Compare this to /auth/login, which requires the
    plaintext password on every single call.
    """
    y = _registered_public_values.get(payload.identifier)
    if y is None:
        raise HTTPException(status_code=404, detail="No public value registered for this identifier.")

    proof = Proof(t=payload.t, s=payload.s)
    if not non_interactive_verify(y, proof):
        raise HTTPException(status_code=401, detail="Proof verification failed.")

    return {"status": "verified", "identifier": payload.identifier}
