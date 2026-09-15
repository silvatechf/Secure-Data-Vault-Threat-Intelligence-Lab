"""
app/auth/keys.py
==================

Generates (once) or loads the RSA key pair used to sign and verify JWTs.

WHY RS256 (ASYMMETRIC) INSTEAD OF HS256 (SYMMETRIC)?
------------------------------------------------------------
HS256 signs and verifies with the SAME secret key -- anything that can
verify a token can also forge one. That's fine when only your own backend
ever needs to check tokens. RS256 uses a key PAIR: the PRIVATE key signs
tokens (only this API can create valid tokens), and the PUBLIC key
verifies them (anything can check a token is genuine, without ever being
able to forge one). This matters the moment more than one service needs to
verify tokens -- e.g. a future microservice that only checks who's calling,
never issues tokens itself. Handing out the public key is safe; handing
out the private key never is.

WHY 2048 BITS HERE (NOT 4096)?
-----------------------------------
2048-bit RSA is still the widely-used standard for JWT signing in 2026 --
signing/verifying happens on every single request, so the extra
computational cost of 4096 bits matters at that frequency in a way it
doesn't for the one-time RSA-4096 keys used in Week 9-10's end-to-end
messenger (EX-11), where a much stronger margin is worth the one-time cost.
"""

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KEYS_DIR = Path(__file__).resolve().parent.parent.parent / "keys"
PRIVATE_KEY_PATH = KEYS_DIR / "jwt_signing_key.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "jwt_signing_key.pub.pem"

JWT_RSA_KEY_SIZE_BITS = 2048


def _generate_key_pair() -> tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=JWT_RSA_KEY_SIZE_BITS)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def load_or_generate_keys(keys_dir: Path = KEYS_DIR) -> tuple[bytes, bytes]:
    """
    Returns (private_pem, public_pem). Generates a fresh key pair and
    writes it to disk on first run; every subsequent run reuses the same
    keys -- tokens signed before a restart must still verify after one.

    NOTE: `keys/` is gitignored, same reasoning as `.env` -- the private
    key must never be committed. In a real multi-instance deployment, this
    would come from a secrets manager instead of a local file; a local
    file is the pragmatic choice for a single-instance portfolio project.
    """
    keys_dir.mkdir(exist_ok=True)
    private_path = keys_dir / "jwt_signing_key.pem"
    public_path = keys_dir / "jwt_signing_key.pub.pem"

    if private_path.exists() and public_path.exists():
        return private_path.read_bytes(), public_path.read_bytes()

    private_pem, public_pem = _generate_key_pair()
    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)
    private_path.chmod(0o600)  # owner read/write only -- see EX-03's whole point
    return private_pem, public_pem
