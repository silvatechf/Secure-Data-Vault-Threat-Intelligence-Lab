"""
app/vault/routes.py
=====================

Ties Week 3-4's encryption/redaction together with Week 5-6's real
authentication: upload (encrypt + redact + store) and download (retrieve
+ decrypt + verify integrity).

WHY BOTH A JWT *AND* A PASSWORD ARE STILL REQUIRED HERE
------------------------------------------------------------------
This looks redundant at first -- if the JWT already proves who you are,
why also ask for `vault_password`? Because they prove two DIFFERENT
things, and collapsing them into one would weaken the design:

- The JWT proves **"this request is authenticated as user X"** -- it's
  what every protected endpoint in this app checks (see
  app/auth/rbac.py's get_current_user).
- `vault_password` is the secret the AES key is DERIVED FROM (see
  app/vault/key_cache.py). The server never stores this key -- it's
  reconstructed on demand. A stolen/leaked JWT alone is NOT enough to
  decrypt anyone's files; an attacker would also need the vault password,
  which never appears in the token itself.

This mirrors a real "zero-knowledge-ish" design choice: session
authentication (JWT) and vault-unlock (password-derived key) are
deliberately separate concerns, so compromising one doesn't
automatically compromise the other. Week 1-2 through Week 3-4 flagged
`user_id` being trusted directly from the client as a known
simplification to fix once JWT existed -- this file is that fix:
`user_id` is no longer accepted from the client at all; it comes from
the validated token.
"""

import os
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, UploadFile
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.auth.rbac import get_current_user
from app.database import get_db
from app.models import User, VaultEntry
from app.vault.key_cache import key_cache
from app.vault.pii_redaction import redact_pii
from app.vault.vault_engine import EncryptedPayload, VaultEngine, VaultIntegrityError

router = APIRouter(prefix="/vault", tags=["vault"])

STORAGE_DIR = Path(__file__).resolve().parent.parent.parent / "encrypted_storage"
STORAGE_DIR.mkdir(exist_ok=True)


class VaultEntryResponse(BaseModel):
    id: int
    filename: str
    description: str | None

    model_config = ConfigDict(from_attributes=True)


def _get_engine_for_current_user(
    vault_password: str, current_user: dict, db: Session
) -> tuple[User, VaultEngine]:
    """
    The JWT (via get_current_user) has already proven WHO is calling.
    This derives the AES key for THAT user from the vault_password they
    additionally supplied -- if it's wrong, key derivation still
    "succeeds" mechanically (PBKDF2 always produces 32 bytes), but the
    resulting key won't match what encrypted the user's files, so
    decryption fails its integrity check. There's no separate
    "is this password right" check here on purpose -- the AES-GCM
    integrity tag is what actually proves it, the same principle as
    login never revealing which part of a credential pair was wrong.
    """
    user = db.query(User).filter(User.id == current_user["user_id"]).first()
    if not user:
        raise HTTPException(status_code=401, detail="User no longer exists.")

    salt = user.password_hash.encode("utf-8")[:16]
    key = key_cache.get_or_derive(user.id, vault_password, salt)
    return user, VaultEngine(key)


@router.post("/upload", response_model=VaultEntryResponse, status_code=201)
async def upload_file(
    vault_password: str,
    description: str = "",
    file: UploadFile = None,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    user, engine = _get_engine_for_current_user(vault_password, current_user, db)

    redacted_filename = redact_pii(file.filename).redacted_text
    redacted_description = redact_pii(description).redacted_text

    plaintext = await file.read()
    payload = engine.encrypt(plaintext)

    dest_filename = f"{user.id}_{os.urandom(8).hex()}.enc"
    dest_path = STORAGE_DIR / dest_filename
    with open(dest_path, "wb") as f:
        f.write(payload.iv)
        f.write(payload.ciphertext)

    entry = VaultEntry(
        owner_id=user.id,
        filename=redacted_filename,
        description=redacted_description,
        encrypted_path=str(dest_path),
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


@router.get("/download/{entry_id}")
def download_file(
    entry_id: int,
    vault_password: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    user, engine = _get_engine_for_current_user(vault_password, current_user, db)

    entry = (
        db.query(VaultEntry)
        .filter(VaultEntry.id == entry_id, VaultEntry.owner_id == user.id)
        .first()
    )
    if not entry:
        raise HTTPException(status_code=404, detail="Vault entry not found.")

    with open(entry.encrypted_path, "rb") as f:
        raw = f.read()
    iv, ciphertext = raw[:12], raw[12:]

    try:
        plaintext = engine.decrypt(EncryptedPayload(iv=iv, ciphertext=ciphertext))
    except VaultIntegrityError:
        raise HTTPException(
            status_code=422,
            detail="File failed integrity verification -- it may have been tampered "
            "with, or the vault password was incorrect.",
        )

    return {"filename": entry.filename, "content_base64": plaintext.hex()}
