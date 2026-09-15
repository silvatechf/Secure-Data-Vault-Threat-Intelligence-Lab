"""
app/cli/password_manager.py
==============================

B-01: a command-line password manager, built entirely on top of pieces
this project already has -- VaultEngine for encryption, key_cache for key
derivation. No new cryptography is introduced here; this exercise is
about APPLYING what Week 3-4 already built to a new use case.

Usage:
    python -m app.cli.password_manager add <site> --username <user>
    python -m app.cli.password_manager get <site>
    python -m app.cli.password_manager list
    python -m app.cli.password_manager generate [--length 20]

WHY REUSE THE VAULT'S MASTER KEY INSTEAD OF A SEPARATE ONE?
------------------------------------------------------------------
A second master password would mean a second thing to remember and a
second thing that could be weak or reused. Deriving from the SAME vault
password (via the SAME PBKDF2 + salt scheme in
app/vault/key_cache.py) means "unlocking the vault" and "unlocking the
password manager" are the same action -- one strong master password
protects everything, which is also how real password managers like
Bitwarden and 1Password work.

WHY CLIPBOARD AUTO-CLEAR MATTERS
-------------------------------------
A password copied to the clipboard sits there until something overwrites
it -- readable by any other application on the machine, or visible in
clipboard history tools some OSes keep. Auto-clearing after a short window
(10 seconds here) limits that exposure to roughly the time it takes to
paste it once, without the user having to remember to clear it manually.
"""

import argparse
import getpass
import logging
import secrets
import string
import sys
import threading
import time

from sqlalchemy.orm import Session

from app.database import Base, SessionLocal, engine
from app.models import SiteCredential, User
from app.vault.key_cache import key_cache
from app.vault.vault_engine import EncryptedPayload, VaultEngine, VaultIntegrityError

logger = logging.getLogger(__name__)

CLIPBOARD_CLEAR_DELAY_SECONDS = 10


def generate_strong_password(length: int = 20) -> str:
    """
    Generates a random password using `secrets` (NOT `random`) -- `random`
    is a general-purpose, predictable PRNG never meant for anything
    security-sensitive; `secrets` is specifically built for this and is
    what Python's own documentation recommends for tokens, passwords, and
    similar secrets.
    """
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _copy_to_clipboard_with_auto_clear(text: str, delay_seconds: int = CLIPBOARD_CLEAR_DELAY_SECONDS) -> bool:
    """
    Copies `text` to the system clipboard and schedules it to be
    overwritten with an empty string after `delay_seconds`. Returns False
    (and prints the password instead) if no clipboard is available --
    common in headless/CI/SSH environments, where failing loudly with an
    unhandled exception would be worse than degrading gracefully.
    """
    try:
        import pyperclip

        pyperclip.copy(text)
    except Exception:
        return False

    def clear_after_delay():
        time.sleep(delay_seconds)
        try:
            import pyperclip

            # Only clear if the clipboard STILL holds what we put there --
            # if the user copied something else in the meantime, clearing
            # unconditionally would wipe THEIR new clipboard content
            # instead of just our stale password.
            if pyperclip.paste() == text:
                pyperclip.copy("")
        except Exception as exc:
            # This runs in a fire-and-forget background thread with no
            # caller waiting for a result, so there's nothing to return
            # False to -- but silently swallowing the exception entirely
            # (bare `pass`) would hide a real, debuggable failure. Logging
            # it is the middle ground: doesn't crash the thread, doesn't
            # bother the user, but also doesn't vanish without a trace.
            logger.warning("Clipboard auto-clear failed: %s", exc)

    threading.Thread(target=clear_after_delay, daemon=True).start()
    return True


def _authenticate(db: Session, username: str, master_password: str) -> tuple[User, VaultEngine]:
    from app.auth.hashing import verify_password

    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(master_password, user.password_hash):
        print("Invalid username or master password.", file=sys.stderr)
        sys.exit(1)

    salt = user.password_hash.encode("utf-8")[:16]
    key = key_cache.get_or_derive(user.id, master_password, salt)
    return user, VaultEngine(key)


def add_credential(db: Session, user: User, engine_: VaultEngine, site: str, site_username: str, site_password: str) -> None:
    username_payload = engine_.encrypt(site_username.encode("utf-8"))
    password_payload = engine_.encrypt(site_password.encode("utf-8"))

    credential = SiteCredential(
        owner_id=user.id,
        site_name=site,
        # Concatenate iv + ciphertext into one blob for storage -- same
        # format as encrypted files on disk (see vault_engine.encrypt_file).
        encrypted_username=username_payload.iv + username_payload.ciphertext,
        encrypted_password=password_payload.iv + password_payload.ciphertext,
    )
    db.add(credential)
    db.commit()


def get_credential(db: Session, user: User, engine_: VaultEngine, site: str) -> tuple[str, str] | None:
    credential = (
        db.query(SiteCredential)
        .filter(SiteCredential.owner_id == user.id, SiteCredential.site_name == site)
        .first()
    )
    if not credential:
        return None

    def _decrypt(blob: bytes) -> str:
        iv, ciphertext = blob[:12], blob[12:]
        return engine_.decrypt(EncryptedPayload(iv=iv, ciphertext=ciphertext)).decode("utf-8")

    try:
        return _decrypt(credential.encrypted_username), _decrypt(credential.encrypted_password)
    except VaultIntegrityError:
        print("Failed to decrypt -- wrong master password or corrupted data.", file=sys.stderr)
        sys.exit(1)


def list_sites(db: Session, user: User) -> list[str]:
    """Site NAMES are not encrypted (needed to list without unlocking every entry) -- only usernames/passwords are."""
    rows = db.query(SiteCredential.site_name).filter(SiteCredential.owner_id == user.id).all()
    return [row[0] for row in rows]


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="password-manager", description="CLI password manager built on the vault's encryption.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    add_parser = subparsers.add_parser("add", help="Store a new site credential.")
    add_parser.add_argument("site")
    add_parser.add_argument("--username", required=True)
    add_parser.add_argument("--generate", action="store_true", help="Auto-generate a strong password instead of typing one.")

    get_parser = subparsers.add_parser("get", help="Retrieve and copy a site credential's password.")
    get_parser.add_argument("site")

    subparsers.add_parser("list", help="List all stored site names (does not decrypt anything).")

    gen_parser = subparsers.add_parser("generate", help="Generate a strong password without storing it.")
    gen_parser.add_argument("--length", type=int, default=20)

    args = parser.parse_args(argv)

    if args.command == "generate":
        print(generate_strong_password(args.length))
        return

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        username = input("Username: ")
        master_password = getpass.getpass("Master password: ")
        user, engine_ = _authenticate(db, username, master_password)

        if args.command == "add":
            site_password = generate_strong_password() if args.generate else getpass.getpass(f"Password for {args.site}: ")
            add_credential(db, user, engine_, args.site, args.username, site_password)
            print(f"Stored credentials for '{args.site}'.")
            if args.generate:
                copied = _copy_to_clipboard_with_auto_clear(site_password)
                print(
                    f"Generated password copied to clipboard (clears in {CLIPBOARD_CLEAR_DELAY_SECONDS}s)."
                    if copied else f"Generated password: {site_password}"
                )

        elif args.command == "get":
            result = get_credential(db, user, engine_, args.site)
            if result is None:
                print(f"No credentials stored for '{args.site}'.", file=sys.stderr)
                sys.exit(1)
            site_username, site_password = result
            print(f"Username: {site_username}")
            copied = _copy_to_clipboard_with_auto_clear(site_password)
            print(
                f"Password copied to clipboard (clears in {CLIPBOARD_CLEAR_DELAY_SECONDS}s)."
                if copied else f"Password: {site_password}"
            )

        elif args.command == "list":
            sites = list_sites(db, user)
            if not sites:
                print("No stored credentials.")
            for site in sites:
                print(f"  - {site}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
