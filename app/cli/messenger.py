"""
app/cli/messenger.py
======================

EX-11: CLI chat module built on top of app/messenger/e2e.py. Each user
generates their own key pair once; sending a message produces a file the
sender hands to the recipient through whatever channel they already use
(email, a shared drive, USB stick) -- the same "encrypt to a file, share
the file" workflow real tools like GPG have used for decades. This
project doesn't need to also build a real-time transport to demonstrate
the cryptography working correctly.

Usage:
    python -m app.cli.messenger keygen alice
    python -m app.cli.messenger keygen bob

    python -m app.cli.messenger send alice bob "Meet at 9pm" --out msg.json
    python -m app.cli.messenger receive bob msg.json
"""

import argparse
import getpass
import json
import sys
from pathlib import Path

from app.messenger.e2e import (
    EncryptedMessage,
    SignatureVerificationError,
    encrypt_and_sign,
    generate_key_pair,
    load_private_key,
    load_public_key,
    serialize_private_key,
    serialize_public_key,
    verify_and_decrypt,
)

KEYS_DIR = Path(__file__).resolve().parent.parent.parent / "keys" / "messenger"


def _private_key_path(username: str) -> Path:
    return KEYS_DIR / f"{username}.pem"


def _public_key_path(username: str) -> Path:
    return KEYS_DIR / f"{username}.pub.pem"


def cmd_keygen(username: str) -> None:
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    passphrase = getpass.getpass(f"Choose a passphrase to protect {username}'s private key: ")

    key_pair = generate_key_pair()
    _private_key_path(username).write_bytes(
        serialize_private_key(key_pair.private_key, passphrase)
    )
    _private_key_path(username).chmod(0o600)
    _public_key_path(username).write_bytes(serialize_public_key(key_pair.public_key))

    print(f"Generated key pair for '{username}'.")
    print(f"  Private key (keep secret): {_private_key_path(username)}")
    print(f"  Public key (share freely): {_public_key_path(username)}")


def cmd_send(sender: str, recipient: str, message: str, out_path: str) -> None:
    if not _public_key_path(recipient).exists():
        print(f"No public key found for '{recipient}'. They need to run 'keygen' first "
              f"and share {_public_key_path(recipient).name} with you.", file=sys.stderr)
        sys.exit(1)

    passphrase = getpass.getpass(f"Passphrase for {sender}'s private key: ")
    try:
        sender_private_key = load_private_key(_private_key_path(sender).read_bytes(), passphrase)
    except ValueError:
        print("Incorrect passphrase -- could not unlock the private key.", file=sys.stderr)
        sys.exit(1)
    recipient_public_key = load_public_key(_public_key_path(recipient).read_bytes())

    encrypted = encrypt_and_sign(message.encode("utf-8"), recipient_public_key, sender_private_key)

    payload = {
        "sender": sender,
        "ciphertext": encrypted.ciphertext.hex(),
        "signature": encrypted.signature.hex(),
    }
    Path(out_path).write_text(json.dumps(payload))
    print(f"Encrypted message written to {out_path}. Send this file to '{recipient}' through any channel.")


def cmd_receive(recipient: str, message_path: str) -> None:
    payload = json.loads(Path(message_path).read_text())
    sender = payload["sender"]

    if not _public_key_path(sender).exists():
        print(f"No public key found for claimed sender '{sender}' -- cannot verify this message.", file=sys.stderr)
        sys.exit(1)

    passphrase = getpass.getpass(f"Passphrase for {recipient}'s private key: ")
    try:
        recipient_private_key = load_private_key(_private_key_path(recipient).read_bytes(), passphrase)
    except ValueError:
        print("Incorrect passphrase -- could not unlock the private key.", file=sys.stderr)
        sys.exit(1)
    sender_public_key = load_public_key(_public_key_path(sender).read_bytes())

    encrypted = EncryptedMessage(
        ciphertext=bytes.fromhex(payload["ciphertext"]),
        signature=bytes.fromhex(payload["signature"]),
    )

    try:
        plaintext = verify_and_decrypt(encrypted, sender_public_key, recipient_private_key)
    except SignatureVerificationError as exc:
        print(f"REJECTED: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"From {sender} (signature verified):")
    print(plaintext.decode("utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description="End-to-end encrypted CLI messenger.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    keygen_parser = subparsers.add_parser("keygen", help="Generate a new key pair.")
    keygen_parser.add_argument("username")

    send_parser = subparsers.add_parser("send", help="Encrypt and sign a message.")
    send_parser.add_argument("sender")
    send_parser.add_argument("recipient")
    send_parser.add_argument("message")
    send_parser.add_argument("--out", default="message.json")

    receive_parser = subparsers.add_parser("receive", help="Verify and decrypt a message.")
    receive_parser.add_argument("recipient")
    receive_parser.add_argument("message_path")

    args = parser.parse_args()

    if args.command == "keygen":
        cmd_keygen(args.username)
    elif args.command == "send":
        cmd_send(args.sender, args.recipient, args.message, args.out)
    elif args.command == "receive":
        cmd_receive(args.recipient, args.message_path)


if __name__ == "__main__":
    main()
