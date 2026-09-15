"""
app/models.py
==============

The five tables that back this platform. Each one maps directly to a
capability described in the project blueprint (docs/ROADMAP.md).

Schema at a glance:
    users          -- accounts, password hashes (never plaintext)
    vault_entries  -- metadata for encrypted files (Week 3-4)
    audit_logs     -- every security-relevant event, for forensics (Week 7-8)
    threat_intel   -- attacks captured by the honeypot (Week 7-8)
    honeypot_logs  -- raw requests hitting the decoy endpoint (Week 7-8)

Only `users` is fully used by the Week 1-2 code in this delivery; the other
four are defined now so the schema is stable and the later weeks build on
top of it instead of migrating it.
"""

import datetime
from datetime import timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)

    # Never a plaintext password column, ever -- only the hash. See
    # app/auth/hashing.py for why this is bcrypt, not something reversible.
    password_hash: Mapped[str] = mapped_column(String(255))

    role: Mapped[str] = mapped_column(String(20), default="user")
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=lambda: datetime.datetime.now(timezone.utc)
    )

    vault_entries: Mapped[list["VaultEntry"]] = relationship(back_populates="owner")


class VaultEntry(Base):
    """Metadata for an encrypted file. The Week 3-4 VaultEngine populates this."""

    __tablename__ = "vault_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    filename: Mapped[str] = mapped_column(String(255))
    # Description is stored AFTER PII redaction (Week 3-4, EX-05) -- never
    # store the raw, unredacted text the user typed.
    description: Mapped[str] = mapped_column(Text, nullable=True)
    encrypted_path: Mapped[str] = mapped_column(String(500))
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=lambda: datetime.datetime.now(timezone.utc)
    )

    owner: Mapped["User"] = relationship(back_populates="vault_entries")


class AuditLog(Base):
    """Every security-relevant event: logins, failed auth, admin actions."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_type: Mapped[str] = mapped_column(String(50))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=True)  # IPv6-safe length
    severity: Mapped[str] = mapped_column(String(20), default="LOW")
    details: Mapped[str] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=lambda: datetime.datetime.now(timezone.utc)
    )


class ThreatIntel(Base):
    """Classified attacks captured by the honeypot (Week 7-8)."""

    __tablename__ = "threat_intel"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_ip: Mapped[str] = mapped_column(String(45))
    attack_type: Mapped[str] = mapped_column(String(50))  # XSS, LFI, RCE, SQLi...
    confidence: Mapped[float] = mapped_column(default=0.0)
    payload: Mapped[str] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=lambda: datetime.datetime.now(timezone.utc)
    )


class HoneypotLog(Base):
    """Raw request log for every hit on the decoy endpoint (Week 7-8)."""

    __tablename__ = "honeypot_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_ip: Mapped[str] = mapped_column(String(45))
    method: Mapped[str] = mapped_column(String(10))
    path: Mapped[str] = mapped_column(String(500))
    headers: Mapped[str] = mapped_column(Text, nullable=True)
    body: Mapped[str] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=lambda: datetime.datetime.now(timezone.utc)
    )


class SiteCredential(Base):
    """
    Encrypted site login credentials, for the CLI password manager
    (B-01, Week 5-6). Each row is encrypted independently with the
    owning user's vault key -- the same AES-256-GCM engine that protects
    vault files, reused here rather than inventing a second encryption
    scheme.
    """

    __tablename__ = "site_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    site_name: Mapped[str] = mapped_column(String(255))
    # Both stored as iv+ciphertext blobs (see app/vault/vault_engine.py) --
    # the site username often isn't sensitive on its own, but encrypting
    # it too costs nothing and avoids having to judge case by case.
    encrypted_username: Mapped[bytes] = mapped_column(nullable=False)
    encrypted_password: Mapped[bytes] = mapped_column(nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=lambda: datetime.datetime.now(timezone.utc)
    )
