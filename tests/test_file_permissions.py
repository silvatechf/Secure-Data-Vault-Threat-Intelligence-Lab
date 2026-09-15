"""
tests/test_file_permissions.py
=================================

Tests for the startup file-permission scanner (EX-03). Includes a
regression test for a real bug found while testing Week 5-6 end to end:
the scanner originally flagged the JWT *public* key as an insecure
secret, which would abort startup every time a fresh key pair was
generated. See app/security/file_permissions.py's PUBLIC_KEY_PATTERNS.
"""

import os

import pytest

from app.security.file_permissions import scan_for_insecure_permissions


@pytest.fixture
def project_dir(tmp_path):
    return tmp_path


def test_secure_env_file_is_not_flagged(project_dir):
    env_file = project_dir / ".env"
    env_file.write_text("SECRET=value")
    env_file.chmod(0o600)

    issues = scan_for_insecure_permissions(project_dir)
    assert issues == []


def test_world_readable_env_file_is_flagged(project_dir):
    env_file = project_dir / ".env"
    env_file.write_text("SECRET=value")
    env_file.chmod(0o644)

    issues = scan_for_insecure_permissions(project_dir)
    assert len(issues) == 1
    assert issues[0].path == env_file


def test_world_readable_private_key_is_flagged(project_dir):
    key_file = project_dir / "signing_key.pem"
    key_file.write_text("-----BEGIN PRIVATE KEY-----")
    key_file.chmod(0o644)

    issues = scan_for_insecure_permissions(project_dir)
    assert len(issues) == 1


def test_world_readable_public_key_is_never_flagged(project_dir):
    """
    THE REGRESSION TEST: a *.pub.pem file is supposed to be world-readable
    -- that's the entire point of a public key. Before this fix, this
    exact scenario (a freshly generated key pair, with the public half at
    the normal default mode 644) made the whole application refuse to
    start.
    """
    public_key_file = project_dir / "jwt_signing_key.pub.pem"
    public_key_file.write_text("-----BEGIN PUBLIC KEY-----")
    public_key_file.chmod(0o644)  # the normal, expected mode for a public file

    issues = scan_for_insecure_permissions(project_dir)
    assert issues == []


def test_private_key_next_to_public_key_is_still_flagged_if_insecure(project_dir):
    """
    The public-key exclusion must be narrow -- it should never accidentally
    also exempt the PRIVATE half of the same key pair sitting in the same
    directory.
    """
    private_key_file = project_dir / "jwt_signing_key.pem"
    private_key_file.write_text("-----BEGIN PRIVATE KEY-----")
    private_key_file.chmod(0o644)  # insecure -- should still be flagged

    public_key_file = project_dir / "jwt_signing_key.pub.pem"
    public_key_file.write_text("-----BEGIN PUBLIC KEY-----")
    public_key_file.chmod(0o644)  # secure by definition -- should not be flagged

    issues = scan_for_insecure_permissions(project_dir)
    assert len(issues) == 1
    assert issues[0].path == private_key_file


def test_venv_directory_is_skipped(project_dir):
    venv_dir = project_dir / ".venv" / "some_package"
    venv_dir.mkdir(parents=True)
    fake_key = venv_dir / "test.pem"
    fake_key.write_text("not a real secret")
    fake_key.chmod(0o644)

    issues = scan_for_insecure_permissions(project_dir)
    assert issues == []
