"""
tests/test_messenger_cli.py
==============================

Tests the CLI layer (app/cli/messenger.py) directly by calling its
command functions -- not via subprocess, since that would need real
terminal input for getpass(). Each test uses monkeypatch to supply a
passphrase without needing an actual TTY.
"""

import json

import pytest

from app.cli import messenger


@pytest.fixture(autouse=True)
def isolated_keys_dir(tmp_path, monkeypatch):
    """Every test gets its own throwaway keys/messenger/ directory -- never the real project's keys/ folder."""
    monkeypatch.setattr(messenger, "KEYS_DIR", tmp_path / "messenger")


class TestKeygen:
    def test_keygen_creates_both_key_files(self, monkeypatch):
        monkeypatch.setattr("getpass.getpass", lambda prompt: "alice-passphrase")
        messenger.cmd_keygen("alice")

        assert messenger._private_key_path("alice").exists()
        assert messenger._public_key_path("alice").exists()

    def test_private_key_file_is_not_world_readable(self, monkeypatch):
        import stat

        monkeypatch.setattr("getpass.getpass", lambda prompt: "alice-passphrase")
        messenger.cmd_keygen("alice")

        mode = stat.S_IMODE(messenger._private_key_path("alice").stat().st_mode)
        assert mode & 0o077 == 0  # no group/other access


class TestSendAndReceive:
    def _keygen(self, username, passphrase, monkeypatch):
        monkeypatch.setattr("getpass.getpass", lambda prompt: passphrase)
        messenger.cmd_keygen(username)

    def test_full_round_trip(self, tmp_path, monkeypatch, capsys):
        self._keygen("alice", "alice-pass", monkeypatch)
        self._keygen("bob", "bob-pass", monkeypatch)

        out_path = str(tmp_path / "msg.json")
        monkeypatch.setattr("getpass.getpass", lambda prompt: "alice-pass")
        messenger.cmd_send("alice", "bob", "the secret plan", out_path)

        monkeypatch.setattr("getpass.getpass", lambda prompt: "bob-pass")
        messenger.cmd_receive("bob", out_path)

        captured = capsys.readouterr()
        assert "the secret plan" in captured.out
        assert "signature verified" in captured.out

    def test_message_file_contains_no_plaintext(self, tmp_path, monkeypatch):
        self._keygen("alice", "alice-pass", monkeypatch)
        self._keygen("bob", "bob-pass", monkeypatch)

        out_path = str(tmp_path / "msg.json")
        monkeypatch.setattr("getpass.getpass", lambda prompt: "alice-pass")
        messenger.cmd_send("alice", "bob", "a very identifiable secret phrase", out_path)

        raw_file_contents = (tmp_path / "msg.json").read_text()
        assert "a very identifiable secret phrase" not in raw_file_contents

        # sanity: it IS valid JSON with the expected shape
        parsed = json.loads(raw_file_contents)
        assert parsed["sender"] == "alice"
        assert "ciphertext" in parsed
        assert "signature" in parsed

    def test_wrong_passphrase_exits_cleanly_instead_of_crashing(self, tmp_path, monkeypatch):
        """
        REGRESSION TEST: found by manually running the CLI end to end with
        a wrong passphrase -- the original version let a raw ValueError
        traceback escape instead of a clean error message and exit code.
        """
        self._keygen("alice", "alice-pass", monkeypatch)
        self._keygen("bob", "bob-pass", monkeypatch)

        out_path = str(tmp_path / "msg.json")
        monkeypatch.setattr("getpass.getpass", lambda prompt: "alice-pass")
        messenger.cmd_send("alice", "bob", "test message", out_path)

        monkeypatch.setattr("getpass.getpass", lambda prompt: "definitely-wrong-passphrase")
        with pytest.raises(SystemExit) as exc_info:
            messenger.cmd_receive("bob", out_path)

        assert exc_info.value.code == 1  # a clean, deliberate exit -- not an unhandled crash

    def test_receiving_with_unknown_sender_key_exits_cleanly(self, tmp_path, monkeypatch):
        self._keygen("bob", "bob-pass", monkeypatch)

        fake_message_path = tmp_path / "msg.json"
        fake_message_path.write_text(
            json.dumps({"sender": "nobody-registered", "ciphertext": "00", "signature": "00"})
        )

        with pytest.raises(SystemExit) as exc_info:
            messenger.cmd_receive("bob", str(fake_message_path))

        assert exc_info.value.code == 1
