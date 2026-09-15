"""
app/security/file_permissions.py
===================================

EX-03: File permission scanner -- runs on startup, before the app accepts
any traffic, and refuses to boot if it finds critical secrets exposed to
every user on the machine.

WHY THIS MATTERS ON A SHARED OR MISCONFIGURED SERVER
----------------------------------------------------------
Unix file permissions are a triplet: owner / group / others. A file mode
of 644 means "owner can read+write, group can read, OTHERS can read" --
and "others" means literally every other user account on that machine.
A `.env` file (holding your database credentials, JWT secret, API keys)
sitting at mode 644 or 664 is readable by any other user or process on a
shared host, a misconfigured container, or a compromised low-privilege
account. This has caused real breaches -- it's not a theoretical risk.

WHY ABORT INSTEAD OF JUST WARNING
--------------------------------------
A warning that scrolls past in a log nobody reads doesn't protect
anything. For files this critical (private keys, secrets), refusing to
start the application is the only guarantee the misconfiguration actually
gets fixed before the app goes live -- the same philosophy as "fail
closed, not open" that shows up throughout this project.
"""

import fnmatch
import stat
from dataclasses import dataclass
from pathlib import Path

# File patterns considered critical enough to abort startup over.
CRITICAL_PATTERNS = ["*.env", "*.pem", "*.key"]

# PUBLIC keys are meant to be world-readable -- that's the entire point of
# a public/private key pair (see app/auth/keys.py). Without this
# exclusion, this scanner would flag jwt_signing_key.pub.pem as an
# "insecure" secret and refuse to start the app every time a fresh key
# pair is generated, which is exactly what happened the first time this
# was tested end to end -- a real bug, not a hypothetical one.
PUBLIC_KEY_PATTERNS = ["*.pub.pem", "*.pub.key", "*_public.pem", "*_public.key"]

# On Unix, mode & 0o077 isolates the "group" and "other" permission bits.
# Any bits set here mean group/others have some access -- for a secret
# file, that should always be zero.
GROUP_OR_OTHER_ACCESS_MASK = 0o077


@dataclass
class PermissionIssue:
    path: Path
    mode: str  # e.g. "644" -- human-readable octal, for the error message


def _is_public_key(path: Path) -> bool:
    return any(fnmatch.fnmatch(path.name, pattern) for pattern in PUBLIC_KEY_PATTERNS)


def scan_for_insecure_permissions(root: Path) -> list[PermissionIssue]:
    """
    Walk `root` looking for files matching CRITICAL_PATTERNS that are
    readable/writable by group or others. Returns every issue found --
    doesn't stop at the first one, so a single startup run reports
    everything that needs fixing at once.
    """
    issues = []
    for pattern in CRITICAL_PATTERNS:
        for path in root.rglob(pattern):
            # Skip anything inside a virtual environment or version control
            # directory -- those aren't secrets this project manages.
            if any(part in (".venv", "venv", ".git", "node_modules") for part in path.parts):
                continue

            # Skip public keys -- see PUBLIC_KEY_PATTERNS above.
            if _is_public_key(path):
                continue

            file_mode = stat.S_IMODE(path.stat().st_mode)
            if file_mode & GROUP_OR_OTHER_ACCESS_MASK:
                issues.append(PermissionIssue(path=path, mode=oct(file_mode)[-3:]))

    return issues


def enforce_secure_permissions(root: Path) -> None:
    """
    Called once at application startup (see app/main.py). Raises
    SystemExit with a clear, actionable message if any critical file has
    insecure permissions -- this is the "abort" half of "scan and abort"
    from the project blueprint.
    """
    issues = scan_for_insecure_permissions(root)
    if not issues:
        return

    lines = [
        "STARTUP ABORTED: insecure permissions on critical file(s).",
        "The following files are readable/writable by group or others:",
    ]
    for issue in issues:
        lines.append(f"  - {issue.path} (mode {issue.mode})")
    lines.append("")
    lines.append("Fix with: chmod 600 <file>   (owner read/write only)")

    raise SystemExit("\n".join(lines))
