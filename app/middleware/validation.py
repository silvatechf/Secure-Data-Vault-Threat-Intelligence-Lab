"""
app/middleware/validation.py
==============================

EX-01: Input validation -- the first line of defense, and the one most
tutorials skip or half-do.

WHY VALIDATE INPUT AT ALL, WHEN THE DATABASE LAYER IS ALREADY SAFE?
------------------------------------------------------------------------
Parameterized queries (see app/insecure/README.md) stop SQL injection, but
they don't stop a user registering with the email "not-an-email" or a
username containing null bytes that break a downstream log parser.
Validation and parameterization solve DIFFERENT problems: validation is
about DATA QUALITY AND INTENT ("is this a real email?"), parameterization
is about EXECUTION SAFETY ("can this string execute as code?"). A secure
system needs both -- one without the other still leaves a real gap.

DESIGN DECISION: RETURN DETAILED ERRORS, BUT NEVER LEAK INTERNALS
-----------------------------------------------------------------------
"Detailed" here means "tells the USER what's wrong with THEIR input"
(e.g. "password must contain a number"), not "tells an attacker something
useful about the system" (e.g. a stack trace, a SQL error, a file path).
This module's errors are entirely about the shape of the input, never
about what the backend did with it.
"""

import re
from dataclasses import dataclass

# --- Patterns -----------------------------------------------------------
# Deliberately conservative (not the "one true regex" some blog posts
# claim exists for RFC 5322 emails -- that regex is famously enormous
# and still wrong at the edges). This catches the overwhelming majority
# of real mistakes and obvious junk input without trying to be a full
# email-format validator.
EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

# Usernames: letters, numbers, underscore, hyphen, 3-30 chars. No spaces,
# no special characters that could cause issues if a username ever ends
# up in a URL, filename, or log line.
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{3,30}$")


@dataclass
class ValidationResult:
    """
    The result of validating one field. `is_valid=False` always comes with
    a human-readable `error` -- callers should never have to guess why
    something failed.
    """

    is_valid: bool
    error: str | None = None


def validate_email(email: str) -> ValidationResult:
    if not email or len(email) > 255:
        return ValidationResult(False, "Email is required and must be under 255 characters.")
    if not EMAIL_PATTERN.match(email):
        return ValidationResult(False, "Email format looks invalid (expected something like name@example.com).")
    return ValidationResult(True)


def validate_username(username: str) -> ValidationResult:
    if not username:
        return ValidationResult(False, "Username is required.")
    if not USERNAME_PATTERN.match(username):
        return ValidationResult(
            False,
            "Username must be 3-30 characters: letters, numbers, underscore, or hyphen only.",
        )
    return ValidationResult(True)


def validate_password(password: str) -> ValidationResult:
    """
    Checks password STRENGTH REQUIREMENTS, not correctness -- this runs at
    registration, before hashing. It never runs at login (a login
    endpoint should never reveal WHY a password is "wrong"; that's a
    minor information leak that helps an attacker enumerate valid
    accounts by process of elimination).
    """
    if not password or len(password) < 10:
        return ValidationResult(False, "Password must be at least 10 characters long.")
    if not re.search(r"[A-Z]", password):
        return ValidationResult(False, "Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        return ValidationResult(False, "Password must contain at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        return ValidationResult(False, "Password must contain at least one number.")
    if not re.search(r"[^A-Za-z0-9]", password):
        return ValidationResult(False, "Password must contain at least one special character.")
    return ValidationResult(True)


def validate_registration_input(username: str, email: str, password: str) -> list[str]:
    """
    Runs all three checks and collects every error, rather than stopping
    at the first failure -- a user fixing one problem only to hit another
    on the next submit is a bad experience this avoids on purpose.
    """
    errors = []
    for result in (
        validate_username(username),
        validate_email(email),
        validate_password(password),
    ):
        if not result.is_valid:
            errors.append(result.error)
    return errors
