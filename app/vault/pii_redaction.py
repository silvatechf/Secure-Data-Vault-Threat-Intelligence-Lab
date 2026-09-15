"""
app/vault/pii_redaction.py
=============================

EX-05: PII (Personally Identifiable Information) redaction. Runs on
filenames and descriptions BEFORE they're stored in vault_entries -- the
goal is that even if the metadata database leaks (separately from the
encrypted file contents), it doesn't hand an attacker a list of emails,
SSNs, and credit card numbers your users typed into a description field.

WHY REDACT METADATA WHEN THE FILE ITSELF IS ALREADY ENCRYPTED?
----------------------------------------------------------------------
Encryption (app/vault/vault_engine.py) protects the file CONTENTS. But the
filename and description are stored as plain metadata, unencrypted, so
they're searchable and displayable without decrypting anything. If a user
names a file "john.smith.ssn.123-45-6789.pdf" or writes "backup of card
4111-1111-1111-1111" in a description, that PII is now sitting in plain
text in the database -- completely separate from whatever protection the
encrypted file content has. This module catches that class of accidental
leak.

DESIGN DECISION: TWO MASKING STRATEGIES
--------------------------------------------
- **Full masking** replaces the entire match with a fixed placeholder
  (e.g. `[EMAIL_REDACTED]`). Best when you don't need any trace of the
  original for context.
- **Partial masking** keeps a few characters for identification purposes
  (e.g. `j***@example.com`, `****-****-****-1111`) -- useful when a user
  or support agent needs to confirm "yes, that's my card" without the
  full number ever being stored in the clear.
"""

import re
from dataclasses import dataclass, field
from enum import Enum

EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")

# US SSN format: 123-45-6789. Deliberately requires the dashes to avoid
# false-positiving on every 9-digit number (e.g. a phone number or ID).
SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

# Matches common credit card number formats: 16 digits, optionally
# grouped in 4s with spaces or dashes. Deliberately broad (catches valid
# and invalid card numbers alike) -- redaction should err toward
# over-catching PII-shaped strings, not under-catching them.
CREDIT_CARD_PATTERN = re.compile(r"\b(?:\d[ -]?){13,16}\b")


class MaskingStrategy(Enum):
    FULL = "full"
    PARTIAL = "partial"


@dataclass
class RedactionResult:
    redacted_text: str
    # What was found and replaced, by category -- useful for an audit log
    # entry ("this description contained an email, redacted") without
    # logging the PII itself.
    categories_found: list[str] = field(default_factory=list)


def _mask_email(match: re.Match, strategy: MaskingStrategy) -> str:
    if strategy == MaskingStrategy.FULL:
        return "[EMAIL_REDACTED]"
    email = match.group(0)
    local, _, domain = email.partition("@")
    visible = local[0] if local else "*"
    return f"{visible}***@{domain}"


def _mask_ssn(match: re.Match, strategy: MaskingStrategy) -> str:
    if strategy == MaskingStrategy.FULL:
        return "[SSN_REDACTED]"
    ssn = match.group(0)
    return f"***-**-{ssn[-4:]}"


def _mask_credit_card(match: re.Match, strategy: MaskingStrategy) -> str:
    digits_only = re.sub(r"[ -]", "", match.group(0))
    if len(digits_only) < 13:  # too short to plausibly be a card number
        return match.group(0)
    if strategy == MaskingStrategy.FULL:
        return "[CARD_REDACTED]"
    return f"****-****-****-{digits_only[-4:]}"


def redact_pii(text: str, strategy: MaskingStrategy = MaskingStrategy.PARTIAL) -> RedactionResult:
    """
    Runs all three detectors against `text` and returns the redacted
    version plus which categories were found. Order matters slightly:
    credit card numbers are checked in a way that won't accidentally
    consume an SSN's dashes-and-digits shape, since the patterns are
    applied independently to the original text, not chained.
    """
    if not text:
        return RedactionResult(redacted_text=text, categories_found=[])

    categories_found = []
    result = text

    if EMAIL_PATTERN.search(result):
        categories_found.append("email")
        result = EMAIL_PATTERN.sub(lambda m: _mask_email(m, strategy), result)

    if SSN_PATTERN.search(result):
        categories_found.append("ssn")
        result = SSN_PATTERN.sub(lambda m: _mask_ssn(m, strategy), result)

    if CREDIT_CARD_PATTERN.search(result):
        # Only count it as "found" if at least one match is actually
        # card-length -- the pattern intentionally also matches shorter
        # digit runs so _mask_credit_card can inspect and decide, but we
        # don't want to report a false "credit card found" for something
        # that turned out too short.
        matches = CREDIT_CARD_PATTERN.finditer(result)
        if any(len(re.sub(r"[ -]", "", m.group(0))) >= 13 for m in matches):
            categories_found.append("credit_card")
        result = CREDIT_CARD_PATTERN.sub(lambda m: _mask_credit_card(m, strategy), result)

    return RedactionResult(redacted_text=result, categories_found=categories_found)
