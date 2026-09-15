"""
app/forensics/string_extractor.py
====================================

EX-13: a forensics utility that mimics the classic Unix `strings` command
-- extracts printable text from a binary file (or memory dump) -- then
filters that output for things forensically interesting: URLs, emails,
and API-key-shaped tokens. Finishes with basic IoC (Indicator of
Compromise) cross-referencing and a simplified YARA-style rule generator.

WHY THIS TECHNIQUE WORKS ON BINARY DATA AT ALL
--------------------------------------------------
Executables, memory dumps, and other binary files are mostly
non-printable machine code and data structures -- but they very often
contain embedded plaintext: hardcoded URLs, error messages, configuration
strings, credentials someone forgot were in there. `strings` (and this
module) scans byte-by-byte for runs of printable ASCII characters at
least N characters long and reports each run as a candidate string,
without needing to understand the file's format at all. This is exactly
the technique real malware analysts use as a first pass on an unknown
binary, before any deeper reverse engineering.
"""

import re
from dataclasses import dataclass, field

MIN_STRING_LENGTH = 4

# Printable ASCII range, matching what `strings` considers printable.
_PRINTABLE_BYTE_RANGE = set(range(0x20, 0x7F)) | {0x09}  # 0x09 = tab

URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")
EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")

# API keys vary wildly by provider, but many share a recognizable shape:
# a long run of mixed-case letters and digits, often with a vendor
# prefix. This pattern is intentionally broad -- catching some
# false positives is the correct trade-off for a forensics triage tool,
# where missing a real key is much worse than flagging a few extra
# candidate strings for a human to glance at and dismiss.
API_KEY_PATTERN = re.compile(
    r"\b(?:sk|pk|key|token|api|AKIA)[-_A-Za-z0-9]{16,}\b", re.IGNORECASE
)


@dataclass
class ExtractedIndicators:
    urls: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    api_keys: list[str] = field(default_factory=list)


def extract_strings(data: bytes, min_length: int = MIN_STRING_LENGTH) -> list[str]:
    """
    Scans raw bytes for runs of printable characters at least
    `min_length` long -- the core `strings`-equivalent behavior. Works on
    a bytes object directly so it can be used on file contents, memory
    dump contents, or any other binary blob without caring about the
    source.
    """
    strings_found = []
    current_run = bytearray()

    for byte in data:
        if byte in _PRINTABLE_BYTE_RANGE:
            current_run.append(byte)
        else:
            if len(current_run) >= min_length:
                strings_found.append(current_run.decode("ascii"))
            current_run = bytearray()

    # Catch a run that extends to the very end of the data.
    if len(current_run) >= min_length:
        strings_found.append(current_run.decode("ascii"))

    return strings_found


def extract_strings_from_file(file_path: str, min_length: int = MIN_STRING_LENGTH) -> list[str]:
    with open(file_path, "rb") as f:
        return extract_strings(f.read(), min_length=min_length)


def filter_iocs(strings: list[str]) -> ExtractedIndicators:
    """
    Runs the three IoC patterns against every extracted string and
    buckets the matches. A single string could theoretically match more
    than one category (unlikely in practice given the patterns' shapes),
    and is added to every category it matches -- no ranking or
    single-category assumption is made.
    """
    indicators = ExtractedIndicators()

    for text in strings:
        indicators.urls.extend(URL_PATTERN.findall(text))
        indicators.emails.extend(EMAIL_PATTERN.findall(text))
        indicators.api_keys.extend(API_KEY_PATTERN.findall(text))

    return indicators


def cross_reference_iocs(indicators: ExtractedIndicators, known_iocs: set[str]) -> list[str]:
    """
    Checks extracted indicators against a set of already-known-bad values
    (e.g. a threat intel feed, or values already in this project's
    threat_intel table). Returns whichever extracted values are also
    present in `known_iocs` -- a real, if simple, match against known
    threat data rather than just "this file contains SOME urls/emails."
    """
    all_extracted = set(indicators.urls) | set(indicators.emails) | set(indicators.api_keys)
    return sorted(all_extracted & known_iocs)


def generate_yara_rule(rule_name: str, indicators: ExtractedIndicators) -> str:
    """
    Produces a simplified YARA-style rule matching on the extracted
    strings -- not a fully spec-compliant YARA rule (real YARA supports
    hex patterns, regex, conditions far beyond "contains any of these
    strings"), but the same basic shape: name a rule, list string
    patterns, require at least one match. Good enough to hand to an
    analyst as a documented starting point, not a drop-in production
    detection rule.
    """
    all_strings = indicators.urls + indicators.emails + indicators.api_keys
    if not all_strings:
        return f'rule {rule_name}\n{{\n    condition:\n        false  // no indicators extracted\n}}'

    string_defs = "\n".join(
        f'    $s{i} = "{value}"' for i, value in enumerate(all_strings)
    )
    condition = " or ".join(f"$s{i}" for i in range(len(all_strings)))

    return (
        f"rule {rule_name}\n"
        f"{{\n"
        f"    strings:\n"
        f"{string_defs}\n"
        f"    condition:\n"
        f"        {condition}\n"
        f"}}"
    )
