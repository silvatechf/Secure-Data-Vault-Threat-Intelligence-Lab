"""
app/honeypot/classifier.py
=============================

Classifies a request's path/headers/body as a probable attack type, with a
confidence score. Used by the honeypot server (EX-12) to decide what to
log as a genuine threat vs. background noise, and to decide when an alert
is worth sending.

WHY CLASSIFY AT ALL, INSTEAD OF JUST LOGGING EVERYTHING?
------------------------------------------------------------
A honeypot on the open internet gets hit constantly by automated scanners
-- most of it low-value noise (bots checking for default WordPress paths,
for example). Classifying WHAT KIND of attack a request looks like, and
HOW CONFIDENT that classification is, is what turns a raw request log into
actual threat intelligence: "here are 40 SQLi attempts and 3 RCE attempts
today" is useful; "here are 4,000 log lines" is not.

WHY PATTERN MATCHING, NOT A ML MODEL
------------------------------------------
The classic attack signatures below (script tags for XSS, path traversal
sequences for LFI, shell metacharacters for RCE, SQL keywords for SQLi)
catch the overwhelming majority of real-world automated attack traffic,
which tends to be unsophisticated and repetitive -- scanners reusing the
same well-known payloads across the entire internet. A full ML-based
classifier is a legitimate next step for a production system, but pattern
matching is transparent (you can always explain exactly why something was
flagged) and requires no training data -- the right starting point for a
portfolio project's threat classifier.
"""

import re
from dataclasses import dataclass
from enum import Enum


class AttackType(Enum):
    XSS = "XSS"
    LFI = "LFI"
    RCE = "RCE"
    SQLI = "SQLi"
    NONE = "none"


@dataclass
class ClassificationResult:
    attack_type: AttackType
    confidence: float  # 0.0 to 1.0
    matched_patterns: list[str]


# Each pattern is deliberately specific enough to avoid flagging ordinary
# text -- e.g. the SQLi patterns require a SQL keyword AND a quote/comment
# marker together, not just the word "select" appearing anywhere.
_XSS_PATTERNS = [
    re.compile(r"<script[\s>]", re.IGNORECASE),
    re.compile(r"on(error|load|click|mouseover)\s*=", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"<img[^>]+onerror", re.IGNORECASE),
]

_LFI_PATTERNS = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"/etc/passwd"),
    re.compile(r"php://(filter|input)", re.IGNORECASE),
    re.compile(r"\.\./+etc/", re.IGNORECASE),
]

_RCE_PATTERNS = [
    re.compile(r";\s*(cat|ls|whoami|id|uname)\b"),
    re.compile(r"\|\s*(cat|ls|whoami|id|nc|bash|sh)\b"),
    re.compile(r"\$\([^)]+\)"),  # command substitution: $(...)
    re.compile(r"`[^`]+`"),      # backtick command substitution
    re.compile(r"\b(exec|system|eval|popen)\s*\("),
]

_SQLI_PATTERNS = [
    re.compile(r"'\s*(or|and)\s*'?\d*'?\s*=\s*'?\d*", re.IGNORECASE),
    re.compile(r"\bunion\s+select\b", re.IGNORECASE),
    re.compile(r"--\s*$"),
    re.compile(r";\s*drop\s+table", re.IGNORECASE),
    re.compile(r"'\s*;\s*--"),
]

_PATTERN_GROUPS = {
    AttackType.XSS: _XSS_PATTERNS,
    AttackType.LFI: _LFI_PATTERNS,
    AttackType.RCE: _RCE_PATTERNS,
    AttackType.SQLI: _SQLI_PATTERNS,
}


def classify_request(path: str, body: str = "", headers: dict | None = None) -> ClassificationResult:
    """
    Checks the request's path and body against every attack category's
    patterns. Confidence scales with how many DISTINCT patterns matched
    within a category (a request matching 2 different SQLi signatures is
    more clearly an attack than one matching a single, more ambiguous
    pattern) -- capped at 1.0. Returns the highest-confidence category, or
    AttackType.NONE if nothing matched.
    """
    headers = headers or {}
    combined_text = " ".join([path, body, " ".join(headers.values())])

    best_result = ClassificationResult(AttackType.NONE, 0.0, [])

    for attack_type, patterns in _PATTERN_GROUPS.items():
        matched = [p.pattern for p in patterns if p.search(combined_text)]
        if not matched:
            continue

        # Each additional distinct pattern match adds confidence, capped at 1.0.
        confidence = min(1.0, 0.5 + 0.25 * len(matched))

        if confidence > best_result.confidence:
            best_result = ClassificationResult(attack_type, confidence, matched)

    return best_result
