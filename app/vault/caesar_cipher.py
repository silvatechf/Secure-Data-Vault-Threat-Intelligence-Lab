"""
app/vault/caesar_cipher.py
=============================

EX-02: Caesar cipher "legacy import" -- this is the ONE cipher in the
whole project that's deliberately weak, kept here purely so the "Legacy
Import" feature can read old Caesar-encrypted files. It exists to be
BROKEN, on purpose, as a teaching contrast to AES-256-GCM
(app/vault/vault_engine.py).

WHAT A CAESAR CIPHER ACTUALLY IS
-------------------------------------
Each letter is shifted a fixed number of positions in the alphabet. Shift
by 3: 'A' becomes 'D', 'B' becomes 'E', and so on, wrapping around at 'Z'.
Julius Caesar reportedly used this to send military orders -- which tells
you how old (and how broken) this "encryption" is: it's roughly 2,000
years old and can be cracked by a teenager with a pen and paper, let alone
a computer.

WHY IT'S TRIVIALLY BREAKABLE: ONLY 25 POSSIBLE KEYS
---------------------------------------------------------
A real cipher's security comes from the key space being astronomically
large -- AES-256 has 2^256 possible keys, a number so large that trying
every one is physically impossible with any conceivable amount of
computing power. A Caesar cipher has exactly 25 possible shifts (26 minus
the useless shift-by-0). A computer can try literally all of them in a
fraction of a second -- there's no "attack" required beyond brute force.

THE BRUTE-FORCE CRACKER: HOW DO YOU KNOW WHICH SHIFT IS RIGHT?
-----------------------------------------------------------------------
Trying all 25 shifts is trivial; the slightly more interesting problem is
picking which of the 25 decrypted outputs is the REAL message, without a
human reading all 25 by hand. This module scores each candidate using
English letter-frequency analysis: real English text has a very
recognizable distribution (E is the most common letter, then T, A, O...),
and the correct decryption will score closest to that expected
distribution. This is a real, simplified version of a technique that
predates modern computing.
"""

from dataclasses import dataclass

ALPHABET_SIZE = 26

# Standard English letter frequencies (%), most common first. Used to
# score how "English-like" a candidate decryption is -- this table is
# well-established and appears in cryptanalysis literature going back
# decades.
ENGLISH_LETTER_FREQUENCY = {
    "E": 12.70, "T": 9.06, "A": 8.17, "O": 7.51, "I": 6.97, "N": 6.75,
    "S": 6.33, "H": 6.09, "R": 5.99, "D": 4.25, "L": 4.03, "C": 2.78,
    "U": 2.76, "M": 2.41, "W": 2.36, "F": 2.23, "G": 2.02, "Y": 1.97,
    "P": 1.93, "B": 1.29, "V": 0.98, "K": 0.77, "J": 0.15, "X": 0.15,
    "Q": 0.10, "Z": 0.07,
}


def caesar_encrypt(plaintext: str, shift: int) -> str:
    """Shifts every letter forward by `shift` positions. Non-letters (spaces, punctuation) pass through unchanged."""
    return _shift_text(plaintext, shift)


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """Shifts every letter backward by `shift` positions -- decryption is just encryption with the negative shift."""
    return _shift_text(ciphertext, -shift)


def _shift_text(text: str, shift: int) -> str:
    result_chars = []
    for char in text:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            shifted = (ord(char) - base + shift) % ALPHABET_SIZE
            result_chars.append(chr(base + shifted))
        else:
            result_chars.append(char)
    return "".join(result_chars)


def _english_likeness_score(text: str) -> float:
    """
    Lower is better -- this is a chi-squared-style distance between the
    text's actual letter frequency and the expected English frequency
    table above. A correctly decrypted English sentence scores much lower
    than any of the 24 wrong shifts, which is what makes automatic
    cracking possible without a human reading every candidate.
    """
    letters_only = [c.upper() for c in text if c.isalpha()]
    if not letters_only:
        return float("inf")

    total = len(letters_only)
    observed_counts = {letter: 0 for letter in ENGLISH_LETTER_FREQUENCY}
    for letter in letters_only:
        if letter in observed_counts:
            observed_counts[letter] += 1

    score = 0.0
    for letter, expected_pct in ENGLISH_LETTER_FREQUENCY.items():
        observed_pct = (observed_counts[letter] / total) * 100
        score += (observed_pct - expected_pct) ** 2

    return score


@dataclass
class CrackResult:
    best_shift: int
    best_plaintext: str
    all_candidates: list[tuple[int, str, float]]  # (shift, plaintext, score) for every shift tried


def brute_force_crack(ciphertext: str) -> CrackResult:
    """
    Tries all 25 possible shifts and returns the one that scores most
    "English-like." This is the entire point of this file existing: it
    proves, mechanically, that a Caesar cipher provides no real
    protection -- no key is needed at all to recover the plaintext, just
    the ciphertext itself and a frequency table.
    """
    candidates = []
    for shift in range(1, ALPHABET_SIZE):
        candidate_plaintext = caesar_decrypt(ciphertext, shift)
        score = _english_likeness_score(candidate_plaintext)
        candidates.append((shift, candidate_plaintext, score))

    best_shift, best_plaintext, _ = min(candidates, key=lambda c: c[2])
    return CrackResult(
        best_shift=best_shift, best_plaintext=best_plaintext, all_candidates=candidates
    )
