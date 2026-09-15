"""
tests/test_caesar_cipher.py
==============================
"""

from app.vault.caesar_cipher import brute_force_crack, caesar_decrypt, caesar_encrypt


class TestCaesarEncryptDecrypt:
    def test_encrypt_then_decrypt_returns_original(self):
        original = "Hello World"
        encrypted = caesar_encrypt(original, shift=3)
        assert caesar_decrypt(encrypted, shift=3) == original

    def test_known_shift_produces_known_output(self):
        """The textbook example: shift 3, 'HELLO' becomes 'KHOOR'."""
        assert caesar_encrypt("HELLO", shift=3) == "KHOOR"

    def test_non_letters_pass_through_unchanged(self):
        result = caesar_encrypt("Hello, World! 123", shift=5)
        assert "," in result
        assert "!" in result
        assert "123" in result

    def test_wraps_around_the_alphabet(self):
        """'Z' shifted by 1 must wrap to 'A', not fall off the end."""
        assert caesar_encrypt("Z", shift=1) == "A"

    def test_case_is_preserved(self):
        result = caesar_encrypt("Hello", shift=3)
        assert result[0].isupper()
        assert result[1].islower()


class TestBruteForceCrack:
    def test_cracker_finds_the_correct_shift_for_english_text(self):
        """
        THE KEY PROOF: no key is provided to the cracker at all -- only
        the ciphertext. If the crack finds the right shift purely from
        letter-frequency analysis, that's the demonstration that a Caesar
        cipher provides no real protection.
        """
        plaintext = (
            "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG WHILE THE "
            "SECURITY TEAM REVIEWS THE ENCRYPTION STANDARDS DOCUMENT"
        )
        ciphertext = caesar_encrypt(plaintext, shift=11)

        result = brute_force_crack(ciphertext)

        assert result.best_shift == 11
        assert result.best_plaintext == plaintext

    def test_cracker_tries_all_25_possible_shifts(self):
        ciphertext = caesar_encrypt("SOME SECRET MESSAGE HERE TODAY", shift=7)
        result = brute_force_crack(ciphertext)
        assert len(result.all_candidates) == 25

    def test_cracker_works_regardless_of_which_shift_was_used(self):
        """Runs the crack against every possible shift value, not just one lucky case."""
        plaintext = "SECURITY THROUGH OBSCURITY IS NOT REAL SECURITY AT ALL"
        for shift in range(1, 26):
            ciphertext = caesar_encrypt(plaintext, shift=shift)
            result = brute_force_crack(ciphertext)
            assert result.best_plaintext == plaintext, f"failed to crack shift={shift}"
