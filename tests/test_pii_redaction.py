"""
tests/test_pii_redaction.py
==============================
"""

from app.vault.pii_redaction import MaskingStrategy, redact_pii


class TestEmailRedaction:
    def test_email_is_detected_and_reported(self):
        result = redact_pii("contact me at john@example.com please")
        assert "email" in result.categories_found

    def test_full_masking_removes_email_entirely(self):
        result = redact_pii("contact me at john@example.com", MaskingStrategy.FULL)
        assert "john@example.com" not in result.redacted_text
        assert "[EMAIL_REDACTED]" in result.redacted_text

    def test_partial_masking_keeps_first_letter_and_domain(self):
        result = redact_pii("contact me at john@example.com", MaskingStrategy.PARTIAL)
        assert "john@example.com" not in result.redacted_text
        assert "j***@example.com" in result.redacted_text


class TestSsnRedaction:
    def test_ssn_is_detected_and_reported(self):
        result = redact_pii("SSN on file: 123-45-6789")
        assert "ssn" in result.categories_found

    def test_full_masking_removes_ssn_entirely(self):
        result = redact_pii("SSN on file: 123-45-6789", MaskingStrategy.FULL)
        assert "123-45-6789" not in result.redacted_text

    def test_partial_masking_keeps_last_four_digits(self):
        result = redact_pii("SSN on file: 123-45-6789", MaskingStrategy.PARTIAL)
        assert "123-45-6789" not in result.redacted_text
        assert "6789" in result.redacted_text


class TestCreditCardRedaction:
    def test_card_number_is_detected_and_reported(self):
        result = redact_pii("card 4111-1111-1111-1111 on file")
        assert "credit_card" in result.categories_found

    def test_full_masking_removes_card_entirely(self):
        result = redact_pii("card 4111-1111-1111-1111 on file", MaskingStrategy.FULL)
        assert "4111-1111-1111-1111" not in result.redacted_text

    def test_partial_masking_keeps_last_four_digits(self):
        result = redact_pii("card 4111-1111-1111-1111 on file", MaskingStrategy.PARTIAL)
        assert "1111-1111" not in result.redacted_text or result.redacted_text.count("1111") <= 1
        assert result.redacted_text.endswith("1111") or "1111" in result.redacted_text


class TestNoFalsePositives:
    def test_plain_text_with_no_pii_is_unchanged(self):
        result = redact_pii("quarterly backup of project files")
        assert result.categories_found == []
        assert result.redacted_text == "quarterly backup of project files"

    def test_empty_string_is_handled_safely(self):
        result = redact_pii("")
        assert result.redacted_text == ""
        assert result.categories_found == []

    def test_short_number_is_not_flagged_as_credit_card(self):
        result = redact_pii("invoice number 12345")
        assert "credit_card" not in result.categories_found


class TestMultiplePiiInOneString:
    def test_email_and_ssn_together_are_both_caught(self):
        result = redact_pii("Contact john@example.com, SSN 123-45-6789", MaskingStrategy.FULL)
        assert "email" in result.categories_found
        assert "ssn" in result.categories_found
        assert "john@example.com" not in result.redacted_text
        assert "123-45-6789" not in result.redacted_text
