"""
tests/test_string_extractor.py
=================================
"""

from app.forensics.string_extractor import (
    cross_reference_iocs,
    extract_strings,
    extract_strings_from_file,
    filter_iocs,
    generate_yara_rule,
)


class TestExtractStrings:
    def test_printable_run_is_extracted(self):
        data = b"\x00\x01\x02Hello World\x00\x03"
        strings = extract_strings(data, min_length=4)
        assert "Hello World" in strings

    def test_run_shorter_than_min_length_is_dropped(self):
        data = b"\x00abc\x00"  # "abc" is only 3 chars
        strings = extract_strings(data, min_length=4)
        assert strings == []

    def test_multiple_separate_runs_are_all_found(self):
        data = b"\x00first-string\x00\x01second-string\x02"
        strings = extract_strings(data, min_length=4)
        assert "first-string" in strings
        assert "second-string" in strings

    def test_run_at_the_very_end_of_data_is_still_caught(self):
        data = b"\x00\x01trailing-text"
        strings = extract_strings(data, min_length=4)
        assert "trailing-text" in strings

    def test_pure_binary_data_produces_no_strings(self):
        data = bytes(range(0, 20))  # all non-printable control bytes
        strings = extract_strings(data, min_length=4)
        assert strings == []

    def test_extract_from_a_real_file(self, tmp_path):
        binary_path = tmp_path / "sample.bin"
        binary_path.write_bytes(b"\x00\x00PAYLOAD-MARKER\x00\x00" + bytes(50))
        strings = extract_strings_from_file(str(binary_path))
        assert "PAYLOAD-MARKER" in strings


class TestFilterIocs:
    def test_url_is_detected(self):
        indicators = filter_iocs(["visit https://malicious-c2.example/beacon for updates"])
        assert "https://malicious-c2.example/beacon" in indicators.urls

    def test_email_is_detected(self):
        indicators = filter_iocs(["contact attacker@evil-domain.example now"])
        assert "attacker@evil-domain.example" in indicators.emails

    def test_api_key_shaped_string_is_detected(self):
        indicators = filter_iocs(["AKIA1234567890ABCDEF hardcoded in binary"])
        assert any("AKIA1234567890ABCDEF" in key for key in indicators.api_keys)

    def test_ordinary_strings_produce_no_indicators(self):
        indicators = filter_iocs(["just a normal debug message", "version 1.2.3"])
        assert indicators.urls == []
        assert indicators.emails == []
        assert indicators.api_keys == []


class TestCrossReferenceIocs:
    def test_known_bad_url_is_matched(self):
        from app.forensics.string_extractor import ExtractedIndicators

        indicators = ExtractedIndicators(urls=["https://known-bad.example/c2"])
        known_iocs = {"https://known-bad.example/c2", "https://other-known-bad.example"}

        matches = cross_reference_iocs(indicators, known_iocs)

        assert matches == ["https://known-bad.example/c2"]

    def test_unknown_url_is_not_matched(self):
        from app.forensics.string_extractor import ExtractedIndicators

        indicators = ExtractedIndicators(urls=["https://totally-benign.example"])
        known_iocs = {"https://known-bad.example/c2"}

        matches = cross_reference_iocs(indicators, known_iocs)

        assert matches == []


class TestGenerateYaraRule:
    def test_rule_contains_every_extracted_string(self):
        from app.forensics.string_extractor import ExtractedIndicators

        indicators = ExtractedIndicators(
            urls=["https://c2.example"], emails=["bad@example.com"], api_keys=[]
        )

        rule = generate_yara_rule("SuspiciousBinary", indicators)

        assert "rule SuspiciousBinary" in rule
        assert "https://c2.example" in rule
        assert "bad@example.com" in rule
        assert "condition:" in rule

    def test_empty_indicators_produce_a_valid_but_unmatchable_rule(self):
        from app.forensics.string_extractor import ExtractedIndicators

        rule = generate_yara_rule("EmptyRule", ExtractedIndicators())

        assert "rule EmptyRule" in rule
        assert "false" in rule
