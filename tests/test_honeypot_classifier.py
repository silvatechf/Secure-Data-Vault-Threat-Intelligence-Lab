"""
tests/test_honeypot_classifier.py
====================================
"""

from app.honeypot.classifier import AttackType, classify_request


class TestXssDetection:
    def test_script_tag_is_classified_as_xss(self):
        result = classify_request(path="/search", body="<script>alert(1)</script>")
        assert result.attack_type == AttackType.XSS

    def test_onerror_handler_is_classified_as_xss(self):
        result = classify_request(path="/comment", body='<img src=x onerror="alert(1)">')
        assert result.attack_type == AttackType.XSS

    def test_multiple_xss_patterns_increase_confidence(self):
        single = classify_request(path="/", body="<script>x</script>")
        double = classify_request(path="/", body="<script>x</script> onerror=alert(1)")
        assert double.confidence > single.confidence


class TestLfiDetection:
    def test_path_traversal_is_classified_as_lfi(self):
        result = classify_request(path="/download?file=../../../../etc/passwd")
        assert result.attack_type == AttackType.LFI

    def test_php_filter_wrapper_is_classified_as_lfi(self):
        result = classify_request(path="/page?file=php://filter/read=convert.base64-encode/resource=index.php")
        assert result.attack_type == AttackType.LFI


class TestRceDetection:
    def test_semicolon_command_chaining_is_classified_as_rce(self):
        result = classify_request(path="/ping", body="host=127.0.0.1; whoami")
        assert result.attack_type == AttackType.RCE

    def test_command_substitution_is_classified_as_rce(self):
        result = classify_request(path="/", body="name=$(cat /etc/shadow)")
        assert result.attack_type == AttackType.RCE


class TestSqliDetection:
    def test_classic_or_1_equals_1_is_classified_as_sqli(self):
        result = classify_request(path="/login", body="username=admin' OR '1'='1")
        assert result.attack_type == AttackType.SQLI

    def test_union_select_is_classified_as_sqli(self):
        result = classify_request(path="/product?id=1 UNION SELECT username,password FROM users--")
        assert result.attack_type == AttackType.SQLI


class TestNoFalsePositives:
    def test_normal_request_is_not_flagged(self):
        result = classify_request(path="/products?category=electronics&sort=price")
        assert result.attack_type == AttackType.NONE
        assert result.confidence == 0.0

    def test_normal_search_query_is_not_flagged(self):
        result = classify_request(path="/search", body="query=best coffee shops near me")
        assert result.attack_type == AttackType.NONE

    def test_headers_are_also_scanned(self):
        result = classify_request(
            path="/", body="", headers={"X-Forwarded-For": "1.1.1.1' OR '1'='1"}
        )
        assert result.attack_type == AttackType.SQLI
