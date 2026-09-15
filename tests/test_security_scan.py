"""
tests/test_security_scan.py
==============================

Tests the AST scanner (app/audit/security_scan.py) against small,
synthetic source files first -- to prove each rule fires (and doesn't
false-positive) in isolation -- then, in TestSelfAudit, runs the scanner
against THIS PROJECT'S OWN REAL SOURCE CODE. That second part is the
actual point of this exercise: "does this codebase pass its own
self-audit with zero critical findings," not just "does the scanner logic
work on toy examples."
"""

from pathlib import Path

import pytest

from app.audit.sarif import findings_to_sarif
from app.audit.security_scan import (
    has_critical_findings,
    scan_directory,
    scan_file,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _write_and_scan(tmp_path, source: str, filename: str = "sample.py"):
    file_path = tmp_path / filename
    file_path.write_text(source)
    return scan_file(file_path)


class TestUnsafeEvalExec:
    def test_eval_call_is_flagged_critical(self, tmp_path):
        findings = _write_and_scan(tmp_path, "result = eval(user_input)\n")
        assert len(findings) == 1
        assert findings[0].rule_id == "unsafe-eval-exec"
        assert findings[0].severity == "CRITICAL"

    def test_exec_call_is_flagged(self, tmp_path):
        findings = _write_and_scan(tmp_path, "exec(some_code)\n")
        assert any(f.rule_id == "unsafe-eval-exec" for f in findings)

    def test_a_function_merely_named_evaluate_is_not_flagged(self, tmp_path):
        """Proves this is real AST analysis, not text matching -- 'evaluate(x)' must not trigger the eval() rule."""
        findings = _write_and_scan(tmp_path, "def evaluate(x):\n    return x\nevaluate(5)\n")
        assert findings == []


class TestWeakHash:
    def test_hashlib_md5_is_flagged(self, tmp_path):
        findings = _write_and_scan(tmp_path, "import hashlib\nh = hashlib.md5(data)\n")
        assert any(f.rule_id == "weak-hash-algorithm" for f in findings)

    def test_hashlib_sha1_is_flagged(self, tmp_path):
        findings = _write_and_scan(tmp_path, "import hashlib\nh = hashlib.sha1(data)\n")
        assert any(f.rule_id == "weak-hash-algorithm" for f in findings)

    def test_hashlib_sha256_is_not_flagged(self, tmp_path):
        findings = _write_and_scan(tmp_path, "import hashlib\nh = hashlib.sha256(data)\n")
        assert findings == []


class TestDebugModeKwarg:
    def test_debug_true_is_flagged(self, tmp_path):
        findings = _write_and_scan(tmp_path, "app.run(debug=True)\n")
        assert any(f.rule_id == "debug-mode-enabled" for f in findings)

    def test_debug_false_is_not_flagged(self, tmp_path):
        findings = _write_and_scan(tmp_path, "app.run(debug=False)\n")
        assert findings == []


class TestHardcodedSecret:
    def test_hardcoded_password_variable_is_flagged(self, tmp_path):
        findings = _write_and_scan(tmp_path, 'password = "hunter2-the-real-one"\n')
        assert any(f.rule_id == "hardcoded-secret" for f in findings)

    def test_placeholder_value_is_not_flagged(self, tmp_path):
        findings = _write_and_scan(tmp_path, 'api_key = "change-me-before-deploy"\n')
        assert findings == []

    def test_secret_loaded_from_environment_is_not_flagged(self, tmp_path):
        """Only literal string constants are 'hardcoded' -- os.environ.get(...) is a Call node, not a Constant."""
        findings = _write_and_scan(
            tmp_path, 'import os\nsecret_key = os.environ.get("SECRET_KEY")\n'
        )
        assert findings == []

    def test_ordinary_string_variable_unrelated_to_secrets_is_not_flagged(self, tmp_path):
        findings = _write_and_scan(tmp_path, 'username = "not_a_secret_name"\n')
        assert findings == []


class TestBareExcept:
    def test_bare_except_is_flagged(self, tmp_path):
        findings = _write_and_scan(tmp_path, "try:\n    pass\nexcept:\n    pass\n")
        assert any(f.rule_id == "bare-except" for f in findings)

    def test_specific_except_is_not_flagged(self, tmp_path):
        findings = _write_and_scan(tmp_path, "try:\n    pass\nexcept ValueError:\n    pass\n")
        assert findings == []


class TestScanDirectory:
    def test_scans_every_py_file_recursively(self, tmp_path):
        (tmp_path / "sub").mkdir()
        (tmp_path / "a.py").write_text("x = eval('1')\n")
        (tmp_path / "sub" / "b.py").write_text("y = eval('2')\n")

        findings = scan_directory(tmp_path)
        assert len(findings) == 2

    def test_excluded_path_is_skipped(self, tmp_path):
        (tmp_path / "insecure").mkdir()
        (tmp_path / "insecure" / "bad.py").write_text("x = eval('1')\n")
        (tmp_path / "good.py").write_text("y = 1\n")

        findings = scan_directory(tmp_path, excluded_paths={"insecure"})
        assert findings == []


class TestHasCriticalFindings:
    def test_true_when_a_critical_finding_exists(self, tmp_path):
        findings = _write_and_scan(tmp_path, "eval('x')\n")
        assert has_critical_findings(findings) is True

    def test_false_when_only_low_severity_findings_exist(self, tmp_path):
        findings = _write_and_scan(tmp_path, "try:\n    pass\nexcept:\n    pass\n")
        assert has_critical_findings(findings) is False  # bare-except is LOW, not CRITICAL


class TestSarifConversion:
    def test_findings_convert_to_valid_sarif_structure(self, tmp_path):
        findings = _write_and_scan(tmp_path, "eval('x')\n")
        sarif = findings_to_sarif(findings)

        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["results"][0]["ruleId"] == "unsafe-eval-exec"
        assert sarif["runs"][0]["results"][0]["level"] == "error"  # CRITICAL maps to "error"

    def test_every_rule_id_in_results_is_declared_in_rules(self, tmp_path):
        (tmp_path / "sample.py").write_text(
            "eval('x')\ntry:\n    pass\nexcept:\n    pass\n"
        )
        findings = scan_file(tmp_path / "sample.py")
        sarif = findings_to_sarif(findings)

        declared_rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        result_rule_ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
        assert result_rule_ids.issubset(declared_rule_ids)

    def test_empty_findings_produce_a_valid_empty_sarif_document(self):
        sarif = findings_to_sarif([])
        assert sarif["runs"][0]["results"] == []


class TestSelfAudit:
    """
    The actual point of this exercise: run the scanner against this
    project's OWN real source code (not synthetic examples) and confirm
    it passes its own bar. This is what the blueprint's checklist item
    "self-audit scanner passes with zero critical findings" actually
    means -- it must be true of the real codebase, not just demonstrable
    on toy input.
    """

    def test_project_source_has_zero_critical_findings(self):
        findings = scan_directory(PROJECT_ROOT / "app")
        critical = [f for f in findings if f.severity == "CRITICAL"]
        assert critical == [], (
            "Critical findings in real project source:\n"
            + "\n".join(f"  {f.file_path}:{f.line} [{f.rule_id}] {f.message}" for f in critical)
        )

    def test_project_source_produces_valid_sarif(self):
        """The self-audit's output must itself be usable -- i.e. convert cleanly to SARIF, not just exist as a Python list."""
        findings = scan_directory(PROJECT_ROOT / "app")
        sarif = findings_to_sarif(findings)
        assert sarif["version"] == "2.1.0"
        assert isinstance(sarif["runs"][0]["results"], list)
