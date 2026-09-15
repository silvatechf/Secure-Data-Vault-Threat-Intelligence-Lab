"""
tests/test_log_analyzer.py
=============================
"""

import json
from datetime import datetime, timedelta

from app.analysis.log_analyzer import (
    Severity,
    analyze,
    detect_brute_force,
    detect_directory_traversal,
    detect_suspicious_user_agents,
    detect_traffic_spikes,
)


def _entry(ip="1.2.3.4", status=200, path="/", user_agent="Mozilla/5.0", offset_seconds=0):
    base_time = datetime(2026, 1, 1, 12, 0, 0)
    return {
        "timestamp": (base_time + timedelta(seconds=offset_seconds)).isoformat(),
        "ip": ip,
        "method": "GET",
        "path": path,
        "status_code": status,
        "user_agent": user_agent,
    }


class TestBruteForceDetection:
    def test_five_failed_logins_in_one_minute_is_flagged(self):
        entries = [_entry(status=401, offset_seconds=i * 5) for i in range(5)]
        findings = detect_brute_force(entries)
        assert len(findings) == 1
        assert findings[0].finding_type == "brute_force"
        assert findings[0].severity == Severity.HIGH

    def test_four_failed_logins_is_not_flagged(self):
        entries = [_entry(status=401, offset_seconds=i * 5) for i in range(4)]
        findings = detect_brute_force(entries)
        assert findings == []

    def test_five_failed_logins_spread_over_an_hour_is_not_flagged(self):
        """Same count, but NOT within the 60-second window -- shouldn't trigger."""
        entries = [_entry(status=401, offset_seconds=i * 900) for i in range(5)]  # 15 min apart
        findings = detect_brute_force(entries)
        assert findings == []

    def test_successful_logins_are_never_counted_as_brute_force(self):
        entries = [_entry(status=200, offset_seconds=i * 5) for i in range(10)]
        findings = detect_brute_force(entries)
        assert findings == []

    def test_different_ips_are_tracked_separately(self):
        entries = [_entry(ip="1.1.1.1", status=401, offset_seconds=i * 5) for i in range(3)] + [
            _entry(ip="2.2.2.2", status=401, offset_seconds=i * 5) for i in range(3)
        ]
        findings = detect_brute_force(entries)
        assert findings == []  # neither IP alone reached the threshold of 5


class TestSuspiciousUserAgentDetection:
    def test_sqlmap_user_agent_is_flagged(self):
        entries = [_entry(user_agent="sqlmap/1.6.12")]
        findings = detect_suspicious_user_agents(entries)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_empty_user_agent_is_flagged(self):
        entries = [_entry(user_agent="")]
        findings = detect_suspicious_user_agents(entries)
        assert len(findings) == 1

    def test_normal_browser_user_agent_is_not_flagged(self):
        entries = [_entry(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)")]
        findings = detect_suspicious_user_agents(entries)
        assert findings == []


class TestDirectoryTraversalDetection:
    def test_dot_dot_slash_is_flagged_as_critical(self):
        entries = [_entry(path="/download?file=../../etc/passwd")]
        findings = detect_directory_traversal(entries)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_normal_path_is_not_flagged(self):
        entries = [_entry(path="/products/123")]
        findings = detect_directory_traversal(entries)
        assert findings == []


class TestTrafficSpikeDetection:
    def test_fifty_requests_in_a_minute_is_flagged(self):
        entries = [_entry(offset_seconds=i) for i in range(50)]
        findings = detect_traffic_spikes(entries)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_normal_browsing_pace_is_not_flagged(self):
        entries = [_entry(offset_seconds=i * 30) for i in range(10)]  # one request every 30s
        findings = detect_traffic_spikes(entries)
        assert findings == []


class TestFullAnalysis:
    def test_analyze_reads_a_real_log_file_and_produces_valid_json(self, tmp_path):
        log_path = tmp_path / "access.log"
        entries = [_entry(status=401, offset_seconds=i * 5) for i in range(5)]
        with open(log_path, "w") as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")

        report = analyze(log_path)
        assert report.total_log_entries == 5
        assert len(report.findings) == 1

        # Must actually be valid, parseable JSON -- not just "looks like JSON".
        parsed = json.loads(report.to_json())
        assert parsed["findings"][0]["finding_type"] == "brute_force"
        assert parsed["findings"][0]["severity"] == "HIGH"

    def test_analyze_handles_a_missing_log_file_gracefully(self, tmp_path):
        report = analyze(tmp_path / "does_not_exist.log")
        assert report.total_log_entries == 0
        assert report.findings == []

    def test_analyze_skips_malformed_lines_without_crashing(self, tmp_path):
        log_path = tmp_path / "access.log"
        with open(log_path, "w") as f:
            f.write("not valid json\n")
            f.write(json.dumps(_entry()) + "\n")

        report = analyze(log_path)
        assert report.total_log_entries == 1  # only the one valid line counted
