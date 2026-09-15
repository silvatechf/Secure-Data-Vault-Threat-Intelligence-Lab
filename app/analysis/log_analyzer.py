"""
app/analysis/log_analyzer.py
===============================

EX-10: a small, SIEM-style log analyzer. Reads the structured access log
(app/middleware/access_log.py) and detects four specific patterns, each
scored with a severity, then produces one JSON report -- the same shape a
real SIEM alert feed uses.

WHY THESE FOUR PATTERNS SPECIFICALLY
------------------------------------------
Each one maps to a genuinely common, genuinely detectable attack
technique, using only what's available in a request log (no payload
inspection needed for three of the four -- that's the honeypot's job):

1. **Brute force**: 5+ failed logins (401s) from the same IP within 60
   seconds is a strong, simple signal -- legitimate users mistype a
   password once or twice, not five times in a minute.
2. **Suspicious user agents**: known scanner/tool signatures (sqlmap,
   nikto, nmap) or a missing user agent entirely -- real browsers always
   send one; most casual scanning tools either announce themselves or
   send nothing.
3. **Directory traversal**: `../` or `/etc/passwd`-style paths hitting
   the REAL application (not the honeypot) -- this is the same LFI
   signature the honeypot classifier looks for, applied here to normal
   traffic, because an LFI attempt against the real app is far more
   serious than one against a decoy.
4. **Traffic spikes**: an unusually high request volume from a single IP
   in a short window -- could be a DoS attempt, an aggressive scraper, or
   a misbehaving client; severity is lower than the other three because
   this pattern has more legitimate explanations.
"""

import json
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    finding_type: str
    severity: Severity
    source_ip: str
    details: str
    evidence_count: int


@dataclass
class SecurityReport:
    generated_at: str
    total_log_entries: int
    findings: list[Finding] = field(default_factory=list)

    def to_json(self) -> str:
        report_dict = asdict(self)
        # asdict() turns the Severity enum into its .value automatically
        # via the dataclass's str-Enum base, but is made explicit here for
        # clarity rather than relying on that implicitly.
        for finding in report_dict["findings"]:
            finding["severity"] = Severity(finding["severity"]).value
        return json.dumps(report_dict, indent=2)


BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_SECONDS = 60

TRAFFIC_SPIKE_THRESHOLD = 50
TRAFFIC_SPIKE_WINDOW_SECONDS = 60

SUSPICIOUS_USER_AGENT_PATTERNS = [
    re.compile(r"sqlmap", re.IGNORECASE),
    re.compile(r"nikto", re.IGNORECASE),
    re.compile(r"nmap", re.IGNORECASE),
    re.compile(r"masscan", re.IGNORECASE),
    re.compile(r"^\s*$"),  # empty user agent
]

DIRECTORY_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./"),
    re.compile(r"/etc/passwd"),
    re.compile(r"\.\.%2f", re.IGNORECASE),  # URL-encoded ../
]


def load_log_entries(log_path: Path) -> list[dict]:
    """Reads the JSON-lines access log. Skips any line that fails to parse rather than crashing the whole analysis run."""
    if not log_path.exists():
        return []

    entries = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def _parse_timestamp(entry: dict) -> datetime:
    return datetime.fromisoformat(entry["timestamp"])


def detect_brute_force(entries: list[dict]) -> list[Finding]:
    findings = []
    failed_logins_by_ip = defaultdict(list)

    for entry in entries:
        if entry.get("status_code") == 401:
            failed_logins_by_ip[entry["ip"]].append(_parse_timestamp(entry))

    for ip, timestamps in failed_logins_by_ip.items():
        timestamps.sort()
        for i in range(len(timestamps) - BRUTE_FORCE_THRESHOLD + 1):
            window_start = timestamps[i]
            window_end = timestamps[i + BRUTE_FORCE_THRESHOLD - 1]
            if (window_end - window_start) <= timedelta(seconds=BRUTE_FORCE_WINDOW_SECONDS):
                findings.append(
                    Finding(
                        finding_type="brute_force",
                        severity=Severity.HIGH,
                        source_ip=ip,
                        details=(
                            f"{BRUTE_FORCE_THRESHOLD}+ failed login attempts within "
                            f"{BRUTE_FORCE_WINDOW_SECONDS}s"
                        ),
                        evidence_count=len(timestamps),
                    )
                )
                break  # one finding per IP is enough, don't duplicate for every sliding position

    return findings


def detect_suspicious_user_agents(entries: list[dict]) -> list[Finding]:
    findings = []
    flagged_by_ip = defaultdict(list)

    for entry in entries:
        user_agent = entry.get("user_agent", "")
        for pattern in SUSPICIOUS_USER_AGENT_PATTERNS:
            if pattern.search(user_agent):
                flagged_by_ip[entry["ip"]].append(user_agent)
                break

    for ip, agents in flagged_by_ip.items():
        findings.append(
            Finding(
                finding_type="suspicious_user_agent",
                severity=Severity.MEDIUM,
                source_ip=ip,
                details=f"Requests with known scanner/empty user agent (e.g. '{agents[0]}')",
                evidence_count=len(agents),
            )
        )

    return findings


def detect_directory_traversal(entries: list[dict]) -> list[Finding]:
    findings = []
    flagged_by_ip = defaultdict(int)

    for entry in entries:
        path = entry.get("path", "")
        if any(pattern.search(path) for pattern in DIRECTORY_TRAVERSAL_PATTERNS):
            flagged_by_ip[entry["ip"]] += 1

    for ip, count in flagged_by_ip.items():
        findings.append(
            Finding(
                finding_type="directory_traversal",
                severity=Severity.CRITICAL,
                source_ip=ip,
                details="Path traversal / LFI pattern detected against the real application",
                evidence_count=count,
            )
        )

    return findings


def detect_traffic_spikes(entries: list[dict]) -> list[Finding]:
    findings = []
    requests_by_ip = defaultdict(list)

    for entry in entries:
        requests_by_ip[entry["ip"]].append(_parse_timestamp(entry))

    for ip, timestamps in requests_by_ip.items():
        timestamps.sort()
        for i in range(len(timestamps) - TRAFFIC_SPIKE_THRESHOLD + 1):
            window_start = timestamps[i]
            window_end = timestamps[i + TRAFFIC_SPIKE_THRESHOLD - 1]
            if (window_end - window_start) <= timedelta(seconds=TRAFFIC_SPIKE_WINDOW_SECONDS):
                findings.append(
                    Finding(
                        finding_type="traffic_spike",
                        severity=Severity.LOW,
                        source_ip=ip,
                        details=(
                            f"{TRAFFIC_SPIKE_THRESHOLD}+ requests within "
                            f"{TRAFFIC_SPIKE_WINDOW_SECONDS}s"
                        ),
                        evidence_count=len(timestamps),
                    )
                )
                break

    return findings


def analyze(log_path: Path) -> SecurityReport:
    entries = load_log_entries(log_path)

    findings = []
    findings.extend(detect_brute_force(entries))
    findings.extend(detect_suspicious_user_agents(entries))
    findings.extend(detect_directory_traversal(entries))
    findings.extend(detect_traffic_spikes(entries))

    return SecurityReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        total_log_entries=len(entries),
        findings=findings,
    )
