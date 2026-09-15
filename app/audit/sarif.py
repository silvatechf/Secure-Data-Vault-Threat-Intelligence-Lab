"""
app/audit/sarif.py
=====================

Converts this scanner's findings into SARIF (Static Analysis Results
Interchange Format) -- the standard JSON format most CI security
dashboards (GitHub code scanning, Azure DevOps, many SIEM integrations)
expect a static analysis tool to emit. Producing SARIF, rather than a
project-specific JSON shape, means these results could be uploaded
directly to GitHub's code scanning UI or similar tooling with no
translation step.

This is a genuinely simplified SARIF document -- real SARIF supports
much more (rule metadata, fingerprints for result de-duplication across
runs, code flow graphs). This implementation covers the core, valid
structure needed to represent "which rule fired, where, how severe" --
the part of the spec that actually matters for a result to be usable by
a SARIF-consuming tool.
"""

from app.audit.security_scan import Finding

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# SARIF's "level" field only accepts these four values -- our own
# CRITICAL/HIGH/MEDIUM/LOW severities are mapped onto them.
_SEVERITY_TO_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def findings_to_sarif(findings: list[Finding], tool_name: str = "SecureDataVaultScanner") -> dict:
    results = []
    for finding in findings:
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning"),
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file_path},
                            "region": {"startLine": finding.line},
                        }
                    }
                ],
                # Not part of the SARIF spec's required fields -- kept as
                # an extra property so our own severity scale survives
                # the round-trip for anything that wants it, without
                # breaking SARIF validity (SARIF permits extra properties).
                "properties": {"severity": finding.severity},
            }
        )

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {"driver": {"name": tool_name, "informationUri": "", "rules": _build_rule_metadata(findings)}},
                "results": results,
            }
        ],
    }


def _build_rule_metadata(findings: list[Finding]) -> list[dict]:
    """SARIF wants every ruleId that appears in results to also be declared once in the tool's rules list."""
    seen_rule_ids = {}
    for finding in findings:
        if finding.rule_id not in seen_rule_ids:
            seen_rule_ids[finding.rule_id] = {"id": finding.rule_id, "name": finding.rule_id}
    return list(seen_rule_ids.values())
