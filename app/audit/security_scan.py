"""
app/audit/security_scan.py
=============================

B-03: a static code scanner that parses this project's OWN source with
Python's built-in `ast` module and flags common security anti-patterns.
This is the exercise that audits everything built in every previous
phase -- it's deliberately the last piece, because it needs a real,
substantial codebase to have anything meaningful to say about.

WHY `ast` INSTEAD OF REGEX OVER THE SOURCE TEXT
-----------------------------------------------------
Regex-based scanning over raw source text is fragile: it can't reliably
tell the difference between `eval(user_input)` (a real problem) and a
variable named `evaluation`, or a string literal that happens to contain
the text "eval(" inside a comment or a docstring. Parsing the actual
Abstract Syntax Tree means every check operates on real, structural facts
-- "is this AST node actually a Call to the built-in function named
`eval`" -- not surface text pattern matching that can be fooled by
formatting or coincidental text.

WHY `app/insecure/` IS DELIBERATELY EXCLUDED FROM SCANNING
------------------------------------------------------------------
`app/insecure/sql_injection_demo.py` (Week 1-2) is INTENTIONALLY
vulnerable, on purpose, as a teaching artifact -- scanning it would
"find" the exact vulnerability it exists to demonstrate, which isn't a
real finding, it's the whole point of the file. Excluding it explicitly,
with this documented reason, is the correct choice -- not a coverage gap
being quietly swept under the rug. Any real deployment scanner would need
the same kind of explicit, justified exclusion list for genuinely
intentional exceptions, rather than either scanning blindly or silently
skipping things with no record of why.
"""

import ast
from dataclasses import dataclass
from pathlib import Path

# Paths (relative to the scan root) excluded from scanning, each with a
# concrete reason -- see the module docstring for the app/insecure/ case.
DEFAULT_EXCLUDED_PATHS = {"insecure"}

SUSPICIOUS_SECRET_VARIABLE_NAMES = {
    "password", "passwd", "secret", "api_key", "apikey", "access_key",
    "private_key", "secret_key", "auth_token",
}

# Values that look like placeholders, not real secrets -- excluded so the
# scanner doesn't flag its own documentation/example code.
PLACEHOLDER_VALUE_PREFIXES = ("change-me", "your-", "example", "placeholder", "xxx", "todo")

WEAK_HASH_ALGORITHMS = {"md5", "sha1"}


@dataclass
class Finding:
    rule_id: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    message: str
    file_path: str
    line: int


class _SecurityVisitor(ast.NodeVisitor):
    """
    Single-pass AST visitor collecting every finding in one file. Each
    `visit_*` method corresponds to one category of AST node this scanner
    cares about -- `ast.NodeVisitor` calls the matching method
    automatically as it walks the tree.
    """

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings: list[Finding] = []

    def visit_Call(self, node: ast.Call) -> None:
        self._check_unsafe_eval_exec(node)
        self._check_weak_hash(node)
        self._check_debug_true_kwarg(node)
        self.generic_visit(node)  # continue walking into this call's arguments, etc.

    def visit_Assign(self, node: ast.Assign) -> None:
        self._check_hardcoded_secret(node)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self._check_bare_except(node)
        self.generic_visit(node)

    def _add(self, rule_id: str, severity: str, message: str, line: int) -> None:
        self.findings.append(
            Finding(rule_id=rule_id, severity=severity, message=message, file_path=self.file_path, line=line)
        )

    def _check_unsafe_eval_exec(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            self._add(
                rule_id="unsafe-eval-exec",
                severity="CRITICAL",
                message=f"Use of '{node.func.id}()' can execute arbitrary code -- avoid entirely.",
                line=node.lineno,
            )

    def _check_weak_hash(self, node: ast.Call) -> None:
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in WEAK_HASH_ALGORITHMS
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "hashlib"
        ):
            self._add(
                rule_id="weak-hash-algorithm",
                severity="HIGH",
                message=f"hashlib.{node.func.attr}() is cryptographically weak -- use bcrypt/argon2 for passwords, SHA-256+ otherwise.",
                line=node.lineno,
            )

    def _check_debug_true_kwarg(self, node: ast.Call) -> None:
        for keyword in node.keywords:
            if keyword.arg == "debug" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                self._add(
                    rule_id="debug-mode-enabled",
                    severity="MEDIUM",
                    message="debug=True can expose stack traces and internals -- never enable in production.",
                    line=node.lineno,
                )

    def _check_hardcoded_secret(self, node: ast.Assign) -> None:
        if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
            return  # only literal strings are "hardcoded" -- os.environ.get(...) etc. are Call nodes, not Constants

        value = node.value.value
        if value.lower().startswith(PLACEHOLDER_VALUE_PREFIXES) or not value:
            return

        for target in node.targets:
            if isinstance(target, ast.Name) and target.id.lower() in SUSPICIOUS_SECRET_VARIABLE_NAMES:
                self._add(
                    rule_id="hardcoded-secret",
                    severity="CRITICAL",
                    message=f"Variable '{target.id}' is assigned a literal string -- secrets must come from environment variables or a secrets manager, never source code.",
                    line=node.lineno,
                )

    def _check_bare_except(self, node: ast.ExceptHandler) -> None:
        if node.type is None:
            self._add(
                rule_id="bare-except",
                severity="LOW",
                message="Bare 'except:' catches every exception, including ones that should propagate -- catch specific exception types.",
                line=node.lineno,
            )


def scan_file(file_path: Path) -> list[Finding]:
    source = file_path.read_text()
    tree = ast.parse(source, filename=str(file_path))
    visitor = _SecurityVisitor(file_path=str(file_path))
    visitor.visit(tree)
    return visitor.findings


def scan_directory(root: Path, excluded_paths: set[str] | None = None) -> list[Finding]:
    """
    Scans every .py file under `root`, skipping any path whose parts
    intersect `excluded_paths` (see DEFAULT_EXCLUDED_PATHS and the module
    docstring for why app/insecure/ is excluded by default).
    """
    excluded_paths = excluded_paths if excluded_paths is not None else DEFAULT_EXCLUDED_PATHS
    findings = []

    for file_path in sorted(root.rglob("*.py")):
        if any(part in excluded_paths for part in file_path.parts):
            continue
        findings.extend(scan_file(file_path))

    return findings


def has_critical_findings(findings: list[Finding]) -> bool:
    return any(f.severity == "CRITICAL" for f in findings)
