"""
creep_static.py — Phase 1: Static Analysis Scanner
Part of Creep: Defensive Adversarial Security Scanner
Author: Leon Priest
License: Apache 2.0
"""

from __future__ import annotations

import ast
import json
import os
import re
import stat
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Iterator


_IS_WINDOWS = sys.platform.startswith('win')

# ---------------------------------------------------------------------------
# Shared Finding model (used by all Creep modules)
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[self.value]

    def __lt__(self, other: "Severity") -> bool:
        return self.rank < other.rank


class Category(str, Enum):
    DANGEROUS_CALL   = "dangerous_call"
    SECRET_EXPOSURE  = "secret_exposure"
    CONFIG_EXPOSURE  = "config_exposure"
    PERMISSION       = "permission"
    DEPENDENCY       = "dependency"
    NETWORK          = "network"
    AUTH             = "auth"
    INJECTION        = "injection"
    AI_RISK          = "ai_risk"
    INFO             = "info"


@dataclass
class Finding:
    severity:  Severity
    category:  Category
    target:    str          # file path or service URL
    title:     str
    detail:    str
    evidence:  str = ""
    line:      int | None = None
    module:    str = "static"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "severity":  self.severity.value,
            "category":  self.category.value,
            "target":    self.target,
            "title":     self.title,
            "detail":    self.detail,
            "evidence":  self.evidence,
            "line":      self.line,
            "module":    self.module,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Dangerous AST patterns
# ---------------------------------------------------------------------------

# (node_type, attr_or_None, severity, title, detail)
_DANGEROUS_CALLS: list[tuple] = [
    # eval / exec
    ("eval",       None,        Severity.CRITICAL, "eval() usage",
     "eval() executes arbitrary code. If any input reaches this call, remote code execution is possible."),
    ("exec",       None,        Severity.CRITICAL, "exec() usage",
     "exec() executes arbitrary code strings. Treat as critical if input is externally influenced."),

    # pickle
    ("pickle",     "loads",     Severity.CRITICAL, "pickle.loads() — unsafe deserialisation",
     "Deserialising untrusted pickle data allows arbitrary code execution."),
    ("pickle",     "load",      Severity.HIGH,     "pickle.load() — unsafe deserialisation",
     "pickle.load() from an untrusted source enables arbitrary code execution."),

    # subprocess with shell=True
    ("subprocess", "call",      Severity.HIGH,     "subprocess.call() — review shell usage",
     "subprocess.call() with shell=True enables shell injection. Verify no user input reaches the command."),
    ("subprocess", "run",       Severity.HIGH,     "subprocess.run() — review shell usage",
     "subprocess.run() with shell=True enables shell injection."),
    ("subprocess", "Popen",     Severity.HIGH,     "subprocess.Popen() — review shell usage",
     "subprocess.Popen() with shell=True enables shell injection."),
    ("subprocess", "check_output", Severity.HIGH,  "subprocess.check_output() — review shell usage",
     "check_output() with shell=True enables shell injection."),

    # os.system / popen
    ("os",         "system",    Severity.HIGH,     "os.system() usage",
     "os.system() passes commands directly to the shell. Shell injection risk if input is unsanitised."),
    ("os",         "popen",     Severity.HIGH,     "os.popen() usage",
     "os.popen() opens a pipe to a shell command. Injection risk."),

    # yaml.load (unsafe)
    ("yaml",       "load",      Severity.HIGH,     "yaml.load() without Loader",
     "yaml.load() without an explicit safe Loader allows arbitrary Python object execution. Use yaml.safe_load()."),

    # marshal
    ("marshal",    "loads",     Severity.HIGH,     "marshal.loads() — unsafe deserialisation",
     "marshal deserialises bytecode and can execute arbitrary code."),

    # __import__ / importlib
    ("__import__", None,        Severity.MEDIUM,   "Dynamic __import__() call",
     "Dynamic imports can load unexpected modules. Verify the import source is trusted."),
    ("importlib",  "import_module", Severity.MEDIUM, "importlib.import_module() — dynamic import",
     "Dynamic module loading. Verify the module name cannot be influenced by untrusted input."),

    # tempfile with predictable names
    ("tempfile",   "mktemp",    Severity.MEDIUM,   "tempfile.mktemp() — race condition",
     "mktemp() has a TOCTOU race condition. Use mkstemp() instead."),

    # hashlib weak algorithms
    ("hashlib",    "md5",       Severity.LOW,      "MD5 usage",
     "MD5 is cryptographically broken. Use SHA-256 or better for security-sensitive hashing."),
    ("hashlib",    "sha1",      Severity.LOW,      "SHA-1 usage",
     "SHA-1 is deprecated for security use. Prefer SHA-256+."),

    # assert used for security checks
    ("assert",     None,        Severity.LOW,      "assert statement",
     "assert statements are stripped by Python optimisation (-O). Never use assert for security checks."),
]

# Modules whose mere import warrants a note
_IMPORT_FLAGS: dict[str, tuple[Severity, str, str]] = {
    "ctypes":    (Severity.MEDIUM, "ctypes imported", "ctypes allows low-level memory access. Verify usage is intentional."),
    "cffi":      (Severity.MEDIUM, "cffi imported",   "cffi provides C FFI access. Verify usage scope."),
    "pty":       (Severity.MEDIUM, "pty imported",    "pty provides pseudo-terminal access. Verify this is necessary."),
    "socket":    (Severity.INFO,   "socket imported", "Raw socket usage detected. Ensure connections are scoped and authenticated."),
    "paramiko":  (Severity.INFO,   "paramiko imported","SSH client library in use. Verify host key checking is enabled."),
    "ftplib":    (Severity.LOW,    "ftplib imported", "FTP transmits credentials in plaintext. Prefer SFTP."),
    "telnetlib": (Severity.HIGH,   "telnetlib imported","Telnet is plaintext. Should never be used in production."),
}


class _ASTVisitor(ast.NodeVisitor):
    """Walk an AST and collect dangerous-call findings."""

    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self.findings: list[Finding] = []

    # ------------------------------------------------------------------
    def _add(self, node: ast.AST, sev: Severity, title: str, detail: str,
             evidence: str = "") -> None:
        self.findings.append(Finding(
            severity=sev,
            category=Category.DANGEROUS_CALL,
            target=self.filepath,
            title=title,
            detail=detail,
            evidence=evidence,
            line=getattr(node, "lineno", None),
            module="static",
        ))

    # ------------------------------------------------------------------
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            base = alias.name.split(".")[0]
            if base in _IMPORT_FLAGS:
                sev, title, detail = _IMPORT_FLAGS[base]
                self._add(node, sev, title, detail, evidence=f"import {alias.name}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        base = (node.module or "").split(".")[0]
        if base in _IMPORT_FLAGS:
            sev, title, detail = _IMPORT_FLAGS[base]
            self._add(node, sev, title, detail,
                      evidence=f"from {node.module} import ...")
        self.generic_visit(node)

    # ------------------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        func = node.func

        # bare name: eval(...), exec(...), __import__(...)
        if isinstance(func, ast.Name):
            fname = func.id
            for (mod, attr, sev, title, detail) in _DANGEROUS_CALLS:
                if attr is None and mod == fname:
                    self._add(node, sev, title, detail, evidence=f"{fname}(...)")

        # attribute call: pickle.loads(), os.system(), subprocess.run(), ...
        elif isinstance(func, ast.Attribute):
            attr = func.attr
            mod  = ""
            if isinstance(func.value, ast.Name):
                mod = func.value.id
            elif isinstance(func.value, ast.Attribute):
                mod = func.value.attr

            for (m, a, sev, title, detail) in _DANGEROUS_CALLS:
                if a and a == attr and (m == mod or m == ""):
                    # Special case: subprocess shell=True check
                    if m == "subprocess":
                        shell_true = any(
                            isinstance(kw.value, ast.Constant) and kw.value.value is True
                            and kw.arg == "shell"
                            for kw in node.keywords
                        )
                        if not shell_true:
                            continue
                    self._add(node, sev, title, detail,
                              evidence=f"{mod}.{attr}(...)" if mod else f"{attr}(...)")

        self.generic_visit(node)

    # ------------------------------------------------------------------
    def visit_Assert(self, node: ast.Assert) -> None:
        self._add(node, Severity.LOW, "assert statement",
                  "assert statements are stripped with -O. Never use for security checks.",
                  evidence=ast.unparse(node)[:120])
        self.generic_visit(node)

    # ------------------------------------------------------------------
    def visit_Call_chmod(self, node: ast.Call) -> None:
        """Handled inline in visit_Call — flagged separately here for clarity."""
        pass

    def visit_Call_extra(self, node: ast.Call) -> None:
        pass


def _check_chmod(node: ast.Call, filepath: str) -> Finding | None:
    """Flag os.chmod calls with overly permissive modes."""
    func = node.func
    if not (isinstance(func, ast.Attribute) and func.attr == "chmod"):
        return None
    if len(node.args) < 2:
        return None
    mode_node = node.args[1]
    if not isinstance(mode_node, ast.Constant):
        return None
    mode = mode_node.value
    if isinstance(mode, int) and (mode & 0o002 or mode & 0o022):
        return Finding(
            severity=Severity.HIGH,
            category=Category.PERMISSION,
            target=filepath,
            title="Overly permissive chmod",
            detail=f"chmod mode {oct(mode)} grants write access to group/world.",
            evidence=ast.unparse(node)[:120],
            line=node.lineno,
            module="static",
        )
    return None


def _scan_ast(filepath: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError as exc:
        findings.append(Finding(
            severity=Severity.INFO,
            category=Category.INFO,
            target=filepath,
            title="SyntaxError — file skipped",
            detail=str(exc),
            module="static",
        ))
        return findings

    visitor = _ASTVisitor(filepath)
    visitor.visit(tree)
    findings.extend(visitor.findings)

    # chmod walk separately
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = _check_chmod(node, filepath)
            if f:
                findings.append(f)

    return findings


# ---------------------------------------------------------------------------
# Secret / credential regex scanner
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, re.Pattern, Severity, str]] = [
    ("AWS Access Key",
     re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"),
     Severity.CRITICAL, "AWS access key ID pattern detected"),

    ("AWS Secret Key",
     re.compile(r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key\s*[=:]\s*['\"]?([A-Za-z0-9/+]{40})['\"]?"),
     Severity.CRITICAL, "AWS secret key pattern detected"),

    ("Generic API key assignment",
     re.compile(r"(?i)(?:api[_\-]?key|apikey|api[_\-]?secret|app[_\-]?secret)\s*[=:]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]"),
     Severity.HIGH, "Hardcoded API key detected"),

    ("Password assignment",
     re.compile(r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{4,})['\"]"),
     Severity.HIGH, "Hardcoded password detected"),

    ("Token assignment",
     re.compile(r"(?i)(?:token|secret|auth[_\-]?token|access[_\-]?token|bearer)\s*[=:]\s*['\"]([A-Za-z0-9_\-\.]{16,})['\"]"),
     Severity.HIGH, "Hardcoded token detected"),

    ("Private key header",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     Severity.CRITICAL, "Private key material embedded in file"),

    ("Connection string",
     re.compile(r"(?i)(?:mongodb|postgresql|mysql|redis|amqp|sqlite)\+?://[^'\"<>\s]{8,}"),
     Severity.HIGH, "Database/service connection string with credentials"),

    ("JWT-like string",
     re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
     Severity.MEDIUM, "JWT token literal detected — do not hardcode tokens"),

    ("GitHub token",
     re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
     Severity.CRITICAL, "GitHub personal access token detected"),

    ("Slack token",
     re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
     Severity.HIGH, "Slack token detected"),

    ("Google API key",
     re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
     Severity.HIGH, "Google API key pattern detected"),

    ("IP + port credential hint",
     re.compile(r"(?i)(?:host|server|endpoint)\s*[=:]\s*['\"](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})['\"]"),
     Severity.LOW, "Hardcoded IP address — verify this is intentional"),
]


def _redact(match: str, max_len: int = 40) -> str:
    """Show first 4 chars then redact the rest."""
    if len(match) <= 4:
        return "****"
    return match[:4] + "*" * min(len(match) - 4, 12) + f"… ({len(match)} chars)"


def _scan_secrets(filepath: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.splitlines()
    for lineno, line in enumerate(lines, start=1):
        # Skip obvious comments
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        for (name, pattern, sev, title) in _SECRET_PATTERNS:
            m = pattern.search(line)
            if m:
                evidence = _redact(m.group(0))
                findings.append(Finding(
                    severity=sev,
                    category=Category.SECRET_EXPOSURE,
                    target=filepath,
                    title=title,
                    detail=f"{name} found at line {lineno}.",
                    evidence=f"Line {lineno}: …{evidence}…",
                    line=lineno,
                    module="static",
                ))
    return findings


# ---------------------------------------------------------------------------
# Config file scanner
# ---------------------------------------------------------------------------

_CONFIG_EXTENSIONS = {".env", ".cfg", ".ini", ".json", ".yaml", ".yml", ".toml", ".conf"}

_CONFIG_SECRET_KEYS = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|token|api[_\-]?key|auth|private[_\-]?key"
    r"|access[_\-]?key|client[_\-]?secret|db[_\-]?pass|database[_\-]?url)\s*[=:]"
)

_DEBUG_FLAGS = re.compile(r"(?i)(?:debug|dev_mode|development)\s*[=:]\s*(?:true|1|yes|on)")


def _scan_config_file(filepath: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        text = Path(filepath).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        stripped = line.lstrip()
        if stripped.startswith("#") or stripped.startswith(";"):
            continue

        m = _CONFIG_SECRET_KEYS.search(line)
        if m:
            # Extract value from after the matched key+separator — handles both
            # KEY=value (dotenv/ini) and KEY: value (YAML/TOML) syntax correctly
            value_part = line[m.end():].strip().strip("\"'")

            # Exempt CI/CD template expressions — runtime-injected refs, not
            # hardcoded secrets: ${{ secrets.X }}, %VAR%, ${VAR}, $(VAR), etc.
            _is_template = (
                value_part.startswith("${{")    # GitHub Actions secrets
                or value_part.startswith("${")  # shell / docker-compose env ref
                or value_part.startswith("$(")  # shell subshell ref
                or value_part.startswith("{{")  # Helm / Jinja2 template
                or value_part.startswith("!vault")   # Ansible Vault ref
                or value_part.startswith("ENC[")     # Ansible Vault inline
                or (value_part.startswith("%") and value_part.endswith("%"))  # Windows env
            )
            if value_part and not _is_template and value_part.lower() not in {
                "", "null", "none", "your_key_here", "changeme",
                "placeholder", "xxx", "<your_key>", "todo",
                "true", "false", "yes", "no", "0", "1",
            }:
                # Redact: show key name only, never the value.
                # Use the regex match start to extract just the key portion —
                # avoids showing the value for YAML (key: value) format.
                key_part = line[:m.start()].strip().rstrip(":=").strip()[:40] or line[:m.end()].strip()[:40]
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category=Category.CONFIG_EXPOSURE,
                    target=filepath,
                    title="Sensitive key in config file",
                    detail=f"Config line {lineno} appears to contain a credential or secret value.",
                    evidence=f"Line {lineno}: {key_part} = [REDACTED]",
                    line=lineno,
                    module="static",
                ))

        if _DEBUG_FLAGS.search(line):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=Category.CONFIG_EXPOSURE,
                target=filepath,
                title="Debug/development mode enabled in config",
                detail="Debug mode may expose stack traces, internal routes, or verbose error output.",
                evidence=f"Line {lineno}: {line.strip()}",
                line=lineno,
                module="static",
            ))

    # Check file permissions (world-readable config)
    # Skip on Windows: NTFS reports all files as 0o666 via os.stat(), making
    # this check produce a false positive for every single file on Windows.
    # Only meaningful on Unix/Linux where permissions are actually enforced.
    if not _IS_WINDOWS:
        try:
            mode = os.stat(filepath).st_mode
            if mode & stat.S_IROTH:
                # Only flag if the file actually looks like it contains secrets
                # (has a credential-like key). Pure device spec YAMLs with 0o666
                # are a filesystem default, not a deliberate exposure.
                if _CONFIG_SECRET_KEYS.search(open(filepath,
                        encoding="utf-8", errors="replace").read()):
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        category=Category.PERMISSION,
                        target=filepath,
                        title="Config file world-readable",
                        detail=(
                            f"File permissions {oct(mode & 0o777)} allow any user "
                            "to read this config, which contains sensitive keys."
                        ),
                        evidence=f"Mode: {oct(mode & 0o777)}",
                        module="static",
                    ))
        except OSError:
            pass

    return findings


# ---------------------------------------------------------------------------
# Top-level scanner
# ---------------------------------------------------------------------------

_PY_SKIP_DIRS = {
    ".git", "__pycache__", ".venv", "venv", "env", ".env",
    "node_modules", "dist", "build", ".tox", "site-packages",
}

# Test directories excluded when skip_tests=True (the default).
# assert statements in test files are intentional and expected — flagging them
# produces hundreds of false positives on any well-tested codebase.
_TEST_DIRS = {
    "tests", "test", "testing", "spec", "specs",
    "__tests__", "e2e", "integration",
}


def _is_test_file(fname: str) -> bool:
    return (
        fname.startswith("test_")
        or fname.endswith("_test.py")
        or fname in ("conftest.py", "fixtures.py")
    )


def _walk_python_files(root: Path, skip_tests: bool = True) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        skip = set(_PY_SKIP_DIRS)
        if skip_tests:
            skip |= _TEST_DIRS
        dirnames[:] = [d for d in dirnames if d not in skip]
        for fname in filenames:
            if not fname.endswith(".py"):
                continue
            if skip_tests and _is_test_file(fname):
                continue
            yield Path(dirpath) / fname


def _walk_config_files(root: Path, skip_tests: bool = True) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        skip = set(_PY_SKIP_DIRS)
        if skip_tests:
            skip |= _TEST_DIRS
        dirnames[:] = [d for d in dirnames if d not in skip]
        for fname in filenames:
            p = Path(fname)
            if p.suffix in _CONFIG_EXTENSIONS or p.name.startswith(".env"):
                yield Path(dirpath) / fname


def run_static_scan(
    target: str | Path,
    *,
    scan_ast:     bool = True,
    scan_secrets: bool = True,
    scan_configs: bool = True,
    skip_tests:   bool = True,
    progress_cb=None,
) -> list[Finding]:
    """
    Run the full Phase 1 static scan on a directory or single file.

    Args:
        target:       Directory or .py file to scan.
        scan_ast:     Run AST dangerous-pattern scan.
        scan_secrets: Run secret/credential regex scan.
        scan_configs: Scan config files for exposed credentials/debug flags.
        skip_tests:   If True (default), skip test directories and test_*.py
                      files. assert statements in test files are intentional
                      and produce hundreds of false positives otherwise.
        progress_cb:  Optional callable(msg: str).

    Returns a list of Finding objects sorted by severity.
    """
    root = Path(target).resolve()
    findings: list[Finding] = []

    def _log(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    if root.is_file():
        py_files    = [root] if root.suffix == ".py" else []
        cfg_files   = [root] if root.suffix in _CONFIG_EXTENSIONS else []
    else:
        py_files  = list(_walk_python_files(root, skip_tests=skip_tests))
        cfg_files = list(_walk_config_files(root, skip_tests=skip_tests))

    # ── Python files ────────────────────────────────────────────────────
    for fp in py_files:
        rel = str(fp.relative_to(root) if root.is_dir() else fp)
        _log(f"Scanning {rel}")
        try:
            source = fp.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            findings.append(Finding(
                severity=Severity.INFO, category=Category.INFO,
                target=rel, title="Could not read file", detail=str(exc),
                module="static",
            ))
            continue

        if scan_ast:
            for f in _scan_ast(str(fp), source):
                f.target = rel
                findings.append(f)
        if scan_secrets:
            for f in _scan_secrets(str(fp), source):
                f.target = rel
                findings.append(f)

    # ── Config files ────────────────────────────────────────────────────
    if scan_configs:
        for fp in cfg_files:
            rel = str(fp.relative_to(root) if root.is_dir() else fp)
            _log(f"Scanning config {rel}")
            for f in _scan_config_file(str(fp)):
                f.target = rel
                findings.append(f)

    # Sort: severity first, then target path
    findings.sort(key=lambda f: (f.severity.rank, f.target, f.line or 0))
    return findings


# ---------------------------------------------------------------------------
# CLI entry point (standalone test)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import json as _json

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"[creep-static] Scanning: {target}\n")

    results = run_static_scan(target, progress_cb=lambda m: print(f"  {m}"))

    print(f"\n{'─'*60}")
    print(f"  {len(results)} finding(s) found")
    print(f"{'─'*60}\n")

    for f in results:
        loc = f":{f.line}" if f.line else ""
        print(f"[{f.severity.value:<8}] {f.title}")
        print(f"           Target  : {f.target}{loc}")
        print(f"           Detail  : {f.detail}")
        if f.evidence:
            print(f"           Evidence: {f.evidence}")
        print()
