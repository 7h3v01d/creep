"""
creep_deps.py — Phase 1: Dependency & CVE Audit
Part of Creep: Defensive Adversarial Security Scanner
Author: Leon Priest
License: Apache 2.0

Discovers requirements files and installed packages within a target project,
audits them against the OSV vulnerability database via pip-audit, and emits
Finding objects consistent with the rest of the Creep pipeline.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterator

from creep_static import Category, Finding, Severity

# ---------------------------------------------------------------------------
# Severity mapping from CVSS score → Creep Severity
# ---------------------------------------------------------------------------

def _cvss_to_severity(score: float | None) -> Severity:
    if score is None:
        return Severity.MEDIUM          # unknown score — treat as notable
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


# ---------------------------------------------------------------------------
# Locate dependency files inside target project
# ---------------------------------------------------------------------------

_REQ_PATTERNS = [
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-test.txt",
    "requirements/*.txt",
    "dev-requirements.txt",
    "test-requirements.txt",
]

_LOCK_PATTERNS = [
    "poetry.lock",
    "Pipfile.lock",
    "pdm.lock",
    "uv.lock",
]

_PROJECT_FILES = [
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Pipfile",
]


def _find_req_files(root: Path) -> list[Path]:
    found: list[Path] = []
    for pattern in _REQ_PATTERNS:
        if "*" in pattern:
            found.extend(root.glob(pattern))
        else:
            p = root / pattern
            if p.exists():
                found.append(p)
    return sorted(set(found))


def _find_lock_files(root: Path) -> list[Path]:
    found: list[Path] = []
    for name in _LOCK_PATTERNS:
        p = root / name
        if p.exists():
            found.append(p)
    return found


def _find_project_files(root: Path) -> list[Path]:
    found: list[Path] = []
    for name in _PROJECT_FILES:
        p = root / name
        if p.exists():
            found.append(p)
    return found


# ---------------------------------------------------------------------------
# Parse a requirements.txt for pinned / unpinned packages (static checks)
# ---------------------------------------------------------------------------

_REQ_LINE = re.compile(
    r"^\s*([A-Za-z0-9_\-\.]+)\s*"       # package name
    r"(==|>=|<=|~=|!=|>|<)?\s*"         # optional operator
    r"([^\s;#]*)?"                        # optional version
)


def _parse_requirements(path: Path) -> list[dict]:
    packages = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return packages

    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        m = _REQ_LINE.match(stripped)
        if m:
            packages.append({
                "name":    m.group(1),
                "op":      m.group(2) or "",
                "version": m.group(3) or "",
                "line":    lineno,
                "file":    str(path),
            })
    return packages


def _check_unpinned(packages: list[dict], rel_path: str) -> list[Finding]:
    """Flag packages without exact pinning (==)."""
    findings: list[Finding] = []
    for pkg in packages:
        if pkg["op"] != "==" or not pkg["version"]:
            findings.append(Finding(
                severity=Severity.LOW,
                category=Category.DEPENDENCY,
                target=rel_path,
                title=f"Unpinned dependency: {pkg['name']}",
                detail=(
                    f"'{pkg['name']}' is not pinned to an exact version "
                    f"('{pkg['op']}{pkg['version']}' or unversioned). "
                    "Unpinned deps can silently pull in vulnerable versions."
                ),
                evidence=f"Line {pkg['line']}: {pkg['name']}{pkg['op']}{pkg['version']}",
                line=pkg["line"],
                module="deps",
            ))
    return findings


# ---------------------------------------------------------------------------
# pip-audit runner
# ---------------------------------------------------------------------------

def _run_pip_audit(
    target: Path,
    req_files: list[Path],
    lock_files: list[Path],
    project_files: list[Path],
    timeout: int = 120,
    scan_env: bool = False,
    progress_cb=None,
) -> list[dict]:
    """
    Run pip-audit against the best available source and return raw vuln dicts.

    Preference order:
      1. requirements files (explicit, fast)
      2. lock files (--locked)
      3. pyproject.toml / setup.py project (project_path mode)
      4. current environment fallback
    """

    if not shutil.which("pip-audit"):
        if progress_cb:
            progress_cb("pip-audit not found — skipping CVE scan (pip install pip-audit)")
        return []

    def _log(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    results: list[dict] = []

    # ── Mode 1: requirements files ────────────────────────────────────
    if req_files:
        args = [sys.executable, "-m", "pip_audit", "-f", "json", "--progress-spinner", "off"]
        for rf in req_files:
            args += ["-r", str(rf)]
        _log(f"pip-audit: scanning {len(req_files)} requirements file(s)…")
        results = _invoke_pip_audit(args, timeout)
        if results is not None:
            return results

    # ── Mode 2: lock files ────────────────────────────────────────────
    if lock_files:
        args = [
            sys.executable, "-m", "pip_audit",
            "-f", "json", "--progress-spinner", "off",
            "--locked", str(target),
        ]
        _log("pip-audit: scanning lock file(s)…")
        results = _invoke_pip_audit(args, timeout)
        if results is not None:
            return results

    # ── Mode 3: project path (pyproject.toml / setup.py) ─────────────
    if project_files:
        args = [
            sys.executable, "-m", "pip_audit",
            "-f", "json", "--progress-spinner", "off",
            str(target),
        ]
        _log("pip-audit: scanning project path…")
        results = _invoke_pip_audit(args, timeout)
        if results is not None:
            return results

    # ── Mode 4: no manifests found — do NOT fall back to current env ───
    # Scanning the Creep interpreter environment instead of the target project
    # would produce misleading findings unrelated to the scanned project.
    # Use run_deps_scan(..., scan_env=True) or --scan-env CLI flag explicitly.
    if scan_env:
        _log("pip-audit: scan_env=True — scanning current interpreter environment…")
        args = [
            sys.executable, "-m", "pip_audit",
            "-f", "json", "--progress-spinner", "off",
            "-l",
        ]
        results = _invoke_pip_audit(args, timeout)
        return results or []

    _log(
        "pip-audit: no dependency manifests found in project. "
        "Pass scan_env=True to audit the current interpreter environment instead."
    )
    return []


def _invoke_pip_audit(args: list[str], timeout: int) -> list[dict] | None:
    """
    Execute pip-audit and parse JSON output.
    Returns list of vulnerability dicts, or None on error.
    """
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        # pip-audit exits non-zero when vulns are found — that's expected
        stdout = proc.stdout.strip()
        if not stdout:
            return []

        data = json.loads(stdout)
        # pip-audit JSON schema: {"dependencies": [...], "fixes": [...]}
        vulns: list[dict] = []
        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulns", []):
                vulns.append({
                    "package":     dep.get("name", "unknown"),
                    "version":     dep.get("version", "unknown"),
                    "id":          vuln.get("id", ""),
                    "aliases":     vuln.get("aliases", []),
                    "description": vuln.get("description", ""),
                    "fix_versions": vuln.get("fix_versions", []),
                })
        return vulns

    except subprocess.TimeoutExpired:
        return None
    except (json.JSONDecodeError, KeyError):
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Convert raw vuln dicts → Findings
# ---------------------------------------------------------------------------

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_CVSS_PATTERN = re.compile(r"CVSS[v\s]*(?:score)?[:\s]+([0-9]+(?:\.[0-9]+)?)", re.IGNORECASE)


def _vuln_to_finding(vuln: dict, rel_target: str) -> Finding:
    pkg      = vuln["package"]
    version  = vuln["version"]
    vid      = vuln["id"]
    aliases  = vuln.get("aliases", [])
    desc     = vuln.get("description", "No description available.")
    fixes    = vuln.get("fix_versions", [])

    # Extract CVSS score from description if present
    cvss_match = _CVSS_PATTERN.search(desc)
    cvss_score = float(cvss_match.group(1)) if cvss_match else None
    severity   = _cvss_to_severity(cvss_score)

    # Build CVE reference string
    cve_ids = [a for a in aliases if a.upper().startswith("CVE-")]
    cve_ref = ", ".join(cve_ids) if cve_ids else vid

    fix_str = f"Fix available: upgrade to {', '.join(fixes)}" if fixes else "No fix version listed."

    detail = (
        f"{pkg}=={version} has a known vulnerability ({cve_ref}). "
        f"{fix_str}"
    )
    if cvss_score is not None:
        detail += f" CVSS score: {cvss_score}."

    evidence = f"{vid}"
    if aliases:
        evidence += f" (aliases: {', '.join(aliases[:3])})"

    return Finding(
        severity=severity,
        category=Category.DEPENDENCY,
        target=rel_target,
        title=f"Vulnerable dependency: {pkg}=={version}",
        detail=detail,
        evidence=evidence,
        module="deps",
    )


# ---------------------------------------------------------------------------
# Outdated package check (via pip list --outdated)
# ---------------------------------------------------------------------------

def _check_outdated(timeout: int = 60, progress_cb=None) -> list[Finding]:
    """
    Run pip list --outdated and flag severely outdated packages (major version behind).
    This is advisory only — many outdated packages are fine, so we emit INFO.
    """
    findings: list[Finding] = []
    if progress_cb:
        progress_cb("Checking for outdated packages…")
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--outdated", "--format=json"],
            capture_output=True, text=True, timeout=timeout,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return findings

        packages = json.loads(proc.stdout)
        for pkg in packages:
            name      = pkg.get("name", "")
            current   = pkg.get("version", "")
            latest    = pkg.get("latest_version", "")

            # Only flag if major version is behind
            try:
                cur_major    = int(current.split(".")[0])
                latest_major = int(latest.split(".")[0])
                if latest_major > cur_major:
                    findings.append(Finding(
                        severity=Severity.INFO,
                        category=Category.DEPENDENCY,
                        target="environment",
                        title=f"Outdated (major version): {name}",
                        detail=(
                            f"{name} is at v{current}, latest is v{latest}. "
                            "Major version lag may indicate missing security patches."
                        ),
                        evidence=f"{name} {current} → {latest}",
                        module="deps",
                    ))
            except (ValueError, IndexError):
                pass

    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        pass

    return findings


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------

def run_deps_scan(
    target: str | Path,
    *,
    check_unpinned:  bool = True,
    check_cves:      bool = True,
    check_outdated:  bool = True,
    scan_env:        bool = False,
    timeout:         int  = 120,
    progress_cb=None,
) -> list[Finding]:
    """
    Run the full Phase 1 dependency audit on a project directory.

    Args:
        scan_env: If True and no manifests found, audit the current
                  interpreter environment. Default False — avoids reporting
                  Creep's own dependencies as project findings.

    Returns a list of Finding objects sorted by severity.
    """
    root = Path(target).resolve()
    findings: list[Finding] = []

    def _log(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    if not root.is_dir():
        findings.append(Finding(
            severity=Severity.INFO,
            category=Category.INFO,
            target=str(target),
            title="deps scan: target is not a directory",
            detail="Dependency scan requires a project root directory.",
            module="deps",
        ))
        return findings

    # ── Discover manifests ────────────────────────────────────────────
    req_files     = _find_req_files(root)
    lock_files    = _find_lock_files(root)
    project_files = _find_project_files(root)

    _log(f"Found: {len(req_files)} req file(s), "
         f"{len(lock_files)} lock file(s), "
         f"{len(project_files)} project file(s)")

    # ── Unpinned dependency check (static) ───────────────────────────
    if check_unpinned and req_files:
        for rf in req_files:
            rel = str(rf.relative_to(root))
            _log(f"Checking pinning in {rel}…")
            packages = _parse_requirements(rf)
            findings.extend(_check_unpinned(packages, rel))

    # ── CVE audit via pip-audit ───────────────────────────────────────
    if check_cves:
        vulns = _run_pip_audit(
            root, req_files, lock_files, project_files,
            timeout=timeout, scan_env=scan_env, progress_cb=progress_cb,
        )
        if vulns:
            _log(f"pip-audit: {len(vulns)} vulnerability/vulnerabilities found")
            for v in vulns:
                findings.append(_vuln_to_finding(v, str(root)))
        else:
            _log("pip-audit: no known vulnerabilities found")

    # ── Outdated packages ─────────────────────────────────────────────
    # Only run if the project has manifests — otherwise we'd be reporting
    # on the Creep interpreter environment, not the target project.
    has_manifests = bool(req_files or lock_files or project_files)
    if check_outdated and (has_manifests or scan_env):
        findings.extend(_check_outdated(timeout=60, progress_cb=progress_cb))
    elif check_outdated and not has_manifests:
        _log("Outdated check skipped — no dependency manifests found in project.")

    # Sort by severity
    findings.sort(key=lambda f: (f.severity.rank, f.target))
    return findings


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"[creep-deps] Scanning: {target}\n")

    results = run_deps_scan(
        target,
        progress_cb=lambda m: print(f"  {m}"),
    )

    print(f"\n{'─'*60}")
    print(f"  {len(results)} finding(s) found")
    print(f"{'─'*60}\n")

    for f in results:
        print(f"[{f.severity.value:<8}] {f.title}")
        print(f"           Target  : {f.target}")
        print(f"           Detail  : {f.detail}")
        if f.evidence:
            print(f"           Evidence: {f.evidence}")
        print()
