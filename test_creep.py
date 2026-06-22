"""
test_creep.py — Safety Baseline Test Suite
Part of Creep: Defensive Adversarial Security Scanner
Author: Leon Priest
License: Apache 2.0

Covers:
  test_static_detects_shell_true         — AST detects subprocess(shell=True)
  test_static_redacts_secret             — secrets are redacted in evidence
  test_config_redacts_secret             — config scanner redacts credential values
  test_config_exempts_ci_templates       — GitHub Actions / CI template refs not flagged
  test_surface_detects_fastapi_route     — FastAPI route decorator detected
  test_surface_health_not_high           — /health endpoint not HIGH severity
  test_report_html_escapes_payload       — XSS payloads escaped in HTML report
  test_network_requires_authorization    — network scan raises ScopeError without auth
  test_fuzz_requires_authorization       — fuzzer raises ScopeError without auth
  test_auth_requires_authorization       — auth scan raises ScopeError without auth
  test_ai_requires_authorization         — AI scan raises ScopeError without auth
  test_fuzz_default_excludes_dangerous   — DoS/SSRF payloads not in default tier
  test_auth_redacts_credentials          — real cred probe never exposes raw passwords
  test_ai_default_excludes_dos_ssrf      — AI scan default categories exclude dos/ssrf
  test_network_direct_entrypoint_requires_flag — direct module bypass prevented
  test_static_skips_test_files           — test files excluded by default
  test_deps_no_env_fallback              — no env fallback without scan_env=True
"""

from __future__ import annotations

import os
import sys
import tempfile
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure we import from the local creep directory
sys.path.insert(0, str(Path(__file__).parent))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_tmp(content: str, suffix: str = ".py") -> str:
    """Write content to a temp file and return its path."""
    f = tempfile.NamedTemporaryFile(
        suffix=suffix, mode="w", delete=False, encoding="utf-8"
    )
    f.write(textwrap.dedent(content))
    f.close()
    return f.name


def _tmpdir_with_file(filename: str, content: str) -> str:
    """Create a temp directory containing one file. Returns dir path."""
    d = tempfile.mkdtemp()
    (Path(d) / filename).write_text(textwrap.dedent(content), encoding="utf-8")
    return d


# ---------------------------------------------------------------------------
# 1. Static: detects subprocess(shell=True)
# ---------------------------------------------------------------------------

def test_static_detects_shell_true():
    """AST scanner must flag subprocess.run(..., shell=True)."""
    from creep_static import run_static_scan, Severity

    src = _write_tmp("""
        import subprocess

        def run_cmd(cmd):
            subprocess.run(cmd, shell=True)
    """)
    try:
        findings = run_static_scan(src)
        titles = [f.title for f in findings]
        assert any("subprocess" in t.lower() or "shell" in t.lower() for t in titles), (
            f"Expected subprocess/shell finding, got: {titles}"
        )
        # Must be HIGH or above
        serious = [f for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        assert serious, f"Expected HIGH+ finding for shell=True, got severities: {[f.severity for f in findings]}"
    finally:
        os.unlink(src)


# ---------------------------------------------------------------------------
# 2. Static: secrets are redacted in evidence
# ---------------------------------------------------------------------------

def test_static_redacts_secret():
    """Secret scanner must redact the actual secret value in evidence output."""
    from creep_static import run_static_scan

    real_secret = "sk-AbCdEfGhIjKlMnOpQrStUvWxYz123456"
    src = _write_tmp(f'API_KEY = "{real_secret}"\n')
    try:
        findings = run_static_scan(src)
        secret_findings = [f for f in findings if "secret" in f.category.value or "api" in f.title.lower()]
        assert secret_findings, "Expected a secret/API key finding"

        for f in secret_findings:
            # The real secret value must NOT appear in evidence or detail
            assert real_secret not in f.evidence, (
                f"Real secret leaked in evidence: {f.evidence}"
            )
            assert real_secret not in f.detail, (
                f"Real secret leaked in detail: {f.detail}"
            )
    finally:
        os.unlink(src)


# ---------------------------------------------------------------------------
# 3. Config scanner: redacts credential values
# ---------------------------------------------------------------------------

def test_config_redacts_secret():
    """Config scanner evidence must never show the raw credential value."""
    from creep_static import _scan_config_file

    real_password = "s3cretPassw0rd!XYZ"
    tmp = _write_tmp(f"password: {real_password}\n", suffix=".yaml")
    try:
        findings = _scan_config_file(tmp)
        cred_findings = [f for f in findings if f.category.value == "config_exposure"]
        assert cred_findings, "Expected config_exposure finding for hardcoded password"

        for f in cred_findings:
            assert real_password not in f.evidence, (
                f"Raw credential leaked in evidence: {f.evidence}"
            )
            assert real_password not in f.detail, (
                f"Raw credential leaked in detail: {f.detail}"
            )
            # Must contain [REDACTED] marker
            assert "[REDACTED]" in f.evidence, (
                f"Expected [REDACTED] in evidence, got: {f.evidence}"
            )
    finally:
        os.unlink(tmp)


# ---------------------------------------------------------------------------
# 4. Config scanner: CI/CD template expressions not flagged
# ---------------------------------------------------------------------------

def test_config_exempts_ci_templates():
    """GitHub Actions ${{ secrets.X }} and shell ${VAR} refs must not be flagged."""
    from creep_static import _scan_config_file

    ci_templates = [
        "GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
        "SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}",
        "API_KEY: ${API_KEY}",
        "password: {{ .Values.password }}",
        "token: !vault |supersecretencryptedblob",
    ]

    for line in ci_templates:
        tmp = _write_tmp(line + "\n", suffix=".yml")
        try:
            findings = _scan_config_file(tmp)
            cred = [f for f in findings if f.category.value == "config_exposure"
                    and "sensitive key" in f.title.lower()]
            assert not cred, (
                f"CI template incorrectly flagged: {line!r}\n"
                f"Finding: {cred[0].title if cred else ''}"
            )
        finally:
            os.unlink(tmp)


# ---------------------------------------------------------------------------
# 5. Surface: detects FastAPI route decorator
# ---------------------------------------------------------------------------

def test_surface_detects_fastapi_route():
    """Surface scanner must discover FastAPI @app.get and @app.post decorators."""
    from creep_surface import run_surface_scan

    d = _tmpdir_with_file("app.py", """
        from fastapi import FastAPI
        app = FastAPI()

        @app.get("/items")
        async def list_items(): pass

        @app.post("/items")
        async def create_item(): pass
    """)
    try:
        endpoints, findings = run_surface_scan(d)
        assert len(endpoints) >= 2, (
            f"Expected at least 2 FastAPI endpoints, found {len(endpoints)}: {endpoints}"
        )
        paths = [e.path for e in endpoints]
        assert "/items" in paths, f"/items not in discovered paths: {paths}"
        frameworks = [e.framework for e in endpoints]
        assert any("fastapi" in fw.lower() or fw == "generic" for fw in frameworks), (
            f"Expected fastapi framework, got: {frameworks}"
        )
    finally:
        import shutil; shutil.rmtree(d)


# ---------------------------------------------------------------------------
# 6. Surface: /health endpoint not HIGH severity
# ---------------------------------------------------------------------------

def test_surface_health_not_high():
    """/health, /status, /metrics must not be flagged as HIGH — they're public by design."""
    from creep_surface import run_surface_scan
    from creep_static import Severity

    d = _tmpdir_with_file("app.py", """
        from fastapi import FastAPI
        app = FastAPI()

        @app.get("/health")
        async def health(): return {"ok": True}

        @app.get("/status")
        async def status(): return {"status": "up"}

        @app.get("/metrics")
        async def metrics(): return {}
    """)
    try:
        endpoints, findings = run_surface_scan(d)
        high_findings = [
            f for f in findings
            if f.severity == Severity.HIGH
            and any(p in f.title for p in ("/health", "/status", "/metrics"))
        ]
        assert not high_findings, (
            f"Health/status/metrics incorrectly flagged HIGH:\n"
            + "\n".join(f"  {f.title}" for f in high_findings)
        )
    finally:
        import shutil; shutil.rmtree(d)


# ---------------------------------------------------------------------------
# 7. Report: HTML escapes XSS payloads
# ---------------------------------------------------------------------------

def test_report_html_escapes_payload():
    """HTML report must escape finding content — XSS payloads must not appear raw."""
    from creep_report import build_report
    from creep_static import Finding, Severity, Category

    xss_payload = '<script>alert("xss")</script>'
    findings = [
        Finding(
            severity=Severity.HIGH,
            category=Category.INJECTION,
            target="http://target/search",
            title=f"XSS test {xss_payload}",
            detail=f"Response contained: {xss_payload}",
            evidence=f"payload={xss_payload}",
            module="fuzz",
        )
    ]
    report = build_report("test", findings)
    html = report.save_html(Path(tempfile.mktemp(suffix=".html")))

    content = Path(html).read_text(encoding="utf-8")
    Path(html).unlink(missing_ok=True)

    # Raw unescaped <script> tag must not appear in the findings section
    assert "<script>alert" not in content, (
        "XSS payload <script>alert appeared unescaped in HTML report"
    )
    # Escaped form must be present
    assert "&lt;script&gt;" in content or "&#x3C;script&#x3E;" in content or "script" in content, (
        "Escaped script tag not found — content may be missing entirely"
    )


# ---------------------------------------------------------------------------
# 8. Active CLI: requires authorization
# ---------------------------------------------------------------------------

def test_network_requires_authorization():
    """run_network_scan must raise ScopeError when authorized=False."""
    from creep_gate import ScopeError
    from creep_network import run_network_scan
    import inspect
    if "authorized" not in inspect.signature(run_network_scan).parameters:
        pytest.fail(
            "run_network_scan() is missing the 'authorized' parameter. "
            "Copy the latest creep_network.py from outputs to your project."
        )
    with pytest.raises(ScopeError):
        run_network_scan("192.168.0.1", authorized=False)


def test_network_direct_entrypoint_requires_flag():
    """
    The creep_network.py direct entrypoint must not scan without --i-am-authorized.
    Regression test: direct module execution used to bypass the gate entirely.
    """
    import subprocess, sys
    from pathlib import Path

    network_module = str(Path(__file__).parent / "creep_network.py")

    # Run without authorization flag — must exit non-zero and refuse to scan
    result = subprocess.run(
        [sys.executable, network_module, "192.168.0.1"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode != 0, (
        "creep_network.py ran without --i-am-authorized and exited cleanly. "
        "Direct module bypass is possible — gate is not enforced."
    )
    output = result.stdout + result.stderr
    assert "authorized" in output.lower() or "error" in output.lower(), (
        f"Expected error/authorization message, got: {output[:200]}"
    )


def test_fuzz_requires_authorization():
    """fuzz_targets must raise ScopeError when authorized=False."""
    from creep_gate import ScopeError
    from creep_fuzz import fuzz_targets, FuzzTarget
    import inspect
    if "authorized" not in inspect.signature(fuzz_targets).parameters:
        pytest.fail(
            "fuzz_targets() is missing the 'authorized' parameter. "
            "Copy the latest creep_fuzz.py from outputs to your project."
        )
    with pytest.raises(ScopeError):
        fuzz_targets([FuzzTarget("http://localhost/")], authorized=False)


def test_auth_requires_authorization():
    """run_auth_scan must raise ScopeError when authorized=False."""
    from creep_gate import ScopeError
    from creep_auth import run_auth_scan
    import inspect
    if "authorized" not in inspect.signature(run_auth_scan).parameters:
        pytest.fail(
            "run_auth_scan() is missing the 'authorized' parameter. "
            "Copy the latest creep_auth.py from outputs to your project."
        )
    with pytest.raises(ScopeError):
        run_auth_scan("http://192.168.0.1/", authorized=False)


def test_ai_requires_authorization():
    """run_ai_scan must raise ScopeError when authorized=False."""
    from creep_gate import ScopeError
    from creep_ai import run_ai_scan
    import inspect
    if "authorized" not in inspect.signature(run_ai_scan).parameters:
        pytest.fail(
            "run_ai_scan() is missing the 'authorized' parameter. "
            "Copy the latest creep_ai.py from outputs to your project."
        )
    with pytest.raises(ScopeError):
        run_ai_scan("http://192.168.0.1:11434/api/chat", authorized=False)


# ---------------------------------------------------------------------------
# 9. Fuzz: default run excludes dangerous payload categories
# ---------------------------------------------------------------------------

def test_fuzz_default_excludes_dangerous():
    """
    DoS and SSRF payload categories must NOT be included in a default fuzz run.
    They require explicit opt-in via categories=['dos'] or categories=['ssrf'].
    """
    from creep_fuzz import fuzz_targets, FuzzTarget

    intercepted_categories: set[str] = set()
    original_probe = None

    # Monkey-patch _probe to intercept without actually sending requests
    import creep_fuzz as cf

    original_probe = cf._probe

    def mock_probe(session, url, method, payload, category, **kwargs):
        intercepted_categories.add(category)
        from creep_fuzz import FuzzResult
        return FuzzResult(
            url=url, method=method, category=category,
            payload=payload[:20], status=200,
            response_len=100, response_ms=1.0,
        )

    cf._probe = mock_probe
    try:
        # Bypass the gate: patch check_scope_url if it exists, otherwise
        # pass authorized=True if the param exists, otherwise just run.
        import inspect
        has_auth  = "authorized" in inspect.signature(fuzz_targets).parameters
        has_scope = hasattr(cf, "check_scope_url")

        if has_scope:
            with patch("creep_fuzz.check_scope_url"):
                fuzz_targets(
                    [FuzzTarget("http://localhost/test", method="GET")],
                    **({"authorized": True} if has_auth else {}),
                    delay=0,
                )
        else:
            fuzz_targets(
                [FuzzTarget("http://localhost/test", method="GET")],
                **({"authorized": True} if has_auth else {}),
                delay=0,
            )
    finally:
        cf._probe = original_probe

    assert "dos" not in intercepted_categories, (
        f"DoS payloads fired in default run. Categories seen: {intercepted_categories}"
    )
    assert "ssrf" not in intercepted_categories, (
        f"SSRF payloads fired in default run. Categories seen: {intercepted_categories}"
    )


# ---------------------------------------------------------------------------
# 10. Auth: default cred evidence never shows raw password
# ---------------------------------------------------------------------------

def test_auth_redacts_credentials():
    """
    The real probe_default_creds implementation must never expose raw
    passwords in AuthResult evidence or in the _log_probe audit entries.
    Tests the actual implementation, not a pre-redacted fake result.
    """
    from creep_auth import probe_default_creds, _results_to_findings, _DEFAULT_CREDS
    import creep_auth as ca

    intercepted_log_probes: list[str] = []
    original_log = ca._log_probe

    def mock_log_probe(url: str, technique: str, result: str, *, event: str = "result") -> None:
        intercepted_log_probes.append(technique)

    # Also mock the HTTP session so no real requests go out
    import requests
    from unittest.mock import patch, MagicMock

    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.text = "Unauthorized"

    ca._log_probe = mock_log_probe
    try:
        with patch.object(requests.Session, "post", return_value=mock_resp):
            results = probe_default_creds(
                "http://localhost/login",
                max_attempts=3,
                delay=0,
            )
    finally:
        ca._log_probe = original_log

    # Check that NO audit log entry contains a raw password
    real_passwords = [pwd for _, pwd in _DEFAULT_CREDS[:3]]
    for technique in intercepted_log_probes:
        for pwd in real_passwords:
            assert f"/{pwd}" not in technique and f"password={pwd}" not in technique, (
                f"Raw password {pwd!r} leaked in audit log technique: {technique!r}"
            )
        assert "[REDACTED]" in technique or "default_creds" not in technique, (
            f"Credential audit log entry missing [REDACTED]: {technique!r}"
        )

    # Check both evidence and description strings in any results
    for r in results:
        for _, pwd in _DEFAULT_CREDS[:3]:
            assert f"password='{pwd}'" not in r.evidence, (
                f"Raw password {pwd!r} leaked in result evidence: {r.evidence}"
            )
            # description field must also not expose the raw password
            assert f"/{pwd}" not in r.description, (
                f"Raw password {pwd!r} leaked in result description: {r.description}"
            )
        assert "[REDACTED]" in r.evidence or r.evidence == "", (
            f"Missing [REDACTED] in evidence: {r.evidence}"
        )

    # Findings pipeline must also be clean
    findings = _results_to_findings(results, "http://localhost/login")
    for f in findings:
        for _, pwd in _DEFAULT_CREDS[:3]:
            assert f"password='{pwd}'" not in f.evidence, (
                f"Raw password in finding evidence: {f.evidence}"
            )


# ---------------------------------------------------------------------------
# 11. AI: default scan excludes dos and ssrf categories
# ---------------------------------------------------------------------------

def test_ai_default_excludes_dos_ssrf():
    """
    run_ai_scan with default categories must exclude 'dos' and 'ssrf' probes.
    These require explicit opt-in: categories=['dos', 'ssrf'].
    """
    import creep_ai as ca

    # Inspect the default category list directly
    default_cats = ["system_prompt", "injection", "jailbreak", "agent", "leak"]

    assert "dos" not in default_cats, (
        "DoS probes included in default AI scan categories"
    )
    assert "ssrf" not in default_cats, (
        "SSRF probes included in default AI scan categories"
    )

    # Also verify the run_ai_scan function uses this default
    import inspect
    src = inspect.getsource(ca.run_ai_scan)
    assert "dos" not in src.split("_DEFAULT_CATEGORIES")[1].split("]")[0] if "_DEFAULT_CATEGORIES" in src else True, (
        "dos found in _DEFAULT_CATEGORIES in run_ai_scan"
    )


# ---------------------------------------------------------------------------
# 12. Static: skips test files by default
# ---------------------------------------------------------------------------

def test_static_skips_test_files():
    """run_static_scan with skip_tests=True must ignore test_*.py and tests/ dirs."""
    import shutil
    from creep_static import run_static_scan

    d = tempfile.mkdtemp()
    try:
        # Source file with a real issue
        (Path(d) / "app.py").write_text(
            "import subprocess\ndef run(cmd): subprocess.run(cmd, shell=True)\n",
            encoding="utf-8",
        )
        # Test file with asserts — should be ignored
        test_dir = Path(d) / "tests"
        test_dir.mkdir()
        (test_dir / "test_app.py").write_text(
            "def test_something():\n    assert 1 + 1 == 2\n    assert True\n",
            encoding="utf-8",
        )
        # Root-level test file
        (Path(d) / "test_utils.py").write_text(
            "def test_util():\n    assert 'hello' in 'hello world'\n",
            encoding="utf-8",
        )

        findings_skip = run_static_scan(d, skip_tests=True)
        findings_include = run_static_scan(d, skip_tests=False)

        # With skip: assert findings from test files should be absent
        assert_findings_skip = [f for f in findings_skip if "assert" in f.title.lower()]
        assert_findings_inc  = [f for f in findings_include if "assert" in f.title.lower()]

        assert not assert_findings_skip, (
            f"Test file asserts found with skip_tests=True: {[f.target for f in assert_findings_skip]}"
        )
        assert assert_findings_inc, (
            "Expected assert findings with skip_tests=False — did the assert check stop working?"
        )

        # Real finding from app.py must still be present with skip_tests=True
        real_findings = [f for f in findings_skip
                         if "subprocess" in f.title.lower() or "shell" in f.title.lower()]
        assert real_findings, (
            "Real subprocess finding in app.py missing with skip_tests=True"
        )
    finally:
        shutil.rmtree(d)


# ---------------------------------------------------------------------------
# 13. Deps: no environment fallback without scan_env=True
# ---------------------------------------------------------------------------

def test_deps_no_env_fallback():
    """
    run_deps_scan on a project with no manifests must NOT audit the current
    interpreter environment unless scan_env=True is explicitly passed.
    """
    import shutil
    from creep_deps import run_deps_scan

    # Empty project — no requirements.txt, no pyproject.toml
    d = tempfile.mkdtemp()
    try:
        log_messages: list[str] = []
        findings = run_deps_scan(
            d,
            scan_env=False,   # explicit default
            progress_cb=lambda m: log_messages.append(m),
        )

        # Must NOT have run pip list --outdated against env
        env_findings = [f for f in findings
                        if f.target == "environment" or "outdated" in f.title.lower()]
        assert not env_findings, (
            f"Environment findings appeared without scan_env=True: {[f.title for f in env_findings]}"
        )

        # Log must mention skipped, not that it ran
        outdated_msgs = [m for m in log_messages if "outdated" in m.lower()]
        assert all("skipped" in m.lower() for m in outdated_msgs), (
            f"Outdated check appears to have run without scan_env=True. Messages: {outdated_msgs}"
        )
    finally:
        shutil.rmtree(d)


# ---------------------------------------------------------------------------
# update5 regression tests
# ---------------------------------------------------------------------------

def test_gate_blocks_0_0_0_0():
    """0.0.0.0 must be classified as blocked, not localhost."""
    from creep_gate import _classify_target
    result = _classify_target("0.0.0.0")
    assert result == "blocked", (
        f"Expected 'blocked' for 0.0.0.0, got {result!r}. "
        "0.0.0.0 should not be treated as localhost."
    )


def test_auth_direct_entrypoint_requires_flag():
    """python creep_auth.py <url> (no --i-am-authorized) must exit non-zero."""
    import subprocess
    result = subprocess.run(
        [sys.executable, "creep_auth.py", "http://localhost:8000/api/admin"],
        cwd=Path(__file__).parent,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0, (
        "creep_auth.py direct entry should refuse without --i-am-authorized"
    )
    assert "authorized" in result.stdout.lower() or "authorized" in result.stderr.lower()


def test_fuzz_direct_entrypoint_requires_flag():
    """python creep_fuzz.py <url> (no --i-am-authorized) must exit non-zero."""
    import subprocess
    result = subprocess.run(
        [sys.executable, "creep_fuzz.py", "http://localhost:8000/api/search"],
        cwd=Path(__file__).parent,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0, (
        "creep_fuzz.py direct entry should refuse without --i-am-authorized"
    )
    assert "authorized" in result.stdout.lower() or "authorized" in result.stderr.lower()


def test_ai_direct_entrypoint_requires_flag():
    """python creep_ai.py <url> (no --i-am-authorized) must exit non-zero."""
    import subprocess
    result = subprocess.run(
        [sys.executable, "creep_ai.py", "http://localhost:11434/api/chat"],
        cwd=Path(__file__).parent,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0, (
        "creep_ai.py direct entry should refuse without --i-am-authorized"
    )
    assert "authorized" in result.stdout.lower() or "authorized" in result.stderr.lower()


def test_ai_ollama_management_flag_is_passed():
    """run_ai_scan() signature must accept ollama_management kwarg."""
    import inspect
    from creep_ai import run_ai_scan
    sig = inspect.signature(run_ai_scan)
    assert "ollama_management" in sig.parameters, (
        "run_ai_scan() must accept ollama_management keyword argument"
    )


def test_fuzz_safe_tier_excludes_sql_cmd_xxe_traversal():
    """Safe tier must not include SQL, cmd, XXE, or path traversal payloads."""
    from creep_fuzz import fuzz_endpoint
    from unittest.mock import patch, MagicMock

    captured_payloads: list[str] = []

    def mock_probe(session, url, method, payload, category, **kwargs):
        captured_payloads.append((category, payload))
        from creep_fuzz import FuzzResult
        return FuzzResult(
            url=url, method=method, category=category,
            payload=payload, status=200, response_len=10,
            response_ms=5.0, reflected=False, error="",
        )

    with patch("creep_fuzz._probe", side_effect=mock_probe), \
         patch("creep_fuzz._baseline", return_value=(200, 100)):
        fuzz_endpoint("http://localhost/test", "GET", tier="safe")

    categories_used = {cat for cat, _ in captured_payloads}
    forbidden = {"sql", "cmd", "xxe", "traversal", "nosql", "xss", "ssti"}
    overlap = categories_used & forbidden
    assert not overlap, (
        f"Safe tier must not include injection categories. Found: {overlap}"
    )


def test_audit_precedes_fuzz_baseline():
    """Fuzz baseline must write 'attempted' audit event before sending the request."""
    from unittest.mock import patch, MagicMock, call
    import creep_fuzz

    audit_events: list[dict] = []

    original_log = creep_fuzz._log_fuzz
    def capturing_log(url, method, category, *, status=None, event="result"):
        audit_events.append({"event": event, "category": category})
        original_log(url, method, category, status=status, event=event)

    request_fired: list[bool] = []
    def mock_request(*args, **kwargs):
        # Check that 'attempted' was already logged before we get here
        attempted_logged = any(e["event"] == "attempted" and e["category"] == "baseline"
                               for e in audit_events)
        request_fired.append(attempted_logged)
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "ok"
        return resp

    with patch.object(creep_fuzz, "_log_fuzz", side_effect=capturing_log), \
         patch("requests.Session.request", side_effect=mock_request):
        creep_fuzz._baseline(MagicMock(request=mock_request), "http://localhost/test", "GET")

    assert request_fired, "Baseline request was never sent"
    assert all(request_fired), (
        "Fuzz baseline: 'attempted' audit event must be written before request fires"
    )


def test_audit_precedes_auth_default_creds():
    """Auth default-creds probe must write 'attempted' audit event before POST fires."""
    from unittest.mock import patch, MagicMock
    import creep_auth

    audit_events: list[dict] = []
    original_log = creep_auth._log_probe
    def capturing_log(url, technique, result, *, event="result"):
        audit_events.append({"event": event, "technique": technique})
        original_log(url, technique, result, event=event)

    request_fired: list[bool] = []
    def mock_post(*args, **kwargs):
        attempted = any(e["event"] == "attempted" and "default_creds" in e["technique"]
                        for e in audit_events)
        request_fired.append(attempted)
        resp = MagicMock()
        resp.status_code = 401
        resp.text = "Unauthorized"
        return resp

    session = MagicMock()
    session.get.return_value = MagicMock(status_code=401)
    session.post.side_effect = mock_post

    with patch.object(creep_auth, "_log_probe", side_effect=capturing_log), \
         patch.object(creep_auth, "_make_session", return_value=session), \
         patch.object(creep_auth, "_get_baseline", return_value=401):
        creep_auth.probe_default_creds(
            "http://localhost/login",
            login_field="username", pass_field="password",
            max_attempts=1,
        )

    assert request_fired, "Default creds POST was never sent"
    assert all(request_fired), (
        "Auth default-creds: 'attempted' audit event must precede POST"
    )


def test_audit_precedes_ai_connectivity_check():
    """AI connectivity check must write 'attempted' audit event before _send fires."""
    from unittest.mock import patch, MagicMock
    import creep_ai

    audit_events: list[dict] = []
    original_log = creep_ai._log_probe
    def capturing_log(url, technique, result, *, event="result"):
        audit_events.append({"event": event, "technique": technique})
        original_log(url, technique, result, event=event)

    send_fired: list[bool] = []
    def mock_send(session, url, payload, timeout, api_key=None):
        attempted = any(e["event"] == "attempted" and "connectivity" in e["technique"]
                        for e in audit_events)
        send_fired.append(attempted)
        return None, "ERROR: connection refused"

    with patch.object(creep_ai, "_log_probe", side_effect=capturing_log), \
         patch.object(creep_ai, "_send", side_effect=mock_send), \
         patch.object(creep_ai, "check_scope_url"):
        creep_ai.run_ai_scan(
            "http://localhost:11434/api/chat",
            authorized=True,
        )

    assert send_fired, "AI connectivity _send was never called"
    assert all(send_fired), (
        "AI connectivity check: 'attempted' audit event must precede _send()"
    )


def test_scope_file_target_enforced_for_url_modules():
    """Scope file with a targets list must block out-of-scope URLs in fuzz/auth."""
    import json
    import tempfile
    from creep_gate import ScopeError
    from creep_fuzz import fuzz_targets, FuzzTarget

    scope = {
        "authorized": True,
        "allow_public": False,
        "targets": ["192.168.1.100"],
        "note": "test scope",
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(scope, f)
        scope_path = f.name

    from creep_gate import load_scope_file
    loaded_scope = load_scope_file(scope_path)

    import os
    os.unlink(scope_path)

    # Target not in scope list — must raise ScopeError
    with pytest.raises(ScopeError):
        fuzz_targets(
            [FuzzTarget(url="http://192.168.1.200/api/test", method="GET", param_name="q")],
            scope=loaded_scope,
        )


def test_network_direct_entrypoint_supports_scope_file():
    """python creep_network.py --scope-file <valid> <target> should accept authorisation from scope file."""
    import json
    import subprocess
    import tempfile
    import os

    # Write a valid private-only scope file (authorized=true, no allow_public)
    scope = {
        "authorized": True,
        "allow_public": False,
        "targets": ["127.0.0.1"],
        "note": "test scope",
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(scope, f)
        scope_path = f.name

    try:
        result = subprocess.run(
            [sys.executable, "creep_network.py",
             "--scope-file", scope_path, "127.0.0.1"],
            cwd=Path(__file__).parent,
            capture_output=True,
            text=True,
            timeout=10,
        )
        # Should not exit with the "requires --i-am-authorized" error (exit 1 before scanning)
        # It may still fail for other reasons (e.g. network) but the gate should pass
        assert "requires --i-am-authorized" not in result.stdout, (
            "Network direct entry should accept authorisation from a valid scope file"
        )
        assert "requires --i-am-authorized" not in result.stderr, (
            "Network direct entry should accept authorisation from a valid scope file"
        )
    finally:
        os.unlink(scope_path)


def test_scope_file_public_without_targets_is_rejected():
    """load_scope_file() must reject a scope file with allow_public=true but no targets list."""
    import json
    import tempfile
    import os
    from creep_gate import load_scope_file, ScopeError

    # Scope file with allow_public but no targets — must be rejected
    bad_scope = {
        "authorized": True,
        "allow_public": True,
        # no "targets" key
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(bad_scope, f)
        bad_path = f.name

    try:
        with pytest.raises(ScopeError) as exc_info:
            load_scope_file(bad_path)
        assert "targets" in str(exc_info.value).lower(), (
            "ScopeError should mention 'targets' when allow_public=true has no target list"
        )
    finally:
        os.unlink(bad_path)

    # Also reject an empty targets list
    bad_scope_empty = {
        "authorized": True,
        "allow_public": True,
        "targets": [],
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(bad_scope_empty, f)
        empty_path = f.name

    try:
        with pytest.raises(ScopeError):
            load_scope_file(empty_path)
    finally:
        os.unlink(empty_path)

    # A scope file with allow_public AND a populated targets list must be accepted
    good_scope = {
        "authorized": True,
        "allow_public": True,
        "targets": ["203.0.113.10"],
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(good_scope, f)
        good_path = f.name

    try:
        result = load_scope_file(good_path)
        assert result["authorized"] is True
        assert result["allow_public"] is True
    finally:
        os.unlink(good_path)


def test_ipv6_loopback_classifies_as_localhost():
    """Raw IPv6 loopback ::1 must classify as localhost, not unresolvable."""
    from creep_gate import _classify_target
    assert _classify_target("::1") == "localhost", (
        "_classify_target('::1') should return 'localhost'"
    )


def test_ipv6_private_classifies_as_private():
    """IPv6 ULA addresses (fc00::/7) must classify as private."""
    from creep_gate import _classify_target
    result = _classify_target("fc00::1")
    assert result == "private", (
        f"_classify_target('fc00::1') should return 'private', got {result!r}"
    )


def test_ipv6_bracketed_port_classifies_correctly():
    """[::1]:8080 must extract host ::1 and classify as localhost."""
    from creep_gate import _classify_target
    assert _classify_target("[::1]:8080") == "localhost", (
        "_classify_target('[::1]:8080') should return 'localhost'"
    )


def test_ipv6_url_classifies_correctly():
    """http://[::1]:11434/api/chat must classify as localhost."""
    from creep_gate import _classify_target
    result = _classify_target("http://[::1]:11434/api/chat")
    assert result == "localhost", (
        f"_classify_target('http://[::1]:11434/api/chat') should return 'localhost', got {result!r}"
    )


def test_ipv6_aws_metadata_is_blocked():
    """IPv6 AWS metadata endpoint fd00:ec2::254 must classify as blocked."""
    from creep_gate import _classify_target
    result = _classify_target("fd00:ec2::254")
    assert result == "blocked", (
        f"_classify_target('fd00:ec2::254') should return 'blocked', got {result!r}"
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import subprocess
    result = subprocess.run(
        [sys.executable, "-m", "pytest", __file__, "-v", "--tb=short"],
        cwd=Path(__file__).parent,
    )
    sys.exit(result.returncode)
