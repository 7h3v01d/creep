"""
creep_surface.py — Phase 1: API Surface Mapper
Part of Creep: Defensive Adversarial Security Scanner
Author: Leon Priest
License: Apache 2.0

Walks a Python project AST to discover every HTTP route, WebSocket endpoint,
UCI capability, and RPC handler. Flags unprotected routes, dangerous HTTP
methods, missing rate limiting, and debug/admin endpoints exposed without auth.

No code is executed. Pure static analysis.
"""

from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from creep_static import Category, Finding, Severity

# ---------------------------------------------------------------------------
# Discovered endpoint model
# ---------------------------------------------------------------------------

@dataclass
class Endpoint:
    path:       str                     # URL path e.g. "/admin/users"
    method:     str                     # GET, POST, ANY, WS, etc.
    handler:    str                     # function/class name
    framework:  str                     # fastapi, flask, django, uci, etc.
    source:     str                     # file path
    line:       int
    auth:       list[str] = field(default_factory=list)   # detected auth decorators
    rate_limit: bool = False
    params:     list[str] = field(default_factory=list)   # path/query params found
    notes:      list[str] = field(default_factory=list)

    @property
    def is_protected(self) -> bool:
        return len(self.auth) > 0

    @property
    def risk_path(self) -> bool:
        """True if path looks sensitive regardless of auth."""
        return bool(_SENSITIVE_PATH.search(self.path))


# ---------------------------------------------------------------------------
# Pattern library
# ---------------------------------------------------------------------------

# HTTP methods we care about
_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options",
                 "websocket", "ws", "route", "api_route", "add_url_rule"}

# Auth-related decorator names (any framework)
_AUTH_NAMES = re.compile(
    r"(?i)(login_required|require_auth|authenticated|jwt_required|"
    r"token_required|oauth|permission|authorize|auth|security|"
    r"depends.*auth|get_current_user|verify_token|api_key|bearer|"
    r"requires_roles?|roles_required|admin_required|staff_required|"
    r"HTTPBearer|OAuth2|APIKeyHeader|Depends)"
)

# Rate-limiting decorator / import names
_RATE_LIMIT_NAMES = re.compile(
    r"(?i)(ratelimit|rate_limit|throttle|limiter|slowapi|flask_limiter)"
)

# Sensitive path tiers — severity varies by category
#
# HIGH: admin, management, shell, exec, internal tooling
_SENSITIVE_HIGH = re.compile(
    r"(?i)(/admin|/root|/superuser|/internal|/manage|"
    r"/shell|/exec|/eval|/console|/config|/settings|"
    r"/env|/secret|/backup|/import|/export|"
    r"/password|/reset|/token|/file)"
)

# MEDIUM: auth endpoints, uploads, dev/test routes
_SENSITIVE_MEDIUM = re.compile(
    r"(?i)(/auth|/login|/register|/upload|/download|"
    r"/debug|/test|/dev|/api/v[0-9])"
)

# LOW: observability endpoints — public by design in most apps
_SENSITIVE_LOW = re.compile(
    r"(?i)(/health|/metrics|/status|/ping|/ready|/live)"
)

# Combined — used for Endpoint.risk_path property
_SENSITIVE_PATH = re.compile(
    r"(?i)(/admin|/root|/superuser|/internal|/manage|"
    r"/shell|/exec|/eval|/console|/config|/settings|"
    r"/env|/secret|/backup|/import|/export|"
    r"/password|/reset|/token|/file|"
    r"/auth|/login|/register|/upload|/download|"
    r"/debug|/test|/dev|"
    r"/health|/metrics|/status|/ping|/ready|/live)"
)

# Execution/debug paths — always HIGH regardless of auth tier
_DEBUG_EXEC_PATH = re.compile(
    r"(?i)/debug|/test|/dev|/internal|/shell|/exec|/eval|/console"
)

# Dangerous HTTP methods that modify state
_DANGEROUS_METHODS = {"post", "put", "patch", "delete"}

# Path parameters patterns — {param}, <param>, <type:param>
_PATH_PARAM = re.compile(r"\{(\w+)\}|<(?:[^:>]+:)?(\w+)>|:(\w+)")

# Frameworks and their route decorator patterns
_FRAMEWORK_PATTERNS: dict[str, list[str]] = {
    "fastapi":   ["get", "post", "put", "patch", "delete", "head",
                  "options", "websocket", "api_route", "route"],
    "flask":     ["route", "get", "post", "put", "patch", "delete",
                  "add_url_rule", "before_request", "after_request"],
    "django":    ["path", "re_path", "url", "include"],
    "starlette": ["route", "websocket_route", "mount"],
    "tornado":   ["get", "post", "put", "patch", "delete"],
    "aiohttp":   ["get", "post", "put", "patch", "delete", "route"],
    "uci":       ["register_capability", "capability", "uci_route",
                  "add_capability", "expose"],
    "generic":   ["endpoint", "handler", "api", "view"],
}

# Flat set of all route-like decorator attr names
_ALL_ROUTE_ATTRS: set[str] = {
    a for attrs in _FRAMEWORK_PATTERNS.values() for a in attrs
}


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

def _get_decorator_name(dec: ast.expr) -> str:
    """Return a flat string representation of a decorator."""
    if isinstance(dec, ast.Name):
        return dec.id
    if isinstance(dec, ast.Attribute):
        return f"{_get_decorator_name(dec.value)}.{dec.attr}"
    if isinstance(dec, ast.Call):
        return _get_decorator_name(dec.func)
    return ""


def _get_string_arg(node: ast.expr | None) -> str | None:
    """Extract a plain string from an AST constant or f-string (best effort)."""
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        # f-string — collect the constant parts
        parts = []
        for val in node.values:
            if isinstance(val, ast.Constant):
                parts.append(str(val.value))
            else:
                parts.append("{?}")
        return "".join(parts)
    return None


def _extract_path_from_call(call: ast.Call) -> str | None:
    """Pull the URL path out of a decorator call like @app.get('/path')."""
    # Positional first arg
    if call.args:
        s = _get_string_arg(call.args[0])
        if s and ("/" in s or s.startswith("^")):
            return s
    # Keyword: path=, url=, pattern=, prefix=
    for kw in call.keywords:
        if kw.arg in ("path", "url", "pattern", "prefix", "route"):
            s = _get_string_arg(kw.value)
            if s:
                return s
    return None


def _has_auth_in_decorators(decorators: list[ast.expr]) -> list[str]:
    """Return list of detected auth decorator names."""
    found = []
    for dec in decorators:
        name = _get_decorator_name(dec)
        if _AUTH_NAMES.search(name):
            found.append(name)
    return found


def _has_rate_limit_in_decorators(decorators: list[ast.expr]) -> bool:
    for dec in decorators:
        name = _get_decorator_name(dec)
        if _RATE_LIMIT_NAMES.search(name):
            return True
    return False


def _has_auth_in_args(call: ast.Call) -> list[str]:
    """Detect FastAPI Depends(get_current_user) style auth in decorator args."""
    found = []
    for kw in call.keywords:
        if kw.arg in ("dependencies", "security"):
            # Look for any Depends / Security calls
            for node in ast.walk(kw.value):
                if isinstance(node, ast.Call):
                    name = _get_decorator_name(node.func)
                    if _AUTH_NAMES.search(name):
                        found.append(name)
    return found


def _detect_framework(name: str) -> str:
    """Map a decorator attribute name to a framework label."""
    for fw, attrs in _FRAMEWORK_PATTERNS.items():
        if name in attrs:
            return fw
    return "generic"


# ---------------------------------------------------------------------------
# Per-file AST scanner
# ---------------------------------------------------------------------------

class _SurfaceVisitor(ast.NodeVisitor):

    def __init__(self, filepath: str, source_lines: list[str]) -> None:
        self.filepath     = filepath
        self.source_lines = source_lines
        self.endpoints:   list[Endpoint] = []

        # Track router/app variable names: e.g. app = FastAPI(), router = APIRouter()
        self._router_vars: set[str] = set()
        self._prefix_map:  dict[str, str] = {}  # var → prefix string

    # ------------------------------------------------------------------
    # Pass 1: collect router variable assignments
    # ------------------------------------------------------------------

    def visit_Assign(self, node: ast.Assign) -> None:
        """Detect: app = FastAPI(), router = APIRouter(), bp = Blueprint(...)"""
        if isinstance(node.value, ast.Call):
            func_name = _get_decorator_name(node.value.func)
            if any(kw in func_name.lower() for kw in
                   ("fastapi", "flask", "application", "apirouter",
                    "blueprint", "router", "app", "api")):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self._router_vars.add(target.id)
                        # Check for prefix= kwarg
                        for kw in node.value.keywords:
                            if kw.arg == "prefix":
                                prefix = _get_string_arg(kw.value) or ""
                                self._prefix_map[target.id] = prefix
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Pass 2: function/class decorators → endpoints
    # ------------------------------------------------------------------

    def _process_decorated(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
    ) -> None:
        handler_name = node.name
        line         = node.lineno

        for dec in node.decorator_list:
            dec_name = _get_decorator_name(dec)
            dec_attr = dec_name.split(".")[-1].lower()

            # Must look like a route decorator
            if dec_attr not in _ALL_ROUTE_ATTRS:
                continue

            # Extract path
            path: str | None = None
            extra_auth: list[str] = []

            if isinstance(dec, ast.Call):
                path = _extract_path_from_call(dec)
                extra_auth = _has_auth_in_args(dec)
            elif isinstance(dec, ast.Attribute):
                path = None   # bare @app.get with no args — unusual but possible

            if path is None:
                # Still record it — path unknown
                path = "<?>"

            # Apply router prefix if known
            obj_name = dec_name.split(".")[0] if "." in dec_name else ""
            prefix = self._prefix_map.get(obj_name, "")
            if prefix and not path.startswith(prefix):
                path = prefix.rstrip("/") + "/" + path.lstrip("/")

            # Method
            method = dec_attr.upper()
            if method in ("ROUTE", "API_ROUTE", "ADD_URL_RULE", "PATH",
                          "RE_PATH", "URL", "REGISTER_CAPABILITY",
                          "CAPABILITY", "EXPOSE"):
                # Try to extract from methods= kwarg
                method = "ANY"
                if isinstance(dec, ast.Call):
                    for kw in dec.keywords:
                        if kw.arg == "methods":
                            if isinstance(kw.value, (ast.List, ast.Tuple)):
                                ms = [_get_string_arg(e) for e in kw.value.elts]
                                method = ",".join(m for m in ms if m)

            # Auth
            auth_decs  = _has_auth_in_decorators(node.decorator_list)
            all_auth   = list(set(auth_decs + extra_auth))

            # Rate limit
            rate_limit = _has_rate_limit_in_decorators(node.decorator_list)

            # Path params
            params = [
                m.group(1) or m.group(2) or m.group(3)
                for m in _PATH_PARAM.finditer(path)
            ]

            framework = _detect_framework(dec_attr)

            ep = Endpoint(
                path=path,
                method=method,
                handler=handler_name,
                framework=framework,
                source=self.filepath,
                line=line,
                auth=all_auth,
                rate_limit=rate_limit,
                params=params,
            )
            self.endpoints.append(ep)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._process_decorated(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._process_decorated(node)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._process_decorated(node)
        self.generic_visit(node)


# ---------------------------------------------------------------------------
# Django URL pattern scanner (urls.py / urlpatterns)
# ---------------------------------------------------------------------------

def _scan_django_urls(filepath: str, source: str) -> list[Endpoint]:
    """Detect Django urlpatterns = [...] style route lists."""
    endpoints: list[Endpoint] = []
    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        return endpoints

    for node in ast.walk(tree):
        # Look for: urlpatterns = [path(...), re_path(...), ...]
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "urlpatterns":
                if not isinstance(node.value, (ast.List, ast.Tuple)):
                    continue
                for elt in node.value.elts:
                    if not isinstance(elt, ast.Call):
                        continue
                    func_name = _get_decorator_name(elt.func)
                    if func_name not in ("path", "re_path", "url", "include"):
                        continue
                    path = _get_string_arg(elt.args[0]) if elt.args else None
                    if path is None:
                        path = "<?>"
                    handler = "<?>"
                    if len(elt.args) > 1:
                        h = elt.args[1]
                        if isinstance(h, ast.Attribute):
                            handler = _get_decorator_name(h)
                        elif isinstance(h, ast.Name):
                            handler = h.id
                    endpoints.append(Endpoint(
                        path=path,
                        method="ANY",
                        handler=handler,
                        framework="django",
                        source=filepath,
                        line=elt.lineno if hasattr(elt, "lineno") else 0,
                    ))
    return endpoints


# ---------------------------------------------------------------------------
# Top-level file scanner
# ---------------------------------------------------------------------------

_SKIP_DIRS = {
    ".git", "__pycache__", ".venv", "venv", "env",
    "node_modules", "dist", "build", ".tox", "site-packages",
    "migrations",
}

# Test directories skipped by default — test files are not deployed surfaces.
# Routes found in test code produce false positives: mock decorators and pytest
# parametrize calls look identical to real route decorators in AST.
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


def _walk_py_files(root: Path, skip_tests: bool = True) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        skip = set(_SKIP_DIRS)
        if skip_tests:
            skip |= _TEST_DIRS
        dirnames[:] = [d for d in dirnames if d not in skip]
        for fname in filenames:
            if not fname.endswith(".py"):
                continue
            if skip_tests and _is_test_file(fname):
                continue
            yield Path(dirpath) / fname


def _scan_file(filepath: Path) -> list[Endpoint]:
    try:
        source = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    endpoints: list[Endpoint] = []
    try:
        tree = ast.parse(source, filename=str(filepath))
    except SyntaxError:
        return []

    lines = source.splitlines()
    visitor = _SurfaceVisitor(str(filepath), lines)
    visitor.visit(tree)
    endpoints.extend(visitor.endpoints)

    # Django urlpatterns supplement
    endpoints.extend(_scan_django_urls(str(filepath), source))

    return endpoints


# ---------------------------------------------------------------------------
# Finding generator
# ---------------------------------------------------------------------------

def _endpoints_to_findings(
    endpoints: list[Endpoint],
    root: Path,
) -> list[Finding]:
    findings: list[Finding] = []

    for ep in endpoints:
        rel = ep.source
        try:
            rel = str(Path(ep.source).relative_to(root))
        except ValueError:
            pass

        # ── Unprotected sensitive route (tiered severity) ───────────
        if ep.risk_path and not ep.is_protected:
            if _SENSITIVE_HIGH.search(ep.path):
                path_sev = Severity.HIGH
                path_note = (
                    f"'{ep.path}' is a high-sensitivity path (admin/config/secret) "
                    f"with no detected authentication on handler '{ep.handler}'. "
                    f"Anyone who can reach this endpoint has unrestricted access."
                )
            elif _SENSITIVE_MEDIUM.search(ep.path):
                path_sev = Severity.MEDIUM
                path_note = (
                    f"'{ep.path}' is an auth/upload/debug path with no detected "
                    f"authentication on handler '{ep.handler}'. "
                    f"Verify access is intentionally public."
                )
            else:
                # LOW: /health, /status, /metrics — public by design
                path_sev = Severity.LOW
                path_note = (
                    f"'{ep.path}' is an observability endpoint (health/status/metrics). "
                    f"These are often intentionally public — verify no sensitive data "
                    f"is exposed in the response."
                )
            findings.append(Finding(
                severity=path_sev,
                category=Category.AUTH,
                target=rel,
                title=f"Unprotected {path_sev.value.lower()}-sensitivity route: "
                      f"{ep.method} {ep.path}",
                detail=path_note,
                evidence=f"{ep.framework} | handler: {ep.handler} | line {ep.line}",
                line=ep.line,
                module="surface",
            ))

        # ── Any unprotected route (lower severity) ───────────────────
        elif not ep.is_protected and ep.method.upper() in (
            m.upper() for m in _DANGEROUS_METHODS
        ):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=Category.AUTH,
                target=rel,
                title=f"Unauthenticated write route: {ep.method} {ep.path}",
                detail=(
                    f"'{ep.path}' accepts {ep.method} (state-modifying) with no "
                    f"detected auth on handler '{ep.handler}'. Verify this is intentional."
                ),
                evidence=f"{ep.framework} | handler: {ep.handler} | line {ep.line}",
                line=ep.line,
                module="surface",
            ))

        # ── Write route without rate limiting ────────────────────────
        if (ep.method.upper() in (m.upper() for m in _DANGEROUS_METHODS)
                and not ep.rate_limit):
            findings.append(Finding(
                severity=Severity.LOW,
                category=Category.AUTH,
                target=rel,
                title=f"No rate limiting on write route: {ep.method} {ep.path}",
                detail=(
                    f"'{ep.path}' ({ep.method}) has no detected rate limiting. "
                    f"Without throttling, this endpoint is vulnerable to brute-force "
                    f"and resource exhaustion."
                ),
                evidence=f"handler: {ep.handler} | line {ep.line}",
                line=ep.line,
                module="surface",
            ))

        # ── Path parameter injection risk ────────────────────────────
        if ep.params:
            findings.append(Finding(
                severity=Severity.INFO,
                category=Category.INJECTION,
                target=rel,
                title=f"Path parameters on {ep.method} {ep.path}",
                detail=(
                    f"Route '{ep.path}' exposes path parameter(s): "
                    f"{', '.join(ep.params)}. "
                    f"Verify each parameter is validated and sanitised before use."
                ),
                evidence=f"params: {ep.params} | handler: {ep.handler} | line {ep.line}",
                line=ep.line,
                module="surface",
            ))

        # ── Debug / shell / exec endpoint (always HIGH, separate from auth tier) ──
        if _DEBUG_EXEC_PATH.search(ep.path):
            findings.append(Finding(
                severity=Severity.HIGH,
                category=Category.CONFIG_EXPOSURE,
                target=rel,
                title=f"Debug/dev endpoint exposed: {ep.method} {ep.path}",
                detail=(
                    f"'{ep.path}' appears to be a debug or development endpoint. "
                    f"These should never be reachable in production. "
                    f"Ensure this route is gated by environment checks or removed."
                ),
                evidence=f"handler: {ep.handler} | line {ep.line}",
                line=ep.line,
                module="surface",
            ))

    return findings


# ---------------------------------------------------------------------------
# Summary table builder
# ---------------------------------------------------------------------------

def _build_surface_summary(endpoints: list[Endpoint]) -> dict:
    protected   = [e for e in endpoints if e.is_protected]
    unprotected = [e for e in endpoints if not e.is_protected]
    sensitive   = [e for e in endpoints if e.risk_path]
    write_eps   = [e for e in endpoints if e.method.upper() in
                   {m.upper() for m in _DANGEROUS_METHODS}]

    by_framework: dict[str, int] = {}
    for ep in endpoints:
        by_framework[ep.framework] = by_framework.get(ep.framework, 0) + 1

    return {
        "total":        len(endpoints),
        "protected":    len(protected),
        "unprotected":  len(unprotected),
        "sensitive":    len(sensitive),
        "write_routes": len(write_eps),
        "by_framework": by_framework,
    }


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------

def run_surface_scan(
    target: str | Path,
    *,
    skip_tests:  bool = True,
    progress_cb=None,
) -> tuple[list[Endpoint], list[Finding]]:
    """
    Scan a project for HTTP/WS/UCI endpoints and flag security issues.

    Args:
        target:      Directory or .py file to scan.
        skip_tests:  If True (default), skip test directories and test_*.py
                     files. Test files produce false positives since mock
                     decorators look like real route decorators.
        progress_cb: Optional callable(msg: str) for live progress.

    Returns:
        (endpoints, findings) — full endpoint inventory + security findings.
    """
    root = Path(target).resolve()
    all_endpoints: list[Endpoint] = []

    def _log(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    if root.is_file():
        py_files = [root] if root.suffix == ".py" else []
    else:
        py_files = list(_walk_py_files(root, skip_tests=skip_tests))

    skipped_note = " (test files excluded)" if skip_tests else ""
    _log(f"Surface scan: {len(py_files)} Python file(s){skipped_note}")

    for fp in py_files:
        eps = _scan_file(fp)
        if eps:
            rel = str(fp.relative_to(root) if root.is_dir() else fp)
            _log(f"  {rel}: {len(eps)} endpoint(s)")
            all_endpoints.extend(eps)

    findings = _endpoints_to_findings(all_endpoints, root)
    findings.sort(key=lambda f: (f.severity.rank, f.target, f.line or 0))

    return all_endpoints, findings


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"[creep-surface] Scanning: {target}\n")

    endpoints, findings = run_surface_scan(
        target,
        progress_cb=lambda m: print(f"  {m}"),
    )

    summary = _build_surface_summary(endpoints)

    print(f"\n{'─'*60}")
    print(f"  Surface summary")
    print(f"{'─'*60}")
    print(f"  Total endpoints  : {summary['total']}")
    print(f"  Protected        : {summary['protected']}")
    print(f"  Unprotected      : {summary['unprotected']}")
    print(f"  Sensitive paths  : {summary['sensitive']}")
    print(f"  Write routes     : {summary['write_routes']}")
    if summary["by_framework"]:
        print(f"  By framework     : {summary['by_framework']}")
    print(f"{'─'*60}\n")

    if endpoints:
        print("  Endpoint inventory:\n")
        for ep in sorted(endpoints, key=lambda e: e.path):
            auth_str = f"  [AUTH: {', '.join(ep.auth)}]" if ep.auth else "  [NO AUTH]"
            rl_str   = " [RATE-LIMITED]" if ep.rate_limit else ""
            print(f"  {ep.method:<8} {ep.path:<40} {auth_str}{rl_str}")
            print(f"           handler: {ep.handler} | {ep.framework} | {ep.source}:{ep.line}")
        print()

    print(f"{'─'*60}")
    print(f"  {len(findings)} finding(s)")
    print(f"{'─'*60}\n")

    for f in findings:
        print(f"[{f.severity.value:<8}] {f.title}")
        print(f"           Target  : {f.target}:{f.line}")
        print(f"           Detail  : {f.detail}")
        if f.evidence:
            print(f"           Evidence: {f.evidence}")
        print()
