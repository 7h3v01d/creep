"""
creep.py — CLI Entry Point
Part of Creep: Defensive Adversarial Security Scanner
Author: Leon Priest
License: Apache 2.0

Usage:
    python creep.py --help
    python creep.py static  ./myproject
    python creep.py deps    ./myproject
    python creep.py surface ./myproject
    python creep.py network 192.168.0.163
    python creep.py fuzz    http://localhost:8000/api/search GET q
    python creep.py auth    http://localhost:8000/api/admin
    python creep.py ai      http://192.168.0.163:11434/api/chat llama3
    python creep.py full    ./myproject --base-url http://localhost:8000
    python creep.py gui
"""

from __future__ import annotations

from creep_gate import load_scope_file, write_scope_template, ScopeError
from creep_network import run_network_scan
import argparse
import json
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print_findings(findings: list, module: str) -> int:
    from creep_static import Severity
    findings.sort(key=lambda f: f.severity.rank)
    crits = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    highs = sum(1 for f in findings if f.severity == Severity.HIGH)

    print(f"\n{'─'*60}")
    print(f"  [{module.upper()}] {len(findings)} finding(s)"
          + (f"  [{crits}C {highs}H]" if crits or highs else ""))
    print(f"{'─'*60}\n")

    for f in findings:
        loc = f":{f.line}" if f.line else ""
        print(f"[{f.severity.value:<8}] {f.title}")
        print(f"           Target  : {f.target}{loc}")
        print(f"           Detail  : {f.detail}")
        if f.evidence:
            print(f"           Evidence: {f.evidence}")
        print()

    return len(findings)


def _save_report(findings: list, target: str, out: str | None) -> None:
    from creep_report import build_report
    report = build_report(target, findings)

    if out:
        p = Path(out)
        if p.suffix == ".json":
            report.save_json(p)
            print(f"\n  JSON report: {p}")
        else:
            report.save_html(p)
            print(f"\n  HTML report: {p}")
    else:
        # Default: both
        report.save_json("creep_report.json")
        report.save_html("creep_report.html")
        print(f"\n  Reports saved: creep_report.json | creep_report.html")

    print(report.summary())


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_static(args: argparse.Namespace) -> None:
    from creep_static import run_static_scan
    findings = run_static_scan(
        args.target,
        progress_cb=lambda m: print(f"  {m}"),
    )
    _print_findings(findings, "static")
    if args.out:
        _save_report(findings, args.target, args.out)


def cmd_deps(args: argparse.Namespace) -> None:
    from creep_deps import run_deps_scan
    offline     = getattr(args, "offline",     False)
    no_cve      = getattr(args, "no_cve",      False)
    no_outdated = getattr(args, "no_outdated", False)
    scan_env    = getattr(args, "scan_env",    False)

    # --offline is a convenience alias that disables all network-touching checks
    check_cves     = not (offline or no_cve)
    check_outdated = not (offline or no_outdated)

    if offline:
        print("  [deps] --offline: skipping CVE lookup and outdated-package check")

    findings = run_deps_scan(
        args.target,
        check_cves=check_cves,
        check_outdated=check_outdated,
        scan_env=scan_env,
        progress_cb=lambda m: print(f"  {m}"),
    )
    _print_findings(findings, "deps")
    if args.out:
        _save_report(findings, args.target, args.out)


def cmd_surface(args: argparse.Namespace) -> None:
    from creep_surface import run_surface_scan
    endpoints, findings = run_surface_scan(
        args.target,
        progress_cb=lambda m: print(f"  {m}"),
    )
    print(f"\n  {len(endpoints)} endpoint(s) discovered")
    _print_findings(findings, "surface")
    if args.out:
        _save_report(findings, args.target, args.out)


def cmd_network(args: argparse.Namespace) -> None:
    print(f"\n  !! ACTIVE SCAN — ensure you have authorisation !!\n")
    scope  = _load_scope(args)
    prange = None
    if hasattr(args, "range") and args.range:
        parts = args.range.split("-")
        prange = (int(parts[0]), int(parts[1]))

    open_ports, findings = run_network_scan(
        args.target,
        port_range=prange,
        authorized=getattr(args, "authorized", False),
        allow_public=getattr(args, "allow_public", False),
        scope=scope,
        progress_cb=lambda m: print(f"  {m}"),
    )
    print(f"\n  {len(open_ports)} open port(s)")
    _print_findings(findings, "network")
    if args.out:
        _save_report(findings, args.target, args.out)


def cmd_fuzz(args: argparse.Namespace) -> None:
    print(f"\n  !! ACTIVE FUZZ — ensure you have authorisation !!\n")
    from creep_fuzz import fuzz_targets, FuzzTarget
    method   = getattr(args, "method", "GET")
    param    = getattr(args, "param", "q")
    as_json  = method.upper() in ("POST", "PUT", "PATCH")
    scope = _load_scope(args)
    _, findings = fuzz_targets(
        [FuzzTarget(url=args.target, method=method, param_name=param, as_json=as_json)],
        tier=getattr(args, "tier", "standard"),
        authorized=getattr(args, "authorized", False),
        allow_public=getattr(args, "allow_public", False),
        scope=scope,
        progress_cb=lambda m: print(f"  {m}"),
    )
    _print_findings(findings, "fuzz")
    if args.out:
        _save_report(findings, args.target, args.out)


def cmd_auth(args: argparse.Namespace) -> None:
    print(f"\n  !! ACTIVE AUTH PROBE — ensure you have authorisation !!\n")
    from creep_auth import run_auth_scan
    scope = _load_scope(args)
    _, findings = run_auth_scan(
        args.target,
        jwt_token=getattr(args, "jwt", None),
        login_url=getattr(args, "login_url", None),
        protected_paths=["/admin", "/api/admin", "/internal"],
        authorized=getattr(args, "authorized", False),
        allow_public=getattr(args, "allow_public", False),
        scope=scope,
        progress_cb=lambda m: print(f"  {m}"),
    )
    _print_findings(findings, "auth")
    if args.out:
        _save_report(findings, args.target, args.out)


def cmd_ai(args: argparse.Namespace) -> None:
    print(f"\n  !! ACTIVE AI PROBE — ensure you have authorisation !!\n")
    from creep_ai import run_ai_scan
    scope       = _load_scope(args)
    model       = getattr(args, "model", "llama3")
    ollama_base = getattr(args, "ollama_base", None)
    _, findings = run_ai_scan(
        args.target,
        model=model,
        ollama_base=ollama_base,
        ollama_management=getattr(args, "ollama_management", False),
        authorized=getattr(args, "authorized", False),
        allow_public=getattr(args, "allow_public", False),
        scope=scope,
        progress_cb=lambda m: print(f"  {m}"),
    )
    _print_findings(findings, "ai")
    if args.out:
        _save_report(findings, args.target, args.out)


def cmd_full(args: argparse.Namespace) -> None:
    """Run static/deps/surface + network/fuzz/auth (+ explicit AI) and produce unified report."""
    from creep_gate import ScopeError

    all_findings: list = []
    target       = args.target
    base_url     = getattr(args, "base_url", "")
    ai_endpoint  = getattr(args, "ai_endpoint", "")
    ai_model     = getattr(args, "ai_model", "llama3")
    ollama_base  = getattr(args, "ollama_base", "")
    ollama_mgmt  = getattr(args, "ollama_management", False)
    authorized   = getattr(args, "authorized", False)
    allow_public = getattr(args, "allow_public", False)
    scope        = _load_scope(args)

    print(f"\n[creep] Full scan: {target}")
    if base_url:
        print(f"[creep] Base URL : {base_url}")
    if ai_endpoint:
        print(f"[creep] AI endpoint: {ai_endpoint}")
    print()

    # Phase 2 gate — fail fast before any work if auth is missing
    if (base_url or ai_endpoint) and not authorized and not scope:
        print("ERROR: Full scan with --base-url or --ai-endpoint requires explicit authorisation.")
        print("       Add --i-am-authorized (or --scope-file scope.json) to proceed.")
        print("       Example: python creep.py --i-am-authorized full ./myproject --base-url http://localhost:8000")
        sys.exit(1)

    # Phase 1
    print("── Phase 1: Static ──────────────────────────────────────")
    from creep_static import run_static_scan
    f = run_static_scan(target, progress_cb=lambda m: print(f"  {m}"))
    all_findings.extend(f)
    print(f"  → {len(f)} finding(s)")

    print("\n── Phase 1: Deps ────────────────────────────────────────")
    from creep_deps import run_deps_scan
    f = run_deps_scan(target, progress_cb=lambda m: print(f"  {m}"))
    all_findings.extend(f)
    print(f"  → {len(f)} finding(s)")

    print("\n── Phase 1: Surface ─────────────────────────────────────")
    from creep_surface import run_surface_scan
    endpoints, f = run_surface_scan(target, progress_cb=lambda m: print(f"  {m}"))
    all_findings.extend(f)
    print(f"  → {len(endpoints)} endpoint(s), {len(f)} finding(s)")

    # Phase 2 — only if base_url provided, authorization already confirmed above
    if base_url:
        print(f"\n  [AUTHORIZED] Active modules targeting: {base_url}\n")

        print("── Phase 2: Network ─────────────────────────────────────")
        import urllib.parse
        host = urllib.parse.urlparse(base_url).hostname or base_url
        _, f = run_network_scan(
            host,
            authorized=authorized,
            allow_public=allow_public,
            scope=scope,
            progress_cb=lambda m: print(f"  {m}"),
        )
        all_findings.extend(f)
        print(f"  → {len(f)} finding(s)")

        print("\n── Phase 2: Fuzz ────────────────────────────────────────")
        from creep_fuzz import fuzz_targets, targets_from_surface
        tgts = targets_from_surface(endpoints, base_url)
        if not tgts:
            from creep_fuzz import FuzzTarget
            tgts = [FuzzTarget(url=base_url, method="GET")]
        _, f = fuzz_targets(
            tgts,
            authorized=authorized,
            allow_public=allow_public,
            scope=scope,
            progress_cb=lambda m: print(f"  {m}"),
        )
        all_findings.extend(f)
        print(f"  → {len(f)} finding(s)")

        print("\n── Phase 2: Auth ────────────────────────────────────────")
        from creep_auth import run_auth_scan
        _, f = run_auth_scan(
            base_url,
            authorized=authorized,
            allow_public=allow_public,
            scope=scope,
            progress_cb=lambda m: print(f"  {m}"),
        )
        all_findings.extend(f)
        print(f"  → {len(f)} finding(s)")

    # Phase 2: AI — only if --ai-endpoint explicitly supplied
    if ai_endpoint:
        print(f"\n── Phase 2: AI ──────────────────────────────────────────")
        from creep_ai import run_ai_scan
        _, f = run_ai_scan(
            ai_endpoint,
            model=ai_model,
            ollama_base=ollama_base or None,
            ollama_management=ollama_mgmt,
            authorized=authorized,
            allow_public=allow_public,
            scope=scope,
            progress_cb=lambda m: print(f"  {m}"),
        )
        all_findings.extend(f)
        print(f"  → {len(f)} finding(s)")

    _save_report(all_findings, target, getattr(args, "out", None))


def cmd_gui(_args: argparse.Namespace) -> None:
    from creep_gui import main
    main()


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="creep",
        description="Creep — Defensive Adversarial Security Scanner\nAuthor: Leon Priest | Apache 2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version="creep 2.0.0-alpha")

    # Global active-scan authorisation flags
    p.add_argument(
        "--i-am-authorized", dest="authorized", action="store_true",
        help="Assert explicit authorisation to run active scans against this target.",
    )
    p.add_argument(
        "--allow-public", dest="allow_public", action="store_true",
        help="Allow scanning public/routable IPs (requires --i-am-authorized).",
    )
    p.add_argument(
        "--scope-file", dest="scope_file", default=None, metavar="FILE",
        help="JSON scope file defining authorised targets (see creep_gate.py).",
    )
    p.add_argument(
        "--init-scope", dest="init_scope", action="store_true",
        help="Write a blank scope.json template and exit.",
    )

    sub = p.add_subparsers(dest="command", required=False)

    # static
    sp = sub.add_parser("static", help="Phase 1: static analysis (AST + secrets + config)")
    sp.add_argument("target", help="Project directory or .py file")
    sp.add_argument("-o", "--out", help="Output file (.json or .html)")
    sp.set_defaults(func=cmd_static)

    # deps
    sp = sub.add_parser("deps", help="Phase 1: dependency CVE audit")
    sp.add_argument("target", help="Project directory")
    sp.add_argument("-o", "--out")
    sp.add_argument(
        "--offline", action="store_true", default=False,
        help="Skip all network-dependent checks (CVE lookup and outdated packages). "
             "Useful for air-gapped environments or when external queries are not desired.",
    )
    sp.add_argument(
        "--no-cve", dest="no_cve", action="store_true", default=False,
        help="Skip CVE audit via pip-audit / OSV (no external queries for vulnerability data).",
    )
    sp.add_argument(
        "--no-outdated", dest="no_outdated", action="store_true", default=False,
        help="Skip outdated-package check (no 'pip list --outdated' call).",
    )
    sp.add_argument(
        "--scan-env", dest="scan_env", action="store_true", default=False,
        help="Also audit the current Python interpreter environment, not just project manifests. "
             "Off by default to avoid reporting Creep's own dependencies as project findings.",
    )
    sp.set_defaults(func=cmd_deps)

    # surface
    sp = sub.add_parser("surface", help="Phase 1: API surface mapping")
    sp.add_argument("target", help="Project directory or .py file")
    sp.add_argument("-o", "--out")
    sp.set_defaults(func=cmd_surface)

    # network
    sp = sub.add_parser("network", help="Phase 2: network port scan (ACTIVE)")
    sp.add_argument("target", help="IP address or hostname")
    sp.add_argument("--range", help="Port range e.g. 1-1024")
    sp.add_argument("-o", "--out")
    sp.set_defaults(func=cmd_network)

    # fuzz
    sp = sub.add_parser("fuzz", help="Phase 2: API fuzzer (ACTIVE)")
    sp.add_argument("target", help="Full URL to fuzz")
    sp.add_argument("method", nargs="?", default="GET", help="HTTP method")
    sp.add_argument("param",  nargs="?", default="q",   help="Parameter name")
    sp.add_argument(
        "--tier", choices=["safe", "standard", "dangerous"], default="standard",
        help="Payload tier: safe (boundary + low-impact JSON) / standard (default) / dangerous (cmd+XXE)",
    )
    sp.add_argument("-o", "--out")
    sp.set_defaults(func=cmd_fuzz)

    # auth
    sp = sub.add_parser("auth", help="Phase 2: auth bypass probes (ACTIVE)")
    sp.add_argument("target",    help="Base URL or protected endpoint")
    sp.add_argument("--jwt",     help="JWT token to attack")
    sp.add_argument("--login-url", dest="login_url", help="Login endpoint for cred probing")
    sp.add_argument("-o", "--out")
    sp.set_defaults(func=cmd_auth)

    # ai
    sp = sub.add_parser("ai", help="Phase 2: AI/LLM probes (ACTIVE)")
    sp.add_argument("target",        help="Chat/generate endpoint URL")
    sp.add_argument("model",         nargs="?", default="llama3", help="Model name")
    sp.add_argument("--ollama-base", dest="ollama_base", help="Ollama base URL for meta probes")
    sp.add_argument(
        "--ollama-management", dest="ollama_management", action="store_true", default=False,
        help="Enable Ollama pull/delete endpoint probes (opt-in, uses fake model name)",
    )
    sp.add_argument("-o", "--out")
    sp.set_defaults(func=cmd_ai)

    # full
    sp = sub.add_parser("full", help="Run static/deps/surface + network/fuzz/auth (+ optional AI) and produce unified report")
    sp.add_argument("target",       help="Project directory")
    sp.add_argument("--base-url",   dest="base_url", default="", help="Service base URL for Phase 2 active modules")
    sp.add_argument("--ai-endpoint", dest="ai_endpoint", default="", help="AI endpoint URL for Phase 2 AI probes (opt-in)")
    sp.add_argument("--ai-model",    dest="ai_model",    default="llama3", help="AI model name (default: llama3)")
    sp.add_argument("--ollama-base", dest="ollama_base", default="", help="Ollama base URL for meta probes")
    sp.add_argument("--ollama-management", dest="ollama_management", action="store_true", default=False,
                    help="Enable Ollama management endpoint probes in full mode")
    sp.add_argument("-o", "--out")
    sp.set_defaults(func=cmd_full)

    # gui
    sp = sub.add_parser("gui", help="Launch the desktop GUI")
    sp.set_defaults(func=cmd_gui)

    return p


def _load_scope(args: argparse.Namespace) -> dict | None:
    """Load scope file if provided, else return None."""
    if getattr(args, "scope_file", None):
        return load_scope_file(args.scope_file)
    return None


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    # --init-scope: write template and exit (valid without a subcommand)
    if getattr(args, "init_scope", False):
        p = write_scope_template()
        print(f"Scope template written to: {p}")
        print("Edit it, set 'authorized': true, then pass --scope-file scope.json")
        return

    # No subcommand given — print help and exit cleanly
    if not getattr(args, "func", None):
        parser.print_help()
        raise SystemExit(2)

    try:
        args.func(args)
    except ScopeError as e:
        print(f"\n[SCOPE ERROR] {e}\n")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
