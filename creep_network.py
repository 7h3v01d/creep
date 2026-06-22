"""
creep_network.py — Phase 2: Network & Service Scanner
Part of Creep: Defensive Adversarial Security Scanner
Author: Leon Priest
License: Apache 2.0

Active network probing module. Performs:
  - TCP port scanning (concurrent, configurable range)
  - Service fingerprinting via banner grabbing
  - SSL/TLS certificate & cipher audit
  - HTTP/HTTPS service detection and header audit
  - Local listening port enumeration (via psutil)
  - Known dangerous port / service flagging

REQUIRES EXPLICIT OPT-IN. Every scan run is logged with timestamp,
target, and operator. Never fires automatically.
"""

from __future__ import annotations

import concurrent.futures
import http.client
import ipaddress
import json
import socket
import ssl
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False

from creep_static import Category, Finding, Severity
from creep_gate  import check_scope, ScopeError

# ---------------------------------------------------------------------------
# Scan audit log
# ---------------------------------------------------------------------------

_AUDIT_LOG = Path.home() / ".creep" / "network_audit.jsonl"


def _log_scan(target: str, ports: str, operator: str = "creep") -> None:
    """Append a scan record to the local audit log. Fail silently."""
    try:
        _AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "operator":  operator,
            "target":    target,
            "ports":     ports,
            "module":    "creep_network",
        }
        with open(_AUDIT_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Port / service knowledge base
# ---------------------------------------------------------------------------

# Common ports to scan when no explicit list given
_DEFAULT_PORTS: list[int] = [
    # Web
    80, 443, 8000, 8001, 8008, 8080, 8443, 8888, 9000, 9443,
    # Databases
    1433, 1521, 3306, 5432, 5433, 6379, 7474, 8529, 9042, 27017, 27018,
    # Message queues / cache
    4369, 5000, 5671, 5672, 6380, 11211, 15672, 61613, 61616,
    # SSH / shell / admin
    21, 22, 23, 25, 110, 143, 389, 636, 2222, 3389, 5900, 5901,
    # AI / ML inference (Ollama, llama.cpp, etc.)
    11434, 11435, 7860, 7861, 5005,
    # FastAPI / uvicorn common defaults
    8001, 8002, 8003, 8004, 8010, 8020, 8030,
    # DNS / NTP (informational)
    53, 123,
    # Misc services
    2375, 2376,  # Docker
    6443,        # Kubernetes API
    9090, 9091,  # Prometheus / Grafana
    3000, 4000,  # Dev servers
    50051,       # gRPC
]

# Port → (service_name, severity, detail)
_DANGEROUS_PORTS: dict[int, tuple[str, Severity, str]] = {
    21:    ("FTP",        Severity.HIGH,     "FTP transmits credentials in plaintext. Disable or replace with SFTP."),
    23:    ("Telnet",     Severity.CRITICAL, "Telnet is unencrypted. All traffic including passwords is in plaintext."),
    25:    ("SMTP",       Severity.MEDIUM,   "Open SMTP relay risk. Verify authentication is required."),
    110:   ("POP3",       Severity.MEDIUM,   "POP3 (plaintext). Prefer POP3S on port 995."),
    143:   ("IMAP",       Severity.MEDIUM,   "IMAP (plaintext). Prefer IMAPS on port 993."),
    389:   ("LDAP",       Severity.MEDIUM,   "Unencrypted LDAP. Prefer LDAPS on port 636."),
    2375:  ("Docker API", Severity.CRITICAL, "Docker daemon API without TLS. Full host compromise possible."),
    2376:  ("Docker API", Severity.HIGH,     "Docker TLS API. Verify certificates are properly validated."),
    3306:  ("MySQL",      Severity.HIGH,     "MySQL exposed. Verify access is restricted to localhost or VPN."),
    5432:  ("PostgreSQL", Severity.HIGH,     "PostgreSQL exposed. Verify access is restricted."),
    5900:  ("VNC",        Severity.HIGH,     "VNC exposed. Verify strong auth and restrict to trusted IPs."),
    5901:  ("VNC",        Severity.HIGH,     "VNC exposed. Verify strong auth and restrict to trusted IPs."),
    6379:  ("Redis",      Severity.CRITICAL, "Redis commonly has no auth by default. Full data access possible."),
    6380:  ("Redis",      Severity.CRITICAL, "Redis (alt port). Verify authentication is configured."),
    11211: ("Memcached",  Severity.HIGH,     "Memcached has no auth. All cached data accessible."),
    27017: ("MongoDB",    Severity.HIGH,     "MongoDB exposed. Verify authentication is enabled."),
    27018: ("MongoDB",    Severity.HIGH,     "MongoDB (shard). Verify authentication is enabled."),
    3389:  ("RDP",        Severity.HIGH,     "RDP exposed. Brute-force and BlueKeep-class risks."),
    11434: ("Ollama",     Severity.MEDIUM,   "Ollama inference API exposed. Verify access is scoped. No auth by default."),
    7860:  ("Gradio",     Severity.MEDIUM,   "Gradio UI likely. Often runs without auth in dev mode."),
    50051: ("gRPC",       Severity.INFO,     "gRPC endpoint. Verify TLS and authentication."),
    9090:  ("Prometheus", Severity.MEDIUM,   "Prometheus metrics endpoint. May expose internal metrics."),
    9091:  ("Pushgateway",Severity.MEDIUM,   "Prometheus Pushgateway. Verify auth is configured."),
}

# HTTP security headers we check for
_SECURITY_HEADERS: dict[str, tuple[Severity, str]] = {
    "strict-transport-security": (Severity.HIGH,   "Missing HSTS header. Forces HTTP downgrade attacks."),
    "x-content-type-options":    (Severity.MEDIUM, "Missing X-Content-Type-Options. MIME sniffing attacks possible."),
    "x-frame-options":           (Severity.MEDIUM, "Missing X-Frame-Options. Clickjacking risk."),
    "content-security-policy":   (Severity.MEDIUM, "Missing Content-Security-Policy. XSS risk increased."),
    "x-xss-protection":          (Severity.LOW,    "Missing X-XSS-Protection header."),
    "referrer-policy":           (Severity.LOW,    "Missing Referrer-Policy header."),
    "permissions-policy":        (Severity.LOW,    "Missing Permissions-Policy header."),
}

# Server banners that reveal version info
_VERBOSE_SERVER = {
    "apache", "nginx", "iis", "lighttpd", "caddy",
    "uvicorn", "gunicorn", "hypercorn",
}

# Weak TLS versions
_WEAK_TLS = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"}


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class OpenPort:
    host:        str
    port:        int
    state:       str           # open / closed / filtered
    service:     str = ""
    banner:      str = ""
    tls:         bool = False
    tls_version: str = ""
    tls_issuer:  str = ""
    tls_expiry:  str = ""
    http_status: int | None = None
    http_headers: dict = field(default_factory=dict)
    latency_ms:  float = 0.0


# ---------------------------------------------------------------------------
# TCP port scanner
# ---------------------------------------------------------------------------

def _probe_port(
    host: str,
    port: int,
    timeout: float = 2.0,
) -> OpenPort | None:
    """
    Attempt TCP connect to host:port.
    Returns OpenPort on success, None if closed/filtered.
    """
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            latency = (time.monotonic() - start) * 1000
            banner  = _grab_banner(sock, port, timeout)
            return OpenPort(
                host=host,
                port=port,
                state="open",
                banner=banner,
                latency_ms=round(latency, 2),
            )
    except (ConnectionRefusedError, socket.timeout, OSError):
        return None


def _grab_banner(sock: socket.socket, port: int, timeout: float) -> str:
    """Attempt to read a service banner from an already-connected socket."""
    # Some services send a banner immediately; others need a prompt
    _PROMPT_PORTS = {
        80: b"HEAD / HTTP/1.0\r\n\r\n",
        8080: b"HEAD / HTTP/1.0\r\n\r\n",
        8000: b"HEAD / HTTP/1.0\r\n\r\n",
        21: None,   # FTP sends banner on connect
        22: None,   # SSH sends banner on connect
        25: None,   # SMTP sends banner on connect
        6379: b"PING\r\n",
        11434: b"GET /api/version HTTP/1.0\r\nHost: localhost\r\n\r\n",
    }

    sock.settimeout(min(timeout, 1.5))
    try:
        prompt = _PROMPT_PORTS.get(port, None)
        if prompt:
            sock.sendall(prompt)
        data = sock.recv(1024)
        return data.decode("utf-8", errors="replace").strip()[:300]
    except (socket.timeout, OSError, UnicodeDecodeError):
        return ""


def scan_ports(
    host: str,
    ports: list[int],
    *,
    timeout:    float = 2.0,
    max_workers: int  = 100,
    progress_cb=None,
) -> list[OpenPort]:
    """
    Concurrent TCP port scan. Returns list of open ports only.
    """
    open_ports: list[OpenPort] = []

    def _log(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    _log(f"Scanning {host} — {len(ports)} port(s) | {max_workers} workers | timeout {timeout}s")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_probe_port, host, p, timeout): p for p in ports}
        done = 0
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            result = fut.result()
            if result:
                open_ports.append(result)
                _log(f"  OPEN  {host}:{result.port}  ({result.latency_ms}ms)")

    open_ports.sort(key=lambda p: p.port)
    return open_ports


# ---------------------------------------------------------------------------
# Service fingerprinting
# ---------------------------------------------------------------------------

def _fingerprint_http(
    host: str,
    port: int,
    *,
    tls:     bool  = False,
    timeout: float = 5.0,
) -> dict:
    """
    Fetch HTTP headers from a service. Returns dict of findings.
    """
    scheme = "https" if tls else "http"
    url    = f"{scheme}://{host}:{port}/"
    result = {
        "url":          url,
        "status":       None,
        "headers":      {},
        "tls_version":  "",
        "tls_issuer":   "",
        "tls_expiry":   "",
        "tls_self_signed": False,
        "error":        None,
    }

    ctx = ssl.create_default_context() if tls else None
    if ctx and tls:
        # We want to see cert info even for self-signed
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

    try:
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "creep-scanner/0.1")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            result["status"]  = resp.status
            result["headers"] = dict(resp.headers)

            if tls and hasattr(resp, "fp") and hasattr(resp.fp, "raw"):
                pass   # SSL info pulled separately below

    except urllib.error.HTTPError as e:
        result["status"]  = e.code
        result["headers"] = dict(e.headers) if e.headers else {}
    except urllib.error.URLError as e:
        result["error"] = str(e.reason)
    except Exception as e:
        result["error"] = str(e)

    # TLS details via direct socket
    if tls and result["error"] is None:
        try:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx2.wrap_socket(raw, server_hostname=host) as ssock:
                    result["tls_version"] = ssock.version() or ""
                    cert = ssock.getpeercert(binary_form=False)
                    if cert:
                        issuer = dict(x[0] for x in cert.get("issuer", []))
                        subject = dict(x[0] for x in cert.get("subject", []))
                        result["tls_issuer"]  = issuer.get("organizationName", "")
                        result["tls_expiry"]  = cert.get("notAfter", "")
                        result["tls_self_signed"] = (
                            issuer.get("commonName") == subject.get("commonName")
                        )
        except Exception:
            pass

    return result


def fingerprint_services(
    open_ports: list[OpenPort],
    *,
    timeout:    float = 5.0,
    progress_cb=None,
) -> list[OpenPort]:
    """
    Enrich open ports with HTTP/TLS fingerprinting where applicable.
    Returns the same list with fields populated.
    """
    def _log(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    for op in open_ports:
        # Determine if likely HTTP/HTTPS
        likely_https = op.port in {443, 8443, 9443} or "ssl" in op.banner.lower()
        likely_http  = op.port in {
            80, 8000, 8001, 8002, 8003, 8004, 8008, 8010, 8020,
            8030, 8080, 8888, 9000, 11434, 7860, 3000, 4000, 5000,
        } or "HTTP" in op.banner.upper()

        if likely_https:
            _log(f"  Fingerprinting HTTPS {op.host}:{op.port}")
            info = _fingerprint_http(op.host, op.port, tls=True, timeout=timeout)
            _apply_http_info(op, info, tls=True)
        elif likely_http:
            _log(f"  Fingerprinting HTTP  {op.host}:{op.port}")
            info = _fingerprint_http(op.host, op.port, tls=False, timeout=timeout)
            # Fallback to HTTPS if HTTP fails
            if info.get("error"):
                info = _fingerprint_http(op.host, op.port, tls=True, timeout=timeout)
                _apply_http_info(op, info, tls=True)
            else:
                _apply_http_info(op, info, tls=False)

        # Service label from banner
        if not op.service:
            op.service = _guess_service(op)

    return open_ports


def _apply_http_info(op: OpenPort, info: dict, tls: bool) -> None:
    op.tls         = tls
    op.http_status = info.get("status")
    op.http_headers = {k.lower(): v for k, v in info.get("headers", {}).items()}
    op.tls_version  = info.get("tls_version", "")
    op.tls_issuer   = info.get("tls_issuer", "")
    op.tls_expiry   = info.get("tls_expiry", "")


def _guess_service(op: OpenPort) -> str:
    """Guess service name from port + banner."""
    banner_low = op.banner.lower()
    known = {
        22:    "SSH",
        21:    "FTP",
        23:    "Telnet",
        25:    "SMTP",
        80:    "HTTP",
        443:   "HTTPS",
        3306:  "MySQL",
        5432:  "PostgreSQL",
        6379:  "Redis",
        11211: "Memcached",
        27017: "MongoDB",
        3389:  "RDP",
        5900:  "VNC",
        11434: "Ollama",
        50051: "gRPC",
    }
    if op.port in known:
        return known[op.port]
    if "ssh" in banner_low:
        return "SSH"
    if "http" in banner_low or "html" in banner_low:
        return "HTTP"
    if "ftp" in banner_low:
        return "FTP"
    if "redis" in banner_low:
        return "Redis"
    if "mongodb" in banner_low:
        return "MongoDB"
    if "postgres" in banner_low or "pg" in banner_low:
        return "PostgreSQL"
    if "mysql" in banner_low or "mariadb" in banner_low:
        return "MySQL"
    if "ollama" in banner_low:
        return "Ollama"
    return "unknown"


# ---------------------------------------------------------------------------
# Local port enumeration (psutil)
# ---------------------------------------------------------------------------

def enumerate_local_ports(progress_cb=None) -> list[OpenPort]:
    """
    Use psutil to enumerate listening ports on the local machine.
    No network traffic — reads /proc/net or platform equivalent.
    """
    if not _PSUTIL:
        return []

    if progress_cb:
        progress_cb("Enumerating local listening ports via psutil…")

    results: list[OpenPort] = []
    try:
        conns = psutil.net_connections(kind="inet")
        for conn in conns:
            if conn.status != "LISTEN":
                continue
            laddr = conn.laddr
            if not laddr:
                continue
            results.append(OpenPort(
                host=laddr.ip or "0.0.0.0",
                port=laddr.port,
                state="listen",
                service=_guess_service(OpenPort(
                    host=laddr.ip or "", port=laddr.port,
                    state="listen", banner="",
                )),
            ))
    except (psutil.AccessDenied, PermissionError):
        if progress_cb:
            progress_cb("  psutil: insufficient permissions for full port list")

    results.sort(key=lambda p: p.port)
    return results


# ---------------------------------------------------------------------------
# Findings generator
# ---------------------------------------------------------------------------

def _ports_to_findings(
    open_ports: list[OpenPort],
    target:     str,
    local:      bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    label = "local" if local else target

    for op in open_ports:
        port_label = f"{op.host}:{op.port}"

        # ── Known dangerous port ─────────────────────────────────────
        if op.port in _DANGEROUS_PORTS:
            svc, sev, detail = _DANGEROUS_PORTS[op.port]
            findings.append(Finding(
                severity=sev,
                category=Category.NETWORK,
                target=label,
                title=f"Dangerous service exposed: {svc} on port {op.port}",
                detail=detail,
                evidence=f"{port_label} | banner: {op.banner[:80]}" if op.banner else port_label,
                module="network",
            ))

        # ── HTTP service: missing security headers ───────────────────
        if op.http_headers:
            for header, (sev, msg) in _SECURITY_HEADERS.items():
                if header not in op.http_headers:
                    findings.append(Finding(
                        severity=sev,
                        category=Category.NETWORK,
                        target=label,
                        title=f"Missing HTTP header: {header} on port {op.port}",
                        detail=msg,
                        evidence=f"{port_label}",
                        module="network",
                    ))

            # Verbose Server header
            server = op.http_headers.get("server", "")
            if any(s in server.lower() for s in _VERBOSE_SERVER) and "/" in server:
                findings.append(Finding(
                    severity=Severity.LOW,
                    category=Category.NETWORK,
                    target=label,
                    title=f"Verbose Server header on port {op.port}",
                    detail=(
                        f"Server header '{server}' reveals software version. "
                        "This aids fingerprinting. Consider suppressing or genericising."
                    ),
                    evidence=f"{port_label} | Server: {server}",
                    module="network",
                ))

            # X-Powered-By leakage
            powered = op.http_headers.get("x-powered-by", "")
            if powered:
                findings.append(Finding(
                    severity=Severity.LOW,
                    category=Category.NETWORK,
                    target=label,
                    title=f"X-Powered-By header leaks tech stack on port {op.port}",
                    detail=(
                        f"X-Powered-By: {powered} reveals framework/runtime. "
                        "Remove this header in production."
                    ),
                    evidence=f"{port_label} | X-Powered-By: {powered}",
                    module="network",
                ))

        # ── TLS checks ───────────────────────────────────────────────
        if op.tls:
            if op.tls_version in _WEAK_TLS:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category=Category.NETWORK,
                    target=label,
                    title=f"Weak TLS version on port {op.port}: {op.tls_version}",
                    detail=(
                        f"{op.tls_version} is deprecated and vulnerable to downgrade attacks. "
                        "Enforce TLS 1.2 minimum, prefer TLS 1.3."
                    ),
                    evidence=f"{port_label} | TLS: {op.tls_version}",
                    module="network",
                ))

            if op.tls_expiry:
                try:
                    from datetime import datetime as dt
                    expiry = dt.strptime(op.tls_expiry, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - dt.utcnow()).days
                    if days_left < 0:
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            category=Category.NETWORK,
                            target=label,
                            title=f"Expired TLS certificate on port {op.port}",
                            detail=f"Certificate expired {abs(days_left)} day(s) ago ({op.tls_expiry}).",
                            evidence=f"{port_label} | issuer: {op.tls_issuer}",
                            module="network",
                        ))
                    elif days_left < 30:
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            category=Category.NETWORK,
                            target=label,
                            title=f"TLS certificate expiring soon on port {op.port}",
                            detail=f"Certificate expires in {days_left} day(s) ({op.tls_expiry}).",
                            evidence=f"{port_label} | issuer: {op.tls_issuer}",
                            module="network",
                        ))
                except (ValueError, TypeError):
                    pass

        # ── HTTP without TLS on non-localhost ────────────────────────
        if (op.http_status is not None and not op.tls
                and op.host not in ("127.0.0.1", "::1", "localhost")):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=Category.NETWORK,
                target=label,
                title=f"HTTP (plaintext) on non-localhost port {op.port}",
                detail=(
                    f"Service on {port_label} serves HTTP without TLS. "
                    "All traffic including auth tokens is in plaintext."
                ),
                evidence=f"HTTP {op.http_status} at {port_label}",
                module="network",
            ))

        # ── Ollama specific: no auth by default ──────────────────────
        if op.port == 11434 or op.service == "Ollama":
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=Category.AUTH,
                target=label,
                title=f"Ollama inference API exposed on port {op.port}",
                detail=(
                    "Ollama has no authentication by default. Any process or user "
                    "that can reach this port can query, pull, or delete models. "
                    "Bind to 127.0.0.1 or add a reverse proxy with auth."
                ),
                evidence=f"{port_label} | banner: {op.banner[:80]}" if op.banner else port_label,
                module="network",
            ))

    findings.sort(key=lambda f: (f.severity.rank, f.target))
    return findings


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------

def run_network_scan(
    target:       str,
    *,
    ports:        list[int] | None = None,
    port_range:   tuple[int, int] | None = None,
    timeout:      float = 2.0,
    max_workers:  int   = 100,
    fingerprint:  bool  = True,
    local_enum:   bool  = True,
    operator:     str   = "creep",
    authorized:   bool  = False,
    allow_public: bool  = False,
    scope:        dict | None = None,
    progress_cb=None,
) -> tuple[list[OpenPort], list[Finding]]:
    """
    Run a full Phase 2 network scan against a host.

    Args:
        target:      IP address or hostname to scan.
        ports:       Explicit port list (overrides port_range and defaults).
        port_range:  (start, end) inclusive range.
        timeout:     Per-port TCP connect timeout in seconds.
        max_workers: Thread pool size for concurrent scanning.
        fingerprint: Whether to HTTP/TLS fingerprint open ports.
        local_enum:  Whether to enumerate local listening ports via psutil.
        operator:     Identity written to the audit log.
        authorized:   Must be True — gate raises ScopeError otherwise.
        allow_public: Allow scanning public/routable IP addresses.
        scope:        Optional scope dict from a scope file.
        progress_cb:  Optional callable(msg: str) for live progress.

    Returns:
        (open_ports, findings)
    """
    def _log(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    # Build port list
    if ports:
        scan_ports_list = ports
    elif port_range:
        scan_ports_list = list(range(port_range[0], port_range[1] + 1))
    else:
        scan_ports_list = _DEFAULT_PORTS

    # ── Scope gate — must pass before any packets go out ────────────────
    check_scope(target, authorized=authorized, allow_public=allow_public,
                scope=scope, module="network")

    # Audit log — written before any packets go out
    _log_scan(target, f"{len(scan_ports_list)} ports", operator)
    _log(f"[AUDIT] Scan logged: {target} | {len(scan_ports_list)} port(s) | operator={operator}")

    all_open:    list[OpenPort] = []
    all_findings: list[Finding] = []

    # ── Remote port scan ─────────────────────────────────────────────
    _log(f"\n── Remote scan: {target} ──────────────────────────────")
    remote_open = scan_ports(
        target, scan_ports_list,
        timeout=timeout, max_workers=max_workers,
        progress_cb=progress_cb,
    )
    all_open.extend(remote_open)

    _log(f"\n  {len(remote_open)} open port(s) found on {target}")

    # ── Service fingerprinting ────────────────────────────────────────
    if fingerprint and remote_open:
        _log(f"\n── Fingerprinting services on {target} ──────────────────")
        remote_open = fingerprint_services(
            remote_open, timeout=timeout + 3, progress_cb=progress_cb,
        )

    # ── Local port enumeration ────────────────────────────────────────
    local_ports: list[OpenPort] = []
    if local_enum:
        _log("\n── Local listening ports ────────────────────────────────")
        local_ports = enumerate_local_ports(progress_cb=progress_cb)
        _log(f"  {len(local_ports)} listening port(s) on localhost")
        all_open.extend(local_ports)

    # ── Generate findings ─────────────────────────────────────────────
    all_findings.extend(_ports_to_findings(remote_open, target, local=False))
    if local_ports:
        all_findings.extend(_ports_to_findings(local_ports, "localhost", local=True))

    all_findings.sort(key=lambda f: (f.severity.rank, f.target))
    return all_open, all_findings


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import argparse

    p = argparse.ArgumentParser(
        description="creep_network — Phase 2 network scanner (ACTIVE)",
        epilog="Only scan systems you own or have written permission to test.",
    )
    p.add_argument("target", help="IP address or hostname to scan")
    p.add_argument(
        "--range", dest="port_range", default=None, metavar="START-END",
        help="Port range to scan, e.g. 1-1024 (default: common ports)",
    )
    p.add_argument(
        "--i-am-authorized", dest="authorized", action="store_true",
        help="Assert explicit authorisation to scan this target (required)",
    )
    p.add_argument(
        "--allow-public", dest="allow_public", action="store_true",
        help="Allow scanning public/routable IPs",
    )
    p.add_argument(
        "--scope-file", dest="scope_file", default=None, metavar="FILE",
        help="Path to a scope.json file (grants authorisation if 'authorized: true' is set).",
    )
    args = p.parse_args()

    # Load scope file if provided — can substitute for --i-am-authorized
    scope = None
    if args.scope_file:
        from creep_gate import load_scope_file, ScopeError as _SE
        try:
            scope = load_scope_file(args.scope_file)
            args.authorized   = args.authorized   or bool(scope.get("authorized",   False))
            args.allow_public = args.allow_public or bool(scope.get("allow_public", False))
        except _SE as e:
            print(f"\n[creep-network] ERROR: {e}\n")
            sys.exit(1)

    if not args.authorized:
        print("ERROR: creep_network.py requires --i-am-authorized to run.")
        print("       This prevents accidental scanning of unauthorized targets.")
        print("       Alternatively, use --scope-file scope.json with 'authorized: true'.")
        print(f"       Example: python creep_network.py --i-am-authorized {args.target}")
        sys.exit(1)

    host   = args.target
    prange = None
    if args.port_range:
        try:
            parts  = args.port_range.split("-")
            prange = (int(parts[0]), int(parts[1]))
        except (ValueError, IndexError):
            print(f"[creep-network] ERROR: --range must be START-END, e.g. 1-1024")
            sys.exit(1)

    print(f"\n[creep-network] Target: {host}")
    print("=" * 60)
    print("  AUTHORIZED — active scan proceeding")
    print("=" * 60 + "\n")

    open_ports, findings = run_network_scan(
        host,
        port_range=prange,
        authorized=args.authorized,
        allow_public=args.allow_public,
        scope=scope,
        progress_cb=lambda m: print(f"  {m}"),
    )

    print(f"\n{'─'*60}")
    print(f"  Open ports: {len([p for p in open_ports if p.state == 'open'])}")
    print(f"  Findings  : {len(findings)}")
    print(f"{'─'*60}\n")

    for op in open_ports:
        if op.state == "open":
            tls_str = f" [TLS:{op.tls_version}]" if op.tls_version else ""
            svc_str = f" ({op.service})" if op.service else ""
            print(f"  OPEN  {op.host}:{op.port}{svc_str}{tls_str}  {op.latency_ms}ms")
            if op.banner:
                print(f"        banner: {op.banner[:100]!r}")

    print()
    for f in findings:
        print(f"[{f.severity.value:<8}] {f.title}")
        print(f"           Target  : {f.target}")
        print(f"           Detail  : {f.detail}")
        if f.evidence:
            print(f"           Evidence: {f.evidence}")
        print()
