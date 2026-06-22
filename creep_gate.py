"""
creep_gate.py — Active Scan Authorisation Gate
Part of Creep: Defensive Adversarial Security Scanner
Author: Leon Priest
License: Apache 2.0

All Phase 2 (active) modules call check_scope() before sending any traffic.
The gate enforces:

  1. Authorisation must be explicitly granted via one of:
       - authorized=True  (programmatic / GUI)
       - --i-am-authorized  (CLI flag, parsed by creep.py)
       - a scope file (--scope-file scope.json)

  2. Target classification:
       ALLOWED by default:
         - localhost / 127.x.x.x / ::1
         - RFC 1918 private ranges (10.x, 172.16-31.x, 192.168.x)
         - Link-local (169.254.x — but NOT AWS metadata endpoint)

       BLOCKED by default (require --allow-public):
         - Public routable IPs and hostnames
         - Cloud metadata endpoints (169.254.169.254, fd00:ec2::254)
         - Multicast / broadcast / reserved ranges

  3. Scope file format (JSON):
       {
         "authorized": true,
         "allow_public": false,
         "targets": ["192.168.0.0/24", "10.0.0.1", "localhost"],
         "note": "Authorised by: Leon Priest, 2026-06-21"
       }

Usage:
    from creep_gate import check_scope, ScopeError

    # Will raise ScopeError if not authorised or target out of scope
    check_scope("192.168.0.163", authorized=True)

    # Raises ScopeError with helpful message
    check_scope("8.8.8.8", authorized=True)
    # ScopeError: 8.8.8.8 is a public IP. Active scans against public targets
    # require --allow-public. Ensure you have written authorisation first.
"""

from __future__ import annotations

import ipaddress
import json
import socket
from pathlib import Path


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------

class ScopeError(Exception):
    """Raised when a target is out of scope or authorisation is missing."""
    pass


# ---------------------------------------------------------------------------
# Known dangerous / blocked addresses
# ---------------------------------------------------------------------------

# Cloud metadata endpoints — never scan these
_BLOCKED_HOSTS = {
    "169.254.169.254",          # AWS / Azure / GCP metadata
    "metadata.google.internal",
    "metadata.internal",
    "fd00:ec2::254",            # AWS IPv6 metadata
}

# Blocked IP networks (regardless of allow_public)
_ALWAYS_BLOCKED_NETWORKS = [
    ipaddress.ip_network("169.254.169.254/32"),   # AWS metadata
    ipaddress.ip_network("100.100.100.200/32"),   # Alibaba Cloud metadata
    ipaddress.ip_network("192.0.0.0/24"),          # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),          # TEST-NET-1 (documentation)
    ipaddress.ip_network("198.51.100.0/24"),       # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),        # TEST-NET-3
    ipaddress.ip_network("240.0.0.0/4"),           # Reserved
    ipaddress.ip_network("255.255.255.255/32"),    # Broadcast
    ipaddress.ip_network("0.0.0.0/8"),             # "This" network
]

# Private / local ranges (allowed by default)
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),           # Loopback
    ipaddress.ip_network("10.0.0.0/8"),            # RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),         # RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),        # RFC 1918
    ipaddress.ip_network("169.254.0.0/16"),        # Link-local (excl. metadata)
    ipaddress.ip_network("::1/128"),               # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),              # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),             # IPv6 link-local
]


# ---------------------------------------------------------------------------
# Scope file loader
# ---------------------------------------------------------------------------

def load_scope_file(path: str | Path) -> dict:
    """
    Load and validate a JSON scope file.
    Returns the parsed dict.
    Raises ScopeError if file is missing, malformed, or missing 'authorized'.
    """
    p = Path(path)
    if not p.exists():
        raise ScopeError(f"Scope file not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ScopeError(f"Scope file is not valid JSON: {e}")
    if not isinstance(data, dict):
        raise ScopeError("Scope file must be a JSON object.")
    if not data.get("authorized"):
        raise ScopeError(
            f"Scope file '{p}' does not contain 'authorized: true'. "
            "Add it to confirm this scan is authorised."
        )
    # If allow_public is true, a non-empty targets list is required.
    # A scope file that grants public access without naming specific targets
    # is too broad to be auditable — it's indistinguishable from "scan anything."
    if data.get("allow_public"):
        targets = data.get("targets", [])
        if not targets:
            raise ScopeError(
                f"Scope file '{p}' sets 'allow_public: true' but has no 'targets' list.\n"
                "Public-target scope files must name at least one hostname, IP, or CIDR.\n"
                "Example: \"targets\": [\"203.0.113.10\", \"example.com\"]\n"
                "This ensures scope files remain auditable rather than a blanket override."
            )
    return data


# ---------------------------------------------------------------------------
# IP resolution and classification
# ---------------------------------------------------------------------------

def _extract_host(target: str) -> str:
    """
    Robustly extract the bare hostname or IP from any of these forms:
      - raw IPv4:           192.168.0.1
      - raw IPv6:           ::1  /  fc00::1  /  fe80::1%eth0
      - host:port:          example.com:8080
      - [ipv6]:port:        [::1]:8080
      - full URL:           http://example.com:8080/path
      - URL with IPv6:      http://[::1]:11434/api/chat

    Returns the bare host string (no brackets, no port, no path).
    """
    import urllib.parse

    s = target.strip()

    # Full URL — let urllib do the heavy lifting
    if s.startswith(("http://", "https://", "ws://", "wss://")):
        parsed = urllib.parse.urlparse(s)
        host = parsed.hostname or s  # hostname strips brackets and lowercases
        return host

    # [ipv6]:port  or  [ipv6]
    if s.startswith("["):
        bracket_end = s.find("]")
        if bracket_end != -1:
            return s[1:bracket_end]   # content between [ and ]
        return s  # malformed — return as-is, let resolution fail later

    # Raw IPv6: contains two or more colons (not a host:port)
    if s.count(":") >= 2:
        # Strip any zone-ID suffix (fe80::1%eth0 → fe80::1)
        return s.split("%")[0]

    # host:port  or  plain host/IPv4
    return s.split(":")[0]


def _resolve_host(target: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Resolve a hostname or IP string to an ip_address object. Returns None on failure."""
    host = _extract_host(target)
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    # Try DNS resolution
    try:
        resolved = socket.getaddrinfo(host, None)[0][4][0]
        return ipaddress.ip_address(resolved)
    except (socket.gaierror, OSError, ValueError):
        return None


def _is_always_blocked(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(addr in net for net in _ALWAYS_BLOCKED_NETWORKS)


def _is_private(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(addr in net for net in _PRIVATE_NETWORKS)


def _classify_target(target: str) -> str:
    """
    Returns one of: 'localhost', 'private', 'public', 'blocked', 'unresolvable'.
    """
    host = _extract_host(target).lower()

    # Blocked hostnames (metadata etc.) — checked before localhost shortcut
    if host in _BLOCKED_HOSTS:
        return "blocked"

    # 0.0.0.0 falls into _ALWAYS_BLOCKED_NETWORKS (0.0.0.0/8); don't shortcut it
    # to "localhost" — let the network check below handle it.
    if host in ("localhost", "127.0.0.1", "::1"):
        return "localhost"

    addr = _resolve_host(target)
    if addr is None:
        return "unresolvable"

    if _is_always_blocked(addr):
        return "blocked"

    if addr.is_loopback:
        return "localhost"

    if _is_private(addr):
        return "private"

    return "public"


def _in_scope_targets(target: str, scope_targets: list[str]) -> bool:
    """Check if target matches any entry in a scope file targets list."""
    host = _extract_host(target).lower()
    addr = _resolve_host(target)

    for entry in scope_targets:
        entry = entry.strip()
        # Exact hostname match
        if entry.lower() == host:
            return True
        # CIDR network match
        try:
            net = ipaddress.ip_network(entry, strict=False)
            if addr and addr in net:
                return True
        except ValueError:
            pass
        # IP exact match
        try:
            if addr and ipaddress.ip_address(entry) == addr:
                return True
        except ValueError:
            pass

    return False


# ---------------------------------------------------------------------------
# Primary gate function
# ---------------------------------------------------------------------------

def check_scope(
    target:       str,
    *,
    authorized:   bool       = False,
    allow_public: bool       = False,
    scope:        dict | None = None,
    module:       str        = "active",
) -> None:
    """
    Validate that an active scan against `target` is permitted.

    Args:
        target:       IP address, hostname, or URL to scan.
        authorized:   Caller asserts explicit authorisation (GUI checkbox,
                      CLI --i-am-authorized flag, or scope file).
        allow_public: Allow scanning public/routable IPs (requires authorized).
        scope:        Parsed scope file dict (from load_scope_file()).
        module:       Name of the calling module (for error messages).

    Raises:
        ScopeError: With a descriptive message if the scan should not proceed.
    """

    # ── Pull settings from scope file if provided ─────────────────────
    if scope:
        authorized   = authorized or bool(scope.get("authorized", False))
        allow_public = allow_public or bool(scope.get("allow_public", False))
        scope_targets: list[str] = scope.get("targets", [])
    else:
        scope_targets = []

    # ── Authorisation required for ALL active modules ─────────────────
    if not authorized:
        raise ScopeError(
            f"[{module}] Active scan requires explicit authorisation.\n"
            f"  CLI:  add --i-am-authorized\n"
            f"  API:  pass authorized=True\n"
            f"  File: use --scope-file scope.json with 'authorized: true'\n"
            f"  GUI:  check the 'I am authorised' box before scanning\n\n"
            f"  Only scan systems you own or have written permission to test."
        )

    # ── Classify the target ───────────────────────────────────────────
    classification = _classify_target(target)

    if classification == "blocked":
        raise ScopeError(
            f"[{module}] Target '{target}' is a blocked address "
            f"(cloud metadata, broadcast, or reserved range).\n"
            f"  Scanning cloud metadata endpoints is never permitted."
        )

    if classification == "unresolvable":
        raise ScopeError(
            f"[{module}] Target '{target}' could not be resolved to an IP address.\n"
            f"  Verify the hostname is correct and reachable before scanning."
        )

    # ── Scope file target list check ──────────────────────────────────
    if scope_targets:
        if not _in_scope_targets(target, scope_targets):
            raise ScopeError(
                f"[{module}] Target '{target}' is not in the scope file's "
                f"allowed targets list.\n"
                f"  Scope file targets: {scope_targets}\n"
                f"  Add the target to the scope file or use a broader CIDR."
            )

    # ── Public IP enforcement ─────────────────────────────────────────
    if classification == "public" and not allow_public:
        raise ScopeError(
            f"[{module}] Target '{target}' resolves to a public IP address.\n"
            f"  Active scans against public targets require explicit opt-in:\n"
            f"  CLI:  add --allow-public\n"
            f"  API:  pass allow_public=True\n"
            f"  File: add 'allow_public: true' to your scope file\n\n"
            f"  Ensure you have written authorisation from the target owner."
        )

    # ── Passed all checks ─────────────────────────────────────────────
    # (returns normally — caller proceeds with scan)


# ---------------------------------------------------------------------------
# URL → host extractor (for fuzz/auth/ai which take URLs not IPs)
# ---------------------------------------------------------------------------

def host_from_url(url: str) -> str:
    """Extract the hostname from a URL for scope checking."""
    return _extract_host(url)


def check_scope_url(
    url:          str,
    *,
    authorized:   bool        = False,
    allow_public: bool        = False,
    scope:        dict | None = None,
    module:       str         = "active",
) -> None:
    """check_scope() for callers that have a URL rather than a bare host."""
    host = host_from_url(url)
    check_scope(
        host,
        authorized=authorized,
        allow_public=allow_public,
        scope=scope,
        module=module,
    )


# ---------------------------------------------------------------------------
# Scope file template generator
# ---------------------------------------------------------------------------

def write_scope_template(path: str | Path = "scope.json") -> Path:
    """Write a blank scope file template to disk."""
    template = {
        "authorized": False,
        "allow_public": False,
        "targets": [
            "192.168.0.0/24",
            "10.0.0.1",
            "localhost"
        ],
        "note": (
            "Set authorized=true and list your targets before scanning. "
            "If allow_public=true, targets must be non-empty (required for auditability)."
        ),
        "operator": "",
        "date": "",
    }
    p = Path(path)
    p.write_text(json.dumps(template, indent=2), encoding="utf-8")
    return p
