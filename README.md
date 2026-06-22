# Creep

**Defensive Adversarial Security Scanner**

> *Scout finds what's there. Creep safely pressure-tests it.*

---

> **⚠ AUTHORISED USE ONLY**
>
> CREEP is for authorised defensive security testing only.
>
> - Do **not** run active modules against systems you do not own or have written permission to test.
> - Active modules **fail closed by default** and require explicit authorisation or a scope file before any traffic is sent.
> - This repository does **not** contain malware, persistence mechanisms, credential theft tooling, command-and-control infrastructure, or destructive payloads.
>
> See [SAFE_USE.md](SAFE_USE.md), [SECURITY.md](SECURITY.md), and [DISCLAIMER.md](DISCLAIMER.md) for full responsible-use guidance.

---

Creep is a local-first, Python-based adversarial security scanner for developers who want to find vulnerabilities in their own systems before anyone else does. It pairs naturally with [UCI Scout](https://github.com/7h3v01d/uci-scout) — Scout maps your API surface, Creep tests it under controlled, governed conditions.

**Author:** Leon Priest
**License:** Apache 2.0
**GitHub:** [7h3v01d](https://github.com/7h3v01d)

---

## What it does

Creep runs in two phases:

**Phase 1 — Static (safe, no network traffic)**
- AST-level code analysis: `eval()`, `pickle.loads()`, `subprocess(shell=True)`, hardcoded secrets, weak crypto, dangerous permissions
- Dependency CVE audit via pip-audit + OSV database: known vulnerabilities, unpinned packages, outdated major versions
- API surface mapping: discovers every HTTP/WebSocket/UCI endpoint, flags unprotected routes, missing rate limiting, debug endpoints

**Phase 2 — Active (opt-in, requires explicit authorisation)**
- Network scan: concurrent TCP port scan, service fingerprinting, banner grab, SSL/TLS audit, HTTP security header check
- API fuzzer: 119 payloads across SQL injection, NoSQL, command injection, path traversal, XSS, SSTI, XXE, boundary inputs, JSON abuse
- Auth bypass probes: JWT attacks (none-alg, weak secret, claim escalation), default credentials, header spoofing, verb tampering, path normalisation bypass
- AI/LLM probes: 56 probes across prompt injection, system prompt extraction, jailbreak, agent boundary violations, SSRF, model info leakage — with dedicated Ollama management endpoint checks

CREEP does not upload source code, findings, or reports anywhere. Every active scan is logged to `~/.creep/` before any traffic goes out. Note: dependency CVE checks (`creep_deps`) may query external package/vulnerability databases (PyPI, OSV) unless the relevant checks are skipped.

---

## Installation

```bash
git clone https://github.com/7h3v01d/creep
cd creep
pip install -r requirements.txt
```

**Requirements:**
- Python 3.10+
- `requests` — HTTP client for active modules
- `pip-audit` — CVE database queries
- `psutil` — local port enumeration
- `PyQt6` — desktop GUI (optional if using CLI only)

---

## Usage

### Desktop GUI

```bash
python creep_gui.py
```

Or via the CLI entry point:

```bash
python creep.py gui
```

The GUI provides a sidebar with Phase 1 modules checked by default and Phase 2 modules unchecked. Active modules prompt for confirmation before any traffic is sent. Findings populate live as the scan runs. Click any finding to expand detail. Export to JSON or HTML when done.

### CLI

```bash
# Phase 1 — safe, no authorization needed
python creep.py static  ./myproject
python creep.py deps    ./myproject
python creep.py surface ./myproject

# deps privacy controls — CVE/outdated checks query PyPI/OSV by default
python creep.py deps ./myproject --offline          # skip all network checks
python creep.py deps ./myproject --no-cve           # skip CVE lookup only
python creep.py deps ./myproject --no-outdated      # skip outdated-package check
python creep.py deps ./myproject --scan-env         # also audit current interpreter env

# Phase 2 — active probes require --i-am-authorized BEFORE the subcommand
# The authorization flag is global and must precede the subcommand name.

python creep.py --i-am-authorized network 192.168.0.163
python creep.py --i-am-authorized network 192.168.0.163 --range 1-1024

# Fuzz with default tier (standard — no cmd injection or XXE)
python creep.py --i-am-authorized fuzz http://localhost:8000/api/search GET q
# Fuzz with safe tier (boundary inputs + low-impact JSON structure probes)
python creep.py --i-am-authorized fuzz http://localhost:8000/api/search --tier safe
# Fuzz with dangerous tier (includes cmd injection + XXE) — use carefully
python creep.py --i-am-authorized fuzz http://localhost:8000/api/search --tier dangerous

python creep.py --i-am-authorized auth http://localhost:8000/api/admin
python creep.py --i-am-authorized auth http://localhost:8000/api/admin \
    --jwt eyJ... \
    --login-url http://localhost:8000/auth/login

python creep.py --i-am-authorized ai http://192.168.0.163:11434/api/chat llama3 \
    --ollama-base http://192.168.0.163:11434
# Include Ollama pull/delete endpoint probes (read-only meta probes run by default)
python creep.py --i-am-authorized ai http://192.168.0.163:11434/api/chat llama3 \
    --ollama-base http://192.168.0.163:11434 --ollama-management

# Full run — Phase 1 always safe; Phase 2 requires --i-am-authorized
python creep.py --i-am-authorized full ./myproject --base-url http://localhost:8000
# Add AI probes explicitly (opt-in)
python creep.py --i-am-authorized full ./myproject \
  --base-url http://localhost:8000 \
  --ai-endpoint http://localhost:11434/api/chat \
  --ai-model llama3
# Public targets also need --allow-public
python creep.py --i-am-authorized --allow-public full ./myproject --base-url https://staging.example.com

# Save reports
python creep.py static ./myproject -o report.html
python creep.py --i-am-authorized full ./myproject -o report.json
```

### As a library

```python
from creep_static  import run_static_scan
from creep_deps    import run_deps_scan
from creep_surface import run_surface_scan
from creep_network import run_network_scan
from creep_fuzz    import fuzz_targets, FuzzTarget, targets_from_surface
from creep_auth    import run_auth_scan
from creep_ai      import run_ai_scan
from creep_report  import build_report

# Phase 1
static_findings           = run_static_scan("./myproject")
deps_findings             = run_deps_scan("./myproject")
endpoints, surf_findings  = run_surface_scan("./myproject")

# Phase 2 — active (requires authorisation)
# Option A: explicit flags
_, net_findings  = run_network_scan("192.168.0.163", authorized=True)

fuzz_tgts        = targets_from_surface(endpoints, "http://localhost:8000")
_, fuzz_findings = fuzz_targets(fuzz_tgts, authorized=True)

_, auth_findings = run_auth_scan("http://localhost:8000/api/admin", authorized=True)

_, ai_findings   = run_ai_scan(
    "http://192.168.0.163:11434/api/chat",
    model="llama3",
    ollama_base="http://192.168.0.163:11434",
    authorized=True,
)

# Option B: scope file (recommended for reproducible scans)
from creep_gate import load_scope_file
scope = load_scope_file("scope.json")   # must contain "authorized": true

_, net_findings  = run_network_scan("192.168.0.163", scope=scope)
_, fuzz_findings = fuzz_targets(fuzz_tgts, scope=scope)
_, auth_findings = run_auth_scan("http://localhost:8000/api/admin", scope=scope)
_, ai_findings   = run_ai_scan(
    "http://192.168.0.163:11434/api/chat",
    model="llama3",
    ollama_base="http://192.168.0.163:11434",
    scope=scope,
)

# Unified report
report = build_report(
    "myproject",
    static_findings, deps_findings, surf_findings,
    net_findings, fuzz_findings, auth_findings, ai_findings,
)
report.save_html("creep_report.html")
report.save_json("creep_report.json")
print(report.summary())
```

---

## Module reference

| File | Lines | Purpose |
|---|---|---|
| `creep.py` | 488 | CLI entry point |
| `creep_static.py` | 647 | AST scan, secret detection, config audit |
| `creep_deps.py` | 496 | CVE audit, unpinned deps, outdated packages |
| `creep_surface.py` | 718 | HTTP/WS/UCI endpoint inventory, auth gaps |
| `creep_network.py` | 805 | Port scan, banner grab, TLS/header audit |
| `creep_fuzz.py` | 831 | 119 payloads — 9 injection categories |
| `creep_auth.py` | 1119 | JWT attacks, default creds, bypass probes |
| `creep_ai.py` | 933 | 56 AI probes — injection, jailbreak, SSRF |
| `creep_gate.py` | 401 | Authorisation gate, scope file loader |
| `creep_report.py` | 528 | Unified report, risk scoring, JSON + HTML |
| `creep_gui.py` | 1366 | PyQt6 desktop GUI |
| `test_creep.py` | 1149 | 38 regression tests |
| **Total** | **9,481** | |

---

## Findings

Every finding has a consistent structure across all modules:

```
[SEVERITY ] Title
             Target  : file/url:line
             Detail  : explanation
             Evidence: specific evidence
```

Severity levels: `CRITICAL` → `HIGH` → `MEDIUM` → `LOW` → `INFO`

The report risk score (0–100) is weighted: CRITICAL×10, HIGH×5, MEDIUM×2, LOW×1, capped at 100.

---

## Payload library

### Fuzzer (119 total)

| Category | Count | Detects |
|---|---|---|
| SQL injection | 16 | Auth bypass, UNION-based, blind SLEEP |
| NoSQL injection | 7 | MongoDB `$gt/$ne/$where` operator abuse |
| Command injection | 17 | Shell metacharacters, time-based blind |
| Path traversal | 16 | `../` variants, URL-encoded, Windows paths |
| XSS | 12 | Reflection, DOM, `javascript:` URI |
| SSTI | 12 | Jinja2, Twig, Freemarker, EL |
| Boundary inputs | 27 | Empty, null byte, integer overflow, format string |
| JSON abuse | 9 | Prototype pollution, deeply nested, oversized |
| XXE | 3 | File read, SSRF (opt-in) |

### Auth (80+ probes per target)

| Technique | Count | Detects |
|---|---|---|
| JWT none-alg | 4 | Case variants — `none/None/NONE/nOnE` |
| JWT weak secret | 26 | Re-signs with common secrets, exact match |
| JWT claim escalation | 15 | `role=admin`, `is_admin=true`, `sub=1`, etc. |
| Default credentials | 20 | admin/admin, root/root, ollama/ollama, etc. |
| Header spoofing | 19 | `X-Forwarded-For`, `X-Role`, `X-Is-Admin`, etc. |
| Verb tampering | 10 | All HTTP methods + `ARBITRARY`/`FAKE` |
| Path normalisation | 12 | Uppercase, double slash, null byte, dot segments |

### AI (56 probes)

| Category | Count | Detects |
|---|---|---|
| System prompt extraction | 10 | Direct ask, translate trick, base64, completion |
| Prompt injection | 10 | Newline, RTL override, zero-width chars, XML/YAML |
| Jailbreak | 10 | DAN, hypothetical, roleplay, grandma trick |
| Agent boundary | 8 | Tool call abuse, file read/write, shell exec |
| Info leakage | 8 | Model name, training data, config, PII |
| DoS | 5 | Token flood, recursive expansion, context bomb |
| SSRF | 5 | Localhost, AWS metadata, Ollama, `file://` |

---

## Audit logs

Every active module writes to `~/.creep/` before sending traffic:

```
~/.creep/
  network_audit.jsonl   # port scans
  fuzz_audit.jsonl      # fuzz probes
  auth_audit.jsonl      # auth probes
  ai_audit.jsonl        # AI probes
```

Each entry records timestamp, target, technique, and result. The log is written before the probe fires — if Creep crashes mid-scan, you still have a record of what was attempted.

---

## Scope files

A scope file is a JSON document that records authorisation for a scan in a reproducible, auditable way. It is the recommended alternative to the `--i-am-authorized` flag for anything beyond a quick one-off test.

```json
{
  "authorized": true,
  "allow_public": false,
  "targets": ["192.168.0.0/24", "10.0.0.1"],
  "operator": "Leon Priest",
  "date": "2026-06-22",
  "note": "Authorised by system owner — internal pentest"
}
```

**Rules enforced by `load_scope_file()`:**

- `authorized` must be `true` — a scope file without it is rejected at load time
- If `allow_public` is `true`, `targets` must be a non-empty list — a public scope file without explicit targets is too broad to be auditable and is rejected
- The `targets` list accepts hostnames, IPs, and CIDR ranges; scope gate enforces this list per-probe

Generate a template with:

```bash
python creep.py --init-scope
```

---

## Design principles

- **Fail-closed defaults** — Phase 2 modules require explicit opt-in every run; they never fire automatically
- **Audit before action** — every active scan logs to disk before any packet goes out
- **No source/report exfiltration** — source code, findings, and reports stay local. Optional dependency CVE/outdated checks may query external package databases (PyPI, OSV) unless disabled with `--offline`, `--no-cve`, or `--no-outdated`
- **Surgical, not scorched earth** — write-class probes (e.g. Ollama model pull/delete) require explicit opt-in flags such as `--ollama-management`; fuzzer DELETE targets are skipped by default and require the library-level `force=True` option; all active traffic is rate-limited by default
- **Consistent finding model** — all modules emit the same `Finding` dataclass; the report pipeline is module-agnostic
- **Local-first** — no API keys, no accounts, no cloud dependency for any Phase 1 operation

---

## Relationship to UCI Scout

[UCI Scout](https://github.com/7h3v01d/uci-scout) scans Python projects to discover UCI-compatible API surfaces. Creep's `creep_surface.py` borrows from Scout's AST crawler and its endpoint inventory feeds directly into `creep_fuzz.targets_from_surface()` — so a Scout scan can seed a Creep fuzz run without any manual configuration.

---

## Disclaimer

Creep is a security research and development tool intended for use on systems you own or have explicit written authorisation to test. Unauthorised use against systems you do not own or control may be illegal. The author accepts no liability for misuse.

---

## Repository structure

```
creep/
├── creep.py              CLI entry point
├── creep_static.py       Phase 1: AST + secret + config scan
├── creep_deps.py         Phase 1: CVE / dependency audit
├── creep_surface.py      Phase 1: API surface mapping
├── creep_network.py      Phase 2: port scan + service fingerprint
├── creep_fuzz.py         Phase 2: API fuzzer
├── creep_auth.py         Phase 2: auth bypass probes
├── creep_ai.py           Phase 2: AI/LLM probes
├── creep_report.py       Unified report generator
├── creep_gui.py          PyQt6 desktop GUI
├── requirements.txt
└── README.md
```
