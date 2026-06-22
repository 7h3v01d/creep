# Safe Use Guide

CREEP is a governed defensive adversarial security scanner. This document explains how to use it responsibly and what safeguards are built in.

---

## The cardinal rule

**Only scan systems you own or have explicit written authorisation to test.**

This applies to every active module: network scanning, API fuzzing, auth bypass probes, and AI/LLM probes. Running active scans against systems without authorisation may be illegal in your jurisdiction regardless of the tool used.

---

## What "authorisation" means in CREEP

CREEP enforces authorisation at the code level. Active modules will refuse to run unless you provide one of:

**Option 1 — CLI flag (one-off)**
```bash
python creep.py --i-am-authorized network 192.168.0.163
```
By passing `--i-am-authorized` you assert that you have permission to scan the target.

**Option 2 — Scope file (recommended for reproducible scans)**
```bash
python creep.py --init-scope        # generates scope.json template
# Edit scope.json: set "authorized": true and list your targets
python creep.py --scope-file scope.json network 192.168.0.163
```

A scope file is a signed record of your authorisation: who approved it, what targets are in scope, and whether public IPs are permitted. It is auditable and reproducible.

**Scope file rules enforced by CREEP:**
- `authorized` must be `true` — scope files without it are rejected at load time
- If `allow_public` is `true`, a non-empty `targets` list is required — blanket public authorisation without explicit targets is rejected

---

## What each phase does and does not do

### Phase 1 — Static analysis (always safe)

Phase 1 modules (`static`, `deps`, `surface`) perform local analysis only. They read source files and dependency manifests on disk. No network traffic is generated. No external systems are contacted, except:

- `deps` may query PyPI and the OSV vulnerability database for CVE data. Use `--offline`, `--no-cve`, or `--no-outdated` to disable these checks.

### Phase 2 — Active probes (opt-in, fail-closed)

Phase 2 modules (`network`, `fuzz`, `auth`, `ai`) send real network traffic to the target. They will not run without explicit authorisation. Every request is logged to `~/.creep/` before it is sent.

**Targets:**
- Localhost and private RFC 1918 ranges are allowed by default once authorised
- Public/routable IPs require both `--allow-public` and an explicit targets list
- Cloud metadata endpoints (AWS/GCP/Azure) are always blocked regardless of flags
- `0.0.0.0` is blocked
- IPv6 is handled: `::1` (localhost), `fc00::/7` (ULA private), `fd00:ec2::254` (blocked)

**Traffic volume:**
- All active modules use configurable delays and rate-limiting by default
- The fuzzer sends one probe at a time with a configurable inter-probe delay
- Network scanning uses concurrent workers but with a sane default cap
- DELETE endpoints in the fuzzer are skipped by default and require library-level `force=True`
- Ollama management probes (pull/delete) require `--ollama-management` and use a fake model name that does not exist

---

## What CREEP does not do

- **No exfiltration** — source code, findings, and reports never leave your machine
- **No persistence** — CREEP installs nothing, creates no scheduled tasks, and does not modify the target system
- **No credential theft** — the auth module probes for default credentials but does not store or transmit them; passwords are redacted in all audit logs and findings
- **No C2** — CREEP has no command-and-control infrastructure; it is a local CLI/desktop tool
- **No destructive payloads** — fuzz payloads are designed to detect vulnerabilities, not exploit or destroy data
- **No autonomous operation** — CREEP does nothing without a user explicitly invoking it

---

## Audit trail

Every active scan writes to `~/.creep/` before traffic goes out:

```
~/.creep/network_audit.jsonl
~/.creep/fuzz_audit.jsonl
~/.creep/auth_audit.jsonl
~/.creep/ai_audit.jsonl
```

Each entry records: timestamp, target URL, technique, event type (`attempted` before the request, `result` after), and status. If CREEP crashes mid-scan, you still have a record of what was attempted.

---

## Before you scan

Checklist before running any Phase 2 module:

- [ ] I own this system, or I have written authorisation from the system owner
- [ ] I have documented the scope (ideally in a `scope.json` file)
- [ ] I understand what traffic the module will send
- [ ] I am not testing a production system where unexpected traffic could cause harm
- [ ] I know how to stop the scan (`Ctrl+C` or the Stop button in the GUI)

---

## Responsible disclosure

If CREEP helps you find a vulnerability in your own system, please:

1. Fix it before disclosing publicly
2. If it affects third-party software, follow the maintainer's responsible disclosure policy
3. Do not publish proof-of-concept exploits without coordinating with the vendor first

For vulnerabilities in CREEP itself, see [SECURITY.md](SECURITY.md).
