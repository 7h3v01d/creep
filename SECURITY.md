# Security Policy

## Supported versions

CREEP is currently in public alpha. Security fixes are applied to the latest release only.

| Version | Supported |
|---|---|
| 2.0.0-alpha (latest) | ✅ |
| Earlier builds | ❌ |

---

## Reporting a vulnerability in CREEP itself

If you find a security vulnerability **in the CREEP codebase** — for example, a bug that causes it to bypass its own authorisation gate, leak credentials from audit logs, or send traffic without user consent — please report it privately rather than opening a public issue.

**Contact:** Leon Priest
**GitHub:** [@7h3v01d](https://github.com/7h3v01d)
**Method:** Open a [GitHub Security Advisory](https://github.com/7h3v01d/creep/security/advisories/new) (preferred), or contact via GitHub profile.

Please include:
- A description of the vulnerability and its impact
- Steps to reproduce
- Which version of CREEP is affected
- Whether you have a proposed fix

I aim to acknowledge reports within 72 hours and publish a fix or mitigation within 14 days for confirmed issues.

---

## This tool's intended use and abuse-report guidance

CREEP is a **defensive adversarial security scanner** intended for use by developers and security practitioners testing systems they own or have explicit written authorisation to test.

**What CREEP is:**
- A local-first Python tool that runs on the tester's own machine
- A governed scanner with fail-closed active modules — nothing fires without explicit opt-in
- A way to find vulnerabilities in your own project before others do

**What CREEP is not:**
- Malware, spyware, or a remote-access tool
- A credential harvester or exfiltration tool
- A command-and-control framework
- A tool for attacking systems without authorisation

**If you believe CREEP is being misused against your systems:**
CREEP's active modules require the `--i-am-authorized` flag or a signed scope file before sending any traffic. If you are receiving unexpected traffic that you believe originates from CREEP, please contact the operator of the scanning system directly.

If you have concerns about this repository's content, please open a GitHub issue or contact [@7h3v01d](https://github.com/7h3v01d) before filing a platform abuse report, so we can address the concern directly.

---

## GitHub platform policies

This repository is published in good faith under GitHub's [Acceptable Use Policy](https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies) and its [policy on security research tooling](https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies#6-information-usage-restrictions). CREEP is designed to support security research and defensive testing, not to facilitate unauthorised access to systems.
