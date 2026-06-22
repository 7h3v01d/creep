# Disclaimer

## Intended use

CREEP (Defensive Adversarial Security Scanner) is designed and published for use by:

- Software developers testing their own applications and infrastructure
- Security practitioners conducting authorised penetration tests or security audits
- Researchers studying vulnerability classes in controlled, isolated environments

---

## Authorised use only

**CREEP must only be used against systems you own or have explicit written authorisation to test.**

Running active scans (`network`, `fuzz`, `auth`, `ai` modules) against systems without authorisation may constitute:

- Unauthorised access or computer fraud under applicable law (including but not limited to the Computer Fraud and Abuse Act in the US, the Computer Misuse Act in the UK, and equivalent legislation in other jurisdictions)
- Civil liability for damages

The presence of the `--i-am-authorized` flag in CREEP is a technical opt-in mechanism. Passing this flag is a declaration by the operator that they have the necessary authorisation. CREEP cannot verify this claim independently.

---

## No warranty

CREEP is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement.

Security testing tools are inherently dual-use. The payloads and probes in CREEP are designed to detect vulnerabilities, not to exploit or destroy systems, but unexpected behaviour is possible when interacting with real systems. Use in production environments at your own risk.

---

## Limitation of liability

In no event shall Leon Priest or contributors to CREEP be liable for any claim, damages, or other liability — whether in an action of contract, tort, or otherwise — arising from, out of, or in connection with the software or the use or other dealings in the software.

This includes but is not limited to:

- Damage caused by running CREEP against systems without authorisation
- Damage caused to target systems during authorised testing
- Legal consequences resulting from misuse of this tool
- Data loss, service disruption, or reputational harm

---

## Third-party components

CREEP depends on several third-party libraries (see `requirements.txt`). Their licences and warranties apply independently. In particular:

- `pip-audit` and OSV database queries are subject to their own terms
- PyPI package metadata is provided by the Python Software Foundation

---

## What this tool is not

To be explicit about what CREEP does not contain:

- No malware or self-replicating code
- No persistence mechanisms (no scheduled tasks, registry entries, startup hooks, or backdoors)
- No command-and-control infrastructure
- No credential harvesting or exfiltration
- No destructive or irreversible payloads
- No code designed to bypass host-based security controls

CREEP is a read-oriented scanner. It looks for problems; it does not exploit them.

---

**By using CREEP you accept full responsibility for ensuring your use complies with applicable law and that you have the necessary authorisation for any systems you test.**

Apache 2.0 License — Leon Priest — https://github.com/7h3v01d/creep
