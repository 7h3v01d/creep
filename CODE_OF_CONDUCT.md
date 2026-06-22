# Code of Conduct

## Our commitment

CREEP is a defensive security tool. Everyone who contributes to, uses, or discusses this project is expected to act in a way that is consistent with its defensive purpose and with basic standards of professional conduct.

---

## Scope

This Code of Conduct applies to:

- The GitHub repository (issues, pull requests, discussions, code review)
- Any communications related to this project (e.g. referencing CREEP in public forums)

---

## Expected behaviour

**Use CREEP defensively.** Contributions and discussions should be oriented toward helping people find and fix vulnerabilities in systems they own or are authorised to test.

**Be accurate about what the tool does.** Do not characterise CREEP as an offensive attack tool, a hacking kit, or something designed to compromise systems without permission. It is a governed defensive scanner.

**Respect the authorisation model.** Do not contribute changes that weaken or remove the authorisation gate, scope enforcement, fail-closed defaults, or audit logging. These are core safety properties, not optional features.

**Be professional.** Engage constructively in issues and pull requests. Disagreements about technical direction are fine; personal attacks are not.

**Disclose responsibly.** If you discover a vulnerability in CREEP itself, report it privately via the process in [SECURITY.md](SECURITY.md) rather than disclosing it publicly without notice.

---

## Unacceptable behaviour

The following are not acceptable in this project:

- Contributing features designed to enable unauthorised access to systems (e.g. removing the authorisation gate, adding persistence, adding C2 functionality, adding exfiltration)
- Publishing or sharing scan results from unauthorised scans and attributing them to CREEP
- Using this project's issues, discussions, or pull requests to solicit help with illegal activity
- Harassment, threats, or personal attacks directed at contributors or users
- Misrepresenting what this tool does in a way that could harm its users or the project's standing

---

## Enforcement

Contributions or comments that violate this Code of Conduct may be removed. Repeat violations may result in being blocked from the repository.

For serious concerns — particularly around safety properties or potential misuse — contact Leon Priest directly via the methods in [SECURITY.md](SECURITY.md).

---

## A note on dual-use

Security tools are inherently dual-use. CREEP is designed with specific technical safeguards (fail-closed defaults, scope enforcement, audit logging, explicit opt-in for all active modules) to make authorised defensive use easy and unauthorised use require deliberate circumvention.

Contributions that maintain or strengthen these properties are welcome. Contributions that weaken them will not be accepted regardless of their stated purpose.

---

This Code of Conduct is adapted from general open source community standards and tailored to the specific context of a security research tool.

Leon Priest — https://github.com/7h3v01d/creep
