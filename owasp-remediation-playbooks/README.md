# OWASP Top 10 Remediation Playbooks

Developer-facing playbooks for the OWASP Top 10 (2021). Not audit guides, not frameworks, not overviews — concrete fixes that land in a PR.

Each file follows the same structure:

1. **What it is** — one short paragraph, plain language, no jargon.
2. **Why it matters** — a realistic exploit scenario describing what an attacker actually does.
3. **How to find it** — manual review indicators and automated tool signatures (Semgrep rule IDs, Snyk check names, Checkov checks where applicable).
4. **How to fix it — Python** — vulnerable code, then secure code with inline comments explaining the fix.
5. **How to fix it — JavaScript** — same pattern.
6. **How to test the fix** — a pytest or Jest test that fails against the vulnerable code and passes against the fix.
7. **Compliance mapping** — which HIPAA Security Rule safeguards, SOC 2 Trust Services Criteria, and NIST Cybersecurity Framework 2.0 subcategories the control addresses.

---

## Playbooks

| # | OWASP Category | File |
| --- | --- | --- |
| A01 | Broken Access Control | [A01-broken-access-control.md](./A01-broken-access-control.md) |
| A02 | Cryptographic Failures | [A02-cryptographic-failures.md](./A02-cryptographic-failures.md) |
| A03 | Injection | [A03-injection.md](./A03-injection.md) |
| A04 | Insecure Design | [A04-insecure-design.md](./A04-insecure-design.md) |
| A05 | Security Misconfiguration | [A05-security-misconfiguration.md](./A05-security-misconfiguration.md) |
| A06 | Vulnerable and Outdated Components | [A06-vulnerable-components.md](./A06-vulnerable-components.md) |
| A07 | Identification and Authentication Failures | [A07-identification-authentication-failures.md](./A07-identification-authentication-failures.md) |
| A08 | Software and Data Integrity Failures | [A08-software-data-integrity-failures.md](./A08-software-data-integrity-failures.md) |
| A09 | Security Logging and Monitoring Failures | [A09-logging-monitoring-failures.md](./A09-logging-monitoring-failures.md) |
| A10 | Server-Side Request Forgery (SSRF) | [A10-ssrf.md](./A10-ssrf.md) |

---

## How to Use These

**During a code review:** find the category that matches the finding, copy the vulnerable/secure code example into the PR comment, link to the playbook. The developer gets a specific recommendation and a test to verify the fix — not a link to owasp.org.

**When building a feature:** if the feature touches authentication, authorization, data storage, or external integrations, read the relevant playbook before you start. The fixes are a lot cheaper to design in than to bolt on.

**During an audit:** the compliance mappings are the audit-ready explanation of what each control addresses. Auditors ask "how do you handle broken access control"; this folder is the answer, with code.

**Operating a security program:** adopt the playbooks as part of your organization's secure coding standards. Reference them from your SDLC documentation so they have authority, and keep them updated — OWASP revises the Top 10 roughly every four years, and threat patterns shift faster.

---

## Scope and Non-Goals

These playbooks focus on the **application layer**. Infrastructure-level controls (network segmentation, cloud IAM boundaries, data-at-rest encryption at the storage layer) are mentioned where they are the right fix, but the detailed patterns live under `cloud-security-patterns/`.

They are also **framework-agnostic within each language**. The Python examples use FastAPI or Flask when a framework is needed; the JavaScript examples use Express. If your stack is Django, NestJS, or Fastify, the principles translate directly — only the decorator/middleware names change.

Finally, they are **not a substitute for threat modeling**. The Top 10 covers the most common bug classes; your system may have specific threats that require their own analysis. Run the threat modeling process in `threat-modeling/` alongside these playbooks.
