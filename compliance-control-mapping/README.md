# Compliance Control Mapping

## Why this folder exists

Auditors ask for evidence. Engineers produce artifacts. Most AppSec programs fail the audit handoff not because the controls are absent — they are usually present — but because nobody translated "we have parameterized queries everywhere" into "§164.312(c)(1) Integrity control, evidenced by the Semgrep custom rule `python.sqlalchemy.security.sqlalchemy-execute-raw-query` enforced as a blocking check in `.github/workflows/appsec-pipeline.yml`, with findings exported to `reports/semgrep.sarif` on every main-branch build."

This folder contains the translation tables. Each document maps a compliance framework's control language to the specific technical control, the implementation example, the evidence artifact, and the tool or process that produces it. The goal is that when an auditor asks "how do you satisfy CC6.1?" the answer is a file path, a workflow run, and a report — not a policy PDF.

## How to use these mappings

**Engineering teams.** Treat these as a two-way index. When you ship a new control, find the compliance rows it satisfies and note them in the PR description so that future audits can trace back from the control to the framework citation. When an auditor sends a request, find the control row, pull the linked artifact, and attach it to the response. You should not have to re-derive this mapping under time pressure during an audit.

**Security architects.** Use these as a gap analysis. Run down the "AppSec Control" column for the framework in scope and confirm that each row has an implementation, not a "planned" stub. The rows that are blank are the audit findings you would rather discover now than during fieldwork.

**Auditors.** These documents are written for you. The "Evidence Artifact" column names the exact file, workflow, or dashboard that substantiates the control. If the artifact is missing or stale, the control has drifted. These mappings also make clear which rows are *partial* matches — a framework requirement may need multiple AppSec controls in combination, or a single control may satisfy rows across multiple frameworks.

## Documents

- **[hipaa-appsec-mapping.md](./hipaa-appsec-mapping.md)** — HIPAA Security Rule §164.308, §164.310, and §164.312 mapped to AppSec controls. Includes a dedicated section on PHI in application logs and the remediation pattern. Scoped to technical safeguards; administrative safeguards are out of scope.
- **[soc2-appsec-mapping.md](./soc2-appsec-mapping.md)** — SOC 2 Trust Services Criteria CC6, CC7, CC8, CC9 mapped to AppSec pipeline gates and code-review checks. Each row identifies the specific workflow job or review item that produces evidence.
- **[nist-csf-mapping.md](./nist-csf-mapping.md)** — NIST CSF 2.0 Govern, Identify, Protect, Detect, Respond, Recover functions mapped to AppSec program activities, with a maturity model (Initial, Managed, Defined, Optimized) for each area.

## What these mappings are not

These are not a substitute for a qualified auditor. They are not a compliance certification. They do not cover every requirement in each framework — only the rows that an AppSec program meaningfully contributes to. Administrative, physical, and purely governance-level controls are referenced where they intersect with AppSec but are not the focus.

They also do not capture the full scope of any of the referenced frameworks. HIPAA includes administrative and physical safeguards; SOC 2 covers system-level controls far beyond the application layer; NIST CSF covers enterprise cybersecurity program activities well outside the AppSec remit. Use these mappings as the AppSec-facing slice of a larger compliance program, not the whole program.

## Source versions

| Framework | Version | Effective |
| --- | --- | --- |
| HIPAA Security Rule | 45 CFR Part 160 and Subparts A and C of Part 164 | Current as of 2026 |
| SOC 2 Trust Services Criteria | 2017 TSC, 2022 revision (AICPA) | Current as of 2026 |
| NIST CSF | 2.0 | Published 2024-02-26 |
| PCI-DSS | v4.0.1 | Current as of 2026 |

When the framework revs, the rows that change are the ones that reference specific subcategory numbers or subsection letters. The underlying mapping logic — "parameterized queries satisfy the integrity control" — is stable across revisions.
