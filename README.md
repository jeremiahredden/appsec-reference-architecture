# Application Security Reference Architecture

### A practitioner's toolkit for embedding security into modern engineering organizations

**Jeremiah Redden** | Senior AI/AppSec Security Architect | CISSP | [github.com/jeremiahredden](https://github.com/jeremiahredden)

---

This repository is a living reference toolkit covering application security architecture, DevSecOps pipeline design, threat modeling, OWASP remediation, AI/LLM security, and cloud security patterns. Content is written for security architects and engineers who need practical, opinionated guidance — not compliance checklists.

The material here reflects how I actually run engagements: lightweight enough that an engineering team will still be talking to me next quarter, rigorous enough that the controls we land survive an audit. Every template has been used in production. Every worked example is anonymized from a real system.

---

## Table of Contents

- **[threat-modeling/](./threat-modeling/)** — STRIDE templates, a worked healthcare API example, and a facilitation guide for running 60-90 minute threat modeling sessions with engineering teams.
- **[secure-code-review/](./secure-code-review/)** — Manual review process guide, Python and JavaScript checklists, and paired vulnerable/secure code examples covering injection, auth, crypto, deserialization, prototype pollution, and secrets.
- **[devsecops-pipeline/](./devsecops-pipeline/)** — Opinionated CI/CD pipeline with SAST, SCA, secrets scanning, IaC scanning, and policy-as-code gates. Working GitHub Actions workflows, custom Semgrep rules, and a documented break-build policy.
- **[owasp-remediation-playbooks/](./owasp-remediation-playbooks/)** — One playbook per OWASP Top 10 2021 category (A01–A10). Each covers the exploit scenario, manual and automated detection, paired vulnerable/secure Python and JavaScript fixes, pytest/Jest tests that lock the fix in, and a compliance-mapping table covering HIPAA, SOC 2, NIST CSF 2.0, and PCI-DSS v4.
- **[compliance-control-mapping/](./compliance-control-mapping/)** — HIPAA Security Rule, SOC 2 Trust Services Criteria, and NIST CSF 2.0 mapped row-by-row to AppSec controls, implementation examples, and evidence artifacts. Includes a NIST CSF maturity model (Initial → Managed → Defined → Optimized) per function and a dedicated section on PHI-in-logs remediation.
- **[architecture-patterns/](./architecture-patterns/)** — Opinionated architecture guidance for secure API design, OAuth2/OIDC flows, Zero Trust on SaaS, and mTLS service mesh with Istio. ASCII diagrams, annotated configs, and adoption playbooks rather than reference-manual tours.
- **[ai-llm-security/](./ai-llm-security/)** — Threat models for LLM-backed applications, prompt injection defense-in-depth, agent isolation and permission tiers, RAG pipeline security, and developer playbooks for each OWASP LLM Top 10 (2025) class. Worked healthcare-assistant STRIDE example; Python and JavaScript hardened patterns.
- **[cloud-security/](./cloud-security/)** — AWS and Azure security reference architectures, IAM least-privilege with deployable SCPs, Entra ID patterns, Defender for Cloud playbook, and multi-cloud CSPM and zero-trust guidance. Opinionated on native-first adoption with clear criteria for when third-party tooling is worth the cost.
- **incident-response/** *(coming)* — Runbooks for common AppSec incident classes: leaked credential, exposed S3 bucket, dependency compromise, prompt injection escape.

---

## How to Use This Repo

**If you are a security architect**, lift the threat modeling templates and facilitation guide verbatim. They are designed to be forked into an engagement Confluence/Notion workspace, lightly customized with your client's trust boundaries, and run the same week.

**If you are a security engineer**, the DevSecOps pipeline reference is where I'd start. Copy the GitHub Actions workflows, tune the severity thresholds to your organization's risk appetite, and ship a baseline before you argue about the perfect tooling.

**If you are an engineering team lead** adopting secure-by-default practices, read the OWASP remediation content alongside your current codebase. Each finding maps to a fix that fits in a single sprint — not a six-month rewrite.

**If you are a hiring manager** evaluating my work, the worked examples (threat models, incident runbooks, secure architecture patterns) are closer to my deliverables than a resume will ever be. Read those first.

---

## Philosophy

Three principles drive every piece of content in this repository.

**1. Security should make teams faster, not slower.** A pipeline gate that blocks deploys with a 40-minute false-positive scan is not a security control — it is a productivity tax that teams will route around. The right security automation shortens the feedback loop: fail fast in the developer's IDE, fail clearly in CI, and give the engineer a patch, not a PDF. I optimize for controls that reduce total friction, even if that means accepting residual risk that a maximalist posture would not.

**2. The right control is the one that actually gets implemented.** A perfect control on a slide deck is worth less than an 80% control running in production on Monday. I would rather land a scoped WAF rule this sprint and iterate than spend a quarter on a comprehensive rewrite that never ships. This is not a license for sloppiness; it is a bias toward delivery. When I document a pattern here, I note the degraded-mode version that ships fast alongside the gold-standard version that ships eventually.

**3. Every finding needs a fix an engineer can act on in the current sprint.** A threat model that ends with "improve authentication posture" has failed. A threat model that ends with "rotate the shared service account JWT signing key to a per-service KMS-backed key by the end of sprint 47, assigned to the platform team, tracked in JIRA-8821" has succeeded. Findings without owners, deadlines, and concrete technical guidance become Word-document landfill. I write every template and every example in this repo with that standard in mind.

---

## License & Attribution

All content in this repository is released under the MIT License unless otherwise noted. Templates and playbooks may be used, modified, and adapted freely — including in commercial engagements and client deliverables. Attribution is appreciated but not required.

If you find something useful, I would like to hear about it. Open an issue, reach out on LinkedIn, or send a pull request with your improvements.
