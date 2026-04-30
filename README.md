# Application Security Reference Architecture

![AppSec Pipeline](https://github.com/jeremiahredden/appsec-reference-architecture/actions/workflows/appsec-pipeline.yml/badge.svg)
![IaC Scan](https://github.com/jeremiahredden/appsec-reference-architecture/actions/workflows/iac-scan.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Maintained](https://img.shields.io/badge/Maintained-yes-green.svg)

### A practitioner's toolkit for embedding security into modern engineering organizations

**Jeremiah Redden** | Senior AI/AppSec Security Architect | CISSP | [github.com/jeremiahredden](https://github.com/jeremiahredden)

---

This repository is a living reference toolkit covering application security architecture, DevSecOps pipeline design, threat modeling, OWASP remediation, AI/LLM security, and cloud security patterns. Content is written for security architects and engineers who need practical, opinionated guidance — not compliance checklists.

The material here reflects how I actually run engagements: lightweight enough that an engineering team will still be talking to me next quarter, rigorous enough that the controls we land survive an audit. Every template has been used in production. Every worked example is anonymized from a real system.

---

## Live Pipeline

This repository runs a live GitHub Actions AppSec pipeline on every push to `main` and every pull request. The same workflow documented in [`devsecops-pipeline/`](./devsecops-pipeline/) is active here — you can watch it run, inspect the findings, and copy it into your own project.

The pipeline scans an intentionally-vulnerable reference application ([`demo-app/`](./demo-app/)) so the Security tab always has real, reproducible findings on it. It exercises the full stack:

- **Semgrep** — SAST against `demo-app/` using the managed `p/default` ruleset plus the custom rules in [`devsecops-pipeline/semgrep-rules/custom-rules.yaml`](./devsecops-pipeline/semgrep-rules/custom-rules.yaml)
- **pip-audit** — Python SCA against `demo-app/python-api/requirements.txt`
- **npm audit** — Node SCA against `demo-app/node-api/`
- **Gitleaks** — secrets scanning across the git history, with a scoped allowlist in [`.gitleaks.toml`](./.gitleaks.toml) so intentional demo secrets don't mask real ones
- **Checkov** — IaC scanning across Terraform, CloudFormation, Kubernetes, Dockerfile, and ARM

**Where to look:**

- Pipeline definition → [`.github/workflows/appsec-pipeline.yml`](./.github/workflows/appsec-pipeline.yml)
- Intentional scan target → [`demo-app/README.md`](./demo-app/README.md)
- Live findings → **Security** tab → **Code scanning** (SARIF from Semgrep and Checkov lands here automatically)
- Break-build policy → [`devsecops-pipeline/policy-as-code/break-build-policy.md`](./devsecops-pipeline/policy-as-code/break-build-policy.md)

The demo app is labeled `EDUCATIONAL USE ONLY` at the top of every file. Every vulnerability is commented `# VULNERABILITY: <class> — intentional for pipeline demonstration` and paired with a secured counterpart. If you want to see what each tool catches on a vulnerable target — and what the secured version looks like — that folder is the artifact to read.

---

## Table of Contents

- **[threat-modeling/](./threat-modeling/)** — STRIDE templates, a worked healthcare API example, and a facilitation guide for running 60-90 minute threat modeling sessions with engineering teams.
- **[secure-code-review/](./secure-code-review/)** — Manual review process guide, Python and JavaScript checklists, and paired vulnerable/secure code examples covering injection, auth, crypto, deserialization, prototype pollution, and secrets.
- **[devsecops-pipeline/](./devsecops-pipeline/)** — Opinionated CI/CD pipeline with SAST, SCA, secrets scanning, IaC scanning, and policy-as-code gates. Working GitHub Actions workflows, custom Semgrep rules, and a documented break-build policy.
- **[owasp-remediation-playbooks/](./owasp-remediation-playbooks/)** — One playbook per OWASP Top 10 2021 category (A01–A10). Each covers the exploit scenario, manual and automated detection, paired vulnerable/secure Python and JavaScript fixes, pytest/Jest tests that lock the fix in, and a compliance-mapping table covering HIPAA, SOC 2, NIST CSF 2.0, and PCI-DSS v4.
- **[compliance-control-mapping/](./compliance-control-mapping/)** — HIPAA Security Rule, SOC 2 Trust Services Criteria, and NIST CSF 2.0 mapped row-by-row to AppSec controls, implementation examples, and evidence artifacts. Includes a NIST CSF maturity model (Initial → Managed → Defined → Optimized) per function and a dedicated section on PHI-in-logs remediation.
- **[architecture-patterns/](./architecture-patterns/)** — Opinionated architecture guidance for secure API design, OAuth2/OIDC flows, Zero Trust on SaaS, and mTLS service mesh with Istio. ASCII diagrams, annotated configs, and adoption playbooks rather than reference-manual tours.
- **[ai-llm-security/](./ai-llm-security/)** *(moved)* — The AI/LLM security material has moved to its own dedicated repo, [ai-security-reference-architecture](https://github.com/jeremiahredden/ai-security-reference-architecture), where it is being expanded into a full reference covering LLM application security, agent security, MLOps security, AI governance, AI infrastructure, AI detection and response, AI privacy, and defensive AI. The folder here now contains a redirect with links to the migrated documents.
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

**4. A security control that only exists in a document doesn't exist. Show your work.** Policy slides, architecture decks, and control matrices are evidence of intent, not of protection. The pipeline running on this repo exists for exactly this reason — it is what turns the `devsecops-pipeline/` folder from a proposal into an operating control. Wherever I can put a claim in front of running code, I do. A "Zero Trust architecture" with no enforcement point, a "least-privilege IAM model" with no deny statements, a "secure SDLC" with no failing build — these are theater. I write this repo to the standard that every architectural claim should be backed by an artifact a reviewer can execute.

---

## License & Attribution

All content in this repository is released under the MIT License unless otherwise noted. Templates and playbooks may be used, modified, and adapted freely — including in commercial engagements and client deliverables. Attribution is appreciated but not required.

If you find something useful, I would like to hear about it. Open an issue, reach out on LinkedIn, or send a pull request with your improvements.
