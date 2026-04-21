# SOC 2 Trust Services Criteria → AppSec Controls Mapping

## Scope

This document maps the SOC 2 Trust Services Criteria (2017 TSC, 2022 revision) to AppSec controls, pipeline gates, and code-review checks. The focus is the **Security** category (the "Common Criteria" CC series) because that is the TSP that every SOC 2 report includes and where AppSec has the most to contribute. Rows from Availability, Confidentiality, Processing Integrity, and Privacy are included only where an AppSec control is the primary evidence source.

The mapping is deliberately opinionated about what produces audit-usable evidence. A control that exists only in a policy document is hard to test; a control enforced by a CI gate produces an artifact on every run. Throughout, the **Pipeline Gate / Review Check** column names the specific enforcement point so that an auditor can see the control operating, not just described.

## CC6 — Logical and Physical Access Controls

### CC6.1 — Logical access is restricted

| Criterion | AppSec Control | Implementation Example | Pipeline Gate / Review Check | Evidence Artifact |
| --- | --- | --- | --- | --- |
| CC6.1 — Logical access security software, infrastructure, and architectures over protected information assets to protect them from security events. | Authentication via enterprise IdP, authorization via role- and resource-scoped checks, secrets in a managed store not in code. | OIDC / SAML SSO required for every production application; FastAPI dependency `require_role()`; `gitleaks` blocking commits that add secrets. | **Gate:** `gitleaks` step in `appsec-pipeline.yml`. **Review check:** every new route in PR diffs is inspected for an authentication dependency. | SARIF from gitleaks run; IdP audit log; authorization test suite results. |
| CC6.1 — …authenticate users, authorize actions… | JWT validation with pinned algorithm, issuer, audience, and required claims; resource-level authorization enforced at the query layer. | `jwt.decode(token, key, algorithms=["RS256"], issuer=..., audience=...)`; SQLAlchemy queries filter by `owner_id=current_user.id`. | **Gate:** pytest integration tests that assert IDOR attempts return 404. **Review check:** no endpoint handler returns an object without a scoped query. | `tests/auth/test_authorization.py` run output; JWT validator unit tests. |
| CC6.1 — …encrypt information… | Encryption at rest (KMS-backed) and in transit (TLS 1.2+); application secrets loaded from a secrets manager at boot. | S3 `aws:kms` default encryption; Postgres disk encryption on the instance and TDE on the database; `aws-sdk` resolves credentials via IAM role, not static keys. | **Gate:** Checkov rule `CKV_AWS_19` (S3 encryption) blocks non-compliant Terraform; Semgrep rule `hardcoded-aws-access-key` blocks committed keys. | Checkov SARIF report; Terraform state showing KMS keys; secrets-manager rotation configuration. |

### CC6.2 — Registration and authorization of new users

| Criterion | AppSec Control | Implementation Example | Pipeline Gate / Review Check | Evidence Artifact |
| --- | --- | --- | --- | --- |
| CC6.2 — New internal and external users are registered and authorized prior to being issued system credentials… | Automated provisioning from HRIS through IdP; deprovisioning on termination within 24 hours; identity proofing on customer signup. | SCIM from Workday → Okta → app via OIDC; customer signup requires verified email + MFA enrollment before first PHI access. | **Review check:** new service integrations confirmed to be SCIM-connected before launch. | SCIM sync logs; IdP deprovisioning report; customer-onboarding flow documentation. |

### CC6.3 — Access modification and removal

| Criterion | AppSec Control | Implementation Example | Pipeline Gate / Review Check | Evidence Artifact |
| --- | --- | --- | --- | --- |
| CC6.3 — The entity authorizes, modifies, or removes access… based on roles, responsibilities, or the system design… | Quarterly access reviews; automated session revocation on role change; audit log of every permission mutation. | IdP group membership drives app roles; on group removal, active sessions invalidated within 5 minutes via session-version counter bumped in Redis. | **Review check:** every new role / permission reviewed against least-privilege baseline. | Access review signoff artifacts; session-revocation timing test results. |

### CC6.6 — Logical access controls for external users and threats

| Criterion | AppSec Control | Implementation Example | Pipeline Gate / Review Check | Evidence Artifact |
| --- | --- | --- | --- | --- |
| CC6.6 — The entity implements logical access security measures to protect against threats from sources outside its system boundaries. | WAF on every internet-facing endpoint; rate limiting per IP + per account; egress controls to prevent SSRF to internal metadata services; DAST scheduled against production. | AWS WAF with managed rule sets (Core rule set, Known-bad inputs, SQLi / XSS); `express-rate-limit` keyed by IP + account; egress proxy with IP allowlist; weekly ZAP active scan against staging. | **Gate:** SSRF-rejecting `safe_fetch` wrapper enforced by Semgrep rule flagging direct `requests.get` / `node-fetch` on user input. **Review check:** every new outbound-URL parameter reviewed for SSRF controls. | WAF rule configuration; rate-limit test results; ZAP scan report; Semgrep SSRF findings. |

### CC6.7 — Data transmission

| Criterion | AppSec Control | Implementation Example | Pipeline Gate / Review Check | Evidence Artifact |
| --- | --- | --- | --- | --- |
| CC6.7 — The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes, and protects it during transmission, movement, or removal. | TLS 1.2+ everywhere with pinned cipher suites; mTLS between services; HSTS with preload; signed webhook payloads; DLP on outbound API responses. | ALB listener policy `ELBSecurityPolicy-TLS13-1-2-2021-06`; Istio mesh mTLS in STRICT mode; Webhook signatures via HMAC-SHA256; response-level PII tagging with `@sensitive` decorators. | **Gate:** testssl.sh run against staging on every release; pytest asserts `Strict-Transport-Security` header. **Review check:** outbound data flows across tenant boundaries reviewed in threat model. | testssl.sh report; header-assertion test output; mesh configuration. |

### CC6.8 — Prevention and detection of unauthorized or malicious software

| Criterion | AppSec Control | Implementation Example | Pipeline Gate / Review Check | Evidence Artifact |
| --- | --- | --- | --- | --- |
| CC6.8 — The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software. | Signed container images admitted via Sigstore; SBOM generated on every release; CVE scanning blocks deploys at HIGH+; image signing verified by Kyverno / Gatekeeper. | `cosign sign` on CI-published images; Trivy SBOM attached as release artifact; Kyverno policy rejects unsigned images in namespace `prod`. | **Gate:** `pip-audit --strict` and `npm audit --audit-level=high` block merges. **Review check:** every new dependency reviewed for maintenance and supply-chain signal. | Cosign signature manifest; Trivy SBOM; Kyverno policy + admission audit log. |

## CC7 — System Operations

### CC7.1 — Detection and monitoring of system vulnerabilities

| Criterion | AppSec Control | Implementation Example | Pipeline Gate / Review Check | Evidence Artifact |
| --- | --- | --- | --- | --- |
| CC7.1 — The entity uses detection and monitoring procedures to identify (1) changes to configurations that result in new vulnerabilities, and (2) susceptibilities to newly discovered vulnerabilities. | SAST (Semgrep) on every PR; SCA (pip-audit, npm audit, Trivy) on every build; IaC scanning (Checkov); continuous dependency monitoring (Dependabot, Snyk); DAST on staging weekly. | `semgrep --config p/default --config ./semgrep-rules --error --severity=ERROR`; pip-audit with `jq` gate on HIGH+CVSS≥7; Dependabot alerts triaged in weekly review. | **Gate:** every tool in `appsec-pipeline.yml` blocks the build when its threshold is breached. **Review check:** triaged findings tracked in a ticket with severity-based SLA. | SARIF uploads to GitHub Security tab; workflow run history; weekly triage meeting notes. |

### CC7.2 — System monitoring for anomalies

| Criterion | AppSec Control | Implementation Example | Pipeline Gate / Review Check | Evidence Artifact |
| --- | --- | --- | --- | --- |
| CC7.2 — The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors affecting the entity's ability to meet its objectives. | SIEM with alert rules on auth-failure rate, privilege escalation attempts, data-volume anomalies, new outbound destinations; structured application logs feed the SIEM. | Grafana / Loki alert rules on `login_failed` rate, `phi_access` volume anomalies (>10× historical avg), new egress domains. | **Review check:** every new alert rule tested in the weekly game day; rules without clear response runbooks are removed. | Alert rule YAML; on-call handoff doc; game-day after-action reports. |

### CC7.3 — Security incident evaluation

| Criterion | AppSec Control | Implementation Example | Pipeline Gate / Review Check | Evidence Artifact |
| --- | --- | --- | --- | --- |
| CC7.3 — The entity evaluates security events to determine whether they could or have resulted in a failure of the entity to meet its objectives and, if so, takes action to prevent or address such failures. | Defined severity rubric for security events; incident-commander rotation; standardized post-incident review with timeline, impact, and remediation. | PagerDuty rotation; Sev 1-3 rubric in `docs/incident/severity.md`; post-incident template in `docs/incident/post-mortem-template.md`. | **Review check:** every security event above Sev 3 produces a written review within 5 business days. | Post-incident reviews (redacted copies in audit scope); PagerDuty incident timeline. |

### CC7.4 — Incident response

| Criterion | AppSec Control | Implementation Example | Pipeline Gate / Review Check | Evidence Artifact |
| --- | --- | --- | --- | --- |
| CC7.4 — The entity responds to identified security incidents by executing a defined incident response program. | Runbooks for common AppSec incident classes (leaked credential, exposed bucket, dependency compromise, prompt injection escape); tabletop exercises semiannually. | Runbooks versioned in `docs/incident/runbooks/`; tabletop exercises with post-exercise gaps tracked as security backlog items. | **Review check:** runbooks updated within 30 days of any incident where they were used. | Runbook revision history; tabletop exercise reports. |

### CC7.5 — Recovery from identified security incidents

| Criterion | AppSec Control | Implementation Example | Pipeline Gate / Review Check | Evidence Artifact |
| --- | --- | --- | --- | --- |
| CC7.5 — The entity identifies, develops, and implements activities to recover from identified security incidents. | Verified backup restore; RPO / RTO defined per service tier; chaos drills that include security recovery scenarios. | Nightly DB snapshots; monthly full-restore drill on non-prod; quarterly "compromised credential" drill that exercises rotation paths. | **Review check:** every recovery drill produces a pass/fail record; failures become sprint items. | Drill reports; restore timing data. |

## CC8 — Change Management

### CC8.1 — Changes to infrastructure, data, software, and procedures

| Criterion | AppSec Control | Implementation Example | Pipeline Gate / Review Check | Evidence Artifact |
| --- | --- | --- | --- | --- |
| CC8.1 — The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures to meet its objectives. | Protected branches requiring review; CI gates on SAST / SCA / IaC / secrets; signed commits on main; separation of duties between author and approver. | GitHub branch protection requires ≥1 code review, status checks pass, signed commits; `CODEOWNERS` assigns review to security for security-sensitive paths. | **Gate:** `appsec-pipeline.yml` required status; CODEOWNERS review on `auth/`, `crypto/`, `infra/`. **Review check:** no direct pushes to main. | Branch protection settings export; CODEOWNERS file; PR history showing review signoffs. |

## CC9 — Risk Mitigation

### CC9.1 — Business disruption risk

| Criterion | AppSec Control | Implementation Example | Pipeline Gate / Review Check | Evidence Artifact |
| --- | --- | --- | --- | --- |
| CC9.1 — The entity identifies, selects, and develops risk mitigation activities for risks arising from potential business disruptions. | Threat modeling identifies security-driven disruptions; DR exercises include a security incident scenario. | STRIDE findings of "Denial of Service" category tracked and remediated; DR exercise #3 each year is a "compromise forces rollback" scenario. | **Review check:** DoS-category findings in threat models not closed without a compensating control. | Threat models; DR exercise reports. |

### CC9.2 — Vendor and business partner risk

| Criterion | AppSec Control | Implementation Example | Pipeline Gate / Review Check | Evidence Artifact |
| --- | --- | --- | --- | --- |
| CC9.2 — The entity assesses and manages risks associated with vendors and business partners. | Security review before any vendor with access to production data is onboarded; SBOM requirement in vendor contracts; continuous monitoring of vendor security posture where available. | Vendor-review checklist; BAAs with subprocessors; Security scorecards on critical vendors. | **Review check:** new vendors with production-data access blocked until security review complete. | Vendor review records; SBOM inventory. |

## Complementary entries from Confidentiality and Availability

| Criterion | AppSec Control | Pipeline Gate / Review Check |
| --- | --- | --- |
| **C1.1** — Identifies and maintains confidential information. | Data classification labels on every schema; sensitive-data discovery scan on new tables. | **Review check:** new tables / columns reviewed against classification taxonomy. |
| **C1.2** — Disposes of confidential information. | Automated deletion on account closure; backup retention bounded; key destruction on data-deletion events. | **Review check:** data-deletion flows tested in integration suite. |
| **A1.2** — Environmental and logical infrastructure protections for availability. | WAF rate-limiting; timeouts, retries, and circuit breakers in application code; SSRF controls that prevent outbound loops. | **Review check:** every new outbound HTTP client has a timeout and a circuit breaker. |

## How to use this mapping during a SOC 2 audit

The auditor will typically sample: pull a set of PRs across the audit period and ask how each was reviewed, tested, and deployed. The efficient answer is:

1. Open the PR.
2. Show the `appsec-pipeline.yml` run — every gate passed, artifacts attached.
3. Show the CODEOWNERS-driven review approvals.
4. Show the branch-protection ruleset that made all of the above required.

That sequence satisfies CC8.1 (change management), CC6.1 (access control on the code), CC7.1 (vulnerability detection), and CC6.8 (malicious software prevention) simultaneously — because the same pipeline enforces all four. This is the point of the mapping: one well-built pipeline satisfies multiple criteria, and the evidence is the workflow run that is already retained for 90+ days by GitHub.

For the criteria that CI alone does not satisfy — CC7.2 (anomaly monitoring), CC7.4 (incident response), CC9 (risk mitigation) — the evidence shifts to SIEM queries, incident post-mortems, and threat-model documents. Those need separate retention and separate access controls, but they are similarly artifact-based: a dashboard screenshot with a timestamp is better than "we monitor our logs."

## What auditors ask that this mapping will not answer

- **Organizational and HR controls** (background checks, security awareness training, code of conduct) — these are genuinely outside AppSec scope. Point the auditor to People Ops.
- **Physical safeguards** — co-lo access, badging, visitor logs. Out of scope here; typically covered by the cloud provider's SOC 2 inherited controls.
- **Financial controls** — segregation of duties on financial transactions, journal entries, etc. Out of scope.

If the auditor asks about a CC-series row not covered in this document, it is probably one of those. Escalate to the control owner rather than manufacturing a forced mapping.
