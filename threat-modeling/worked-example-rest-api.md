# Worked Example: Threat Model for a Healthcare Data REST API

> This is a complete, realistic threat model deliverable produced during a hypothetical engagement with a mid-sized digital health company. The system is representative of a class of healthcare APIs I have assessed: a PHI-handling REST service sitting between a patient-facing application and a PostgreSQL store, integrating with several third-party vendors. All names, identifiers, and specifics are fictional; the threats and mitigations are drawn from real engagements and published vulnerability patterns.
>
> Read this to calibrate the level of specificity you are aiming for in your own threat models. Vague findings like "improve input validation" do not belong in a deliverable. Specific findings like the ones below do.

---

## Document Metadata

| Field | Value |
| --- | --- |
| **System Name** | Meridian Patient Data API (MPD-API) v2.4 |
| **System Owner** | Platform Engineering — Tech Lead: *[redacted]* |
| **Business Owner** | VP Product, Clinical Workflows |
| **Date** | 2026-02-11 |
| **Facilitator** | Jeremiah Redden, Senior AppSec Architect |
| **Participants** | 2 backend engineers, 1 SRE, 1 product manager, 1 clinical compliance analyst, 1 security engineer |
| **Session Duration** | 85 minutes |
| **Data Classification** | **Restricted — PHI under HIPAA**; subset of records fall under 42 CFR Part 2 (SUD treatment records) with stricter disclosure rules |
| **Environment Scope** | Production. Staging is within scope for secrets-management findings; dev sandboxes are explicitly out of scope. |
| **Revision** | 2.0 (refresh of 1.0 from 2025-03; triggered by introduction of the vendor e-prescribe integration) |
| **Prior Model Reference** | `/docs/security/threat-model-v1.md` |

### Trust Boundary Summary

The MPD-API has five trust boundaries. From outermost to innermost: (1) the public internet to the WAF/CDN edge; (2) the edge to the OAuth2 authorization server (Okta tenant); (3) the authenticated API tier to the internal service mesh, where mTLS authenticates workloads; (4) the service mesh to the PostgreSQL data plane, where IAM database authentication is enforced; and (5) outbound egress to three third-party vendors (e-prescribe, labs, insurance eligibility). The e-prescribe integration is new in v2.4 and handles controlled-substance prescriptions, which raises its risk profile relative to the other vendor integrations.

---

## Data Flow Diagram

```
+-------------------------------+
|  Patient Mobile / Web App      |     Trust Zone 0 (Untrusted)
|  (Meridian Patient iOS/Android)|
+---------------+---------------+
                | HTTPS (TLS 1.3, cert pinning on mobile)
                v
======= Boundary 1: Edge (CloudFront + AWS WAF) ================
                |
                v
+---------------------------+
|  AWS WAF                   |     Trust Zone 1 (Edge)
|  - OWASP CRS rules         |     - Geo-block non-US
|  - Bot Control (high)      |     - Rate limit 60/min/IP
|  CloudFront (TLS term)     |
+---------------+-----------+
                |
                v
======= Boundary 2: Identity (Okta OIDC) ========================
                |
          [auth redirect]
                |
                v
+---------------------------+
|   Okta Tenant              |     Trust Zone 2 (Identity Plane)
|   - Patient realm (MFA)    |     - Separate realm: clinicians
|   - Authz server: MPD-API  |     - Custom scopes: phi.read,
|   - Issues RS256 JWTs      |                        phi.write,
+---------------+-----------+                         rx.write
                |
          [JWT + scope claims returned to app]
                |
                v
+---------------------------+
|  Meridian API Gateway      |     Trust Zone 3 (Authenticated API)
|  (Kong OSS + custom plugin)|     - JWT validation
|  - Per-tenant rate limits  |     - Scope enforcement
|  - OpenAPI schema validate |     - Request ID injection
+---------------+-----------+
                |
                v mTLS (SPIFFE IDs issued by Istio)
                |
+---------------+---------------+
|                               |
v                               v
+-----------------+   +--------------------+
|  Patient Svc    |   |  Rx Svc (NEW v2.4) |     Trust Zone 4 (Service Mesh)
|  (demographics, |   |  - e-Rx workflow    |     - mTLS between services
|   appointments) |   |  - Controlled subs  |     - Istio AuthorizationPolicies
|                 |   |    2FA requirement  |
+--------+--------+   +---------+----------+
         |                      |
         | (IAM DB auth)        | (IAM DB auth)
         v                      v
+---------------------------+
|   PostgreSQL (RDS)         |     Trust Zone 5 (Data Store)
|   - Separate DB per domain |     - Encrypted at rest (KMS CMK)
|   - RLS on PHI tables      |     - pgAudit enabled
|   - Replicas in 2 AZs      |     - Automated backups to S3+KMS
+---------------+-----------+
                |
========= Boundary 5: Vendor Egress (NAT + allowlist) =========
                |
                v
+----------------+  +----------------+  +----------------+
| Surescripts    |  | Quest Labs HL7 |  | Change HC       |     Trust Zone 6 (Vendors)
| (e-Rx)         |  | (lab orders)    |  | (eligibility)   |     - Per-vendor API keys in
| mTLS + API key |  | SFTP + PGP      |  | OAuth2 client   |       AWS Secrets Manager
+----------------+  +----------------+  +----------------+       - Outbound via NAT GW
                                                                  - Egress allowlist enforced
```

---

## Scope and Assumptions

**In scope:** the MPD-API code and its direct infrastructure (ECS tasks, the RDS instance, the API Gateway, the Kong API Gateway layer, the three vendor integrations, the observability stack). The patient-facing mobile and web clients are in scope for their interaction with the API (token handling, request signing, data-at-rest on device) but not their internal feature set.

**Out of scope:** the Okta tenant's own configuration (assumed correct; covered by a separate identity provider assessment), the AWS account boundary controls (covered by the quarterly AWS security review), and the vendors' own systems. We model the vendor *integration* as a trust boundary, not the vendor itself.

**Assumptions:** developers do not have direct production database access; the break-glass role requires two approvals; the service is deployed behind CloudFront; IMDSv2 is enforced on all ECS tasks; all code is reviewed by at least one other engineer before merge.

---

## STRIDE Enumeration

### Scoring

Likelihood (L): 1 = theoretical, 2 = requires privileged access, 3 = plausible external, 4 = trivial.
Impact (I): 1 = single user, 2 = tenant, 3 = regulated-data exposure, 4 = full breach / material harm.
Risk = L × I. Bands: 1-3 Low, 4-6 Medium, 7-11 High, 12-16 Critical.

### Spoofing

| # | Component | Threat | Current Mitigation | L | I | Risk | Recommended Control | Owner |
| - | - | - | - | :-: | :-: | :-: | - | - |
| S1 | API Gateway | Forged JWT accepted because the Gateway validates signature but does not validate the `iss` claim against the expected Okta authorization server URL. An attacker with access to any Okta tenant's signing key could forge tokens. | RS256 validation with JWKS cached from Okta. | 2 | 4 | 8 H | Enforce `iss` claim exact match against the configured Meridian authz server URL. Enforce `aud` claim. Pin to specific `kid` values and alert on unknown `kid`. | Platform |
| S2 | Patient Svc | Identity confusion when a patient has multiple records across merged practices — the `sub` claim is Okta-scoped, not practice-scoped, so a patient authenticated as Practice A can retrieve their own records at Practice B if the `practice_id` path parameter is not validated. | Patient service checks `sub` matches `patient_id` in the record. | 3 | 3 | 9 H | Issue JWTs with a `practice_ids` claim enumerating the practices the patient is consented into. Validate the `practice_id` path parameter is in that list on every request. | Identity |
| S3 | Rx Svc | E-prescribe signatures require a clinician NPI (National Provider Identifier) which is currently trusted from the JWT without verification that the clinician is active and DEA-registered for controlled substances. A terminated clinician with a still-valid JWT could sign prescriptions. | JWT `npi` claim is populated at login. JWTs have a 1-hour TTL. | 2 | 4 | 8 H | At the moment of prescription signing, call the internal clinician-directory service to confirm the NPI is active and the clinician has a current DEA registration. Do not cache for more than 5 minutes. | Rx Team |

### Tampering

| # | Component | Threat | Current Mitigation | L | I | Risk | Recommended Control | Owner |
| - | - | - | - | :-: | :-: | :-: | - | - |
| T1 | API Gateway | Mass-assignment on patient update — the PATCH `/patients/{id}` endpoint accepts the full patient record including the `practice_id` field, allowing a patient to re-associate their record with a different practice. | OpenAPI schema restricts fields to a PATCH-specific model. | 2 | 3 | 6 M | Enforce the restricted PATCH schema in code, not just in the OpenAPI documentation. Treat schema drift between docs and handlers as a CI-failing condition. | Patient Svc |
| T2 | Rx Svc | Prescription field tampering between signing and transmission — the prescription payload is signed client-side, then modified server-side to append clinic metadata, then transmitted. The server-side modification invalidates the signature, and the current implementation re-signs with the service account key rather than rejecting. | Signature is re-computed with a service key before transmission. | 2 | 4 | 8 H | Separate the clinician signature (covers clinical fields only) from the transport envelope (covers metadata). Never re-sign clinical fields server-side. Transmission to Surescripts should include both signatures. | Rx Team |
| T3 | PostgreSQL | Audit log tampering — pgAudit logs are written to the same RDS instance they are auditing. A DBA with emergency-access credentials could alter the audit trail. | pgAudit enabled. RDS automated backups. | 2 | 3 | 6 M | Ship pgAudit output to CloudWatch Logs with a log destination owned by a different AWS account. Use S3 Object Lock for long-term retention. Make the audit sink write-only from the database's IAM role. | Data Platform |

### Repudiation

| # | Component | Threat | Current Mitigation | L | I | Risk | Recommended Control | Owner |
| - | - | - | - | :-: | :-: | :-: | - | - |
| R1 | Rx Svc | A clinician disputes having written a controlled-substance prescription. The current audit record includes the clinician's NPI and timestamp but not the MFA assertion, session ID, client IP, or device posture. Insufficient non-repudiation to withstand a DEA audit. | Rx record includes NPI, timestamp, patient ID, drug code, prescription text. | 2 | 3 | 6 M | Capture MFA assertion reference, Okta session ID, client IP, user-agent, and device fingerprint at signing time. Store in a dedicated `rx_audit` table with RLS allowing compliance role read only. | Rx Team + Compliance |
| R2 | Patient Svc | Patient-initiated record access (e.g., pulling their own lab results) is logged at INFO level and rotated at 30 days. HIPAA accounting-of-disclosures requires 6-year retention. | CloudWatch Logs, 30-day retention. | 4 | 3 | 12 C | Ship all PHI access events to a dedicated audit sink with 7-year retention (exceeds HIPAA requirement, matches state law ceilings). Include actor, patient_id, data_classification, and access reason. | Data Platform |

### Information Disclosure

| # | Component | Threat | Current Mitigation | L | I | Risk | Recommended Control | Owner |
| - | - | - | - | :-: | :-: | :-: | - | - |
| I1 | Patient Svc | IDOR on appointments — the `/appointments/{id}` endpoint validates that the requester is an authenticated patient but does not validate that the appointment belongs to them. | JWT required. Appointment lookup by ID. | 4 | 3 | 12 C | Enforce `appointment.patient_id == jwt.sub` at the handler level. Add an integration test that exercises cross-patient access and must fail with 404 (not 403 — do not confirm existence). | Patient Svc |
| I2 | PostgreSQL | PHI returned in error messages — an unhandled constraint violation includes row data in the PostgreSQL error, which is propagated to the API response in the `detail` field during debugging. | Generic 500 handler strips stack traces. | 3 | 4 | 12 C | Never propagate database error details to API responses. Map all database errors to sanitized error codes at a single error-handling middleware. Verify with a test suite that no database error can reach a client. | Platform |
| I3 | Rx Svc | Controlled-substance prescriptions (Schedule II-V) are logged at INFO level with the full drug code and quantity. Log aggregation destination has broader read access than the prescription database. | Logs go to CloudWatch. CloudWatch Logs have IAM restrictions. | 3 | 3 | 9 H | Log only the prescription ID at INFO level. Emit controlled-substance details to a separate `rx_events` stream with stricter access. Redact drug details in stack traces. | Rx Team |
| I4 | Surescripts Integration | E-prescribe responses include the patient's full medication history from external pharmacies. This data is stored in MPD-API's local cache with the same access control as Meridian-originated prescriptions, but it contains data the patient has not consented to share with Meridian clinicians. | All prescription data access controlled by patient-clinician relationship check. | 3 | 3 | 9 H | Tag externally-sourced medication history with a separate classification. Require patient consent affirmation before displaying to clinicians. Auto-purge external data after 90 days or on consent withdrawal. | Rx Team + Compliance |

### Denial of Service

| # | Component | Threat | Current Mitigation | L | I | Risk | Recommended Control | Owner |
| - | - | - | - | :-: | :-: | :-: | - | - |
| D1 | API Gateway | The `/patients/search` endpoint allows wildcard queries against a non-indexed field (`last_name LIKE %x%`). A malicious authenticated user can trigger multi-second queries and exhaust the connection pool. | Query timeout 30s. Connection pool size 50. | 3 | 2 | 6 M | Require minimum 3-character prefix on search terms. Add a GIN trigram index on `last_name`. Enforce per-user concurrent query limit via a semaphore. | Patient Svc |
| D2 | Rx Svc | Surescripts vendor dependency — if Surescripts is slow or unresponsive, prescription signing blocks the API thread. A single upstream outage can degrade the entire Rx service. | 30-second HTTP timeout on Surescripts calls. | 3 | 2 | 6 M | Move Surescripts calls to an async job queue. Return an "accepted — processing" response to the client and deliver the final status via a webhook or the client's long-poll. Implement a circuit breaker with exponential backoff. | Rx Team |

### Elevation of Privilege

| # | Component | Threat | Current Mitigation | L | I | Risk | Recommended Control | Owner |
| - | - | - | - | :-: | :-: | :-: | - | - |
| E1 | Service Mesh | The Rx Service has a database connection with write permissions to the `patient_demographics` table, which it does not need. A compromised Rx Service (e.g., via a dependency vulnerability) could modify patient demographics. | IAM database auth per service. | 2 | 4 | 8 H | Split credentials per domain. The Rx Service should have read-only access to `patient_demographics` and write access only to `rx_*` tables. Enforce via PostgreSQL schemas and grant minimum privileges. | Data Platform |
| E2 | API Gateway | JWT scope claims are checked at the Gateway, but individual services re-read the raw JWT and trust other claims (like a `role` claim) that are not validated. A compromised upstream service (or a future bug that allows JWT pass-through) could enable horizontal privilege escalation. | Scope check at Gateway. | 2 | 4 | 8 H | Terminate the client JWT at the Gateway. Mint a short-lived internal token (signed by a platform key) that carries only the claims services need. Remove services' ability to parse client JWTs directly. | Platform |
| E3 | CI/CD | The MPD-API GitHub Actions deploy workflow uses an IAM role assumed via OIDC, but the role's trust policy does not constrain the `ref` of the workflow. A pull request from a fork could trigger a deploy if a maintainer approves the workflow run. | OIDC federation. Protected branches. | 2 | 4 | 8 H | Constrain the IAM role's trust policy to `repo:meridian/mpd-api:ref:refs/heads/main` only. Require manual approval for deploys regardless. Treat the deploy role as an infrastructure-critical IAM identity with its own change-review process. | DevOps |
| E4 | Rx Svc | The e-prescribe signing endpoint requires step-up MFA but caches the step-up assertion for 30 minutes via a signed cookie. The cookie is scoped to the domain but not bound to the specific prescription being signed, so one step-up can authorize many prescriptions within the window. | Step-up MFA required. Assertion cached 30 min. | 3 | 3 | 9 H | Require per-prescription step-up MFA for Schedule II controlled substances (DEA requirement under EPCS). Bind the step-up assertion to the prescription hash; reject on mismatch. | Rx Team + Compliance |

---

## Findings Summary

### System Overview

The Meridian Patient Data API (MPD-API) provides authenticated access to patient demographics, clinical appointments, and — new in v2.4 — electronic prescribing of controlled substances. It handles PHI under HIPAA and a subset of SUD-treatment records under 42 CFR Part 2. The API is consumed by Meridian's patient-facing mobile and web applications and by clinicians via an internal clinician portal.

### Assessment Scope and Method

STRIDE-based threat model conducted in an 85-minute facilitated session on 2026-02-11 with six participants spanning engineering, SRE, product, and clinical compliance. Scope included the API service, its backing data store, its three vendor integrations, and its CI/CD pipeline. Okta configuration and AWS account-boundary controls were excluded (covered by separate assessments). The model is a refresh of v1.0, triggered by the introduction of the Surescripts e-prescribe integration.

### Top Risks Identified

**Critical (3):**
- **I1** — IDOR on appointments endpoint (cross-patient data access).
- **I2** — PHI leakage in API error messages.
- **R2** — PHI access logs retained only 30 days; HIPAA requires 6 years.

**High (8):**
- **S1** — JWT `iss`/`aud` claims not fully validated.
- **S2** — Patient multi-practice identity confusion.
- **S3** — Clinician status not revalidated at prescription signing.
- **T2** — Server-side re-signing of e-prescriptions breaks non-repudiation chain.
- **I3** — Controlled-substance details in application logs.
- **I4** — Externally-sourced medication history classification gap.
- **E1** — Over-broad database privileges for Rx Service.
- **E2** — Client JWT pass-through into internal services.
- **E3** — GitHub OIDC deploy role not constrained by branch.
- **E4** — Step-up MFA assertion not bound to individual prescription.

**Medium (5):** T1, T3, R1, D1, D2 — details in the STRIDE table above.

### Recommended Remediation Plan

- **Sprint 47 (current sprint, ends 2026-02-25):** fix all 3 Critical findings. **I1** is a one-handler code change (≈1 engineer-day including test). **I2** is a middleware change (≈2 engineer-days). **R2** is a logging-infrastructure change (≈5 engineer-days; coordinate with Data Platform).
- **Sprint 48 (2026-02-26 to 2026-03-11):** High findings in the API service (S1, S2, I3, E2, E4). Estimated 12 engineer-days across Platform, Identity, and Rx teams.
- **Sprint 49 (2026-03-12 to 2026-03-25):** remaining High findings (S3, T2, I4, E1, E3) — these span team boundaries and require coordination. Estimated 10 engineer-days.
- **Sprint 50 and beyond:** Medium findings and architectural defense-in-depth. The audit log segregation (T3) is a platform investment of ≈3 weeks and should be scoped as its own project.

### Residual Risk Statement

After remediation, the principal residual risk is the classic insider-with-valid-credentials scenario: a clinician with legitimate access who queries patients outside their care relationship. Technical controls alone cannot prevent this, and we are managing it with detective controls: patient-access logs reviewed by the compliance team, anomaly detection on access volume, and patient-facing "who viewed my record" transparency. A second residual risk is vendor compromise — if Surescripts is breached, externally-sourced medication history may be exposed. This is managed by per-vendor credential isolation, outbound network allowlists, and a pre-defined incident response runbook for vendor breach notification.

### Re-Assessment Triggers

- Any new vendor integration (each adds a new trust boundary).
- Any change to the authentication model (Okta tenant consolidation, new IdP, etc.).
- Introduction of a new data class (e.g., genetic data, which has separate regulatory status in some states).
- Addition of a clinician-to-clinician messaging feature (substantially changes the IDOR surface).
- Any incident that the current model did not anticipate — the model missed something, and we need to understand why before the next release.
- Annually, on or before 2027-02-11, regardless of other triggers.
