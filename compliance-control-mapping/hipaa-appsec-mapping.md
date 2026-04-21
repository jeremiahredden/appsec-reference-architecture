# HIPAA Security Rule → AppSec Controls Mapping

## Scope

This document maps the HIPAA Security Rule (45 CFR Part 164, Subpart C) to concrete AppSec controls, implementations, and evidence artifacts that an engineering organization can produce. The focus is on **Technical Safeguards (§164.312)** — the subsection where application security has the most to contribute — with selected entries from **Administrative Safeguards (§164.308)** and **Organizational Requirements (§164.314)** where an AppSec control is the primary evidence source.

"Addressable" and "Required" designations come directly from the regulation. *Addressable* does not mean optional — it means the covered entity must either implement the specification, implement a reasonable alternative, or document why neither is reasonable and appropriate. In practice, most AppSec-relevant addressable specifications become required de facto under any modern threat model.

## §164.312 Technical Safeguards

### §164.312(a) Access Control

| Requirement | Text (paraphrased) | AppSec Control | Implementation Example | Evidence Artifact | Tool / Process |
| --- | --- | --- | --- | --- | --- |
| §164.312(a)(1) | Implement technical policies and procedures for electronic information systems that maintain ePHI to allow access only to authorized persons. (Required) | Authorization framework with role- and resource-level checks; tenant isolation at the query layer. | FastAPI dependency `require_role("clinician")` on every PHI endpoint; SQLAlchemy queries scoped by `tenant_id=current_user.tenant_id`. | `app/auth/rbac.py` + integration tests under `tests/auth/test_authorization.py`; Semgrep custom rule `flask-route-missing-auth` blocking PRs that add unauthenticated routes. | Semgrep + pytest in `.github/workflows/appsec-pipeline.yml`. |
| §164.312(a)(2)(i) | Assign a unique name and/or number for identifying and tracking user identity. (Required) | Unique immutable user ID propagated from IdP through to every log line and audit record. | OIDC `sub` claim persisted as `users.external_id`; application writes `user_id` to every structured log event. | Sample log export showing per-request `user_id`; user-provisioning workflow doc. | IdP (Okta / Entra) + structured logger (pino / stdlib logging with JSONFormatter). |
| §164.312(a)(2)(ii) | Establish procedures for obtaining necessary ePHI during an emergency. (Required) | "Break-glass" account with elevated access, logged and alerted separately, expiring within 24 hours. | Dedicated `break_glass` role in IdP; access triggers PagerDuty notification to CISO and security ops; usage audit in weekly security review. | Break-glass usage report; runbook at `docs/incident/break-glass.md`. | IdP + SIEM alert rule. |
| §164.312(a)(2)(iii) | Automatic logoff after a predetermined period of inactivity. (Addressable) | Session timeout and idle-timeout on every authenticated session. | `SESSION_COOKIE_MAX_AGE=43200` (12h absolute), idle timeout 30 minutes enforced server-side; SPA refreshes tokens on activity, logs out on inactivity. | Session configuration in `app/config.py`; pytest assertion in `tests/auth/test_session_timeout.py`. | Flask/Express session middleware + automated test. |
| §164.312(a)(2)(iv) | Implement a mechanism to encrypt and decrypt ePHI. (Addressable) | Authenticated encryption (AES-GCM / AES-CCM) at the storage layer with KMS-managed keys. | PostgreSQL `pgcrypto` for column-level PHI fields; S3 objects encrypted with `aws:kms` and a CMK restricted by `aws:PrincipalOrgID`. | KMS key policy JSON; Terraform for `aws_s3_bucket_server_side_encryption_configuration`; migration that adds encrypted columns. | AWS KMS + Terraform + Checkov rule `CKV_AWS_19` (S3 bucket encryption). |

### §164.312(b) Audit Controls

| Requirement | Text (paraphrased) | AppSec Control | Implementation Example | Evidence Artifact | Tool / Process |
| --- | --- | --- | --- | --- | --- |
| §164.312(b) | Implement hardware, software, and procedural mechanisms that record and examine activity in information systems that contain or use ePHI. (Required) | Structured application audit log with stable event vocabulary, per-request identity, and centralized aggregation. | Every PHI read emits `phi_access` event with `user_id`, `patient_id`, `reason`, `request_id`; logs shipped to Loki / CloudWatch with 13-month retention. | Sample log query showing `phi_access` events; retention policy doc; SIEM dashboard screenshot. | pino-http / Python `logging` + Loki / Splunk / CloudWatch. |

### §164.312(c) Integrity

| Requirement | Text (paraphrased) | AppSec Control | Implementation Example | Evidence Artifact | Tool / Process |
| --- | --- | --- | --- | --- | --- |
| §164.312(c)(1) | Policies and procedures to protect ePHI from improper alteration or destruction. (Required) | Parameterized queries everywhere; schema-validated input at every API boundary; ORM-only writes; signed audit events for privileged changes. | No raw SQL in application code (Semgrep `formatted-sql-query` blocking); pydantic / zod schemas on every POST/PUT; critical state transitions append a signed record to an append-only table. | `audit_events` table with HMAC signatures; Semgrep SARIF report showing zero raw-SQL findings; schema definitions under `app/schemas/`. | Semgrep + pydantic + application code review. |
| §164.312(c)(2) | Mechanism to authenticate ePHI (verify it has not been altered or destroyed in an unauthorized manner). (Addressable) | Content hashing on immutable artifacts; HMAC-signed audit events; database row-level timestamps and checksums on critical tables. | Object-store artifacts keyed by SHA-256 of content; `audit_events.signature = HMAC_SHA256(body, signing_key)` verified on read; DB migrations append rows, never update. | Hash-verification job run; sample audit-event row with signature. | Application code + nightly integrity job. |

### §164.312(d) Person or Entity Authentication

| Requirement | Text (paraphrased) | AppSec Control | Implementation Example | Evidence Artifact | Tool / Process |
| --- | --- | --- | --- | --- | --- |
| §164.312(d) | Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed. (Required) | OIDC / SAML SSO via enterprise IdP; MFA enforced at the IdP; JWTs with pinned algorithm, issuer, audience, and required claims. | `jwt.decode(token, public_key, algorithms=["RS256"], issuer=..., audience=..., options={"require": ["exp","iss","aud","sub"]})`; IdP policy requires MFA for access to any app classified as PHI-handling. | Token validation code in `app/auth/jwt.py`; IdP policy export; MFA enrollment report. | IdP + application JWT validation + unit tests. |

### §164.312(e) Transmission Security

| Requirement | Text (paraphrased) | AppSec Control | Implementation Example | Evidence Artifact | Tool / Process |
| --- | --- | --- | --- | --- | --- |
| §164.312(e)(1) | Technical security measures to guard against unauthorized access to ePHI transmitted over an electronic communications network. (Required) | TLS 1.2+ on every external boundary; mTLS for service-to-service within the VPC; HSTS with preload. | ALB listener with `TLS_1_2_2021` policy; Istio / Linkerd sidecars enforce mTLS; `helmet()` in Express, `Talisman` in Flask emits `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`. | `testssl.sh` report; Istio PeerAuthentication YAML; helmet config in `app/server.js`. | testssl.sh + Terraform + mesh config + pytest transport-security assertion. |
| §164.312(e)(2)(i) | Implement security measures to ensure that ePHI is not improperly modified without detection until disposed of. (Addressable) | Authenticated encryption on the wire (TLS AEAD ciphers); payload integrity via HMAC or signed JWT on critical API responses. | Cipher suite list restricted to `TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256`; webhook deliveries signed with `X-Signature-256`. | ALB / NGINX cipher configuration; webhook signing code; receiver verification snippet shared with integrators. | Load balancer config + application code. |
| §164.312(e)(2)(ii) | Implement a mechanism to encrypt ePHI when deemed appropriate. (Addressable) | Encryption is the baseline — TLS 1.2+ required on all paths, no plaintext fallback. | HTTP listener redirects to HTTPS at the ALB; origin refuses HTTP; outbound client pinned to HTTPS-only schemes. | ALB listener rules; outbound-client config showing HTTPS enforcement. | Terraform + client library config. |

## §164.308 Administrative Safeguards — AppSec-relevant rows

| Requirement | Text (paraphrased) | AppSec Control | Evidence Artifact |
| --- | --- | --- | --- |
| §164.308(a)(1)(ii)(A) — Risk Analysis | Conduct an accurate and thorough assessment of potential risks and vulnerabilities to ePHI. (Required) | Threat modeling every new service and every major feature that touches PHI. | STRIDE threat model docs under `docs/threat-models/`; see `threat-modeling/worked-example-rest-api.md` in this repo for the format. |
| §164.308(a)(1)(ii)(B) — Risk Management | Implement security measures sufficient to reduce risks to a reasonable and appropriate level. (Required) | Tracked remediation of threat-model findings, SAST findings, and SCA vulnerabilities with severity-based SLAs. | Break-build policy at `devsecops-pipeline/policy-as-code/break-build-policy.md`; JIRA export of open security findings. |
| §164.308(a)(1)(ii)(D) — Information System Activity Review | Regularly review records of information system activity. (Required) | SIEM dashboards, weekly log review, scheduled tabletop exercises on log queryability. | Dashboard screenshots; meeting notes from weekly security review. |
| §164.308(a)(5)(ii)(B) — Protection from Malicious Software | (Addressable) | SCA in CI (pip-audit, npm audit), SBOM on every release, image signing, admission controller that rejects unsigned images. | `.github/workflows/appsec-pipeline.yml` SCA jobs; Sigstore cosign signatures; Gatekeeper / Kyverno policy. |
| §164.308(a)(5)(ii)(C) — Log-in Monitoring | Procedures for monitoring log-in attempts and reporting discrepancies. (Addressable) | Alert rules on failed-login rate, geographic anomalies, impossible-travel. | Grafana / SIEM alert rule YAML; on-call runbook entry. |
| §164.308(a)(5)(ii)(D) — Password Management | (Addressable) | Argon2id password hashing; enforced minimum entropy via IdP; breached-password check against Have I Been Pwned on change. | IdP password policy export; auth service configuration. |
| §164.308(a)(8) — Evaluation | Perform a periodic technical and nontechnical evaluation. (Required) | Annual penetration test, continuous SAST/SCA/DAST, third-party code audit on major releases. | Pen test report (executive summary only, full report under access control); quarterly Semgrep / Snyk trend report. |

## §164.314 Organizational Requirements — AppSec-relevant rows

| Requirement | Text (paraphrased) | AppSec Control | Evidence Artifact |
| --- | --- | --- | --- |
| §164.314(a)(2)(i) — Business Associate Contracts | BA must implement safeguards that reasonably and appropriately protect the ePHI. | Subprocessor security review; vendor SBOM requirement; DPA with specific incident-notification SLAs. | Vendor-review tracker; signed BAAs; subprocessor page on public site. |

## A dedicated section: PHI in application logs

The single most common finding in HIPAA-scoped AppSec audits is PHI in application logs. It happens because logs default to *verbose* — an exception handler catches an error, serializes the request body into the log, and a patient identifier, SSN fragment, or diagnosis code ends up in a log store with broader access than the primary application. The log store is typically not part of the same access-review scope as the database, so the log becomes an uncontrolled secondary copy of the regulated data.

The fix is a four-part discipline:

1. **Define a redaction allowlist, not a denylist.** A denylist ("don't log `ssn`, `dob`, `diagnosis`") will never be complete. An allowlist says: the only fields in log lines are the ones we explicitly approved. Structured logging with a fixed schema enforces this by construction.
2. **Strip PHI at the logger, not at the handler.** Apply redaction in the logging formatter so that every code path — including exception handlers and third-party library logs — is filtered. Do not rely on every developer to remember.
3. **Scope log-store access at least as tightly as database access.** If the database requires break-glass, the log store requires break-glass. This is often the quickest fix because the database access controls already exist; the log store has simply never been tiered to match.
4. **Test the redaction.** A unit test per log event that fuzzes the known PHI field names and asserts they never appear in emitted log lines. If the redaction filter regresses in a library upgrade, the test catches it before production.

**Remediation pattern (Python):**

```python
import logging, json

class PHIRedactFilter(logging.Filter):
    PHI_KEYS = {"ssn", "dob", "date_of_birth", "diagnosis",
                "mrn", "patient_name", "address", "phone"}

    def _scrub(self, obj):
        if isinstance(obj, dict):
            return {k: ("[REDACTED]" if k.lower() in self.PHI_KEYS
                        else self._scrub(v)) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._scrub(v) for v in obj]
        return obj

    def filter(self, record):
        if isinstance(record.args, dict):
            record.args = self._scrub(record.args)
        if hasattr(record, "ctx"):
            record.ctx = self._scrub(record.ctx)
        return True
```

The filter attaches at the root logger so that every library — not just your application code — passes through it. Pair it with a pytest assertion that emits a synthetic record with every PHI field name populated and asserts `[REDACTED]` appears in the output.

**Remediation pattern (JavaScript):**

```javascript
const pino = require("pino");

const logger = pino({
  redact: {
    paths: [
      "*.ssn", "*.dob", "*.dateOfBirth", "*.diagnosis",
      "*.mrn", "*.patientName", "*.address", "*.phone",
      "req.body.ssn", "req.body.dob", "req.headers.authorization",
    ],
    censor: "[REDACTED]",
  },
});
```

pino's wildcard redaction paths (`*.ssn`) apply at any object depth, so nested request bodies are covered.

**Evidence artifact for the auditor:** the redaction configuration file, a pytest / Jest test that asserts PHI never appears in emitted logs, and a sample log export from production showing `[REDACTED]` in the relevant fields on requests that would otherwise have contained PHI.

## Using this document during an audit

When the auditor asks "walk me through how you satisfy §164.312(c)(1)" the answer is:

> We satisfy §164.312(c)(1) Integrity through three layered controls. First, parameterized queries are enforced as a blocking CI check — see the Semgrep SARIF report in the last main-branch run of our appsec-pipeline workflow, which shows zero findings for the `formatted-sql-query` rule. Second, every API endpoint validates its input against a pydantic or zod schema before any database interaction — here's the schema definition for the PHI-writing endpoint and the corresponding integration test. Third, privileged state transitions append HMAC-signed rows to the `audit_events` table — here's the signing code, the verification job that runs nightly, and the most recent run showing zero integrity failures.

That answer is better than a policy PDF because it names the artifact, the tool, the file path, and the run. The auditor can verify each element without a follow-up request. Every row in this document is structured to support that conversation.
