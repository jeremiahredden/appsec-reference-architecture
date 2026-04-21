# STRIDE Threat Model Template

> Fork this document into your engagement workspace. Replace the example content in each section with the system under analysis. The example rows in the STRIDE table are illustrative — delete them and author threats specific to your target system. Do not ship this template with example data still in it.

---

## Document Metadata

| Field | Value |
| --- | --- |
| **System Name** | *e.g., Patient Records API v2* |
| **System Owner** | *Engineering team and tech lead* |
| **Business Owner** | *Product owner accountable for data decisions* |
| **Date** | *YYYY-MM-DD of session* |
| **Facilitator** | *Security architect running the session* |
| **Participants** | *Names and roles of everyone in the room* |
| **Session Duration** | *Actual time spent, e.g., 75 min* |
| **Data Classification** | *Public / Internal / Confidential / Restricted — and regulatory scope (HIPAA, PCI-DSS, GDPR, etc.)* |
| **Environment Scope** | *Production only / includes staging / includes dev sandboxes* |
| **Revision** | *1.0 for initial, increment for major re-modeling* |
| **Prior Model Reference** | *Link to previous threat model if this is a refresh* |

### Trust Boundary Summary

One paragraph describing where trust changes hands in this system. Name the boundaries, do not just enumerate components. Example:

> The system has four trust boundaries: (1) the public internet to the edge (WAF + CDN), (2) the edge to the authenticated API tier (OAuth2/JWT validation), (3) the API tier to the data plane (mTLS + workload identity), and (4) the data plane to third-party vendor APIs (outbound allowlist + per-vendor API keys in secrets manager). Data sensitivity increases monotonically from boundary 1 to boundary 4.

---

## Trust Boundary Diagram

```
+---------------------------+     Trust Zone 0: Untrusted Internet
|        End User            |     - Anyone on the public internet
|  (Browser / Mobile / SDK)  |     - No authenticated identity
+-------------+--------------+
              | HTTPS (TLS 1.3)
              v
======== Boundary 1: Edge (WAF + CDN) ========================
              |
              v
+---------------------------+     Trust Zone 1: Edge / Ingress
|  Load Balancer + WAF       |     - L7 filtering, rate limiting
|  (AWS ALB + AWS WAF)       |     - TLS termination, DDoS protection
+-------------+--------------+     - No application secrets
              |
              v
======== Boundary 2: AuthN/AuthZ (OAuth2 / JWT) ===============
              |
              v
+---------------------------+     Trust Zone 2: Authenticated API
|     API Gateway            |     - JWT validation, scope enforcement
|  (Kong / Envoy / APIGW)    |     - Request routing, schema validation
+-------------+--------------+     - Per-tenant rate limits
              |
              v
+---------------------------+     Trust Zone 3: Service Mesh
|   Service Mesh (Istio)     |     - mTLS between services
|   + Workload Identity      |     - SPIFFE/SPIRE or cloud-native
+-------------+--------------+     - Per-service authz policies
              |
              v
+---------------------------+     Trust Zone 4: Microservices
|   Application Services     |     - Business logic
|   (users, billing, docs)   |     - Validated inputs only
+-------------+--------------+     - No direct DB writes across domains
              |
              v
======== Boundary 3: Data Plane (mTLS + IAM) ==================
              |
              v
+---------------------------+     Trust Zone 5: Data Stores
|   Primary Data Store       |     - Encrypted at rest (KMS CMK)
|   (PostgreSQL / DynamoDB)  |     - IAM database authentication
+-------------+--------------+     - Row-level security enforced
              |
              v
======== Boundary 4: Third-Party Egress ========================
              |
              v
+---------------------------+     Trust Zone 6: External Vendors
|   Vendor APIs              |     - Outbound allowlist only
|   (Stripe, Twilio, etc.)   |     - Per-vendor secrets in KMS
+---------------------------+     - Bounded blast radius on compromise
```

Redraw the diagram above to reflect the system under analysis. Keep it in ASCII in the Markdown file so it diffs cleanly in pull requests. If the system warrants a richer diagram, link to a Mermaid or draw.io source alongside this one — but always keep the ASCII version as the source of truth that reviewers see in the PR.

---

## STRIDE Threat Enumeration

### Scoring Rubrics

**Likelihood (L):** 1 = Theoretical / requires insider with existing credentials, 2 = Requires meaningful effort or privileged position, 3 = Plausible external attacker with publicly available tools, 4 = Trivial / can be exploited by an unauthenticated attacker with Burp in an afternoon.

**Impact (I):** 1 = Single user affected, recoverable in minutes, 2 = Tenant-scoped impact, recoverable in hours, 3 = Multi-tenant or regulated data exposure, multi-day recovery, 4 = Platform-wide or full data breach, material business harm.

**Risk = L × I**, mapped to severity bands: 1-3 = **Low**, 4-6 = **Medium**, 7-11 = **High**, 12-16 = **Critical**.

### Threat Table

*The rows below are illustrative examples spanning all six STRIDE categories. Replace them with threats specific to your system.*

| # | Component | Threat Category | Threat Description | Current Mitigation | L | I | Risk | Recommended Control | Owner | Status |
| --- | --- | --- | --- | --- | :-: | :-: | :-: | --- | --- | --- |
| 1 | API Gateway | **Spoofing** | Attacker forges a JWT using a weak HMAC secret leaked in a prior commit to reach authenticated endpoints as an arbitrary user. | JWTs signed with HS256 using a shared secret in environment variables. Secret has not been rotated in 18 months. | 3 | 4 | **12 — Critical** | Migrate to RS256 with per-environment private keys in KMS. Rotate on compromise and quarterly. Add JWT claim pinning (`kid` header validation). | Platform Team | Open |
| 2 | User Service | **Spoofing** | Account takeover via password reset token brute force — tokens are 6-digit numeric with no rate limit per account. | Email-delivered 6-digit OTP, 15-minute TTL. Global rate limit at WAF (10 req/sec per IP). | 3 | 3 | **9 — High** | Increase token entropy to 128-bit URL-safe random. Enforce per-account rate limit (5 attempts / 15 min / account) at application layer. Lock account and notify on 5 failures. | Identity Team | Open |
| 3 | Billing Service | **Tampering** | Client-side price manipulation — cart total is submitted from the browser and trusted by the checkout endpoint. | Schema validation on the `total` field (must be positive number). | 4 | 3 | **12 — Critical** | Never accept price from client. Recompute total server-side from product catalog and applied discounts. Log and alert on any client-submitted total that mismatches server calculation. | Commerce Team | Open |
| 4 | File Upload Service | **Tampering** | Path traversal in upload filename — attacker uploads with `../../../etc/passwd` as filename to write outside the tenant bucket. | Filename is used directly as the S3 object key. | 3 | 3 | **9 — High** | Generate a server-side UUID as the S3 key. Store the user-provided filename as metadata only. Validate filename against a strict allowlist regex (`^[a-zA-Z0-9_.-]{1,255}$`) before accepting. | Storage Team | Open |
| 5 | API Gateway | **Repudiation** | Privileged administrative actions (user deletion, permission changes) are not logged to an immutable audit store. Admin can deny having performed an action, and logs can be altered on the application host. | Application-level logging to stdout, shipped to CloudWatch with 30-day retention. Logs are mutable by the service account that writes them. | 2 | 3 | **6 — Medium** | Emit structured audit events to a dedicated append-only store (CloudTrail + S3 with Object Lock, or a SIEM with WORM retention). Include actor, action, target, timestamp, and request ID. Retain 7 years for regulated actions. | Platform Team | Open |
| 6 | Document Service | **Repudiation** | Document signing/approval workflow does not capture the signer's authentication context (MFA assertion, session ID, client IP) at the time of signature. | Signer name and timestamp stored in the document record. | 2 | 2 | **4 — Medium** | Capture authentication context at the moment of signature: MFA assertion type, session ID, client IP, user-agent. Store alongside document hash in a separate audit ledger. | Document Team | Open |
| 7 | User Service | **Information Disclosure** | User enumeration via login error messages — "user not found" vs. "wrong password" are distinguishable, allowing account enumeration. | Distinct error messages in the login response. | 4 | 2 | **8 — High** | Return a single generic error ("invalid credentials") for both cases. Ensure timing is constant between the two paths (compute a dummy password hash for the user-not-found case). | Identity Team | Open |
| 8 | Search Service | **Information Disclosure** | Cross-tenant data exposure via search — the search index is shared across tenants and row-level authorization is applied at the API layer, not the index layer. A bug in the filter could expose other tenants' data. | API layer filters results by `tenant_id` from the JWT. No defense in depth at the index. | 2 | 4 | **8 — High** | Partition the search index per tenant (separate ElasticSearch index per tenant or strict namespace isolation). Validate tenant isolation in integration tests. Add an index-layer filter as a second enforcement point. | Search Team | Open |
| 9 | Data Store | **Information Disclosure** | Database backups are stored in an S3 bucket with KMS encryption, but the KMS key policy allows any IAM role in the account to decrypt. A compromised non-database IAM role could exfiltrate backups. | S3 bucket policy restricts access to the backup service role. KMS key policy grants `kms:Decrypt` to `Root`. | 2 | 4 | **8 — High** | Scope the KMS key policy to the specific backup service role and the break-glass role only. Remove `Root` principal. Log all `kms:Decrypt` calls to CloudTrail and alert on decrypts outside the expected service context. | Data Platform | Open |
| 10 | Public API | **Denial of Service** | Unbounded response size — the `/export` endpoint returns all records matching a query with no pagination or size limit. A malicious client can trigger memory exhaustion. | WAF rate limit (100 req/min per IP). No application-level response size cap. | 3 | 2 | **6 — Medium** | Enforce mandatory pagination on all list endpoints (max page size 1000). For exports, stream to S3 and return a pre-signed URL instead of a synchronous response. Cap total query result size at the ORM layer. | Platform Team | Open |
| 11 | Authentication Service | **Denial of Service** | Expensive password hashing (Argon2id at high cost factor) on the login endpoint has no pre-validation, allowing an attacker to exhaust CPU with invalid-username requests. | Argon2id with 3 iterations, 64MB memory, 4 parallelism. No pre-check on username existence. | 3 | 3 | **9 — High** | Add a lightweight pre-validation step (username format, account exists) before invoking the hash function. Keep hash function constant-time for valid usernames to prevent enumeration. Apply strict per-IP rate limits on `/login`. | Identity Team | Open |
| 12 | Service Mesh | **Elevation of Privilege** | Missing authorization between internal microservices — any service in the mesh can call any other service, because mTLS authenticates identity but no authorization policy restricts which callers reach which services. | mTLS via Istio. Network-level ALLOW ALL between meshed services. | 3 | 4 | **12 — Critical** | Implement Istio AuthorizationPolicies per service, defaulting to DENY. Explicitly allow known call graphs. Treat this as a platform-provided capability — individual service teams should not have to write their own mTLS+authz code. | Platform Team | Open |
| 13 | Admin Console | **Elevation of Privilege** | Horizontal privilege escalation — the `/admin/users/{user_id}` endpoint trusts the `user_id` path parameter without verifying the authenticated admin has authority over that user's tenant. | JWT validated. Role claim (`admin`) checked. No per-tenant scoping. | 3 | 4 | **12 — Critical** | Enforce tenant scoping on every admin endpoint: the admin's JWT carries an allowed-tenants claim, and the target resource's tenant is validated against that claim at the handler level. Add an integration test that exercises cross-tenant access and must fail. | Admin Team | Open |
| 14 | Billing Service | **Elevation of Privilege** | SSRF in the invoice-to-PDF rendering service — a tenant-supplied URL is fetched server-side to include external images in the generated PDF. Can reach the AWS IMDS (169.254.169.254) and steal IAM credentials. | URL is validated to be HTTP(S). | 3 | 4 | **12 — Critical** | Use an egress proxy with an allowlist of public CDN domains only. Block RFC1918, link-local, and loopback addresses. Require IMDSv2 with hop-limit 1 on all EC2 instances as a defense-in-depth measure. | Billing Team | Open |
| 15 | CI/CD Pipeline | **Elevation of Privilege** | GitHub Actions workflows run with a long-lived AWS IAM user access key stored as a repository secret. A malicious pull request from a fork could exfiltrate the key via a modified workflow. | Key is stored as a GitHub Actions secret. Workflows restricted to the default branch for deploy steps. | 2 | 4 | **8 — High** | Replace IAM user keys with GitHub OIDC federation to an IAM role scoped by repository and branch. Remove the long-lived access key entirely. Enforce branch protection with required reviewers on workflow file changes. | DevOps Team | Open |

---

## Findings Summary (Executive Section)

*This section is what you include in a status report to leadership. Keep it to one page.*

### System Overview

*One paragraph: what the system does, what data it handles, who uses it, what the regulatory context is.*

### Assessment Scope and Method

*Two to three sentences: STRIDE methodology, session duration, participants, any scope exclusions.*

### Top Risks Identified

List the Critical and High findings with their one-line descriptions. Do not paste the full threat table here — that lives in the appendix. Example:

- **Critical (5):** JWT signing key weakness; client-trusted pricing; cross-service authorization gap; horizontal privilege escalation in admin console; SSRF in PDF rendering.
- **High (5):** password reset token brute force; path traversal in file upload; user enumeration on login; cross-tenant search exposure; hash function DoS on login.
- **Medium (5):** mutable audit logs; signature context capture; unbounded export size; and *(two more as applicable)*.

### Recommended Remediation Plan

*Group recommendations into sprint-level work:*

- **Sprint N (current):** fixes for all Critical findings. Estimated effort: *X engineer-days*.
- **Sprint N+1:** fixes for all High findings. Estimated effort: *Y engineer-days*.
- **Sprint N+2:** Medium findings and defense-in-depth improvements. Estimated effort: *Z engineer-days*.
- **Ongoing / architectural:** any finding whose fix is a platform investment spanning multiple quarters — call it out separately, with a product-and-engineering owner, and a rough delivery window.

### Residual Risk Statement

*One paragraph describing what risk remains after the recommended controls are implemented, and the compensating controls (detection, response) that manage it. Do not claim zero residual risk. Do not catastrophize. Name the residual risk precisely enough that a CISO can sign off on accepting it.*

### Re-Assessment Triggers

*List the specific events that should trigger a re-run of this model — new external integrations, new data classifications handled, significant architecture changes, regulatory scope changes, or incidents that the current model did not anticipate.*
