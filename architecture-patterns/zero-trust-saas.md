# Zero Trust SaaS — A Reference Architecture

## The opinion up front

Zero trust is an architectural commitment, not a product. No appliance, mesh, or vendor "ZTNA" makes a system zero trust on its own. What makes a system zero trust is that **authorization decisions do not rely on network location** — not on "we're inside the VPC," not on "this came through the corporate VPN," not on "this is the internal admin subnet." Every request carries identity, every hop verifies it, and every access decision is made against a current policy using current signals, not a cached trust assumption from last week's login.

If you are building a SaaS from scratch, zero trust is cheaper to adopt than to retrofit. The expensive part of retrofitting is ripping out the implicit trust that accumulates in internal services over years. Start with explicit identity on every call and you avoid that debt entirely.

## Reference architecture

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                                  USER TIER                                       │
│                                                                                   │
│   ┌──────────────┐      ┌──────────────┐      ┌──────────────┐                   │
│   │  Employees   │      │  Customers   │      │  Integrators │                   │
│   │  (Workforce) │      │  (B2C / B2B) │      │  (OAuth2 CC) │                   │
│   └──────┬───────┘      └──────┬───────┘      └──────┬───────┘                   │
│          │                     │                      │                           │
│          │  ▼ SSO + MFA + device posture              │                           │
│          └───────────┬─────────┴──────────────────────┘                           │
│                      │                                                             │
└──────────────────────┼─────────────────────────────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────────────────────────┐
│                         IDENTITY TIER  (trust zone: IdP)                        │
│                                                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │  Identity Provider (Okta / Entra / Auth0 / Keycloak)                    │   │
│   │  · OIDC + SAML  · MFA policy  · Device trust  · Risk signals            │   │
│   │  · Publishes JWKS at /.well-known/jwks.json                             │   │
│   │  · Emits authN/authZ events to SIEM                                     │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
└──────────────────────┬──────────────────────────────────────────────────────────┘
                       │  signed JWT (iss, aud, sub, scope, amr, acr, exp)
                       │
┌──────────────────────▼──────────────────────────────────────────────────────────┐
│                       EDGE TIER  (trust zone: public)                           │
│                                                                                 │
│   ┌─────────────────────────┐   ┌──────────────────────────┐                    │
│   │  CDN / WAF (Cloudflare, │   │  API Gateway             │                    │
│   │  AWS WAF, Cloudfront)   │──▶│  · JWT signature + claims│                    │
│   │  · TLS 1.3 only         │   │  · Coarse authZ (scope)  │                    │
│   │  · Managed rule sets    │   │  · Per-client rate limits│                    │
│   │  · Bot mitigation       │   │  · Propagates:           │                    │
│   │  · IP / ASN rate limits │   │      - request_id         │                   │
│   │                         │   │      - user_id / client_id│                   │
│   │                         │   │      - trace span         │                   │
│   └─────────────────────────┘   └─────────────┬─────────────┘                   │
└──────────────────────────────────────────────┼──────────────────────────────────┘
                                               │  mTLS (mesh)
┌──────────────────────────────────────────────▼──────────────────────────────────┐
│                    SERVICE TIER  (trust zone: workload)                         │
│                                                                                 │
│   ┌────────────────────────────┐     ┌────────────────────────────┐             │
│   │  Service A                 │     │  Service B                 │             │
│   │  · SPIFFE identity         │◀───▶│  · SPIFFE identity         │             │
│   │  · Authorizes by caller +  │ mesh│  · Authorizes by caller +  │             │
│   │    user token + resource   │ mTLS│    user token + resource   │             │
│   │  · Schema-validated input  │     │  · Schema-validated input  │             │
│   │  · Structured audit log    │     │  · Structured audit log    │             │
│   └────────────┬───────────────┘     └────────────┬───────────────┘             │
│                │                                   │                             │
│                │  Service-mesh authZ policy (Istio AuthorizationPolicy):        │
│                │    - only Service A → Service B                                 │
│                │    - on paths /internal/orders/*                                │
│                │    - when user token has scope orders:write                     │
└────────────────┼───────────────────────────────────┼─────────────────────────────┘
                 │                                   │
┌────────────────▼───────────────────────────────────▼─────────────────────────────┐
│                         DATA TIER  (trust zone: regulated)                       │
│                                                                                   │
│   ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐      │
│   │  PostgreSQL         │  │  S3 (encrypted)     │  │  KMS                │      │
│   │  · Row-Level Security│ │  · Bucket policy    │  │  · Per-tenant CMK   │      │
│   │  · Per-service user │  │  · Access logs      │  │  · Key-use audit    │      │
│   │  · Audit triggers   │  │  · Object lock      │  │                     │      │
│   └─────────────────────┘  └─────────────────────┘  └─────────────────────┘      │
└──────────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────────┐
│                       CONTROL PLANE  (isolated from data plane)                  │
│                                                                                   │
│   ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐      │
│   │  CI/CD              │  │  PAM (Teleport,     │  │  SIEM               │      │
│   │  · OIDC-federated   │  │  AWS SSM Session    │  │  · Identity events  │      │
│   │  · Signed commits   │  │  Manager, StrongDM) │  │  · Mesh access logs │      │
│   │  · Artifact signing │  │  · Break-glass      │  │  · App audit logs   │      │
│   │                     │  │  · Session record   │  │  · Correlation      │      │
│   └─────────────────────┘  └─────────────────────┘  └─────────────────────┘      │
└──────────────────────────────────────────────────────────────────────────────────┘
```

## The seven principles, applied to SaaS

NIST SP 800-207 defines zero trust through seven tenets. Below is each tenet with its SaaS-architecture interpretation.

### 1. All data sources and computing services are considered resources

Every service, database, queue, object store, and pipeline is a resource requiring identity-based access. There is no "internal" service that skips authN/authZ because it's behind a firewall. Practically:

- Every service endpoint requires a verified identity on every request. No internal-only ports without auth.
- Storage systems accept credentials, not IP allowlists, as the primary access control. IP allowlists are defense in depth, not the front door.
- Message queues and databases have per-workload credentials with scoped permissions.

### 2. All communication is secured regardless of network location

- TLS 1.2+ on every hop, external and internal.
- mTLS for service-to-service within the cluster; identity is cryptographic, not network-derived.
- No plaintext HTTP on any port, including "internal" metrics endpoints. Prometheus scrapes over mTLS or TLS-with-auth, not port 9090 open to the mesh.

### 3. Access to individual enterprise resources is granted on a per-session basis

- Short-lived access tokens (5–60 minutes) rather than long-lived API keys.
- Per-request authorization decisions; no "logged in, access granted for 8 hours" pattern at the resource level.
- Session-version counters that can be bumped to revoke all active sessions for a user.

### 4. Access is determined by dynamic policy including client identity, application/service, and requesting asset

- Authorization is a function of who (user + device + workload), what (resource), and context (time, location, risk signals).
- Policy engines (OPA, Cedar, or equivalent) evaluate these inputs; they are not baked into service code.
- Device posture is an input: an unmanaged laptop gets read-only access; a managed, compliant laptop gets write.

### 5. The enterprise monitors and measures the integrity and security posture of all owned and associated assets

- Workload identity is bound to continuously attested infrastructure (SPIFFE / SPIRE, AWS IAM Roles Anywhere with device certs, GCP Workload Identity).
- Image signatures verified at admission (Sigstore / cosign).
- EDR on endpoints; runtime threat detection (Falco, CloudWatch agent) on workloads.
- Drift detection on IaC — if someone changes a security group by hand, the change is detected and reverted or flagged.

### 6. All resource authentication and authorization is dynamic and strictly enforced before access is allowed

- Enforcement is **continuous**, not one-time-at-login. Every API call re-validates the token; short TTLs force re-authentication; risk signals can terminate sessions mid-use.
- No "trust me, I validated this two hops ago." Each service re-validates the incoming identity.

### 7. The enterprise collects as much information as possible about the current state of assets, network infrastructure, and communications and uses it to improve security posture

- Identity, network, application, and cloud control-plane events land in a SIEM with a common request-ID / trace-ID correlation key.
- Telemetry drives detection rules and policy updates, not just post-mortem forensics.

## Identity-first access — continuous verification, not just login

The most important shift: authorization at every request, not just at login. Concretely:

### 1. Short access tokens + refresh-token rotation

- **Access tokens** live 5–60 minutes. When they expire, the client must refresh.
- **Refresh tokens** live hours to days, rotate on every use, and are server-revocable.
- **Impact of compromise:** bounded to one access-token lifetime after detection.

### 2. Step-up authentication on sensitive operations

- Normal operations: standard session token.
- Sensitive operations (change billing, export data, rotate admin): require a fresh MFA challenge (OIDC `acr_values`, `max_age`, or custom claim).
- The policy lives in the IdP; the service enforces by reading the `amr` / `acr` claims on the access token.

### 3. Risk-based reauthentication

- IdP ingests risk signals: new IP, new device, impossible travel, unusual time-of-day, anomalous behavior.
- High-risk scores trigger MFA re-prompt or session termination.
- Services respect an "auth context" claim that summarizes the risk tier; e.g., a session flagged as "new device, pending verification" can read but not write.

### 4. Device posture as an authorization input

- MDM-enrolled, fully patched, disk-encrypted laptop → full access.
- Unenrolled or non-compliant → limited access (view-only, or blocked entirely).
- Policy lives in the IdP or a ZTNA broker (Cloudflare Access, Google BeyondCorp Enterprise, Tailscale, Zscaler).

### 5. Session-version counters for instant revocation

JWTs are hard to revoke. A common mitigation:

```
access_token.claims = {
  sub: "u-42",
  session_version: 7,    // incremented in the user record on revocation
  exp: 1800,
  ...
}
```

Every service call checks `claims.session_version == user.current_session_version`. On revocation, bump the counter; all active tokens for the user are rejected on their next call. Cache the counter in Redis with a short TTL to keep the check cheap.

## Micro-segmentation at the service level (service mesh)

Zero-trust micro-segmentation means that workload-to-workload communication requires **identity-level authorization**, not network reachability. Two workloads on the same subnet are segmented because the mesh policy says so — not because they are on different subnets.

### Using Istio as the reference

```yaml
# Require mTLS with verified identity on every call to the orders service.
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: orders-strict
  namespace: orders
spec:
  mtls:
    mode: STRICT
---
# Only the checkout service may call the orders service, and only
# on the /internal paths, and only when a request carries a user
# JWT with the orders:write scope.
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: orders-authz
  namespace: orders
spec:
  selector:
    matchLabels:
      app: orders
  action: ALLOW
  rules:
    - from:
        - source:
            principals: ["cluster.local/ns/checkout/sa/checkout"]
      to:
        - operation:
            methods: ["POST"]
            paths: ["/internal/orders", "/internal/orders/*"]
      when:
        - key: request.auth.claims[scope]
          values: ["*orders:write*"]
```

The principal `cluster.local/ns/checkout/sa/checkout` is a SPIFFE identity tied to the Kubernetes service account of the checkout workload. It cannot be spoofed by a different pod on the same node because Istio's proxy rejects any peer whose SPIFFE cert does not match.

Pair `AuthorizationPolicy` with **NetworkPolicy** (Calico, Cilium) for defense in depth at the L3/L4 layer. If a misconfiguration turns off mTLS in the mesh, the network policy still blocks east-west traffic to unallowed destinations.

### Linkerd equivalents

Linkerd uses `Server` and `ServerAuthorization` / `HTTPRoute`-based policies; the principle is the same — identity-derived rules that are evaluated per request. Choose whichever mesh the team will actually operate; a perfectly configured mesh no one understands is a time bomb.

## Privileged access management (production access)

Humans sometimes need production access for incident response or debugging. Zero trust requires the path to be auditable and time-bounded.

### Baseline

- **No direct SSH or `kubectl` from laptops to production.** All access mediated by a bastion / broker.
- **Just-in-time access, not standing permissions.** Engineers request access for a specific task; the request is logged and approved; access expires automatically (30 min to 4 h).
- **Session recording on every privileged session.** Teleport, AWS SSM Session Manager, or StrongDM record command-level activity for audit.
- **Break-glass accounts** exist but generate a high-severity alert to the CISO's rotation on use.

### Reference workflow

```
 Engineer          Broker (Teleport)              Approver           Production
    │                    │                            │                    │
    │  request access    │                            │                    │
    │───────────────────▶│                            │                    │
    │                    │   notify approver          │                    │
    │                    │───────────────────────────▶│                    │
    │                    │                            │                    │
    │                    │          approve (2-person │                    │
    │                    │          for Sev 1/2)      │                    │
    │                    │◀───────────────────────────│                    │
    │                    │                            │                    │
    │                    │   issue short-lived cert   │                    │
    │                    │   (TTL 1h, scope: cluster  │                    │
    │                    │    X, namespace Y, action  │                    │
    │                    │    get/logs only)          │                    │
    │◀───────────────────│                            │                    │
    │                    │                            │                    │
    │  kubectl via broker, all commands recorded      │                    │
    │─────────────────────────────────────────────────────────────────────▶│
    │                                                                      │
    │                    │   session stream to S3 (object lock)            │
    │                    │─────────────────────────────────────────────────▶│
```

**Anti-patterns.** Shared service-account passwords in a vault. Long-lived SSH keys. Production access via the same identity as CI/CD. "Admin laptops" with standing root.

## Data plane vs. control plane isolation

A zero-trust SaaS separates the **data plane** (the paths customer data traverses) from the **control plane** (the paths engineers and systems manage the service). The two planes have different trust boundaries, different telemetry, and ideally different credentials.

### Why isolation matters

If an attacker compromises the data plane, they can read customer data (bad). If they compromise the control plane, they can alter the service itself — deploy backdoored code, rotate keys, disable logging (catastrophic). The two risks are different; the controls should be too.

### Practical separation

| Plane | Identity | Network | Credential store | Audit |
| --- | --- | --- | --- | --- |
| **Data** | Customer + service account identities; OIDC / SAML / workload identity | Production VPC, service mesh, tenant-scoped access | Per-tenant KMS keys, app-level secrets manager | SIEM with per-tenant log partitions |
| **Control** | Engineer identities (separate IdP group or separate IdP altogether); CI/CD identities via OIDC federation | Jump-host / broker, isolated VPC or direct IdP → control endpoints | Separate secrets manager scope for admin secrets; HSM-backed keys for signing | SIEM with CISO-only access partition; immutable bucket |

Separate **CI/CD credentials** from **production credentials** from **developer-laptop credentials**. A compromised laptop should not yield production access; a compromised CI/CD token should not yield the ability to rewrite git history; a compromised production key should not include the signing key for new releases.

## Telemetry — what you must log to detect lateral movement

Zero trust presumes breach. The design is that when (not if) an attacker gets a foothold, their next moves are observable and detectable before they reach data.

### Minimum event set

| Event class | Source | Why |
| --- | --- | --- |
| Authentication events (success, failure, MFA challenge, risk signal) | IdP | Credential abuse detection. |
| Token issuance and refresh | IdP / AS | Attribution, impossible-travel detection. |
| API gateway access logs | Gateway | Per-client / per-user request rate and path. |
| Service-mesh access logs | Mesh (Envoy access log) | East-west traffic attribution and anomaly detection. |
| Application audit log (structured) | Service | Business-semantic events (PHI access, admin actions, config changes). |
| Database query log | DB / proxy | Query-level attribution; detection of table enumeration. |
| Cloud control-plane events (CloudTrail, Azure Activity Log, GCP Audit) | Cloud provider | Infrastructure changes, privilege escalations at the cloud layer. |
| Secret retrievals | Secrets manager | Who pulled which secret, when, from where. |
| Privileged session recordings | PAM broker | Command-level forensic evidence. |
| IaC drift events | Drift detector | Detect out-of-band infrastructure changes. |

### Correlation requirements

- **Common trace ID** (W3C traceparent or similar) propagated from edge to data tier.
- **Common user ID** attached to every event originating from that user's request chain.
- **Common request ID** that survives cross-service calls in the mesh.

Without these, correlation at incident time requires guesswork. With them, the question "what did user X do between 14:00 and 14:30?" is a single SIEM query.

### Detection rules that matter

- **New device authenticating with existing credentials** — credential theft signal.
- **Impossible travel** — session from two geographic locations within a window shorter than physically plausible.
- **Service-to-service call not in the allowed caller list** — lateral movement signal, even when mesh policy blocks the call.
- **Secret retrieval from a workload that has not retrieved that secret before** — compromised workload.
- **Cloud API call to a region or service the account has never used** — attacker exfiltration pattern.
- **Download volume anomaly per user** — bulk-export signal.
- **New egress destination from production** — data exfiltration, C2 beaconing.

Each rule needs a runbook; undetected alerts with no response path are worse than no alerts.

## What zero trust is not

- **A perimeter replacement that eliminates the network firewall.** Defense in depth still applies. Zero trust says "do not trust the network"; it does not say "do not have a network."
- **A product.** No single vendor delivers zero trust. Assemble from: IdP + policy engine + mesh + PAM + SIEM + endpoint posture.
- **An all-or-nothing transition.** Adopt it per service boundary, per tier. Incremental adoption is the norm.
- **Free.** Expect higher operational complexity: certificate rotations, policy management, more telemetry volume.

## Adoption roadmap

| Phase | Target | Signal of completion |
| --- | --- | --- |
| 0 — Baseline | SSO + MFA everywhere; TLS on every hop; structured app logs to SIEM. | No internal-only services without auth; no plaintext HTTP. |
| 1 — Identity propagation | User identity and trace ID propagated end-to-end; gateway validates tokens. | Any request can be traced by user + request ID in the SIEM. |
| 2 — Workload identity | SPIFFE / workload identity for every service; mTLS in STRICT mode. | `PeerAuthentication: STRICT` in every namespace. |
| 3 — Policy engine | Authorization policies in code (OPA / Cedar / mesh policies). | New service is policy-as-code by default. |
| 4 — Dynamic policy | Risk signals, device posture, step-up auth integrated. | Sensitive ops require fresh MFA; high-risk sessions blocked. |
| 5 — Control / data separation | PAM broker; separate identity scopes for engineers vs services; immutable audit. | No standing production shell access; every privileged session recorded. |
| 6 — Continuous assurance | Detection rules mapped to ATT&CK; drift detection; regular purple-team. | Monthly red-team exercise yields fewer findings each quarter. |

Most organizations can reach phase 3 in 6–12 months on greenfield, 18–24 on brownfield. Phases 4–6 are the long tail; they depend more on operational maturity than technology.

## Further reading

- [NIST SP 800-207 — Zero Trust Architecture](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf).
- [NIST SP 800-207A — A Zero Trust Architecture Model for Access Control in Cloud-Native Applications](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207A.pdf).
- [CISA Zero Trust Maturity Model v2.0](https://www.cisa.gov/zero-trust-maturity-model).
- [BeyondCorp papers (Google)](https://cloud.google.com/beyondcorp) — the original industry-documented implementation.
- [SPIFFE / SPIRE](https://spiffe.io/) — the workload-identity standard.
