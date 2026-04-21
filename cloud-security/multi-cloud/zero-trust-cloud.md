# Zero Trust Across Multi-Cloud

Zero trust is a model, not a product, and in a multi-cloud environment it is the only coherent way to reason about access. Each cloud has its own IAM, its own network primitives, its own telemetry. Zero trust is the discipline that treats them as implementations of the same principles — identity as the perimeter, continuous verification, explicit authorization per resource — and wires them together so that a human, a workload, or a data flow doesn't gain implicit trust by being "inside" any particular cloud's account boundary.

This document is the reference architecture for that. It is the cloud-infrastructure counterpart to [../../architecture-patterns/zero-trust-saas.md](../../architecture-patterns/zero-trust-saas.md), which covers the application-tier story. The two overlap deliberately; zero trust is a stack, not a layer.

## Target architecture

```
                    ┌─────────────────────────────────────────────┐
                    │    Identity Provider (source of truth)       │
                    │    Okta or Entra ID — one IdP for humans     │
                    │    - All employees, contractors, vendors     │
                    │    - MFA + device posture + risk signals     │
                    │    - Provisioning → AWS / Azure / GCP        │
                    └──────────────────┬──────────────────────────┘
                                       │
                  SAML / OIDC           │         SCIM provisioning
         ┌────────────────────┬─────────┼──────────┬──────────────────┐
         │                    │                    │
         ▼                    ▼                    ▼
   AWS IAM Identity      Azure Entra ID       GCP Workforce
   Center (federated)    (same tenant)        Identity Federation
         │                    │                    │
         │  (assumes roles)   │                    │
         ▼                    ▼                    ▼
   ┌──────────────┐    ┌──────────────┐     ┌──────────────┐
   │ AWS accounts │    │ Azure subs   │     │ GCP projects │
   │              │    │              │     │              │
   │   Workloads  │    │   Workloads  │     │   Workloads  │
   └──────┬───────┘    └──────┬───────┘     └──────┬───────┘
          │                   │                    │
          │  workload-to-workload identity:        │
          └──────── SPIFFE/SPIRE federation ───────┘
                           │
                           ▼
                 ┌────────────────────────┐
                 │  Central SIEM          │
                 │  (Sentinel / Splunk)   │
                 │  - All cloud auth logs │
                 │  - All resource access │
                 │  - All network flow    │
                 │  - Correlation rules   │
                 └────────────────────────┘

    Remote user access:
         User (any network) → IdP (MFA + device posture check)
              → ZTNA gateway (Cloudflare / Zscaler / Tailscale)
              → Per-app access, not VPN
              → Auth propagated to cloud via OIDC

    Inter-cloud data plane:
         AWS ↔ Azure: Azure VPN / ExpressRoute + AWS TGW
         AWS ↔ GCP:   GCP Interconnect / VPN + AWS TGW
         Azure ↔ GCP: ExpressRoute / Interconnect
         All private, all inspected, all logged
```

Three principles to carry through the rest of the document:

1. **One IdP, three cloud consumers.** The IdP (Okta or Entra) is the source of truth. The cloud-native identity systems (AWS IAM Identity Center, Entra in its Azure role, GCP Workforce Identity Federation) are consumers that federate from it. No user is authoritative in any single cloud.
2. **Workload identity is its own story.** SPIFFE / SPIRE (or its cloud-native equivalents) assigns cryptographic identity to workloads independent of where they run. That is how a service in AWS authenticates to a service in Azure without a shared secret.
3. **Telemetry is central or it's nothing.** Zero trust's "continuous verification" is a lie unless the signals from all clouds land in one place that can correlate them.

## Identity as the new perimeter

### One IdP, federated to every cloud

A multi-cloud organization with three IdPs (AWS IAM users, Entra users, GCP users each locally defined) cannot do zero trust. The identity sprawl makes offboarding uncertain, MFA inconsistent, and audit impossible. The foundational move is: one IdP, federated out.

Recommended shape:

- **Okta or Entra ID** as the IdP.
- **AWS IAM Identity Center** federated via SAML from the IdP. Users log in via the IdP, single sign-on into AWS accounts via permission sets assigned to IdP groups.
- **Azure Entra ID** — if Entra is your IdP, this is native. If Okta is your IdP, federate Okta → Entra via SCIM + SAML.
- **GCP Workforce Identity Federation** — GCP's modern mechanism for federating external IdPs. Users log into the Console with their IdP credentials; IAM bindings target external identities like `principal://iam.googleapis.com/locations/global/workforcePools/POOL/subject/USER_ID`.

The effect: an employee joining gets IdP access; provisioning pushes them into the three clouds automatically. An employee leaving is de-provisioned from the IdP; access to all three clouds disappears within the SCIM cycle.

### MFA and device posture signals

MFA is table stakes, but MFA alone is not zero trust. Zero trust requires *continuous verification* — every access attempt re-checks identity, device, and risk.

What the IdP should evaluate at every sign-in:

- **Authentication factors** — password + phishing-resistant MFA (FIDO2 / WebAuthn preferred over TOTP, TOTP preferred over SMS).
- **Device posture** — managed via MDM (Intune / Jamf / Workspace ONE), with required controls: disk encryption, screen lock, OS patch level, EDR present.
- **Network signal** — source IP, ASN, country; flag anomalies without auto-blocking legitimate travel.
- **User risk** — Identity Protection in Entra, Okta Risk Engine, Google Identity Threat Detection. Leaked-credential feeds, impossible-travel detection, anomalous sign-ins.
- **App risk context** — sensitive apps (admin consoles, financial systems, regulated data) have stricter requirements than low-sensitivity apps.

Conditional access — implemented via Okta Sign-On Policies, Entra Conditional Access, or both — is how the IdP operationalizes continuous verification. See [../azure/entra-id-patterns.md](../azure/entra-id-patterns.md) for the Entra CA treatment.

### Privileged access

Standing privileged access is the antithesis of zero trust. Every privileged role — Global Administrator, AWS account Admin, GCP Project Owner — should be just-in-time:

- **Entra PIM** for Entra roles and Azure resource roles.
- **AWS**: IAM Identity Center permission sets with short session durations (1 hour for admin sets); for higher tiers, integrate a PAM tool (Teleport, StrongDM, Okta Access Requests) to gate access behind approval.
- **GCP**: IAM Conditions for time-bound bindings, or a PAM tool doing the same.
- **Cross-cloud**: when an SRE needs admin in all three clouds during an incident, one request to the PAM tool grants temporary access in all three, not three separate click-paths.

## Network zero trust

### Why VPN is not zero trust

VPN is network-centric: pass the VPN challenge, land on an internal network, and move laterally with whatever permissions your IP grants. Zero trust is identity-centric: every application access re-authenticates, re-authorizes, and re-evaluates trust for that specific access.

VPNs also become a single point of failure and single target. The VPN concentrator is an open inbound port; compromised VPN credentials grant blanket network access. Modern breaches routinely involve VPN compromise as the pivot.

### ZTNA for remote user access

Zero Trust Network Access (ZTNA) products — Cloudflare Access, Zscaler Private Access, Tailscale, Twingate, Palo Alto Prisma Access — replace VPN for most use cases.

The shape:

```
    User → IdP auth (MFA + device) → ZTNA broker
          → per-app access decision (policy: user X can access app Y if conditions)
          → tunneled to the specific application, not the network
```

Key properties:

- **Per-application access**, not network access. A user authorized for app A cannot probe app B.
- **No inbound ports on the target.** The ZTNA agent on the application side initiates an outbound connection to the broker; the user's traffic rides that connection. No public firewall holes.
- **Device posture re-checked** at each session.
- **Session recording** available for sensitive apps (SSH / RDP to admin bastions).

For a typical workforce today, ZTNA replaces VPN entirely. VPN remains appropriate for legacy system-to-system tunnels where an application-layer approach is not feasible, but new deployments should be ZTNA-first.

### Inter-cloud private connectivity

Workload-to-workload traffic across clouds must not traverse the public internet. Options:

- **AWS ↔ Azure**: Azure ExpressRoute (or VPN) terminated at a Network Virtual Appliance (or Azure VPN Gateway), peered to an AWS Transit Gateway via a Direct Connect partner or a site-to-site VPN to AWS Customer Gateway.
- **AWS ↔ GCP**: Partner Interconnect / Dedicated Interconnect from GCP side, peered to AWS via a colo partner; or IPsec VPN for lower volume.
- **Azure ↔ GCP**: ExpressRoute + Interconnect via common partners (Equinix, Megaport).

Each circuit is private, supports stable routing, and can be inspected by firewall in the hub VNet / VPC on each side.

For lower-volume inter-cloud integrations, Cloud-native VPN (IPsec) is often sufficient. Private connectivity via partners is for bulk traffic (data lake replication, analytics workloads, backup).

### Egress inspection

Zero trust means egress is as constrained as ingress. Typical controls:

- AWS: Network Firewall or a Gateway Load Balancer with a third-party firewall (Palo Alto, Check Point).
- Azure: Azure Firewall Premium with IDPS and TLS inspection.
- GCP: Cloud NGFW or third-party NVA behind a route.

Egress allowlists scoped to approved destinations (Microsoft / Google / AWS service endpoints, specific SaaS domains, defined partner APIs). Unknown egress is either blocked or alerted — not silently permitted.

## Workload identity across clouds

Human identity is only half the story. Workloads — a Lambda in AWS calling a storage account in Azure, an AKS pod calling a BigQuery dataset in GCP — need identity too, and that identity must be tamper-resistant and short-lived.

### The shared secret anti-pattern

The wrong way: a client secret or API key provisioned into the calling workload, stored as an environment variable or mounted secret. Problems:

- Long-lived; rotates rarely.
- Portable; can be exfiltrated and reused.
- No binding to the workload; a compromised workload's secret is usable from anywhere.
- Audit trail is thin (the secret signed in, not the specific workload instance).

### SPIFFE / SPIRE

SPIFFE (Secure Production Identity Framework For Everyone) is a specification for workload identity; SPIRE is the reference implementation. A SPIFFE identity looks like `spiffe://trust-domain.example.com/ns/payments/sa/checkout`.

The value proposition:

- **Cryptographic identity issued at runtime** — short-lived X.509 certs or JWT-SVIDs. Typically 1-hour lifetime with auto-rotation.
- **Workload attestation** — SPIRE verifies the workload's identity via platform-native signals (EC2 instance metadata, Kubernetes service account, process selectors) before issuing a SVID. You can't just ask for an identity; the platform has to corroborate it.
- **Federation across trust domains** — an AWS trust domain and an Azure trust domain can mutually validate each other's SVIDs. A workload in AWS presents its SPIFFE cert; Azure verifies against the federated trust bundle.

In practice this means: an EKS pod can call an Azure service, authenticating with its SPIFFE SVID, with no shared secret anywhere. Entra OIDC federation accepts the SPIFFE JWT-SVID and maps it to an Azure role.

### Cloud-native workload identity

SPIRE is the cross-cloud general solution. Each cloud also has its own:

- **AWS**: IAM Roles (for EC2 / Lambda / ECS) and IAM Roles for Service Accounts (IRSA) for EKS. STS issues short-lived credentials.
- **Azure**: Managed Identity (system-assigned / user-assigned) and Azure AD Workload Identity for AKS. Entra issues short-lived tokens.
- **GCP**: Service Accounts with Workload Identity for GKE, or direct impersonation via IAM binding. Google issues short-lived tokens.

These are great within a single cloud. For cross-cloud, you either:

1. Use OIDC federation — AWS Lambda → GCP via Workload Identity Federation; GCP service account → AWS via OIDC federation trust; Entra Workload Identity Federation for GitHub / AWS / GCP tokens.
2. Use SPIFFE / SPIRE as a unifying layer that sits above all three.

The OIDC-federation approach is lower-setup-cost for a few integrations. SPIRE is higher-setup but scales to dozens of services and adds the attestation guarantee.

### Workload-identity policy shape

Regardless of mechanism, the policy is per-workload, per-resource, short-lived:

```yaml
# Pseudocode: a checkout service in AWS authorized to call an Azure Storage Account
workload_identity: spiffe://example.com/aws/prod/checkout
resource: azure storage account prod-orders
permissions: [blob.read, blob.write]
conditions:
  - time of day: any
  - MFA: n/a (workload)
  - source IP range: AWS prod egress CIDRs
  - cert lifetime: <= 1h
```

Not "a key that grants access." A verified claim, evaluated per request.

## Data classification and protection across clouds

Data in a multi-cloud environment moves. A dataset is produced in GCP BigQuery, replicated to AWS S3 for an ML pipeline, and a subset ends up in Azure SQL for reporting. Each copy carries the same sensitivity obligations. Zero trust for data means those obligations are enforced wherever the data goes.

### Tagging as the first control

Every cloud supports resource tagging. Mandate a `DataClass` tag on every data-holding resource:

| DataClass | Examples | Controls |
| --- | --- | --- |
| `public` | Marketing assets, public docs | Default controls |
| `internal` | Business docs, non-sensitive metrics | Internal-only network, default encryption |
| `confidential` | Customer data, financial records | CMK encryption, audit logging, Private Endpoints |
| `regulated` | PHI, PCI, HIPAA-scoped, GDPR-scoped | CMK in HSM, tight IAM, private-only network, detailed audit |

Enforce via policy:

- **AWS**: SCP requiring `DataClass` tag on S3 / RDS / DynamoDB / EBS / EFS creation. Config rule for any missing tag.
- **Azure**: Azure Policy requiring `DataClass` tag on Storage / SQL / Cosmos / Key Vault creation. Policy initiative linking tag value to required encryption method.
- **GCP**: Organization Policy + resource tags + custom constraints for required tag coverage.

Without tagging, the rest of the data-protection story is manual.

### DLP across clouds

DLP tools — native (Macie, Purview, Cloud DLP) or third-party (Wiz Data Security, Varonis, Immuta) — scan data-at-rest and data-in-motion to identify sensitive content and flag mismatches between sensitivity and controls. Key use cases:

- **Finding regulated data in unapproved locations** — PHI that appears in a dev bucket, PII that shows up in a public share.
- **Finding mislabeled data** — a bucket tagged `internal` that actually contains PHI.
- **Egress monitoring for sensitive data** — a file upload to an unapproved external destination.

For a multi-cloud organization, the practical pattern is:

1. Use each cloud's native DLP to scan that cloud's storage at rest.
2. Consolidate DLP findings into the central SIEM.
3. For in-motion DLP (email, uploads, SaaS), use a dedicated tool (Netskope, Zscaler, Microsoft Purview) that spans clouds.

### Encryption key sovereignty

The "who holds the key" question matters for data sovereignty and regulatory obligations:

| Approach | Who controls rotation / access |
| --- | --- |
| Cloud-managed key (default) | The cloud provider |
| Customer-managed key (CMK) in cloud KMS | You, but still inside the cloud's KMS |
| Customer-managed key in external HSM (External Key Store, Entra Key Vault HSM, KMS with EKM) | You, with key material never inside the cloud |
| Bring-Your-Own-Key (BYOK) with on-prem HSM | You entirely; fully independent |

For most regulated workloads, CMK in cloud KMS is sufficient. For workloads under national-sovereignty-style concerns (some financial, defense, government), external key store or BYOK is required. The trade-off: external keys add latency and operational burden; most organizations shouldn't opt in without a specific regulatory reason.

Cross-cloud replication: when data moves between clouds, the source and destination CMKs are different by necessity. Document the key-handoff: at-rest CMK A in source, decrypt during replication, re-encrypt with CMK B in destination, audit log both sides of the handoff.

## Continuous verification — telemetry and correlation

Zero trust is evaluated continuously. That requires telemetry from everywhere, correlated, with detection rules that span clouds.

### What to collect from each cloud

The minimum useful telemetry for zero trust detection:

**AWS**:
- CloudTrail (all regions, management events + S3 / Lambda / KMS data events for regulated resources)
- VPC Flow Logs (all VPCs, Parquet where possible)
- GuardDuty findings
- IAM Access Analyzer findings
- ALB / CloudFront / WAF logs
- S3 server access logs for regulated buckets

**Azure**:
- Entra sign-in logs and audit logs (all users, all applications)
- Azure Activity log (all subscriptions)
- Resource-level diagnostic logs (Key Vault, Storage, SQL, AKS)
- NSG Flow Logs (Traffic Analytics)
- Defender for Cloud alerts
- App Gateway / Azure Firewall logs

**GCP**:
- Cloud Audit Logs — Admin Activity, Data Access (at least for regulated resources), System Events
- VPC Flow Logs
- Firewall Rules Logging
- Security Command Center findings
- Cloud Load Balancing logs

### Central SIEM

One SIEM with all of the above. Practical choices:

- **Microsoft Sentinel** if Azure-heavy — native ingestion for Azure and Entra, good for AWS / GCP via connectors.
- **Splunk** if existing investment — connectors for all three clouds.
- **Chronicle / Google Security Operations** if GCP-heavy.
- **Elastic Security** if you want open-source.

The choice matters less than the discipline: one SIEM, all cloud auth / access / network logs, detection rules maintained.

### Detection rules worth writing

Rules that specifically catch zero-trust-relevant patterns:

**Cross-cloud lateral movement**:
- Same user authenticated in two different clouds within 5 minutes (potentially legitimate for an admin, but investigate each time).
- Workload identity from cloud A making unusual call patterns to cloud B — e.g., a service that normally does read-only calls suddenly doing writes.

**Privilege escalation**:
- Any new Global Administrator / AWS account Admin / GCP Project Owner role assignment.
- Any change to Conditional Access policies / SCPs / Organization Policies.
- Service principal credential added to a high-privilege app registration.

**Data exfiltration**:
- Storage object downloaded to an IP outside known ranges, size > N GB.
- Database dump operations from a production instance.
- Egress to an unapproved external destination, especially encrypted channels to unknown ASNs.

**Break-glass account activity**:
- Any sign-in from any break-glass account — investigate immediately, these are not supposed to be used.

**Anomalous auth patterns**:
- Impossible travel across cloud auth events.
- Password spray across many accounts from a single source.
- Unusual MFA prompt patterns (many prompt-denies then an accept, indicating MFA fatigue attack).

### Correlation is the unlock

A single event in isolation is often ambiguous. A chain of events across systems is the signal:

Example chain:
1. User signs in via Okta from new country (medium risk).
2. Two minutes later, user authenticated in AWS.
3. Three minutes later, user assumes production admin role.
4. Five minutes later, S3 GetObject on regulated bucket, 50 GB transferred.

Each event in isolation is unremarkable. Together, they are a credential-theft incident in progress.

This is what a SIEM with cross-cloud ingestion buys you; without it, each cloud's native tool sees its slice and no one sees the whole picture.

## Adoption roadmap

Zero trust is a multi-year program. For a multi-cloud organization, a realistic six-phase plan:

**Phase 1 — IdP consolidation (months 1–3)**
- Pick the IdP (Okta or Entra). Kill off any secondary IdPs.
- Federate each cloud to the IdP.
- SCIM provisioning enabled.
- Baseline Conditional Access / Sign-On Policies.

**Phase 2 — MFA and device posture (months 3–6)**
- MFA for all users, phishing-resistant where practical.
- Device management via MDM; enforce compliance for admin access.
- Risk signals integrated (Identity Protection, Okta Risk Engine).

**Phase 3 — Just-in-time privilege (months 6–9)**
- PIM for Entra roles.
- IAM Identity Center permission sets with tight session durations.
- PAM tool (Teleport or similar) for highest-privilege operations.

**Phase 4 — ZTNA (months 9–12)**
- ZTNA rollout for internal app access; VPN decommissioning plan.
- Per-application policies in the ZTNA tool.

**Phase 5 — Workload identity (months 12–18)**
- Inventory of service-principal-with-secret and IAM-user-with-key usage.
- Migration to Managed Identity / IRSA / Workload Identity.
- SPIFFE / SPIRE deployment for cross-cloud workloads, if scale justifies.

**Phase 6 — Telemetry and detection (ongoing, starts month 3)**
- Central SIEM with all cloud logs.
- Detection rules built and tuned over time.
- Regular tabletop exercises simulating cross-cloud incidents.

The phases overlap; the order is about where to invest *first*, not mandatory sequencing. The IdP consolidation is load-bearing; nothing else works until it is done.

## Common failures

Patterns I see fail in the field:

- **"We're on Okta" as the entire zero-trust story.** Okta is the foundation, not the solution. Without device posture, JIT privilege, and workload identity, an Okta breach is a full-environment breach.
- **VPN split-tunneled around "zero trust apps."** Half-migration. Either the app is behind ZTNA or it isn't; leaving VPN in place "for special cases" is how VPN perpetuates.
- **SPIFFE adopted without federation.** An AWS SPIRE server not federated with Azure / GCP is just a fancier way of doing per-cloud IAM. The federation is the point.
- **Central SIEM with only AWS logs.** The Azure and GCP events that matter most are the ones you're not looking at.
- **Conditional Access / SCPs sprawling with exceptions.** Every exception weakens the control; eventually the exceptions are the policy.
- **Zero-trust-branded vendor tooling adopted without the process to use it.** A tool does not make you zero trust; the discipline does.

## Compliance mapping

| Framework | Control | Satisfied by |
| --- | --- | --- |
| HIPAA §164.312(a)(1) | Access control | IdP + per-resource IAM + ZTNA |
| HIPAA §164.312(b) | Audit controls | Central SIEM with cross-cloud ingestion |
| HIPAA §164.312(d) | Person/entity authentication | Phishing-resistant MFA, device posture, risk signals |
| HIPAA §164.312(e)(1) | Transmission security | TLS everywhere, private inter-cloud connectivity |
| SOC 2 CC6.1, CC6.2, CC6.3 | Logical access and authentication | End-to-end |
| SOC 2 CC6.6 | Boundary protection | Per-resource network isolation; egress inspection |
| SOC 2 CC7.1, CC7.2 | Detection and monitoring | SIEM + detection rules + correlation |
| NIST CSF 2.0 PR.AC, PR.DS, DE.CM | Access control, data security, monitoring | End-to-end |
| NIST SP 800-207 | Zero trust architecture | Model-level adherence |

## Further reading

- **[NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final)** — the authoritative document; read it once per year.
- [SPIFFE / SPIRE documentation](https://spiffe.io/docs/latest/spiffe-about/overview/)
- [AWS Workload Identity Federation with OIDC](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html)
- [Azure Workload Identity Federation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation)
- [GCP Workforce Identity Federation](https://cloud.google.com/iam/docs/workforce-identity-federation)
- This repo: [../../architecture-patterns/zero-trust-saas.md](../../architecture-patterns/zero-trust-saas.md) for the application-tier story; [../aws/security-reference-architecture.md](../aws/security-reference-architecture.md), [../azure/security-reference-architecture.md](../azure/security-reference-architecture.md), [cspm-strategy.md](./cspm-strategy.md)
