# Azure Security Reference Architecture

A reference architecture for a regulated workload on Azure, sized for implementability. This document is the Azure counterpart to [aws/security-reference-architecture.md](../aws/security-reference-architecture.md); the security concepts map, but the Azure mechanisms are different enough that a direct translation loses the important details.

## Target architecture

```
                    ┌───────────────────────────────────────────────────┐
                    │           Entra ID tenant (IdP root)              │
                    │  Conditional Access, PIM, Workload Identities,    │
                    │  B2B / external collaboration governance          │
                    └───────────────────────────────────────────────────┘
                                          │
                                          ▼
    ┌─────────────────────────────────────────────────────────────────────┐
    │                    Management Group: Tenant Root                     │
    │                          - Default Policy Initiatives (CIS, NIST)    │
    └─────────────────────────────────────────────────────────────────────┘
                  │                 │                 │
                  ▼                 ▼                 ▼
        ┌────────────────┐ ┌────────────────┐ ┌────────────────┐
        │ MG: Platform   │ │ MG: Landing    │ │ MG: Sandbox    │
        │                │ │     Zones      │ │                │
        └────────────────┘ └────────────────┘ └────────────────┘
                │                 │                 │
  ┌─────────────┼─────────────┐   │   ┌─────────────┼─────────────┐
  ▼             ▼             ▼   ▼   ▼             ▼             ▼
┌──────────┐┌──────────┐┌──────────┐┌──────────┐┌──────────┐┌──────────┐
│ Sub:     ││ Sub:     ││ Sub:     ││ Sub:     ││ Sub:     ││ Sub:     │
│ Identity ││ Mgmt     ││ Connect- ││ Prod-    ││ Non-Prod ││ Dev /    │
│          ││ (Sentinel││ ivity    ││ workload ││ workload ││ Sandbox  │
│ Entra    ││  Log     ││  (hub)   ││          ││          ││ (budget  │
│ Domain   ││  Analyt- ││          ││          ││          ││  capped) │
│ Services ││  ics)    ││          ││          ││          ││          │
│ (if used)││ Defender ││ Azure    ││ App      ││ App      ││          │
│          ││  for     ││ Firewall ││ Gateway  ││ Gateway  ││          │
│          ││  Cloud   ││ VPN GW   ││ AKS      ││ AKS      ││          │
│          ││          ││ Express- ││ Storage  ││ Storage  ││          │
│          ││          ││ Route GW ││ (CMK)    ││ (CMK)    ││          │
│          ││          ││ DNS      ││ SQL (CMK)││ SQL (CMK)││          │
│          ││          ││ private  ││ Key Vault││ Key Vault││          │
│          ││          ││ resolver ││ (HSM)    ││          ││          │
└──────────┘└──────────┘└──────────┘└──────────┘└──────────┘└──────────┘

 Hub-Spoke network (Connectivity subscription hosts the hub):
  ┌──────────── hub VNet (Connectivity sub) ────────────┐
  │  Azure Firewall  │  VPN GW  │ ExpressRoute GW       │
  │  Private DNS     │  Bastion │ Hub services          │
  └──────────────┬───────────────┬───────────────┬──────┘
                 │ peered        │ peered        │ peered
                 ▼               ▼               ▼
         spoke VNet     spoke VNet        spoke VNet
         (Prod)         (Non-Prod)        (Dev)
```

Three things the diagram is trying to say:

1. **Management Groups carry policy** — Azure Policy applied at a Management Group flows to every Subscription beneath it. This is the structural control plane.
2. **Subscriptions are the blast-radius boundary** — like AWS accounts, but lighter weight. A production subscription contains the Prod workload and nothing else.
3. **The hub VNet in Connectivity is the network backbone** — all spoke VNets peer to it; inter-spoke traffic is forced through the hub (via UDRs + Azure Firewall) for logging and policy.

## Management Group strategy

### Why Management Groups matter

A Subscription is the primary Azure billing and access-control boundary, but Subscriptions alone do not scale: if you have 20 subscriptions, you do not want to attach Azure Policy to each of them individually. Management Groups are hierarchical containers for Subscriptions, and policies applied at a Management Group inherit down.

### Layout

Minimum viable Management Group hierarchy:

| Management Group | Purpose | Typical policy |
| --- | --- | --- |
| **Tenant Root** | Applies to every subscription in the tenant | Mandatory tagging, deny creation in un-approved regions, require TLS 1.2+, audit requirements |
| **Platform** | Identity, management, connectivity subscriptions | Tighter network controls, mandatory Defender plans, private link required |
| **Landing Zones — Corp** | Internal-only workloads | Deny public IPs, require private endpoints, strict egress |
| **Landing Zones — Online** | Public-facing workloads | Allow public IPs with WAF requirement, stricter logging |
| **Sandbox** | Developer exploration | Budget cap policy, auto-delete resource tag, looser controls |
| **Decommissioned** | Subs pending deletion | Read-only policy, no new resource creation |

Don't overbuild the hierarchy. Three layers is usually enough: Root → Category → Subscription. Deeper hierarchies become hard to reason about, and Azure Policy assignment inheritance is easier to mis-configure.

### Subscription roles

| Subscription | Purpose | Resources | Who has access |
| --- | --- | --- | --- |
| **Identity** | Entra connect, optional domain services | Entra Domain Services, hybrid identity infra | IdentityOps only |
| **Management** | Log Analytics workspace, Sentinel, Defender for Cloud config | Sentinel, LAW, Automation account | SecOps |
| **Connectivity** | Hub VNet, Azure Firewall, VPN/ExpressRoute, Private DNS zones | Azure Firewall, VPN gateway, Private DNS | NetOps |
| **Production Workload** | Customer-serving apps | AKS, Storage (CMK), SQL (CMK), Key Vault, App Gateway | Platform + constrained app teams |
| **Non-Prod Workload** | Pre-prod, structurally identical to Prod | Same as Prod, lower SKUs | Engineering |
| **Dev/Sandbox** | Per-team or per-engineer | Loose | Engineers |

## Microsoft Defender for Cloud

See [defender-for-cloud.md](./defender-for-cloud.md) for the plan-by-plan treatment. In the reference architecture:

- **Enable at the tenant root Management Group.** Applies to every Subscription, current and future.
- **Defender CSPM** (the free tier) is on by default. Turn on the Defender Cloud Security Posture Management **Plan 2** (paid) for the Prod subscription if the Attack Path Analysis and Agentless Scanning features justify the cost.
- **Defender plans for workload protection** — budget-permitting: Defender for Servers P2, Defender for SQL, Defender for Storage, Defender for Key Vault, Defender for Containers, Defender for App Service.
- **Regulatory compliance dashboard** — enable the standards that match your obligations (HIPAA/HITRUST, PCI-DSS 4.0, ISO 27001, NIST SP 800-53, SOC 2). These are assessment overlays, not additional controls; they help auditor conversations and surface gaps.

## Identity

### Entra ID as the source of truth

Every human and workload identity resolves through Entra ID. See [entra-id-patterns.md](./entra-id-patterns.md) for Conditional Access, PIM, and Workload Identity patterns. In the reference architecture:

- **Conditional Access** applies to every user for every cloud app. Baseline: MFA for all users, block legacy auth, block risky sign-ins, require compliant device for admin access.
- **Privileged Identity Management** for any role with elevated permissions. No standing Global Administrator; all Global Admin access is eligible + activation + MFA + approval.
- **Workload Identity** (formerly Managed Identity) everywhere a service needs to authenticate to Azure. Service Principals with secrets are deprecated for net-new workloads.

### Role strategy

Four role categories, applied at the Management Group or Subscription level:

1. **Tenant admins** — Global Administrator, Privileged Role Administrator. PIM-eligible only, activation time-limited, MFA + approval required. Maybe 3 people in the organization.
2. **Cloud platform admins** — Owner on Platform + Connectivity subscriptions. PIM-eligible, 8-hour activation, MFA required.
3. **Workload engineers** — Contributor on specific subscriptions or resource groups. Typically standing access for non-prod; PIM-eligible for prod.
4. **Read-only auditors** — Reader at the Tenant Root MG. Used by SecOps, auditors, and automation.

Assign roles to groups, not individuals. Manage group membership in your IdP (or in Entra), not via Azure role assignments.

## Data protection

### Key Vault hierarchy

Azure Key Vault is the backbone of data protection in Azure. Tier vaults the way you tier CMKs in AWS:

```
                Key Vault: platform-hsm-prod (Premium, HSM-backed)
                          │
                          ├── CMK for Storage Accounts holding regulated data
                          ├── CMK for Azure SQL TDE
                          └── CMK for AKS etcd envelope encryption

                Key Vault: secrets-prod (Standard)
                          │
                          ├── Database connection strings
                          ├── API keys for third-party services
                          └── Client certs for mTLS

                Key Vault: platform-hsm-nonprod (Premium)
                Key Vault: secrets-nonprod (Standard)
```

Rules:

- **Separate vaults for keys vs secrets.** A key vault containing both CMKs and app secrets cannot be access-controlled at the granularity you need.
- **Premium tier (HSM-backed) for regulated-data CMKs.** The price difference is modest; the FIPS 140-2 Level 2 validation matters for HIPAA / PCI / FedRAMP conversations.
- **RBAC, not access policies.** Key Vault's legacy access policies do not integrate with Entra PIM. Use Azure RBAC with roles like `Key Vault Crypto User`, `Key Vault Secrets User`.
- **Purge protection and soft-delete on.** Non-negotiable for vaults holding keys that back regulated data; a compromised admin cannot cause irrecoverable data loss by deleting the key.

### Customer-Managed Keys (CMK) for storage and databases

Azure encrypts at rest by default with platform-managed keys. For regulated workloads, move to CMK:

- **Storage Accounts**: CMK referencing Key Vault key, via a user-assigned Managed Identity on the Storage Account.
- **Azure SQL**: TDE with CMK.
- **Azure SQL Managed Instance**: TDE with CMK.
- **Cosmos DB**: CMK for account.
- **AKS**: enable envelope encryption for etcd with a CMK.

The main reason: BYOK gives you the ability to revoke access by revoking the key, which is the key escrow story your compliance team needs.

### Microsoft Purview for PHI/PII discovery

Purview (formerly Azure Purview) is Microsoft's data governance platform. For a regulated workload, use it to:

1. Scan Storage Accounts, Azure SQL, Synapse, Cosmos DB for PII/PHI classification.
2. Maintain a data map so you can answer "where is customer X's data?" during an access request.
3. Surface classification findings into Defender for Cloud / Sentinel.

Purview costs money and takes effort to set up. For a small company with one or two workloads, a manual inventory spreadsheet can serve the same purpose. For anything larger, Purview pays for itself the first time you need to answer a GDPR subject access request or a HIPAA BAA audit.

## Network security

### Hub-spoke with Azure Firewall

```
                    ┌─────────────────────────────────────────┐
                    │   Hub VNet (Connectivity subscription)   │
                    │                                          │
                    │   Azure Firewall Premium                 │
                    │     - TLS inspection                     │
                    │     - IDPS                               │
                    │     - FQDN-based rules                   │
                    │                                          │
                    │   VPN GW / ExpressRoute GW               │
                    │   Azure Bastion                          │
                    │   Private DNS Resolver                   │
                    └──────────────┬──────────┬───────────────┘
                                   │ peer     │ peer
                       ┌───────────┴───┐   ┌──┴───────────┐
                       │ Spoke: Prod   │   │ Spoke: Dev   │
                       │  VNet         │   │  VNet        │
                       │  app subnet   │   │              │
                       │  data subnet  │   │              │
                       └───────────────┘   └──────────────┘

 User-Defined Routes on spoke subnets force 0.0.0.0/0 → Azure Firewall in hub.
 Spoke-to-spoke traffic also goes through the hub (not direct peering) for inspection.
```

Spoke VNets do not have public IPs. All inbound comes through Application Gateway (for public HTTPS) or Azure Firewall (for controlled ingress). All outbound goes through the Firewall.

### Network Security Groups and Application Security Groups

NSGs are stateful, attached to subnets or NICs. Application Security Groups (ASGs) let you reference groups of resources in NSG rules rather than IP ranges. Use ASGs — they age better than IP rules as the VNet grows.

Baseline NSG pattern:

- **App subnet NSG**: inbound from App Gateway subnet only, on 443; outbound to data subnet, Azure services via service tags (Storage, KeyVault, AzureMonitor), and Firewall for internet.
- **Data subnet NSG**: inbound from app subnet ASG only, on DB ports; no outbound to internet.
- **Every NSG has deny-all at the bottom.** Azure's default deny-all is there but explicit is safer.

### Private Endpoints vs Service Endpoints

- **Service Endpoints** give a subnet a shortcut to an Azure service over the Microsoft backbone. Fast to enable. The limitation: the service still has a public endpoint; you have to layer firewall rules on the service itself. Good for low-sensitivity workloads.
- **Private Endpoints** give the Azure service a private IP inside your VNet. The service's public endpoint can then be disabled. This is the right pattern for regulated workloads. Every Storage Account, Key Vault, SQL server, and Cosmos DB account holding regulated data gets a Private Endpoint, and its public network access is turned off.

Apply via Azure Policy:

```
- deny StorageAccounts with publicNetworkAccess != "Disabled"
- deny KeyVault without privateEndpointConnections
- deny SQL servers with publicNetworkAccess enabled
```

### Azure Bastion for VM access

Don't put RDP/SSH on a public IP. Azure Bastion puts a jumpbox inside the VNet with no public IP itself; users reach it via the Azure portal over TLS. Session recording available at the Premium tier.

## Logging and monitoring

### Diagnostic settings

Every Azure resource that produces logs sends them to Log Analytics via Diagnostic Settings. The goal: one Log Analytics Workspace (LAW) per Subscription environment class (all Prod subs share one LAW in the Management subscription; all Non-Prod subs share another; Dev/Sandbox is on its own).

Resources to enable diagnostic settings on:

- **Entra ID logs** → LAW (audit, sign-ins, provisioning, risk events)
- **Azure Activity Log** per subscription → LAW
- **Key Vault audit events** → LAW
- **Storage Account** (blob, file, queue, table) → LAW
- **Azure SQL** audit logs → LAW
- **AKS** control plane logs → LAW
- **App Gateway / Azure Firewall** logs → LAW
- **NSG Flow Logs** (via Network Watcher) → Storage → LAW via Traffic Analytics

Apply via Azure Policy at the Management Group level (`DeployIfNotExists` effect) so new resources automatically get diagnostic settings configured.

### Microsoft Sentinel

Sentinel is Microsoft's SIEM, layered on Log Analytics. In the reference architecture:

- Sentinel attached to the shared Log Analytics Workspace.
- **Data connectors** enabled: Entra ID, Azure Activity, Microsoft 365 Defender, Defender for Cloud, Threat Intelligence (Microsoft TI + commercial feeds if any).
- **Analytics rules** from the Microsoft Sentinel Content Hub, tuned for the environment.
- **Automation rules** for common workflows: auto-close low-fidelity duplicates, auto-assign by tag, auto-enrichment.
- **Workbooks** for management reporting — not for operational triage.

Cost discipline matters. Sentinel is priced per GB ingested. Be intentional about what you ingest: Activity logs, identity logs, and Defender alerts are essential. Full NSG flow logs are optional and expensive; sample or apply filters.

## Policy

Azure Policy is the primary compliance enforcement mechanism. Three initiative categories to apply at the Tenant Root or Platform Management Group:

### Initiative 1 — Foundational guardrails

Built from the Azure Security Benchmark or CIS Microsoft Azure Foundations Benchmark. Key effects:

- Audit or deny untagged resources
- Audit Storage Accounts without private endpoints
- Audit Key Vaults without soft-delete and purge protection
- Audit SQL servers without TDE or auditing
- Deny resources in non-approved regions
- Deny resources without required diagnostic settings (DeployIfNotExists)

### Initiative 2 — Industry compliance overlay

Defender for Cloud includes built-in initiatives for HIPAA/HITRUST, NIST SP 800-53 R5, PCI-DSS, ISO 27001. Assign the one(s) matching your obligations. These are audit-mode (Assessment), not deny-mode — they surface gaps without blocking.

### Initiative 3 — Organization-specific

Custom rules the built-ins do not cover: internal tagging taxonomy, internal network patterns, internal naming conventions. Build these in parallel with the foundational initiatives; they get tighter over time.

Initiative assignment pattern:

```
Tenant Root MG
  ├── Foundational guardrails (Audit mostly, Deny for critical like public network)
  └── Org tagging and naming (Audit → Deny over 3-month ramp)

Landing Zones MG
  └── Compliance overlay (HIPAA + SOC 2) — Audit

Prod MG
  └── Tightened subset of guardrails (Deny for public network, require private endpoints)
```

Roll Audit → Deny incrementally. Setting a new Deny policy at Tenant Root on day one blocks existing resources from routine operations and creates a bad adoption story.

## Adoption order

For a new Azure environment, or an existing environment being hardened:

1. **Week 1**: Management Group hierarchy. Entra Conditional Access baseline (MFA + block legacy auth). PIM set up for Global Admin. Break-glass accounts (2) excluded from CA, documented, locked in a safe.
2. **Week 2**: Log Analytics Workspace + Sentinel + Defender for Cloud (free tier) enabled at the tenant root. Diagnostic settings policy applied org-wide.
3. **Week 3–4**: Private Endpoints on existing Storage / Key Vault / SQL. Hub-Spoke network if not already present; force egress through Firewall. NSGs tightened.
4. **Month 2**: CMK for Storage / SQL / AKS. Key Vault Premium for regulated workloads. Purview scan of first Storage Account.
5. **Month 3**: PIM for all Owner/Contributor assignments at Subscription or higher. Workload Identity migration from Service Principals with secrets. Defender paid plans turned on for Prod.
6. **Month 4+**: Policy initiative ramp from Audit → Deny. Sentinel analytics rule tuning. Purview full data map.

## Compliance mapping

| Framework | Control | Where satisfied |
| --- | --- | --- |
| HIPAA §164.312(a)(1) | Access control | Entra CA + PIM + Azure RBAC + Private Endpoints |
| HIPAA §164.312(b) | Audit controls | Diagnostic Settings → LAW → Sentinel; Activity logs; Entra sign-in logs |
| HIPAA §164.312(c)(1) | Integrity | Storage immutable blobs for audit, Key Vault soft-delete + purge protection |
| HIPAA §164.312(e)(1) | Transmission security | TLS 1.2+ policy, Private Endpoints, Azure Firewall TLS inspection |
| SOC 2 CC6.1 | Logical access | Entra + PIM + Azure RBAC |
| SOC 2 CC6.6 | Boundary protection | NSGs, Azure Firewall, Private Endpoints |
| SOC 2 CC7.1, CC7.2 | Detection and monitoring | Defender for Cloud + Sentinel + analytics rules |
| PCI-DSS 10.x | Logging and monitoring | Centralized LAW, Sentinel, Activity logs |
| NIST CSF 2.0 PR.AC, DE.CM, RS.MI | Identity, monitoring, response | Covered across the stack |

## Further reading

- [Microsoft Cloud Adoption Framework — Azure Landing Zones](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/)
- [Azure Security Benchmark](https://learn.microsoft.com/en-us/security/benchmark/azure/)
- [Microsoft Sentinel content hub](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog)
- This repo: [entra-id-patterns.md](./entra-id-patterns.md), [defender-for-cloud.md](./defender-for-cloud.md), [../multi-cloud/cspm-strategy.md](../multi-cloud/cspm-strategy.md)
