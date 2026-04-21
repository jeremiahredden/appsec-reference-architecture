# Getting Real Value from Microsoft Defender for Cloud

Defender for Cloud is two products in one: a Cloud Security Posture Management (CSPM) tool that continuously assesses your configuration against benchmarks, and a set of Cloud Workload Protection (CWP / "Defender Plans") subscriptions that add runtime detection on specific resource types. Both cost money. Neither is a turnkey outcome.

This document is how I approach it when a team inherits a Defender tenant that is either under-used (just the free CSPM tier, findings ignored) or over-adopted (every plan enabled at cost, no triage process, alerts ignored). Both failure modes are common.

## CSPM — reading the Secure Score

### What it is

Secure Score is a 0–100 number Defender assigns to each subscription (or aggregated up to the tenant). It reflects the percentage of applicable recommendations satisfied, weighted by severity. Each recommendation is a configuration check — "Storage Accounts should not allow public access," "Key Vaults should have soft-delete enabled," "SQL servers should have auditing enabled."

The score looks simple. It is not the actual product. Two warnings up front:

1. **Chasing the score is not the goal.** Teams that treat Secure Score as a KPI end up implementing low-value, high-score recommendations (tagging) while skipping high-value, high-effort ones (private endpoints on Storage). Judge by what risk you retired, not by the number.
2. **Not all recommendations apply.** Some are genuinely irrelevant to your architecture. Mark them as "Not applicable" with a reason — you are building your own scorecard as you go, and a score of 87 with 10 documented exceptions beats a score of 92 via silently-ignored recommendations.

### Triage by impact vs effort

The Defender recommendations page lists everything in one pile, which is how teams get overwhelmed. Triage in a 2×2:

```
                           EFFORT
                    Low                High
              ┌────────────────┬──────────────────┐
              │                │                  │
              │  DO FIRST      │  PLAN FOR        │
        HIGH  │                │                  │
              │  - Enable TDE  │  - Private       │
              │    on SQL      │    Endpoints on  │
              │  - Enable      │    Storage/KV/SQL│
   IMPACT     │    storage     │  - CMK migration │
              │    soft-delete │  - Zero-trust    │
              │  - Enable KV   │    network       │
              │    soft-delete │    redesign      │
              │                │                  │
              ├────────────────┼──────────────────┤
              │                │                  │
              │  FILL IN       │  DEFER           │
         LOW  │                │                  │
              │  - Tagging     │  - Micro-        │
              │  - Diagnostic  │    segmentation  │
              │    settings    │    across        │
              │                │    dormant VNets │
              │                │                  │
              └────────────────┴──────────────────┘
```

Spend 80% of the cycles on "Do First" and "Plan For." The other quadrants will get done eventually without needing explicit attention.

### Using exemptions correctly

Defender lets you create Exemptions with a justification. Use them. A recommendation marked as exempt with "This storage account holds only public marketing images, public access is intentional — see [ticket]" is vastly better than a recommendation left as "unhealthy" and quietly ignored.

Exemption hygiene:

- Every exemption has a link to a ticket, an owning team, and a review date.
- Exemptions with a `Waiver` category are used for risk-accepted items.
- Exemptions with a `Mitigated` category are used for items addressed by a compensating control outside of Defender's visibility.
- Quarterly review: sweep exemptions, confirm each is still valid.

### Attack Path Analysis

Paid CSPM (Plan 2) includes Attack Path Analysis — Defender models your environment as a graph and shows you attack paths from exposed resources to sensitive data.

Example output: *"Internet-exposed VM → has Contributor role on Resource Group → which contains Storage Account holding PHI → attack path severity: High."*

These paths are the most valuable output of Defender CSPM. One attack path with three steps is worth more than a hundred individual recommendations because it tells you what to fix to break the chain.

For a regulated workload, Plan 2 pays for itself the first time Attack Path Analysis surfaces a chain you didn't know existed.

## Defender Plans worth enabling

There are 10+ Defender plans, priced per-resource-per-month. Not all are worth the cost for every workload. Here is the plan-by-plan recommendation for a regulated SaaS workload.

### Defender for Servers

**Recommended: Plan 2.** Plan 1 gives you basic anti-malware signals. Plan 2 adds file integrity monitoring, just-in-time VM access, adaptive application controls, and (crucially) free integration with Microsoft Defender for Endpoint.

Worth it for:
- Any VM holding regulated data or running critical services
- Any VM with public network exposure

Skip for:
- Ephemeral, immutable, container-pattern VMs where you don't persist state (just rebuild instead of responding to an alert)

**Cost rough order**: Plan 2 ~$15/VM/month. For a fleet of 10 servers, ~$1800/year — cheaper than any EDR replacement.

### Defender for SQL

**Recommended: yes, for Prod databases.** Adds advanced threat protection (detection of SQL injection attempts, anomalous queries, data exfiltration patterns) and vulnerability assessment. The VA is a poor substitute for a real SQL security audit but catches obvious misconfigurations.

Worth it for:
- Azure SQL Database / Managed Instance / SQL on IaaS running Prod
- Any database holding regulated data

Skip for:
- Dev/Stage databases if the budget is constrained
- Synapse serverless SQL pools (coverage is limited)

### Defender for Storage

**Recommended: yes for regulated-data accounts.** Monitors blob access patterns, detects malware uploads (signature scanning), detects unusual access from anonymous or anomalous sources, detects exfiltration patterns.

Plan 2 (Malware Scanning + Sensitive Data Threat Detection) is the one you want. Plan 1 is cheaper but misses the most useful detections.

Worth it for:
- Storage accounts holding PHI, PII, PCI data
- Storage accounts that accept user uploads (malware scanning is the key win)

Skip for:
- Pure internal-only storage with no ingress from untrusted sources
- High-volume telemetry storage where per-GB scanning cost explodes

**Cost warning**: Malware scanning is priced per GB scanned. For user-upload patterns with high write volume, model the cost first.

### Defender for Key Vault

**Recommended: yes.** Low cost (~$2/vault/month). Detects unusual secret access patterns and known-suspicious IPs calling Key Vault APIs.

A hit on Defender for Key Vault is almost always either a real incident or a genuine operational anomaly worth investigating. Signal-to-noise is good.

Worth it for: all production Key Vaults.

### Defender for Containers

**Recommended: yes for AKS Prod.** Covers the whole container lifecycle:
- Registry scanning for vulnerabilities in images in ACR
- Admission-time checks
- Runtime detection in AKS via the Defender DaemonSet

For regulated workloads running AKS, this is non-optional. Container security without runtime detection is half a control.

### Defender for App Service

**Recommended: yes if using App Service in Prod.** Detects anomalous outbound traffic, known-malicious command execution patterns, web shell indicators.

Useful for workloads where you can't easily instrument the app itself.

### Defender for Resource Manager

**Recommended: yes.** Low cost. Detects suspicious resource-creation patterns, privilege escalation attempts, unusual role assignments. Catches things like "attacker creates a VM in us-east-1 with a large SKU for cryptomining" before the bill arrives.

### Defender for DNS

**Recommended: maybe.** Detects DNS-based exfiltration and queries to known-malicious domains. Value depends on your egress-inspection story — if you already have Azure Firewall Premium with IDPS, DNS protection is redundant. If not, this is a cheap add.

### Defender for Open-Source Relational Databases (Postgres, MySQL, MariaDB)

**Recommended: yes for Prod instances.** Same shape as Defender for SQL but for the open-source databases. Same reasoning.

### Defender for Cosmos DB

**Recommended: yes for Prod.** Anomalous access detection for Cosmos. Low cost, high signal if Cosmos holds regulated data.

### Defender for APIs

**Recommended: conditional.** If your public APIs are published via Azure API Management, Defender for APIs adds detection for common abuse patterns. If your APIs are behind App Gateway or Front Door with WAF, the incremental value is smaller.

### Plans I'd skip in most cases

Plans that are either low-value or overlap heavily with other controls:

- **Defender for Azure Cosmos DB** and **Defender for Azure CosmosDB for PostgreSQL** — overlap, enable only one.
- **Defender EASM (External Attack Surface Management)** — valuable for very large orgs with sprawling internet footprints; for a mid-size SaaS, a simpler vuln scanner and regular port-scan-of-own-public-IP will do.

### Total cost orientation

For a mid-sized SaaS (10–30 VMs, 5–10 databases, 20–50 storage accounts, a few AKS clusters, Key Vaults, etc.), the Defender bill lands somewhere in $2–5K/month with the recommended set. For a company with a real HIPAA / SOC 2 obligation, that is in the same order of magnitude as a single SIEM licensing line item. It is reasonable.

## Regulatory compliance dashboard

Defender's Regulatory Compliance blade maps recommendations to frameworks. Out of the box it covers:

- Azure Security Benchmark (Microsoft's own)
- CIS Microsoft Azure Foundations Benchmark
- PCI-DSS 4.0
- ISO 27001:2013
- SOC 2 Type 2
- NIST SP 800-53 Rev. 5
- HIPAA / HITRUST
- FedRAMP

Enable the frameworks you actually need to satisfy. Each one adds a set of assessments to your Defender findings.

### Using it for audit conversations

This is Defender's best feature for the audit cycle. When an auditor asks "show me evidence that you have access controls in place for access to the environment," you can point to the HIPAA §164.312(a)(1) row and show:

- Which Azure resources are in scope
- Which resources pass the assessment
- Which fail and why
- Evidence per resource

Workflow:

1. At the start of audit prep, export the Regulatory Compliance report for your framework.
2. Identify all the controls that currently show as failing.
3. For each, decide: remediate, document as an exception with compensating control, or document as an exemption with justification.
4. Produce the report again at audit time; diff shows your improvement.

### Caveats

- **The mapping is Microsoft's interpretation.** An auditor may not accept Defender's assessment as full evidence; it is a strong starting point, not a stamp.
- **Some controls are "manual attestation."** Defender cannot assess them; you claim compliance. The dashboard marks them but does not validate.
- **Coverage is uneven across frameworks.** HIPAA is well-covered; some NIST controls map awkwardly.

## Workflow automation

Defender findings go where? Out of the box: the Defender portal and Microsoft Sentinel. For automation, use Event Grid → Logic Apps.

### The pattern

```
  Defender finding generated
          │
          ▼
     Event Grid system topic (Microsoft.Security subscription)
          │
          ▼
     Event Grid subscription (filtered by severity, resource type)
          │
          ▼
     Logic App (or Azure Function)
          │
          ├── Enrich (query related resources, look up owner from tags)
          ├── Route (ServiceNow / JIRA / PagerDuty based on severity + tag)
          └── (for very narrow set) Auto-remediate
```

### Workflows that pay off

**Workflow 1 — High-severity finding → ServiceNow ticket with owner auto-assigned**

Trigger: Defender finding with Severity = High.

Logic:
1. Read the finding's resource ID.
2. Query the resource's tags for `Owner` or `Team`.
3. Look up the team's ServiceNow queue.
4. Create a ticket with the Defender finding details, CVSS, recommended remediation.
5. Link back to Defender for the evidence.

**Workflow 2 — Storage account turned public → auto-remediate**

Trigger: Defender finding "Storage account should not allow public access," resource tag `AutoRemediate=true`.

Logic:
1. Confirm the resource was not intentionally made public (check for an `IntentionallyPublic=true` tag).
2. Set `AllowBlobPublicAccess=false` on the storage account.
3. Post to security-alerts Slack with remediation result.
4. Open a ticket even after success, so the team knows why their bucket got remediated.

**Workflow 3 — Anomalous Key Vault access → page oncall**

Trigger: Defender for Key Vault finding, severity High, pattern "Unusual location from which a user has accessed a Key Vault."

Logic:
1. Enrich with the user's recent sign-in history.
2. Page oncall via PagerDuty.
3. Auto-open an investigation record in Sentinel.

### Anti-pattern: auto-remediating everything

Some findings look auto-remediable but are not. "SQL auditing should be enabled" looks like `set-auditing-on` — but if auditing wasn't on, you also need to decide where the audit target goes, how much to log, what SKU of storage to attach, and an auto-remediation that sets auditing with default values will produce a misconfigured result that satisfies the assessment without producing the audit data you actually needed.

Rule of thumb: auto-remediate for finding classes where the correct action is a single, unambiguous API call. Open a ticket for anything that requires judgment.

## Integration with Microsoft Sentinel

Sentinel is Microsoft's SIEM; Defender is one of many data sources for it. The integration is native: enable the Defender for Cloud data connector in Sentinel, and findings flow in as alerts.

### What to forward, what to filter

- **Forward**: high-severity findings, findings on regulated workloads, findings for control-plane changes (IAM, role assignments, CA policy modifications), security-related Azure Activity.
- **Filter or skip**: low-severity findings that are already ticketed elsewhere, recommendations (as opposed to alerts) — those belong in the posture dashboard, not the SIEM.

Forwarding everything makes Sentinel noisy and expensive. The cost of Sentinel ingestion adds up.

### Noise reduction tactics

1. **Defender alert grouping**: Defender groups related alerts into Security Incidents. Forward incidents, not raw alerts; fewer items to triage.
2. **Sentinel analytics rules that close duplicates**: if an alert fires from both Defender and a custom analytics rule, auto-close the duplicate.
3. **Per-environment tuning**: the same finding in Prod is a ticket; in Dev, maybe a daily digest. Use Sentinel automation rules to route by resource tag.

### Which Sentinel analytics rules pair well with Defender data

- **"New admin role assigned"** — Sentinel rule using Entra audit logs, correlated with Defender's Resource Manager findings.
- **"Suspicious login followed by Defender alert"** — Identity Protection risk signal + Defender finding on the same subscription within 1 hour.
- **"Storage mass download"** — Defender for Storage anomalous access alert + Storage diagnostic logs showing >N GB downloaded.

## Measuring program maturity

The Defender program metrics worth tracking monthly:

| Metric | What to watch |
| --- | --- |
| Secure Score trend | Quarter-over-quarter, by subscription |
| High-severity findings age | Time to close, grouped by severity |
| Exemption count | Should not grow unchecked; quarterly review |
| Plans enabled coverage | % of Prod resources under a Defender plan |
| Alert-to-ticket ratio | Should be high; if low, routing is broken |
| False positive rate per rule | > 50% FP rate → tune or disable |
| Regulatory dashboard pass rate | % of controls passing, per framework |

Report these monthly to the security leadership group. They are boring until they aren't; the trend is how you notice a regression.

## Compliance mapping

| Framework | Control | Satisfied by |
| --- | --- | --- |
| HIPAA §164.308(a)(1)(ii)(D) — Information system activity review | Defender recommendation scan + Sentinel alert review |
| HIPAA §164.308(a)(8) — Evaluation | Defender regulatory compliance assessment |
| SOC 2 CC7.1 — Detection of anomalies | Defender plans + Sentinel analytics |
| SOC 2 CC7.2 — Monitoring and detection | Workflow automation via Event Grid + Logic Apps |
| NIST CSF 2.0 DE.CM | Continuous monitoring |

## Further reading

- [Microsoft Defender for Cloud documentation](https://learn.microsoft.com/en-us/azure/defender-for-cloud/)
- [Defender for Cloud pricing page](https://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/) — plans and per-resource pricing
- [Defender for Cloud regulatory compliance docs](https://learn.microsoft.com/en-us/azure/defender-for-cloud/regulatory-compliance-dashboard)
- This repo: [security-reference-architecture.md](./security-reference-architecture.md), [entra-id-patterns.md](./entra-id-patterns.md), [../multi-cloud/cspm-strategy.md](../multi-cloud/cspm-strategy.md)
