# Multi-Cloud CSPM Strategy

Cloud Security Posture Management is the continuous discipline of detecting misconfigurations — publicly exposed resources, weak IAM policies, missing encryption, deviation from compliance baselines — and getting them fixed. Every cloud has a native tool. Most mid-size and larger organizations end up with a third-party tool on top. This document is the strategy: where native tools are sufficient, when third-party is worth the cost, how to build a finding workflow that actually produces remediations, and what to measure.

## The starting position

### Native tools per cloud

| Cloud | Tool | What it covers |
| --- | --- | --- |
| AWS | Security Hub + Config + GuardDuty + IAM Access Analyzer | Foundational Security Best Practices, CIS, PCI-DSS standards; per-account + cross-account Config rules; runtime threat detection (GuardDuty); IAM external access + unused permissions |
| Azure | Microsoft Defender for Cloud (CSPM Plan 1 free, Plan 2 paid) | Secure Score, Azure Security Benchmark, regulatory compliance dashboard, Attack Path Analysis (Plan 2) |
| GCP | Security Command Center (Standard free, Premium/Enterprise paid) | Security Health Analytics, Event Threat Detection, Container Threat Detection, Attack Path Simulation (Enterprise) |

Each of these native tools is a genuine product — not a checkbox. The free tiers are enough to get a posture baseline stood up. The paid tiers add capabilities (attack path, runtime detection, data classification) that are non-trivial to replicate.

### What native tools give you that third-party tools struggle to replicate

- **Depth in the cloud they belong to.** AWS Security Hub knows every AWS service's configuration options with full fidelity. Third-party CSPM tools are always chasing this; they support the top 80% of services well and the long tail patchily.
- **Real-time signal.** Native tools can react to resource changes within seconds via EventBridge / Event Grid / Pub/Sub. Third-party tools poll.
- **Tight integration with remediation.** Config auto-remediation, Defender workflow automation, SCC Event Threat Detection — all can invoke cloud-native remediation without leaving the cloud's IAM model.
- **No separate credential boundary.** The native tool is inside your cloud's IAM; the third-party tool needs cross-account read permissions broad enough to inventory everything.

### Where native tools fall short

- **Cross-cloud normalization.** If you run AWS + Azure + GCP, three native dashboards is three places to look. Severity rubrics differ; finding taxonomy differs; naming differs. Aggregation is a real problem.
- **Non-cloud assets.** SaaS (Salesforce, Workday), on-prem, Kubernetes-elsewhere. The cloud-native tool doesn't see these.
- **Identity-graph analysis across clouds.** "Which human has privileged access to every cloud" is a question that crosses tool boundaries.
- **Workflow sophistication.** Native remediation is powerful but procedural. Complex workflows (approval routing by team, cross-finding correlation, SOC 2 evidence generation) often need a dedicated tool.

## When to add a third-party CSPM

Third-party CSPM tools — Wiz, Prisma Cloud, Orca Security, Lacework, CrowdStrike (via its acquisition), and a handful of others — are priced per-resource or per-cloud-account and land in the tens to hundreds of thousands of dollars annually. They are not automatic purchases.

The use cases that justify the cost:

### Use case 1 — Multi-cloud operating at scale

Organizations running two or three major clouds and accumulating meaningful footprint in each (tens of accounts, thousands of resources) need a single pane of glass. The alternative is a spreadsheet merged nightly, which works for 50 resources and does not work for 5000. Wiz and Orca are particularly strong here.

Threshold I use: if the security team spends more than 2 hours/week normalizing findings across native tools, third-party starts paying off.

### Use case 2 — Attack-path and toxic-combination analysis

The single highest-value feature of modern CSPM tools is the graph: internet-exposed resource → has role → has access to sensitive data. Defender Plan 2 has Attack Path Analysis in Azure. SCC Enterprise has Attack Path Simulation in GCP. AWS doesn't have a first-class equivalent (Security Hub + Access Analyzer get you part of the way, but the graph is do-it-yourself).

If your architecture is complex enough that attack paths are not obvious, a tool that computes them is worth the money.

### Use case 3 — Agentless workload vulnerability scanning

Traditional vulnerability scanning requires agents on every VM or container. CSPM tools increasingly offer agentless scanning — snapshotting VM disks or container images out-of-band and scanning them without runtime overhead. This is qualitatively better than agent-based for:
- Ephemeral workloads where agents never stay installed long enough
- Third-party-managed or legacy systems where you cannot deploy an agent
- Coverage completeness (the tool finds what it sees; agentless sees everything)

### Use case 4 — Data classification across clouds

Macie (AWS), Purview (Azure), DLP (GCP) each cover their cloud's storage. A cross-cloud data-classification story often needs a tool that inventories sensitive data across all three. This is especially important in regulated industries where the compliance question is "where is PHI anywhere in our infrastructure."

### Use case 5 — Compliance automation for audit

SOC 2, ISO 27001, HIPAA audits involve evidence collection. Third-party CSPM tools have built-in compliance packs with evidence export. The evidence comes pre-formatted for auditors. For a company going through multiple audits per year, this saves weeks of manual work.

### Use cases that do NOT justify third-party CSPM

- "We have a budget and should spend it." Don't adopt tooling without a specific problem it solves.
- "Our engineers find the native console hard to use." This is a UX problem, not a security problem. A third-party tool replaces one UI with another. Fix the workflow (routing, ownership tags, runbooks) instead.
- "We need better alerting." Native tools alert fine; alerting quality is usually a tuning problem, not a tool problem.
- "We need to cover SaaS." SaaS security posture management (SSPM) is a different product category — AppOmni, Obsidian, Valence. Don't buy a CSPM expecting SSPM.

### Picking a tool

If you conclude a third-party CSPM is worth the budget, evaluate on:

1. **Coverage depth** for the clouds you run (pull a list of 50 resource types across AWS/Azure/GCP and ask the vendor to confirm each is covered). Skip vendor-led "100% coverage" claims; verify.
2. **Attack path / graph quality**. Demo against your own environment, not the vendor's scripted demo.
3. **Workflow integration** — does it integrate with your existing ticketing (ServiceNow, JIRA), comms (Slack, Teams), and SIEM (Sentinel, Splunk)? Native exports to CSV don't count.
4. **Finding deduplication** with the native tools you're keeping. A third-party tool that re-reports every Security Hub finding doubles your triage load.
5. **Pricing model**. Per-resource pricing encourages resource hygiene (good). Per-account pricing punishes you for multi-account (bad). Negotiate.

## Building a unified finding workflow

Regardless of tool choice, the workflow shape is the same. The goal: a finding generated anywhere ends up in front of the right person with enough context to act, and closes when fixed.

```
       AWS Security Hub           Azure Defender for Cloud        GCP SCC
            │                            │                          │
            └────────────────┬───────────┴──────────┬───────────────┘
                             │                      │
                             ▼                      ▼
                      (optional) Third-party CSPM aggregator
                             │
                             ▼
                       ┌───────────────────────────┐
                       │   Normalization layer     │
                       │   - common schema         │
                       │   - severity mapping      │
                       │   - deduplication         │
                       └───────────────────────────┘
                             │
                             ▼
                       ┌───────────────────────────┐
                       │   Enrichment              │
                       │   - resource owner        │
                       │     (from tags)           │
                       │   - environment class     │
                       │   - data sensitivity      │
                       │   - risk score            │
                       └───────────────────────────┘
                             │
                             ▼
                       ┌───────────────────────────┐
                       │   Routing                 │
                       │   by severity + env class:│
                       │   - Critical → PagerDuty  │
                       │   - High     → Ticket now │
                       │   - Medium   → Digest     │
                       │   - Low      → Dashboard  │
                       └───────────────────────────┘
                             │
                             ▼
                       ┌───────────────────────────┐
                       │   Tracking & SLA          │
                       │   - ticket aging          │
                       │   - SLA breach alerts     │
                       │   - auto-close on fix     │
                       └───────────────────────────┘
```

### Normalization

Native findings have different schemas. Convert each to a common shape at ingest time:

```json
{
  "finding_id": "aws-sh-abc123",
  "source_system": "aws_security_hub",
  "source_finding_id": "arn:aws:securityhub:...:finding/abc123",
  "rule_id": "EC2.7",
  "rule_name": "EBS default encryption should be enabled",
  "severity": "HIGH",
  "resource": {
    "cloud": "aws",
    "account_id": "111111111111",
    "resource_type": "AWS::EC2::Region",
    "resource_arn": "arn:aws:ec2:us-east-1:111111111111:region/us-east-1",
    "region": "us-east-1",
    "tags": {"Environment": "prod", "Team": "platform"}
  },
  "first_seen": "2026-04-18T12:33:00Z",
  "last_seen": "2026-04-20T03:15:00Z",
  "state": "OPEN",
  "compliance_frameworks": ["CIS_AWS_Foundations_4.0/2.2.1", "PCI_DSS_v4/3.6.1"],
  "remediation_url": "https://docs.aws.amazon.com/securityhub/..."
}
```

Severity normalization: AWS uses `CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL`, Azure uses `High/Medium/Low`, GCP uses `CRITICAL/HIGH/MEDIUM/LOW`. Map to a single rubric.

### Deduplication

Same misconfiguration reported by multiple tools (native + third-party) should generate one ticket, not three. Key for dedup: `cloud + account_id + resource_type + resource_id + rule_family`.

### Risk scoring

Don't trust the tool's severity alone. Re-score:

```
risk_score = base_severity × environment_multiplier × data_sensitivity_multiplier × exposure_multiplier

where:
  base_severity:       CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1
  environment:         prod=1.5, stage=1.0, dev=0.5
  data_sensitivity:    regulated=1.5, internal=1.0, public=0.7
  exposure:            internet_exposed=1.5, accessible_from_vpn=1.0, internal_only=0.7
```

A misconfiguration on a dev resource with public data is low priority even if the tool says HIGH. A misconfiguration on a prod regulated-data resource with internet exposure is critical even if the tool says MEDIUM.

### Routing

Route by:

1. **Severity** after re-scoring (determines urgency path)
2. **Resource owner** (from tags — which is why a tagging policy is a CSPM prerequisite, not a separate initiative)
3. **Finding type** (some classes always go to platform team regardless of resource owner)

Implementation: Lambda / Logic App / Cloud Function subscribed to the aggregator output; route to ticketing + Slack.

### SLA tracking

Assign SLAs by severity:

| Severity | Time to fix |
| --- | --- |
| Critical | 24 hours |
| High | 7 days |
| Medium | 30 days |
| Low | 90 days or "fix or accept" |

Aging reports show findings that have breached SLA. Escalation paths defined: Critical → security lead, continued breach → engineering VP, continued breach → exec review.

## Metrics that matter

Posture-management programs that do not measure themselves drift. The metrics I report monthly:

### Coverage

- **% of cloud accounts/subscriptions/projects under continuous posture monitoring**. Should be 100%. If it isn't, that's the top finding.
- **% of production workloads with CWP (runtime) in addition to CSPM**. Targets depend on budget but explicit.

### Detection timeliness

- **Mean Time To Detect (MTTD) misconfiguration** — from "resource created in misconfigured state" to "finding generated." Native tools: usually < 15 minutes. If it's hours, something is broken.

### Remediation timeliness

- **Mean Time To Remediate (MTTR) by severity**. Break down by critical/high/medium/low.
- **% of findings remediated within SLA, by severity**. Target: > 90% for Critical and High. The team that remediates 60% of high-severity findings within 7 days is materially better off than the team that remediates 95% within 30 days.
- **SLA breach count, by team**. Concentrates attention where it needs to go.

### Finding quality

- **False positive rate, per rule**. Rules > 50% FP → tune or disable. A noisy rule trains the team to ignore its entire class.
- **Duplicate finding rate** post-dedup. Should be low; if not, dedup logic is broken.
- **Findings with no owner** — the team can't route them. This should be zero. If non-zero, the tagging policy is failing and that is the top priority.

### Risk reduction

- **High/Critical findings 30-day trend**. Should trend down.
- **Attack paths open, by severity**. If using attack-path tooling: the count of open critical attack paths is the single most useful posture metric.

### Cost hygiene

- **Per-finding cost of your CSPM program**: total spend / total findings generated. Watch for the case where the spend goes up 50% and findings stay flat — you bought features you don't use.

## Drift detection

CSPM is most of the value. Drift detection is the piece that catches the other side: you built a compliant baseline, someone changed it manually, it no longer matches.

Two layers:

### Layer 1 — Config/Defender/SCC continuous assessment

Already baked in. Config rules / Defender recommendations / SCC findings run continuously and raise new findings on drift. This is the "we notice" part.

### Layer 2 — Infrastructure-as-Code reconciliation

The higher-fidelity answer: diff actual state against the IaC that created it. If Terraform created a bucket with `encryption = aws:kms` and someone manually changed it to `AES256` in the console, the Terraform plan shows drift.

Options:

- **`terraform plan` in CI, scheduled**: run `terraform plan` against every workspace daily and alert on any non-empty diff. Free, requires the team to have IaC coverage.
- **Cloud Custodian (c7n)**: open-source policy-as-code engine that checks for drift and can auto-remediate. Less IaC-dependent.
- **Commercial drift tools**: Env0, Firefly, Gruntwork Pipelines. Pay for the UX and the audit log.

Drift detection closes a specific gap: a manual console change that silently reverts your security baseline. It is a relatively cheap control that catches a pattern traditional CSPM may rate as OK (the resource is "compliant" in its new state, just different from the intended IaC).

## CSPM for AI/ML workloads

AI/ML workloads have security-relevant configurations that general CSPM tools often miss. The additional checks:

### SageMaker (AWS)

- **Training jobs with internet access** (`EnableNetworkIsolation=false`). For regulated training data, network isolation should be on.
- **Notebook instances with internet access enabled** and no VPC attachment. Default configuration is insecure.
- **Training data buckets without encryption** using the account's regulated-data KMS CMK.
- **Model hosting endpoints without encryption in transit** (`EndpointConfig.DataCaptureConfig` not encrypted, inference data exposed).
- **Model registry without approval workflow** for promotions — a security-adjacent supply-chain check.

### Azure ML

- **Workspaces with public network access** (`publicNetworkAccess != Disabled`).
- **Compute instances without managed identity** (using the user's credentials instead).
- **Training runs writing to storage accounts without CMK** or with public access.
- **Model registry without RBAC controls** on model deployment.

### Vertex AI (GCP)

- **Training jobs without VPC Service Controls** perimeter enforcement on regulated data.
- **Endpoints without private service access** (public endpoints on inference services).
- **Model registry without IAM binding hygiene** (too-broad `aiplatform.user` role on projects with sensitive models).

### Cross-cloud AI/ML

- **Model artifacts without signature verification** in any CI/CD deploying models.
- **Training data buckets without Macie / Purview / DLP scanning** — you are potentially training on PHI without knowing.
- **Feature store access control** — feature stores often are the data gravity point for ML; they need CSPM treatment similar to data warehouses.
- **LLM endpoints without prompt logging** for compliance — distinct from general posture, but CSPM tools are starting to check.

Most third-party CSPM tools have basic SageMaker / Azure ML / Vertex AI checks; depth varies. If AI/ML is a major part of your environment, specifically evaluate coverage for these services during tool selection, don't assume.

## Adoption roadmap

A realistic phased roadmap:

**Phase 1 (weeks 1–4): Native foundations**
- Enable Security Hub (AWS), Defender for Cloud CSPM (Azure), Security Command Center (GCP) across all accounts/subscriptions/projects.
- Turn on the foundational benchmark standards (CIS, Foundational Best Practices, Security Benchmark).
- Tag inventory (ensure every resource has `Environment`, `Owner`, `DataClass`).
- Export findings to a central S3/Blob/GCS bucket daily for persistence.

**Phase 2 (weeks 5–8): Normalization and routing**
- Stand up normalization + dedup pipeline (Lambda / Function).
- Route by severity and owner tag to ticketing.
- Stand up SLA tracking.
- Weekly review of new findings; monthly review of aging findings.

**Phase 3 (months 3–4): Attack path and remediation**
- Enable Defender CSPM Plan 2 (Azure) and SCC Enterprise (GCP) if in scope.
- For AWS: hand-build attack-path queries against Security Hub + Access Analyzer, or consider a third-party tool here.
- Identify the top 5 auto-remediable finding classes; implement remediation.

**Phase 4 (months 5–6): Third-party if justified**
- Re-evaluate: is the pain genuinely multi-cloud normalization, attack path, or data classification?
- If yes, run a 30-day trial of the two top candidates against your real environment.
- If adopted, keep native tools as the source of truth for their cloud; use third-party as the unified view.

**Phase 5 (ongoing): Measurement and tuning**
- Monthly metric review.
- Quarterly rule tuning (disable noisy rules, add custom rules for org-specific concerns).
- Annual tool re-evaluation against the use-case criteria above.

## Compliance mapping

| Framework | Control | Satisfied by |
| --- | --- | --- |
| HIPAA §164.308(a)(1)(ii)(A) — Risk analysis | Continuous posture assessment; risk-scored findings |
| HIPAA §164.308(a)(8) — Evaluation | Regulatory compliance dashboards; audit evidence export |
| SOC 2 CC7.1 — Detection of anomalies | CSPM + drift detection |
| SOC 2 CC7.2, CC7.3 — Monitoring and response | Routing, SLA tracking, remediation workflow |
| NIST CSF 2.0 ID.RA, DE.CM, RS.MI | Risk assessment, continuous monitoring, response |
| PCI-DSS 11.5 | Change detection (drift) |

## Further reading

- [AWS — Multi-account security best practices](https://docs.aws.amazon.com/whitepapers/latest/organizing-your-aws-environment/organizing-your-aws-environment.html)
- [Microsoft — Secure Score in Defender for Cloud](https://learn.microsoft.com/en-us/azure/defender-for-cloud/secure-score-security-controls)
- [GCP — Security Command Center documentation](https://cloud.google.com/security-command-center/docs/concepts-security-command-center-overview)
- [Cloud Custodian](https://cloudcustodian.io/) — open-source policy-as-code for CSPM-adjacent enforcement
- This repo: [../aws/security-reference-architecture.md](../aws/security-reference-architecture.md), [../azure/defender-for-cloud.md](../azure/defender-for-cloud.md), [zero-trust-cloud.md](./zero-trust-cloud.md)
