# Cloud Security

## What this folder is

A practitioner's reference for cloud security on AWS, Azure, and across multi-cloud. The material covers the patterns I put in front of engineering teams when a regulated workload is already running (or about to run) in the cloud and the question is: *what do we actually need to do?*

## The organizing principle

Every pattern here is implementable. That is the test for whether something belongs in this folder.

Cloud security suffers from a very specific failure mode: the vendor-hosted reference architecture that shows 47 services wired together, costs six figures per year in licensing, requires two dedicated FTEs to operate, and has no path to incremental adoption. A team that inherits a workload and a tight SOC 2 deadline cannot use that reference architecture. They need a sequence of concrete moves that each ship within a sprint and each improve the posture measurably.

So the documents here assume you have:

- An existing workload (or soon will), not a greenfield
- A budget that is not unlimited
- An engineering team that has to keep shipping the product while adopting security controls
- A compliance obligation that is real (HIPAA, SOC 2, PCI) rather than aspirational

Every recommendation is sized to that reality: the 80% control that ships this quarter, not the 100% control that ships never.

## Layout

```
cloud-security/
├── README.md                                        (this file)
├── aws/
│   ├── security-reference-architecture.md           Multi-account AWS security architecture
│   ├── iam-least-privilege.md                       Practical least-privilege on AWS IAM
│   └── scp-guardrails.json                          Drop-in SCPs for AWS Organizations
├── azure/
│   ├── security-reference-architecture.md           Management Group + Subscription architecture
│   ├── entra-id-patterns.md                         Identity patterns for Entra ID
│   └── defender-for-cloud.md                        Getting real value from Defender for Cloud
└── multi-cloud/
    ├── cspm-strategy.md                             CSPM across AWS + Azure + GCP
    └── zero-trust-cloud.md                          Zero trust in a multi-cloud reality
```

## How to use this section

**If you are inheriting an AWS account that has not been hardened** — start with [aws/scp-guardrails.json](./aws/scp-guardrails.json). Apply the SCPs in a non-prod OU first, then roll out. You will prevent a meaningful fraction of the most common incidents with a day of work.

**If you are building out a new AWS landing zone** — [aws/security-reference-architecture.md](./aws/security-reference-architecture.md) is the target architecture. Adopt it in phases; the document orders the phases.

**If you are struggling with over-privileged IAM roles** — [aws/iam-least-privilege.md](./aws/iam-least-privilege.md) walks from CloudTrail data to right-sized policies. Permission Boundaries and IAM Access Analyzer do most of the work.

**If you are on Azure and need to justify the Defender for Cloud spend** — [azure/defender-for-cloud.md](./azure/defender-for-cloud.md) identifies the Defender plans worth paying for and how to avoid noise.

**If you are running multi-cloud** — [multi-cloud/cspm-strategy.md](./multi-cloud/cspm-strategy.md) and [multi-cloud/zero-trust-cloud.md](./multi-cloud/zero-trust-cloud.md) describe the native-first approach and where third-party CSPM is worth the budget.

## Scope and caveats

This folder covers cloud **infrastructure** security — accounts, IAM, network, posture management, identity. Application-level controls (input validation, auth inside the app, secure API design) live in [../architecture-patterns/](../architecture-patterns/) and [../owasp-remediation-playbooks/](../owasp-remediation-playbooks/).

GCP appears in the multi-cloud documents as a first-class participant but does not have its own dedicated subfolder here. Most of the patterns have direct GCP analogues (Organization policies ≈ SCPs, Security Command Center ≈ Security Hub ≈ Defender for Cloud, Workload Identity ≈ IAM Roles for Service Accounts). If you are GCP-primary, read the AWS and Azure documents for the patterns and translate.

Costs are called out when they are a material decision driver (e.g., whether to enable a Defender plan). Licensing prices change; treat the dollar figures as directional, not quoted.

## A note on what this folder is not

- **A CIS benchmark walkthrough.** The CIS benchmarks are valuable; they are also comprehensive enough to be their own project. Use a CSPM tool to measure compliance against them. The patterns here are about which controls matter most and how to implement them without drowning.
- **A vendor comparison.** Where a specific tool is named (Teleport, Wiz, Okta, Entra ID), it is because the pattern is easier to explain concretely. Substitute your vendor of choice; the pattern is what matters.
- **A complete IR guide for cloud incidents.** Incident response lives in [../incident-response/](../incident-response/) (forthcoming). This folder focuses on preventive and detective controls.
