# AWS Security Reference Architecture

A reference architecture for a regulated SaaS workload on AWS — the shape I would build or recommend for a company with a real HIPAA or SOC 2 obligation, a production workload serving customers, and a team that needs to keep shipping the product. The architecture is tuned for *implementability*: every component can be adopted incrementally, and the order of adoption is called out.

## Target architecture

```
                                  ┌────────────────────────────────────────────┐
                                  │              AWS Organization              │
                                  │          (management / payer account)       │
                                  │    - Organization CloudTrail (org-trail)    │
                                  │    - Service Control Policies (SCPs)        │
                                  │    - IAM Identity Center (SSO)              │
                                  └────────────────────────────────────────────┘
                                                    │
                      ┌─────────────────────────────┼─────────────────────────────┐
                      │                             │                             │
                      ▼                             ▼                             ▼
          ┌──────────────────────┐      ┌──────────────────────┐      ┌──────────────────────┐
          │  OU: Security        │      │  OU: Infrastructure  │      │  OU: Workloads       │
          │                      │      │                      │      │                      │
          │  ┌────────────────┐  │      │  ┌────────────────┐  │      │  ┌────────────────┐  │
          │  │ Security Acct  │  │      │  │ Shared Svcs    │  │      │  │ Prod Workload  │  │
          │  │ ┌────────────┐ │  │      │  │ ┌────────────┐ │  │      │  │ ┌────────────┐ │  │
          │  │ │ GuardDuty  │ │  │      │  │ │ Route 53   │ │  │      │  │ │ ALB        │ │  │
          │  │ │ Security   │ │  │      │  │ │ ACM        │ │  │      │  │ │ EKS/ECS    │ │  │
          │  │ │  Hub       │ │  │      │  │ │ TGW hub    │ │  │      │  │ │ RDS (KMS)  │ │  │
          │  │ │ Access     │ │  │      │  │ │ VPC        │ │  │      │  │ │ S3 (KMS)   │ │  │
          │  │ │ Analyzer   │ │  │      │  │ └────────────┘ │  │      │  │ └────────────┘ │  │
          │  │ │ Config     │ │  │      │  └────────────────┘  │      │  └────────────────┘  │
          │  │ │ aggregator │ │  │      │                      │      │                      │
          │  │ └────────────┘ │  │      │                      │      │  ┌────────────────┐  │
          │  └────────────────┘  │      │                      │      │  │ Stage Workload │  │
          │                      │      │                      │      │  └────────────────┘  │
          │  ┌────────────────┐  │      │                      │      │  ┌────────────────┐  │
          │  │ Logging Acct   │  │      │                      │      │  │ Dev Workload   │  │
          │  │ ┌────────────┐ │  │      │                      │      │  └────────────────┘  │
          │  │ │ S3 (org    │ │  │      │                      │      │                      │
          │  │ │  trail,    │ │  │      │                      │      │                      │
          │  │ │  VPC flow, │ │  │      │                      │      │                      │
          │  │ │  config    │ │  │      │                      │      │                      │
          │  │ │  history)  │ │  │      │                      │      │                      │
          │  │ │ OLock on   │ │  │      │                      │      │                      │
          │  │ └────────────┘ │  │      │                      │      │                      │
          │  └────────────────┘  │      │                      │      │                      │
          └──────────────────────┘      └──────────────────────┘      └──────────────────────┘

Data flows:
  - All accounts send CloudTrail, Config, VPC Flow, GuardDuty findings → Security + Logging accounts
  - Security Hub in Security account aggregates findings from all accounts and all regions
  - Logging account S3 is the single authoritative log sink, with Object Lock (compliance mode) and KMS-CMK
```

### Workload VPC (inside each workload account)

```
   ┌────────────────────────────── VPC 10.20.0.0/16 ──────────────────────────────┐
   │                                                                               │
   │   ┌──────── Public ────────┐   ┌─────── Private (app) ──────┐   ┌─ Data ───┐ │
   │   │  AZ-a  10.20.0.0/24    │   │   AZ-a  10.20.10.0/24     │   │ 10.20.50 │ │
   │   │  AZ-b  10.20.1.0/24    │   │   AZ-b  10.20.11.0/24     │   │ 10.20.51 │ │
   │   │                        │   │                             │   │ 10.20.52 │ │
   │   │   - ALB (public)       │   │   - EKS / ECS nodes         │   │ - RDS    │ │
   │   │   - NAT Gateway (egress│   │   - EC2 app tier            │   │ - Elastic│ │
   │   │     for private subnet)│   │   - Lambda VPC ENIs         │   │   Cache  │ │
   │   └────────────────────────┘   └─────────────────────────────┘   └──────────┘ │
   │                                                                               │
   │   VPC Endpoints (Interface + Gateway):                                        │
   │      s3, ddb (gateway) | sts, logs, monitoring, ssm, secretsmanager,          │
   │      kms, ecr.api, ecr.dkr, sns, sqs, eventbridge (interface)                 │
   │                                                                               │
   │   AWS Network Firewall OR Gateway Load Balancer (egress inspection, optional)│
   └───────────────────────────────────────────────────────────────────────────────┘
```

---

## Account strategy

### Why multi-account matters

A single AWS account is a single blast radius. Any IAM policy that grants a permission grants it against every resource. Any misconfiguration that exposes an S3 bucket exposes it to all users who have any S3 read. Any compromised credential inside the account can (depending on its role) reach production data.

Multi-account containment is structural: you *cannot* reach a resource across accounts unless you have explicitly cross-wired access. That structural boundary is worth a lot of process and tooling. The cost of multi-account is real (cross-account IAM plumbing, Route 53 private hosted zones, shared services, log aggregation), but every regulated-workload incident response I have been part of benefited from the blast-radius isolation.

### Account layout

Baseline recommended minimum:

| Account | Purpose | Who writes to it |
| --- | --- | --- |
| **Management** | AWS Organizations root, consolidated billing, SCPs, IAM Identity Center | No workloads. Terraform/CloudFormation only, from a pipeline. |
| **Security** | GuardDuty delegated administrator, Security Hub delegated administrator, IAM Access Analyzer org-level, Config aggregator | SecOps via role assumption. |
| **Logging** | Org CloudTrail S3 sink, VPC Flow Logs, Config history, ALB/WAF logs | No humans write directly. Immutable sink. |
| **Shared Services** | Route 53, ACM, Transit Gateway, shared VPC endpoints, ECR, artifact buckets | Platform team. |
| **Workload — Prod** | Production customer-serving resources | Platform + Engineering via constrained roles. |
| **Workload — Stage** | Pre-prod, structurally identical to Prod | Engineering. |
| **Workload — Dev** | Per-team dev sandboxes, disposable | Engineering (loose). |
| **Workload — Sandbox** | Individual-engineer-owned, $X/month budget cap, auto-nuke on weekend | Engineers (wide permissions, strict SCPs). |

Delegated administrator matters: do not enable GuardDuty / Security Hub / Config from the management account. Delegate to the Security account. The management account should be the quietest account in the org.

### The Shared Services account is load-bearing

Most teams underinvest in Shared Services until they are deploying things 14 times (once per workload account). Centralize there:

- **Route 53** private hosted zones shared via RAM
- **ACM** public certs (and regional private CA if you use ACM PCA)
- **Transit Gateway** hub for inter-VPC routing
- **ECR** for container images, with replication to workload accounts where needed
- **Interface VPC endpoints** shared via PrivateLink

This is not a security control on its own; it keeps the workload accounts thin enough that the SCPs on them can be tight.

---

## Detective controls

The target: a finding generated anywhere in the org is visible in one place within 15 minutes, and high-severity findings trigger an automated or human response within an hour.

### Pipeline

```
    GuardDuty / Inspector / Macie / custom finders (per account, per region)
                                    │
                                    ▼
                     Security Hub  (per account, per region)
                                    │
                                    ▼
                 Security Hub delegated admin in Security account
                 (org-wide aggregation, cross-region aggregation)
                                    │
                                    ▼
              EventBridge rule on "AWS Security Hub Findings - Imported"
                                    │
                     ┌──────────────┼──────────────┐
                     ▼              ▼              ▼
                 Lambda          SNS → PD       S3 archive
             (auto-remediate)  (page oncall)   (compliance)
```

### What to enable

- **GuardDuty** in every account, every active region. Delegated admin in Security account. Enable Malware Protection, EKS runtime monitoring, RDS protection, S3 protection, Lambda protection as budget permits.
- **AWS Config** in every account, every region, recording all supported resource types. Aggregator in Security account. Conformance packs: AWS CIS, HIPAA, your internal baseline.
- **Security Hub** with AWS Foundational Security Best Practices, CIS AWS Foundations, and PCI-DSS (if applicable) standards enabled.
- **IAM Access Analyzer** at the organization level, for external access findings, plus unused-access analyzers in Security account.
- **Inspector** for EC2 / ECR / Lambda vulnerability findings.
- **Macie** in accounts that hold S3 buckets with regulated data. See "Data protection" below.
- **CloudTrail** organization trail, multi-region, log file validation enabled, landing in the Logging account S3 bucket.
- **VPC Flow Logs** on every VPC, delivered to the Logging account (or Amazon S3 in log account) in Parquet where possible.

### Auto-remediation pattern

For a narrow set of high-confidence findings, automated remediation beats human response. Candidates:

| Finding | Automated action |
| --- | --- |
| S3 bucket becomes public (Config rule `s3-bucket-public-read-prohibited`) | Lambda re-applies Block Public Access and removes offending ACL/policy |
| Security Group opens 0.0.0.0/0 on sensitive ports (22, 3389, 3306, 5432, 6379) | Lambda removes the offending rule and files a ticket |
| IAM user created (org policy: no IAM users except break-glass) | Lambda disables the user's access keys and alerts |
| EC2 instance without IMDSv2 | Lambda enforces IMDSv2 via `ModifyInstanceMetadataOptions` |
| CloudTrail disabled or modified | Alert — do not auto-remediate, because disabling is sometimes legitimate during recovery; page oncall |

Auto-remediation Lambdas live in the Security account and assume cross-account roles into workload accounts. Each remediation emits an audit event so the ticket trail is intact.

### What not to auto-remediate

Anything that could break production or destroy data. No automated quarantining of EC2 instances without a human in the loop. No automated EKS pod termination. No automated KMS key deletion ever. The cost of a bad auto-remediation is higher than the cost of a 30-minute human response.

---

## Data protection

### S3

Block Public Access at the account level *and* at the bucket level. Yes, both. The account-level setting is a safety net; the bucket-level setting is a defense against "someone turned off the account setting for a migration and forgot to turn it back on." If any bucket genuinely needs to be public (marketing assets, public file sharing), put those buckets in a dedicated account with looser SCPs and no regulated data.

Bucket policy pattern for a regulated-data bucket:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnencryptedTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::phi-bucket", "arn:aws:s3:::phi-bucket/*"],
      "Condition": {"Bool": {"aws:SecureTransport": "false"}}
    },
    {
      "Sid": "DenyUnencryptedPut",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::phi-bucket/*",
      "Condition": {"StringNotEquals": {"s3:x-amz-server-side-encryption": "aws:kms"}}
    },
    {
      "Sid": "DenyWrongKmsKey",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::phi-bucket/*",
      "Condition": {
        "StringNotEqualsIfExists": {
          "s3:x-amz-server-side-encryption-aws-kms-key-id":
            "arn:aws:kms:us-east-1:111122223333:key/KEY_ID"
        }
      }
    }
  ]
}
```

Enable S3 Access Logs or S3 Server Access Logging → CloudTrail data events for buckets holding regulated data. Object-level events are not free but are forensically invaluable.

### KMS key hierarchy

Do not use a single "company key" for everything. Tier keys by data class and blast radius:

```
  ┌──── CMK: phi-data (Logging account)
  │         - Used by Logging S3 bucket (audit trail)
  │         - Key policy: only Logging S3, CloudTrail, Security account admins
  │
  ├──── CMK: phi-data (Workload account, per-environment)
  │         - Used by RDS (primary DB), S3 (document storage), EBS (EKS node vols)
  │         - Key policy: workload service roles, backup role, BYOK break-glass admin
  │
  ├──── CMK: secrets (Workload account)
  │         - Used by Secrets Manager, Parameter Store
  │         - Key policy: application roles only, NOT humans
  │
  └──── CMK: backups (Workload account)
            - Used by AWS Backup vault
            - Key policy: backup service role, DR role, read-only for compliance evidence
```

Each CMK has a key policy limiting principals explicitly. Rely on the account-level root trust statement only for operational flexibility in dev accounts; in prod, trim it.

Key rotation: annual automatic rotation on all symmetric CMKs. For asymmetric CMKs (signing, envelope encryption), rotation is manual and must be planned.

### Macie for PHI / PII discovery

If you have S3 buckets holding regulated data, run Macie against them — not continuously (that gets expensive), but on a schedule. Two goals:

1. **Coverage verification**: confirm your designated-regulated buckets contain regulated data and your designated-non-regulated buckets do not. Macie is the auditable evidence that you know where PHI lives.
2. **Drift detection**: catch when a new bucket appears with regulated content, often because an engineer ran an ad-hoc export. These should trigger an investigation, not a finding auto-close.

Configure Macie to emit findings to Security Hub; route high-severity findings (credit card data in a non-PCI bucket, SSN in a non-PHI bucket) to the security-alerts channel and create a ticket automatically.

---

## Network security

### Security Groups vs NACLs

Both exist for historical reasons; most teams get in trouble by using both for the same control.

**Security Groups** are stateful, attached to ENIs, allow-only. Use them as the primary access-control mechanism. Scope tightly: SG for the ALB allows 443 from 0.0.0.0/0; SG for app tier allows from ALB SG only; SG for data tier allows from app tier SG only.

**Network ACLs** are stateless, attached to subnets, allow and deny. Use them sparingly, for blast-radius containment that SGs cannot express: "nothing in the data subnet can initiate outbound traffic to the internet." Do not try to enumerate application-port rules in NACLs; you will burn out and leave them permissive.

Rule of thumb: Security Groups are how you grant access. NACLs are how you constrain a whole subnet. If you feel yourself adding a rule to both, you are probably adding it in the wrong place.

### VPC endpoints for AWS services

Interface endpoints (PrivateLink) and Gateway endpoints (S3, DynamoDB) keep traffic to AWS services off the public internet. For a regulated workload, treat VPC endpoints as a compliance control, not a performance optimization:

- **Gateway endpoints**: `s3`, `dynamodb`. Free. Add a bucket policy condition on `aws:sourceVpce` to the regulated buckets so even a leaked credential cannot reach the bucket from outside your VPC.
- **Interface endpoints**: `sts`, `kms`, `secretsmanager`, `ssm`, `ssmmessages`, `ec2messages`, `logs`, `monitoring`, `ecr.api`, `ecr.dkr`, `sns`, `sqs`, `eventbridge`. Billed per hour + per GB. Add them in the workload VPC; route to them via Route 53 private hosted zones managed by AWS.

For multi-account efficiency, create interface endpoints in the Shared Services VPC and consume them across workload VPCs via PrivateLink + TGW. This is more expensive to set up once and cheaper at scale.

### PrivateLink for third-party services

When your workload calls a third-party SaaS (Snowflake, Databricks, a vendor LLM), prefer PrivateLink over public-internet egress. Benefits:

- Traffic does not traverse the public internet
- The destination is a private DNS name resolvable only from your VPC
- You can require that specific SGs have access via endpoint policies
- Reduces NAT Gateway egress costs at scale

The downside is setup effort and the vendor needing to support PrivateLink. For regulated workloads, this is nearly always worth it.

### Egress inspection

For workloads with a strong egress story (e.g., must not exfiltrate to arbitrary internet destinations), run AWS Network Firewall or a Gateway Load Balancer in front of the NAT Gateway, with a domain allowlist. This catches:

- Compromised instances beaconing to attacker-controlled domains
- Accidental calls to unapproved SaaS (data leakage)
- Unknown dependencies that appear after a deploy

For workloads where this level of control is overkill, skip it. The infrastructure and operational cost is real; do not adopt because someone else has it.

---

## Identity

Three mechanisms compose:

1. **SCPs** — organizational guardrails; the outer deny-list. See [scp-guardrails.json](./scp-guardrails.json) and [iam-least-privilege.md](./iam-least-privilege.md).
2. **Permission Boundaries** — developer self-service with a ceiling.
3. **IAM roles** — the actual grants.

### IAM Identity Center as the human access path

Do not use IAM users for humans. Ever. Hard rule. Every human accesses AWS via IAM Identity Center (formerly AWS SSO), federated from your IdP (Okta, Entra ID, Google Workspace). Permission sets replace per-account IAM users.

Benefits that add up:

- One-click offboarding (remove user from IdP; all AWS access disappears)
- MFA enforced at the IdP
- Session duration configurable, short by default
- Audit trail lives in your IdP (and CloudTrail)

Break-glass: one IAM user per account with a long, random password stored in a physical safe, MFA on a hardware token in the same safe, and a CloudTrail alarm on any use of that user. Never use it; rotate it annually.

### Roles vs users

For workloads: IAM roles, not users. Every service principal (EC2, EKS pod, Lambda, ECS task) uses an IAM role. IAM users for machines are an anti-pattern — they produce long-lived access keys that will leak eventually.

If you find IAM users with access keys in your org, run an inventory, tag them, and prioritize migration to roles (IRSA for EKS, task roles for ECS, instance profiles for EC2, execution roles for Lambda).

### Cross-account access

```
     Workload account                      Security account
     ┌──────────────────┐               ┌──────────────────┐
     │                  │               │                  │
     │  IAM role:       │◄── AssumeRole │  IAM role:       │
     │  SecurityAuditor │               │  CrossAcctAudit  │
     │  (trust: Sec     │               │  (Lambda/Human)  │
     │   account role)  │               │                  │
     │                  │               │                  │
     └──────────────────┘               └──────────────────┘
```

The trust policy in the workload account names the specific role in the Security account, not the whole account. If you name the account, any role in the Security account can assume; if you name a role, only that role can.

Add `ExternalId` when the caller is a third party (vendor, consultant, cross-org); skip it when both sides are inside your org.

---

## Adoption order

If you are starting from nothing:

1. **Week 1**: AWS Organizations, Security + Logging accounts, Org CloudTrail to Logging S3 with Object Lock. Apply `scp-guardrails.json` to the non-prod OU first, observe for a week, then roll to prod OU.
2. **Week 2**: GuardDuty + Security Hub + Config, delegated to Security account. IAM Identity Center set up, humans onboarded, first permission set live.
3. **Week 3–4**: Workload account VPC redesign if needed (split to public/private/data tiers, add VPC endpoints). S3 Block Public Access everywhere. KMS CMK for RDS and critical S3.
4. **Month 2**: Macie scans of regulated buckets. Inspector on EC2/ECR. First auto-remediation Lambdas (S3 public, SG wide-open).
5. **Month 3**: IAM right-sizing pass (see [iam-least-privilege.md](./iam-least-privilege.md)). Access Analyzer external findings to zero. Permission Boundary for developer roles.
6. **Month 4+**: PrivateLink for third-party dependencies, egress inspection if applicable, CMK tier refinement, KMS key policy tightening.

Any shorter than this and you will ship broken. Any longer than this and the incident that justifies the program will arrive first.

---

## Compliance mapping

| Framework | Control | Where satisfied |
| --- | --- | --- |
| HIPAA §164.312(a)(1) | Access control | IAM Identity Center, IAM roles, SCPs |
| HIPAA §164.312(b) | Audit controls | CloudTrail org trail, Config, GuardDuty, Security Hub |
| HIPAA §164.312(c)(1) | Integrity | CloudTrail log file validation, S3 Object Lock on Logging bucket |
| HIPAA §164.312(e)(1) | Transmission security | TLS everywhere (ALB with ACM certs, RDS in-transit encryption), VPC endpoints |
| SOC 2 CC6.1 | Logical access | IAM + SCPs + Permission Boundaries |
| SOC 2 CC6.6 | Boundary protection | Security Groups, NACLs, VPC endpoints, Network Firewall |
| SOC 2 CC7.1, CC7.2 | Detection and monitoring | GuardDuty → Security Hub → EventBridge auto-remediation |
| PCI-DSS 10.x | Logging and monitoring | CloudTrail + VPC Flow Logs + ALB logs in immutable Logging S3 |
| NIST CSF 2.0 PR.AC, DE.CM, RS.MI | Identity, monitoring, response | Covered across the stack |

---

## Further reading

- [AWS Security Reference Architecture (AWS SRA)](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/) — the canonical AWS document this section borrows structure from.
- [AWS Well-Architected Framework — Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- CIS AWS Foundations Benchmark — enable as a Security Hub standard; treat as a posture-management baseline, not a complete control set.
- This repo: [iam-least-privilege.md](./iam-least-privilege.md) for the IAM half, [../../architecture-patterns/zero-trust-saas.md](../../architecture-patterns/zero-trust-saas.md) for the broader identity-first story.
