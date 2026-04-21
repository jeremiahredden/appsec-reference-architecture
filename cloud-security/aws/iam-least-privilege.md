# AWS IAM Least Privilege — A Practical Guide

Least privilege in theory: grant only the permissions a principal needs to do its job. Least privilege in practice: a three-part mechanical exercise you run continuously, not a one-time architectural decision. This document is how I do it.

## The IAM policy evaluation logic

Before right-sizing anything, you need to be able to read the outcome. The evaluation logic is small but unforgiving.

For a request to be allowed, **all** of the following must be true:

1. There is no applicable **explicit deny** — in any identity policy, resource policy, SCP, Permission Boundary, or session policy.
2. There is at least one applicable **explicit allow** — somewhere in identity policies, resource policies, or (for cross-account) both.
3. The request satisfies all applicable **Permission Boundary** and **SCP** constraints (both must separately allow).

The decision tree in order:

```
    Start
      │
      ▼
   ┌──────────────────────────────────┐
   │ Any explicit Deny applicable?    │── yes ──► DENY (final)
   └──────────────────────────────────┘
      │ no
      ▼
   ┌──────────────────────────────────┐
   │ SCP in the account's path allows?│── no  ──► DENY
   └──────────────────────────────────┘
      │ yes
      ▼
   ┌──────────────────────────────────┐
   │ Permission Boundary (if any)     │── no  ──► DENY
   │ on this principal allows?        │
   └──────────────────────────────────┘
      │ yes
      ▼
   ┌──────────────────────────────────┐
   │ Identity-based or resource-based │── no  ──► DENY (implicit)
   │ allow?                           │
   └──────────────────────────────────┘
      │ yes
      ▼
     ALLOW
```

Two mental models this enforces:

- **SCPs and Permission Boundaries do not grant anything.** They cap. An IAM role with no identity policy plus the broadest Permission Boundary in the world is still denied — there is no allow.
- **Explicit deny always wins.** A deny in an SCP cannot be overridden by adding an identity allow. This is why SCPs are the right place for organizational guardrails: they cannot be unset by a workload engineer.

If you remember only these two things when reading IAM, you will avoid most of the common misreads.

## Right-sizing existing permissions

The common failure mode is overly broad policies (`s3:*`, `Resource: "*"`) applied to service roles because at the time of writing, the engineer did not know exactly which actions were needed. The right-sizing process converts that into specifics.

### Step 1 — CloudTrail as ground truth

CloudTrail records every API call. The simplest right-sizing technique is:

1. Choose a role to right-size.
2. Pull CloudTrail events for that role over the last 90 days (or one full business cycle — month-end-close if relevant).
3. Enumerate the distinct `eventSource` + `eventName` combinations.
4. Write a policy that allows exactly those actions on exactly the observed resources.
5. Deploy to a staging copy of the role; run workload; iterate.

Query template for Athena over CloudTrail in S3:

```sql
SELECT DISTINCT
    eventSource,
    eventName,
    count(*) AS call_count
FROM cloudtrail_logs
WHERE userIdentity.sessionContext.sessionIssuer.userName = 'RoleNameHere'
  AND eventTime >= current_timestamp - INTERVAL '90' DAY
  AND errorCode IS NULL
GROUP BY 1, 2
ORDER BY call_count DESC;
```

Two gotchas:

- **Dormant actions are invisible in CloudTrail.** If the role has a permission it has not used in 90 days, you have no evidence it needs it. This is fine for the trim pass, but monitor for usage after trimming so you catch the month-end job you missed.
- **Read-only actions can hide required list-before-write sequences.** A role that writes to S3 likely also calls `ListBucket`. Capture the full call sequence, not just the headline action.

### Step 2 — IAM Access Analyzer policy generation

IAM Access Analyzer has a `generate-policy` feature that does the CloudTrail analysis for you. Use it as a starting point:

```bash
aws accessanalyzer start-policy-generation \
  --policy-generation-details principalArn=arn:aws:iam::111111111111:role/AppRole \
  --cloud-trail-details accessRole=arn:aws:iam::111111111111:role/AccessAnalyzerTrail,trails=[{cloudTrailArn=arn:aws:cloudtrail:...,regions=[us-east-1]}],startTime=2026-01-01T00:00:00Z
```

The generated policy will likely list more actions than you need (every action the role *used*, not every action the role *needs for its job*) and will name specific resources. Treat it as a draft: delete anything that looks accidental (one-off manual runs), confirm the resource ARNs are the right level of specificity (bucket vs object level).

### Step 3 — Unused-access findings

Access Analyzer's "unused access" feature flags:

- Roles that have not been used in N days
- Users with credentials (access keys, passwords) not rotated in N days
- Permissions granted but not exercised

Run this monthly in the Security account. Each finding is either a role to remove, a permission to trim, or a documented exception. No category should silently accumulate.

## Permission Boundaries

### What they are

A Permission Boundary is a managed policy attached to a principal that caps its maximum permissions, regardless of what identity policies also attached to that principal say. The resulting permission is the **intersection** of identity policy and boundary.

```
     Identity policy (what you CAN do)        Boundary (what you MAY do)
          ┌─────────────────────┐                 ┌──────────────────────┐
          │  s3:*  ec2:*  iam:* │                 │  s3:Get*  s3:Put*    │
          └─────────────────────┘                 │  ec2:Describe*       │
                                                  └──────────────────────┘
                               │
                               ▼  (intersection)
                      ┌─────────────────────┐
                      │  s3:Get*  s3:Put*   │   ← effective permissions
                      │  (ec2:* denied; no  │
                      │   ec2 in boundary)  │
                      └─────────────────────┘
```

### When to use them

Permission Boundaries solve one specific problem: **delegating IAM to developers safely**.

Imagine you want to let engineers create IAM roles for their Lambdas without having to review every PR. Without a boundary, an engineer could create a role with `AdministratorAccess`. With a boundary, you require the creation to include `PermissionsBoundary: DevRoleBoundary` — now the developer can grant whatever identity policy they want, but the resulting role is capped.

Concretely: if you are using Terraform or CDK and engineers are shipping IAM changes without security review on every PR, you need Permission Boundaries.

### Annotated example

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowServiceAccessCommon",
      "Effect": "Allow",
      "Action": [
        "logs:*",
        "cloudwatch:PutMetricData",
        "cloudwatch:GetMetricData",
        "xray:PutTraceSegments",
        "xray:PutTelemetryRecords"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowS3OnAppBucketsOnly",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::app-*",
        "arn:aws:s3:::app-*/*"
      ]
    },
    {
      "Sid": "AllowDynamoOnAppTables",
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:DeleteItem",
        "dynamodb:Query",
        "dynamodb:BatchGetItem",
        "dynamodb:BatchWriteItem"
      ],
      "Resource": "arn:aws:dynamodb:*:*:table/app-*"
    },
    {
      "Sid": "AllowSecretsInApp",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:*:*:secret:app/*"
    },
    {
      "Sid": "DenyIAMWriteEscalation",
      "Effect": "Deny",
      "Action": [
        "iam:CreateUser",
        "iam:AttachUserPolicy",
        "iam:PutUserPolicy",
        "iam:CreateAccessKey",
        "iam:DeleteAccountPasswordPolicy",
        "iam:UpdateAssumeRolePolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyDestructiveGlobal",
      "Effect": "Deny",
      "Action": [
        "organizations:*",
        "account:*",
        "aws-marketplace:*",
        "kms:ScheduleKeyDeletion",
        "kms:DisableKey"
      ],
      "Resource": "*"
    }
  ]
}
```

Four things this policy does:

1. **Allow the common cross-cutting permissions** (logs, metrics, tracing) that every role needs without thinking about it.
2. **Allow data-plane access** to app-prefixed resources only. An engineer cannot accidentally grant access to the security account's `security-audit-*` bucket.
3. **Deny IAM escalation explicitly.** An engineer cannot create a role that can create users, attach AdministratorAccess, or modify trust policies.
4. **Deny destructive organizational and KMS operations.** Even if an identity policy permits them, the boundary blocks.

Pair this with an SCP requiring the boundary on all IAM role creations:

```json
{
  "Sid": "RequireBoundaryOnIAMRoles",
  "Effect": "Deny",
  "Action": ["iam:CreateRole", "iam:PutRolePolicy", "iam:AttachRolePolicy"],
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "iam:PermissionsBoundary":
        "arn:aws:iam::*:policy/DevRoleBoundary"
    }
  }
}
```

Now developers have self-service for IAM, and the organization has a safety net.

## Service Control Policies — the 10 that matter

SCPs are organization-wide guardrails. They do not grant; they deny. Ten SCPs that every regulated organization should have. See [scp-guardrails.json](./scp-guardrails.json) for a deployable subset of five; the rest are below.

The exact JSON for each is included — copy into AWS Organizations, attach to the appropriate OU (usually: test on non-prod OU, roll to prod OU after 1 week with no false-positive fires).

### 1. Deny root account usage

Root credentials should be stored in a safe. Any use is suspicious.

```json
{
  "Sid": "DenyRootUser",
  "Effect": "Deny",
  "Action": "*",
  "Resource": "*",
  "Condition": {
    "StringLike": {"aws:PrincipalArn": "arn:aws:iam::*:root"}
  }
}
```

Note: applying this to a management account's own SCP is risky (you can lock yourself out). Apply to workload OUs, not the management account's own OU. Keep the management account quiet and root unused through process, not SCP self-targeting.

### 2. Require MFA for IAM user console access

Relevant mainly for break-glass users (humans use Identity Center).

```json
{
  "Sid": "RequireMFAForConsole",
  "Effect": "Deny",
  "NotAction": [
    "iam:CreateVirtualMFADevice",
    "iam:EnableMFADevice",
    "iam:GetUser",
    "iam:ListMFADevices",
    "iam:ListVirtualMFADevices",
    "iam:ResyncMFADevice",
    "sts:GetSessionToken"
  ],
  "Resource": "*",
  "Condition": {
    "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"},
    "Null": {"aws:MultiFactorAuthPresent": "false"}
  }
}
```

### 3. Restrict to approved regions

Every unused region is attack surface. If you operate in `us-east-1` and `eu-west-1`, deny everything else. Common mistake: forgetting that IAM, CloudFront, Route 53, and some Support APIs are effectively global (`us-east-1`). Exempt those services:

```json
{
  "Sid": "DenyRegionsOutsideApproved",
  "Effect": "Deny",
  "NotAction": [
    "iam:*", "route53:*", "cloudfront:*", "waf:*", "wafv2:*",
    "support:*", "organizations:*", "sts:*", "budgets:*",
    "globalaccelerator:*", "aws-portal:*"
  ],
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {"aws:RequestedRegion": ["us-east-1", "eu-west-1"]}
  }
}
```

### 4. Prevent disabling CloudTrail

```json
{
  "Sid": "ProtectCloudTrail",
  "Effect": "Deny",
  "Action": [
    "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail",
    "cloudtrail:UpdateTrail",
    "cloudtrail:PutEventSelectors"
  ],
  "Resource": "arn:aws:cloudtrail:*:*:trail/org-trail"
}
```

Replace `org-trail` with your organization trail name. Note this protects the org trail specifically; account-level trails may legitimately be updated by the account owner.

### 5. Require IMDSv2 on all EC2 instances

IMDSv2 mitigates SSRF-based credential theft from the instance metadata service. It has been the default on new AMIs for a while but is not retroactive.

```json
{
  "Sid": "RequireIMDSv2",
  "Effect": "Deny",
  "Action": "ec2:RunInstances",
  "Resource": "arn:aws:ec2:*:*:instance/*",
  "Condition": {
    "StringNotEquals": {"ec2:MetadataHttpTokens": "required"}
  }
}
```

### 6. Prevent public S3 buckets

```json
{
  "Sid": "DenyS3PublicAclAndPolicy",
  "Effect": "Deny",
  "Action": [
    "s3:PutBucketAcl",
    "s3:PutObjectAcl",
    "s3:PutBucketPolicy",
    "s3:PutBucketPublicAccessBlock",
    "s3:DeleteBucketPolicy"
  ],
  "Resource": "*",
  "Condition": {
    "StringEquals": {"s3:x-amz-acl": ["public-read", "public-read-write", "authenticated-read"]}
  }
}
```

Pair with account-level S3 Block Public Access enforced by a Config rule. The SCP blocks the ACL-setting call; Block Public Access prevents public policies.

### 7. Prevent public EBS snapshots

```json
{
  "Sid": "DenyPublicEBSSnapshot",
  "Effect": "Deny",
  "Action": "ec2:ModifySnapshotAttribute",
  "Resource": "*",
  "Condition": {
    "StringEquals": {"ec2:CreateVolumePermission": "all"}
  }
}
```

### 8. Restrict EC2 instance types (optional, cost + blast-radius)

Prevents engineers from launching a `x1e.32xlarge` on accident.

```json
{
  "Sid": "LimitEC2InstanceTypes",
  "Effect": "Deny",
  "Action": "ec2:RunInstances",
  "Resource": "arn:aws:ec2:*:*:instance/*",
  "Condition": {
    "StringNotLike": {
      "ec2:InstanceType": [
        "t3.*", "t4g.*", "m6i.large", "m6i.xlarge", "m6i.2xlarge",
        "c6i.large", "c6i.xlarge", "r6i.large", "r6i.xlarge"
      ]
    }
  }
}
```

Adjust the allowlist to your workload. This is more cost-hygiene than security, but it prevents a specific class of compromised-credential abuse (cryptominers launching the biggest instances they can).

### 9. Require resource tagging at creation

For chargeback, inventory, and IR scope.

```json
{
  "Sid": "RequireCostCenterTag",
  "Effect": "Deny",
  "Action": [
    "ec2:RunInstances",
    "rds:CreateDBInstance",
    "s3:CreateBucket"
  ],
  "Resource": "*",
  "Condition": {
    "Null": {"aws:RequestTag/CostCenter": "true"}
  }
}
```

Harder to retrofit; easier to adopt at the beginning.

### 10. Deny leaving AWS Organizations

A compromised member account can try to leave the org to escape SCPs.

```json
{
  "Sid": "DenyLeaveOrganizations",
  "Effect": "Deny",
  "Action": [
    "organizations:LeaveOrganization"
  ],
  "Resource": "*"
}
```

Attached to every member OU.

## Cross-account role patterns

Cross-account access is how services in one account reach resources in another. Two common patterns, each with its own trust-policy shape.

### Pattern A — SecOps reads across the org

Every workload account has an audit role that SecOps can assume from the Security account.

**Workload account role trust policy:**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::SEC_ACCT_ID:role/SecurityAuditor"
    },
    "Action": "sts:AssumeRole"
  }]
}
```

**Workload account role permission policy**: read-only — `ReadOnlyAccess` or a tighter custom managed policy.

Humans in the Security account assume `SecurityAuditor`, which can then assume-into the workload roles. This is the cleanest audit trail: one CloudTrail entry in the Security account (human → auditor) and one in the workload account (auditor → target role).

### Pattern B — Workload calls another workload

Service in Account A needs to write to an SQS queue in Account B. Two equivalent patterns:

- **Resource-based policy on the queue in B** that allows the role in A. No cross-account role assumption; the write call goes through directly.
- **Cross-account role** in B that A assumes before writing.

Prefer resource-based policies for simple data-plane integrations; fewer moving parts. Use a cross-account role when the target service does not support resource-based policies, or when you want the permissions scoped to a short STS session.

### Pattern C — Third-party vendor integration

A vendor needs access to your account for scanning, observability, cost management.

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::VENDOR_ACCT_ID:role/VendorWorker"
    },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {
        "sts:ExternalId": "your-uniquely-generated-external-id-here"
      }
    }
  }]
}
```

**The `ExternalId` is required for all third-party trusts.** It prevents the confused-deputy problem where a misconfigured vendor lets one customer's role assume into another customer's target. Generate a unique one per tenant (the vendor usually handles this) and store it in the trust policy.

## Anti-patterns to remove on sight

If you see any of these, fix them first:

| Anti-pattern | Why it's bad | What to do instead |
| --- | --- | --- |
| IAM users with access keys for workload services | Keys leak; no rotation; inventory decays | IAM roles; IRSA for EKS, task roles for ECS, instance profiles for EC2 |
| `Action: "*", Resource: "*"` on a workload role | No evidence this is needed; any compromise is total | Right-size with CloudTrail + Access Analyzer |
| `iam:PassRole` with `Resource: "*"` | Privilege escalation primitive | Scope PassRole to specific role ARNs the caller legitimately needs |
| Wildcarded trust policies (`"Principal": "*"` with no condition) | Anyone in any account can assume | Specific principal ARN or `aws:PrincipalOrgID` condition |
| Long-lived access keys (age > 90 days) | Rotation hygiene failure; one of the most common root causes in real incidents | Rotate; migrate to roles; alert on age |
| Shared IAM users for a team | Unattributable actions | One user per human, or better, Identity Center |
| Break-glass user with MFA token on the same laptop | Defeats the purpose | MFA on hardware token in a physical safe, separated from the password |
| `AdministratorAccess` on a CI/CD role | Any pipeline compromise is total | Tight custom policy; document every added permission in the PR |
| Inline policies everywhere | No reuse, no auditability | Managed policies with versioning; inline only for genuinely one-off cases |

## The measurement

Least privilege is not a destination; it is a metric that decays if you stop measuring. Track monthly:

- **Unused roles** (> 90 days no use)
- **Unused permissions** (in Access Analyzer unused-access findings)
- **Roles without a Permission Boundary** (for OUs where boundary is required)
- **Access keys older than 90 days**
- **IAM users created outside of a documented break-glass exception**
- **External access findings** from Access Analyzer (should trend to zero)

Put these in a dashboard. Show them to leadership. A rising trend is the signal that IAM hygiene has fallen off the priority list.

## Further reading

- [AWS IAM documentation — Policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [IAM Access Analyzer — Generate policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-generation.html)
- [AWS Organizations — SCPs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- [scp-guardrails.json](./scp-guardrails.json) in this folder — deployable SCP set
- [security-reference-architecture.md](./security-reference-architecture.md) — the architecture this IAM work sits inside
