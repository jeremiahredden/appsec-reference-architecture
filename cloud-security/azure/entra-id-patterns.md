# Entra ID Security Patterns

Entra ID (formerly Azure AD) is the identity system at the center of nearly every Microsoft-shop security architecture. This document is the set of patterns I want in place at any organization taking identity seriously — not a catalog of every feature, but the ones that move the needle.

## Conditional Access — the baseline policy set

Conditional Access (CA) is how Entra enforces runtime decisions at sign-in: *given who the user is, what they are doing, and where they are coming from, should this sign-in succeed?* The engine evaluates a set of policies on every sign-in. Any policy that blocks, blocks.

A small, well-designed CA policy set does more for your security posture than almost any other Azure control. A sprawling, incoherent CA policy set does the opposite: it fails open because admins punch holes to keep things working.

### The six policies every organization needs

Policy naming convention here: `CA00N-Description-TargetAudience-Effect`. Numbering helps with troubleshooting ("which policy blocked me?") and evaluation order reasoning.

#### CA001 — Require MFA for all users

```
Name:         CA001-Require-MFA-AllUsers
Assignments:
  Users:      All users
  Exclude:    Break-glass accounts (2), Service principals (none — these use CA
              workload identity policies)
  Cloud apps: All cloud apps
Conditions:   None (this is the baseline; no conditions make it universal)
Grant:        Require multifactor authentication
Session:      -
State:        On (after rollout)
```

This is the non-negotiable baseline. Exclusions:

- **Break-glass accounts**: two of them, named `brk-glass-01@tenant.onmicrosoft.com` and `brk-glass-02@...`, with long randomly-generated passwords stored in a physical safe along with the FIDO2 hardware tokens for MFA. These accounts are excluded from CA (because CA itself could lock them out during an IdP incident), never used day-to-day, and alerted on any sign-in.
- **Service principals**: never excluded from CA in the same policy as users. Use workload identity CA (separate policy type) if you need to condition on service-principal sign-ins.

#### CA002 — Block legacy authentication

```
Name:         CA002-Block-Legacy-Auth-AllUsers
Assignments:
  Users:      All users
  Exclude:    Break-glass
  Cloud apps: All cloud apps
Conditions:
  Client apps: Exchange ActiveSync clients, Other clients (legacy protocols like
               POP, IMAP, SMTP, older Office clients without modern auth)
Grant:        Block access
State:        On
```

Legacy authentication protocols do not support MFA. An attacker who finds a password will try IMAP before they try Microsoft 365 web. This policy closes that door.

Before enabling: run a sign-in log query for 30 days filtering on legacy client apps, make sure no legitimate system is still using them. Common remediations: migrate a scanner from SMTP basic auth to Graph API, update an old Outlook version, replace a hardcoded password in a mail-sending script with a service principal + cert.

#### CA003 — Block risky sign-ins

```
Name:         CA003-Block-HighRisk-Signins-AllUsers
Assignments:
  Users:      All users
  Exclude:    Break-glass
  Cloud apps: All cloud apps
Conditions:
  Sign-in risk: High
Grant:        Block access
State:        On
```

Entra's Identity Protection machine learning assigns sign-in risk scores based on anomalous IP addresses, impossible travel, infected devices, leaked credential feeds, anonymizers. High-risk sign-ins are rare and usually correct — block them outright.

Pair with:

- **CA004 — Medium risk requires MFA + password change**: if the risk is medium, require MFA and prompt for password change (the `User action: Password change` control).

#### CA005 — Require compliant device for admin access

```
Name:         CA005-RequireCompliantDevice-Admins
Assignments:
  Users:      Role: Global Administrator, Security Administrator,
              Privileged Role Administrator, Exchange Administrator,
              SharePoint Administrator, Conditional Access Administrator,
              (and your internal workload-admin groups)
  Cloud apps: All cloud apps (OR scope to Azure Management if desired)
Conditions:   -
Grant:        Require device to be marked as compliant (Intune-managed)
              OR Require Hybrid Azure AD joined device
State:        On
```

Administrative work from a personal laptop is an attacker's entry point. This policy forces admin work to happen from a managed device where you can enforce disk encryption, screen lock, up-to-date patches, and EDR.

#### CA006 — Require MFA for Azure management

```
Name:         CA006-RequireMFA-AzureMgmt-AllUsers
Assignments:
  Users:      All users
  Exclude:    Break-glass
  Cloud apps: Microsoft Azure Management
Conditions:   -
Grant:        Require multifactor authentication
              AND Require device to be marked as compliant (Prod admins only)
State:        On
```

Even if your baseline CA001 already requires MFA for all apps, having a policy specifically scoped to Azure Management makes the audit conversation trivial and protects against any future loosening of the baseline.

### Policies to add once the baseline is solid

- **Block sign-ins from non-approved countries.** Named Location list of approved countries → block access from elsewhere. Consider carefully: travel, remote employees, vendors. Useful for a tightly geographically-scoped workforce; noisy for global organizations.
- **Require session re-authentication every 4–12 hours for high-risk apps.** `Session controls → Sign-in frequency`. Trade-off between security and friction; pick a window based on the app's sensitivity.
- **Block copy/paste and downloads in web session for contractors accessing sensitive apps.** `Session controls → Use app-enforced restrictions` with Microsoft 365 Cloud App Security.

### CA design principles

- **Exclusion groups are a trap.** Every time you exclude someone from a CA policy, you accumulate technical debt. Over time, exclusions multiply and the policy becomes toothless. Review exclusions quarterly.
- **Report-only mode before Enabled.** Every new policy spends at least a week in Report-only mode. Check the sign-in logs for policies that would have blocked legitimate users. Adjust.
- **Test each policy in isolation.** When a policy blocks a legitimate user, the sign-in log tells you exactly which policy fired. Don't let multiple overlapping policies make the diagnosis harder than it needs to be.
- **Policies compose as AND, not OR, at the Grant stage.** If policy A says "require MFA" and policy B says "require compliant device," both must be satisfied. Users will not always understand this; document it in the runbook.

## Named locations and trusted IP ranges

Named Locations let CA policies condition on IP ranges or countries. Two use cases that work, one that doesn't.

### Good use — excluding corporate IPs from MFA prompts

For some organizations, requiring MFA every time a user at the corporate office accesses a low-sensitivity app is too much friction. Mark the corporate egress IP range as a Named Location with `Mark as trusted`, then in CA have a policy like "require MFA for all sign-ins **not** from trusted locations."

Caveats:

- Only applies to low-sensitivity apps. Admin access, sensitive data apps, Azure management → always MFA regardless of location.
- Only useful if your corporate IP range is stable. WFH breaks this. Most organizations no longer have a meaningful "office IP."

### Good use — blocking traffic from hostile countries

If your business operates in the US and EU, there is no legitimate reason for a sign-in from North Korea. Named Location → `Countries / regions` → block.

Apply with care: travel, vendors, contractors. Use `Block` selectively; combine with exclusions for specific groups who travel.

### Bad use — trusting IP as a primary access control

"Users from this IP are trusted, others are not" is a VPN-era idea. In cloud, IPs are owned by the attacker within the hour. Don't rely on IP allowlisting as the primary control. IP ranges are a signal, not a perimeter. Combine them with identity, device, and risk signals — never alone.

## Privileged Identity Management

PIM converts standing privileged access into just-in-time activation. Done right, it eliminates the perpetually-online Global Administrator.

### The model

```
  User assigned as "Eligible" to a role
                │
                │ when needed, user activates
                ▼
  PIM activation flow:
    - MFA re-challenge
    - Justification text
    - Optional approval from a peer/manager
    - Maximum activation duration (e.g., 8 hours)
                │
                ▼
  User holds the role for the activation window
                │
                ▼
  Role assignment auto-expires
```

Benefits:

- **Standing privilege is effectively zero** — a stolen credential for a Global Admin-eligible user is not itself a Global Admin credential; the attacker still needs to pass MFA and (often) an approval.
- **Every activation is logged** — auditable answer to "who had admin at the time of the incident?"
- **Access reviews are enforced** — PIM integrates with access reviews that periodically prompt approvers to re-confirm or revoke eligibility.

### What to PIM

Tier by risk:

| Role | PIM treatment |
| --- | --- |
| Global Administrator | Eligible only. MFA + approval + 2-hour max duration. 2 approvers. Alert on every activation. |
| Privileged Role Administrator | Eligible only. MFA + approval + 2-hour max. |
| Security Administrator, Conditional Access Administrator | Eligible only. MFA + justification + 4-hour max. |
| Exchange / SharePoint / Teams Administrator | Eligible only. MFA + justification + 8-hour max. |
| Subscription Owner / Contributor on Prod | Eligible only (PIM for Azure Resources). MFA + approval for Prod. |
| Workload admins | Standing Reader + PIM-eligible Contributor for day-to-day; Owner never standing. |

### Activation approval workflow

For the highest-privilege roles, require peer or manager approval. The approver is another PIM-eligible user in the same or higher tier. Approval text should include business context ("responding to incident INC-5521, need to rotate a compromised service principal secret"). The approval + activation pair creates the audit record a post-incident review needs.

### Anti-patterns

- **PIM-eligible but MFA not required.** PIM without MFA is not PIM; it is just a calendar reminder. Always require MFA on activation, even if CA already required MFA at sign-in (the activation MFA is a separate challenge against a potentially-older-MFA-claim).
- **All engineers PIM-eligible for Global Admin "in case."** No. A very small number of people should be eligible; the rest get lower roles.
- **Infinite activation duration.** A 30-day PIM activation is not PIM; it is standing access with more steps. Cap at 8 hours for most roles, shorter for the sensitive ones.

## Workload Identity / Managed Identity

Service principals with passwords or client secrets are an anti-pattern. Here is why and what to do instead.

### The problem with service principal secrets

A service principal with a client secret is, functionally, an API key. It is:

- **Long-lived**: typical expiry 1–2 years. Real-world observation: many are set to "never expire" and then forgotten.
- **Portable**: once the secret leaves the Key Vault (into a config file, a CI/CD variable, an engineer's terminal), it can be copied anywhere.
- **Hard to rotate**: requires coordinating across every consumer. Teams defer.
- **Audit-thin**: the audit log tells you the service principal signed in, not which process held the secret.

Every leaked-secret incident I have been part of (and it is a long list) involved a service principal secret in the wrong place — checked into git, dropped into a shared Slack channel, baked into a container image, printed in a CI log.

### Managed Identity

Managed Identity (part of Workload Identity Federation in Entra) attaches an Entra identity directly to an Azure resource — a VM, AKS pod, Function App, App Service, Container App, Logic App. The Azure platform gives the identity short-lived tokens automatically. There is no secret.

```
  Azure VM (with system-assigned Managed Identity)
        │
        │ IMDS (169.254.169.254) request for a token
        ▼
  Entra ID issues short-lived token for identity
        │
        ▼
  VM uses token to call Azure APIs (Key Vault, Storage, SQL)
```

No secret ever exists in the VM. The identity cannot be copied out. Rotation is implicit.

### Migration pattern

For an existing workload using a service principal with a secret:

1. **Inventory**: list all Azure resources authenticating to other Azure services (Key Vault, Storage, SQL, Service Bus, etc.).
2. **Enable Managed Identity** on each resource (system-assigned, or user-assigned if the identity needs to be reused across resources).
3. **Grant the Managed Identity the same roles** the service principal had (on the target resources).
4. **Update code** to use `DefaultAzureCredential` (Azure SDK) — this picks up Managed Identity automatically when running in Azure.
5. **Remove the service principal's role assignments**, then delete the service principal.
6. **Verify** by checking sign-in logs for any remaining activity from the old service principal.

Managed Identity does not cover every scenario — cross-tenant, on-prem systems, third-party integrations. For those, use **Workload Identity Federation with federated credentials** (GitHub Actions OIDC → Entra, AWS → Entra, etc.) instead of a stored secret.

## Cross-tenant access and B2B

External collaboration is inevitable — partners, vendors, contractors. Entra handles external users through B2B and B2C flows; the security decisions are in the settings.

### Cross-tenant access settings

Entra has explicit settings for each external tenant you collaborate with:

- **Outbound access**: can your users access the external tenant? Which apps? Which users?
- **Inbound access**: can external users from that tenant access your tenant? Which apps?
- **Trust settings**: do you trust MFA and device claims from the other tenant? (By default, no — which means external users re-do MFA in your tenant.)

Defaults to adjust:

- **Trust external MFA claims** for tenants you closely partner with (reduces user friction; requires trust in the partner's MFA hygiene). For vendors you barely know, leave it off.
- **Allow guest self-service sign-up** — off unless you have a genuine reason.
- **Default outbound block on all tenants**, explicit allow on known partner tenants. Prevents users from accidentally creating guest relationships in random tenants.

### B2B guest account hygiene

Guest accounts accumulate like email CC lists. Controls:

- **Access reviews** on guest access to any sensitive app. Quarterly at minimum.
- **Guest user restriction**: guests can see only the objects they are explicitly shared with (setting: `Guest user access restrictions = most restricted`).
- **Named Locations** excluding guest-user-typical source countries from sensitive apps.
- **Conditional Access policies targeting guests explicitly** — the baseline user CA policies apply, but add extras (e.g., require MFA always for guests, block guest access to specific highly sensitive apps).

### External collaboration risks — what actually goes wrong

- **A partner's compromised account pivots into your tenant**. The partner's MFA was bypassed via an attacker-in-the-middle; the guest account now has access to a SharePoint site with sensitive data. Mitigation: do not trust external MFA blindly; apply device compliance requirements to guest access to sensitive apps.
- **A former contractor's guest account remains active for years**. Access reviews are how you catch this.
- **A poorly-configured guest-invite process lets anyone with an email be invited**. Restrict guest-invite permission to specific roles; require admin approval for inviting users from external tenants.

## App registration security

App registrations are the Entra abstraction for "an application that authenticates users or accesses APIs." Every OAuth/OIDC integration goes through one. They are a common misconfiguration vector.

### Redirect URI hygiene

A malicious or too-broad redirect URI is the Entra-side counterpart to open redirects.

Rules:

- **Exact URIs, no wildcards.** Entra allows wildcards in some cases; don't use them. Enumerate every legitimate redirect URI.
- **HTTPS only in production.** HTTP redirect URIs are allowed only for `localhost` development.
- **Prune test / stage URIs from prod app registrations.** A leftover `https://staging.example.com/callback` in the prod app's redirect URIs list is an attack avenue if stage is compromised.

### Secret and certificate expiry

App registrations with client secrets must have those secrets rotated. Two good practices:

- **Prefer certificate-based credentials over client secrets.** Certificates are harder to exfiltrate (private key can be in Key Vault or a hardware token) and support longer validity with controlled rotation.
- **Alert on secrets expiring in < 30 days** — gives the owning team time to rotate. Alert on secrets with expiry > 1 year — gives someone a chance to shorten it.

Track with a scheduled Entra Graph API query:

```kusto
GraphAPICall
| where target == "applications"
| project appId, displayName, passwordCredentials, keyCredentials
| mv-expand passwordCredentials
| where passwordCredentials.endDateTime < now() + 30d
```

Or use Entra's built-in "Apps expiring soon" report.

### Permission scope hygiene

App registrations request API permissions — Graph API (Mail.Read, User.Read.All, Directory.ReadWrite.All, etc.), SharePoint, Teams, custom APIs.

Common failures:

- **Over-scoped permissions**: `Directory.ReadWrite.All` when the app only needs `User.Read`.
- **Application permissions** (app-only) granted for things that should be **delegated** (on-behalf-of-user). Application permissions bypass user consent and run with full privilege — grant only when the app actually needs to run autonomously.
- **Admin consent granted broadly** for low-trust apps.

Annual review of every app registration:

1. What permissions does it hold?
2. Which are actively used (via sign-in logs)?
3. Can any be removed?
4. Who owns the app? If the owner has left the company, the app is likely dead — delete it.

### High-value targets for attackers

App registrations are the current hot area for attackers in Entra. The patterns to watch for:

- **Consent phishing** — attacker tricks a user into consenting to a malicious app that requests `Mail.Read`. Mitigation: disable user consent for apps requesting high-risk permissions (Entra admin center → Enterprise applications → Consent and permissions → User consent settings).
- **App registration modification** — attacker gains temporary admin access and adds their own credential to an existing high-privilege app. Mitigation: alert on any `Update application` event in audit logs, especially credential changes. Detection rules in Sentinel are well-known for this.
- **Service principal created with Global Admin** — rare but catastrophic. Alert immediately on role assignment to any service principal.

## Monitoring and detection

The identity signals to forward to Sentinel (or your SIEM of choice):

- **Sign-in logs** (successful + failed) — volume is high; filter if needed but keep at least 90 days.
- **Audit logs** — app registrations, role assignments, CA policy changes, PIM activations, MFA configuration changes.
- **Provisioning logs** — for any SCIM provisioning (from Okta, Workday, etc.).
- **Risk detections** — Identity Protection findings for user risk and sign-in risk.

Detection rules that pay off:

1. **Global Administrator role assigned to any user** — alert on creation, investigate every time.
2. **MFA disabled or reduced for a user** — attacker mitigating their own future sign-in challenge.
3. **New app registration created with high-privilege permissions** (Mail.ReadWrite, Directory.Read.All, etc.).
4. **Service principal credential added to an existing app registration** by a user who is not the app's normal owner.
5. **Break-glass account sign-in** — always investigate; they should not be signing in during normal operation.
6. **Impossible travel** — Identity Protection's sign-in risk, escalated.
7. **Password spray pattern** — many failed sign-ins from one source IP across many users.

Azure Sentinel's Content Hub ships rules for all of the above. Start there; tune.

## Compliance mapping

| Framework | Control | Satisfied by |
| --- | --- | --- |
| HIPAA §164.308(a)(4) — Access management | Standing-privilege elimination via PIM; access reviews |
| HIPAA §164.312(a)(2)(i) — Unique user IDs | Entra ID for all users; no shared accounts |
| HIPAA §164.312(d) — Person/entity authentication | MFA via CA001; sign-in risk blocking via CA003 |
| SOC 2 CC6.1 — Logical access | Baseline CA set + PIM + Managed Identity |
| SOC 2 CC6.2 — Authentication | MFA + Identity Protection |
| SOC 2 CC6.3 — Access provisioning and de-provisioning | Group-based role assignment + access reviews |
| NIST CSF 2.0 PR.AC-1, PR.AC-7 | Identity management; strong authentication |

## Further reading

- [Microsoft — Conditional Access design principles and framework](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policies)
- [Microsoft — Privileged Identity Management documentation](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure)
- [Microsoft — Managed identities for Azure resources](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview)
- This repo: [security-reference-architecture.md](./security-reference-architecture.md), [defender-for-cloud.md](./defender-for-cloud.md), [../../architecture-patterns/oauth2-oidc-flows.md](../../architecture-patterns/oauth2-oidc-flows.md) for the general OAuth/OIDC context
