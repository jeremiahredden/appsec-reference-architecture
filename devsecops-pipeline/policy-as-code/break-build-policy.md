# Break-Build Policy

This is the rules-of-engagement document for the AppSec pipeline. It tells developers exactly what will fail their build and why, what the exception process looks like, and how risk acceptances are recorded. It tells security engineers what the agreed thresholds are so they can tune tools to match.

The policy exists to make the pipeline predictable. A build that fails for reasons the team cannot anticipate is a build the team routes around. A build that fails for clearly-documented, previously-agreed reasons is a build the team respects.

**Owner:** Head of Application Security. Reviewed quarterly with Platform Engineering and CTO.
**Last reviewed:** 2026-04-20.
**Next review:** 2026-07-20.

---

## What Breaks the Build

The pipeline will **fail the build** and prevent merge to `main` when any of the following is true on the PR branch.

### Hard-Gate Findings — No Exceptions Without Written Approval

These are always a build-breaking failure. They require written approval from the Head of AppSec to bypass, and the bypass is recorded in the exception register for quarterly audit.

| Finding | Source | Rationale |
| --- | --- | --- |
| Hardcoded secret detected anywhere in the repo, including tests and fixtures | Gitleaks | Every committed secret is compromised the moment it lands in git history. This is not a severity question; it is an "always rotate, always investigate" event. |
| Semgrep rule with `severity: ERROR` fires, including every custom rule in `semgrep-rules/custom-rules.yaml` | Semgrep | The custom `ERROR` rules have been hand-authored for high precision on this codebase. A fired ERROR rule is not noise; it is a reviewed, named class of bug. |
| IaC misconfiguration at severity HIGH or CRITICAL | Checkov | Infrastructure misconfigurations have broad blast radius — a public S3 bucket affects every object; an overly-permissive IAM policy affects every principal. They are cheap to fix at commit time and expensive to fix later. |
| Dependency with a known CVE at CVSS ≥ 9.0 (Critical) | pip-audit, npm audit, GitHub dependency-review | Critical CVEs are where we spend incident response time. The cost of not merging a PR until the dependency is upgraded is orders of magnitude lower than the cost of the next incident. |
| Adding a license from the deny list (GPL-2.0, GPL-3.0, AGPL-3.0 for binary-distributed services) | GitHub dependency-review | License compliance is a legal requirement, not a security one. Treat a new denied-license dependency as an immediate-stop event. |

### Soft-Gate Findings — Fail by Default, Exception with Ticket

These fail the build by default but have a lighter-weight exception path. A developer can request a time-limited risk acceptance through the process in the next section. Exceptions are recorded on the PR and expire automatically.

| Finding | Source | Rationale |
| --- | --- | --- |
| Dependency with a known CVE at CVSS 7.0–8.9 (High) | pip-audit, npm audit | High-CVSS dependencies should be upgraded at the earliest reasonable opportunity. "Earliest reasonable" sometimes means "next sprint" because the upgrade is disruptive — that case is what the exception process exists for. |
| IaC misconfiguration at severity MEDIUM that touches an internet-facing resource | Checkov | An ALB with permissive listener rules is a medium finding, but internet-facing context makes it a higher practical priority. |
| New Semgrep `WARNING` rule triggers on changed code (not existing code) | Semgrep | We do not ship new warnings. Existing baseline warnings are tracked separately; new ones on touched lines need justification. |

### Report-Only Findings — Annotate the PR, Do Not Break the Build

These appear as PR annotations and Security-tab entries. They do not block merge. The security team reviews the Security tab weekly and files issues for patterns that emerge.

| Finding | Source | Rationale |
| --- | --- | --- |
| Semgrep `INFO` findings | Semgrep | Informational patterns; useful for long-tail code health but not worth blocking merges on. |
| Dependency with a known CVE at CVSS < 7.0 (Medium and below) | pip-audit, npm audit | Below the operational threshold. Tracked in aggregate, addressed during dependency-maintenance sprints. |
| IaC misconfiguration at severity LOW | Checkov | Defense-in-depth advisories (e.g., "enable access logging on this bucket"). Important, not blocking. |
| Gitleaks findings on files outside the commit diff in PR mode | Gitleaks | History scan surfaces historical secrets separately in the weekly review. Do not make PR authors responsible for the whole repo's history. |

---

## Exception Process (Soft-Gate Findings)

When a soft-gate finding cannot be fixed in the current PR, the developer may request a **time-limited risk acceptance**. The process is designed to take less than 10 minutes end-to-end so that the exception path is lower-friction than "disable the scanner."

### Step 1 — Open the exception on the PR

Comment on the PR with the `/sec-accept` command (handled by the security bot), structured as:

```
/sec-accept
finding: <rule id or CVE id, exactly as it appears in the finding>
reason: <1-3 sentences explaining why the fix is not in this PR>
expiry: <ISO date, max 90 days from today>
ticket: <link to a tracked issue where the remediation is scheduled>
```

Every field is required. An exception without a tracking ticket is rejected — the entire point of the process is that risk acceptances expire and remediation happens on a schedule.

### Step 2 — Approval

- **Automatic approval** if the finding is in the pre-approved exception list (see `exceptions/auto-approved.yaml` — e.g., CVEs in dependencies where the vulnerable function is provably unreachable, tuned Semgrep false positives that have been reviewed once).
- **Security team approval** otherwise. The AppSec on-call reviews exception requests within 1 business day. Decisions are recorded on the PR.
- **Head of AppSec approval** for exceptions on hard-gate findings. These are rare and require a written justification. Minimum target is zero per quarter.

### Step 3 — Merge

With the exception in place, the build moves from "failed" to "passing with exception." The PR can merge. The exception is recorded with the PR URL, the finding, the expiry, and the tracking ticket.

### Step 4 — Expiry

At the expiry date, the security bot re-opens a follow-up issue referencing the original PR and the tracking ticket. If the finding is still present in the codebase, a new exception must be filed — it does not roll over automatically. This forcing function is what prevents exceptions from turning into permanent suppressions.

---

## Exception Register

All active and historical exceptions are tracked in `exceptions/register.md` (source of truth: the GitHub project board, exported to markdown quarterly for audit).

The register contains, for each exception:

- Exception ID (auto-generated: EXC-YYYY-NNNN).
- PR where the exception was filed.
- Finding identifier (rule ID, CVE ID, or Checkov check ID).
- Requestor and approver.
- Reason.
- Expiry date.
- Tracking ticket.
- Status: Active / Expired / Closed.

Quarterly, the AppSec team reviews the register with Engineering Management:

- Exceptions approaching expiry (30-day horizon).
- Exceptions repeatedly renewed on the same finding (signal of an undersupported remediation).
- Patterns across exceptions (many exceptions on the same rule → is the rule wrong, or is there a systemic gap?).

---

## Finding Tracking to Closure

Every finding — accepted or not — is tracked somewhere. The rule is: if it is worth having a scanner find it, it is worth tracking the fix.

**Break-build findings fixed in the PR:** no separate tracking needed; the PR itself is the record. The pipeline confirms the finding is gone on re-run.

**Break-build findings with an exception:** tracked in the engineering ticket system (JIRA / Linear / GitHub Issues, per team). The exception references the ticket; the ticket references the exception. Tickets for accepted security findings carry a `security-debt` label and a SLA driven by severity:

| Severity | SLA to close the ticket |
| --- | --- |
| Critical (CVSS ≥ 9.0, hard-gate bypasses) | 14 days |
| High (CVSS 7.0–8.9) | 30 days |
| Medium | 90 days |
| Low | Best-effort, closed during dependency-maintenance sprints |

**Report-only findings:** tracked in aggregate via the Security tab. The AppSec team reviews weekly and files engineering tickets when a pattern warrants it.

---

## Requesting a New Exception Category

If a rule produces consistent false positives on this codebase, the right response is not a permanent exception per PR — it is to tune the rule. The process:

1. Open a PR against `semgrep-rules/custom-rules.yaml` (or the equivalent configuration for the other tools) adjusting the rule.
2. Include a justification: what the rule was catching, why it fires wrong here, how the change keeps the original intent intact.
3. Pair with an AppSec engineer for review.
4. Run the tuned rule against the default branch before merge; confirm no regressions in real findings.

Tuning is preferred to suppression. Suppression is preferred to permanent acceptance. Permanent acceptance is rare and requires Head-of-AppSec sign-off plus a note in the register.

---

## Audit and Transparency

The pipeline, the exception register, and this policy are open to every engineer in the organization. There is no separate "security view" of the findings — developers see what security sees. Quarterly, the AppSec team publishes a summary to Engineering All-Hands:

- Number of findings by severity, trended across quarters.
- Exceptions issued, expired, renewed.
- Mean time to remediation by severity.
- Any rules retired, added, or retuned.

Transparency is a feature, not a risk. A policy that the team cannot see is a policy the team cannot trust.

---

## Summary — The Three Sentences to Remember

1. **The pipeline breaks your build only for findings where the right answer is "fix before merge," and it tells you exactly what to fix.**
2. **If the fix is not in this PR, there is a 10-minute exception process with a required expiry and tracking ticket.**
3. **Every finding — fixed, excepted, or tracked — has a named owner and a visible state. Nothing gets silently suppressed.**
