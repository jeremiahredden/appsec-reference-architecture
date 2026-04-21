# DevSecOps Pipeline

An opinionated reference implementation of a security pipeline for GitHub-hosted projects. Copy, adapt, ship. The workflow files are intended to be dropped into a repo's `.github/workflows/` directory with minimal edits — the target is a working pipeline on Monday, not a perfect pipeline next quarter.

---

## Design Philosophy

Three principles shape every decision in this pipeline.

### 1. Catch issues when they are cheap to fix.

The cost of a security bug scales with where it is found.

| Where found | Approximate cost to fix | Who fixes it |
| --- | --- | --- |
| Developer's IDE | Minutes | The author, in flow |
| Pre-commit hook | Minutes | The author, briefly annoyed |
| Pull request CI | Tens of minutes | The author, reviewer |
| Default-branch CI | An hour | The author, a day later, context-switched |
| Pen test | Days | A different engineer, deep in a ticket backlog |
| Production incident | Weeks, plus revenue impact | Incident responders, then the team |

A pipeline that ships a finding to the pen testers when the scanner could have caught it in the PR has failed at cost-shifting. Every stage of this pipeline is placed as far left as it can reasonably go.

### 2. Automate the noise so humans focus on judgment calls.

Scanner false-positive rates are typically 30-60% in a cold configuration. A pipeline that ships every raw finding into the team's review queue burns its credibility in two weeks — the team learns that "security CI is usually wrong" and clicks through every warning. The only way to keep automation trusted is to aggressively tune out the noise:

- Rules with known-bad precision on your codebase are disabled in the base configuration and re-enabled only after tuning.
- Findings below the break-build threshold are reported (as informational annotations on the PR) but do not block merges.
- Findings above the threshold are blocked with a clear explanation of what to fix — not just a scanner rule ID.
- When a rule produces a false positive on your code, add a justified suppression at the site (not a global exclusion) and open a ticket to review the suppression in 90 days.

The goal is a pipeline where every break-build failure is a real finding. Once developers trust that, they fix the findings instead of routing around the pipeline.

### 3. Fail builds only on actionable findings.

A build failure must point to an exploitable condition with a concrete fix. "Your dependency tree contains a package with a published CVE" is not actionable on its own — is the vulnerable function even reached? "Your application uses an HTTP client with a known SSRF bypass, and your codebase has 4 call sites matching the vulnerable pattern" is actionable.

This pipeline breaks the build only when:

- A hardcoded secret is detected (always exploitable, always actionable).
- A Semgrep rule marked `severity: ERROR` fires (each rule is hand-reviewed for precision on this codebase).
- A dependency has a CVE with CVSS ≥ 7.0 AND the import graph indicates the vulnerable code is reachable.
- An IaC scan finds a Critical misconfiguration (public storage bucket, unencrypted secrets, open security groups).

Everything else is reported as a PR annotation or an informational comment. Developers see it, can act on it, but can still merge if the finding is a known false positive or a lower-severity issue scheduled for the next sprint.

---

## Tools and Their Role

| Tool | What it catches | Why it is in the pipeline |
| --- | --- | --- |
| **Gitleaks** | Hardcoded secrets, API keys, tokens, private keys | The highest-signal, lowest-false-positive scanner category. Hardcoded credentials are always a finding. A single leak detected at commit time saves a secret-rotation incident. |
| **Semgrep** | Language-specific dangerous patterns, custom organizational rules | Precision-first SAST. The `p/default` ruleset has reasonable defaults; custom rules in `semgrep-rules/` encode the organization's specific patterns (missing auth decorators, Flask debug mode, MD5 for passwords). Not a CodeQL replacement — different trade-offs. |
| **pip-audit** | Python dependency CVEs via PyPI / OSV | Standard library-owned tool, low false-positive rate, fast. Reads `requirements.txt` and the lockfile. Fails the build only for high/critical CVSS. |
| **npm audit** (with `--audit-level=high`) | JavaScript dependency CVEs | npm-native, zero install, acceptable signal. For deeper supply-chain analysis, consider adding Snyk or Socket.dev. |
| **Checkov** | Terraform, CloudFormation, ARM, Kubernetes, Dockerfile misconfigurations | Broadest IaC coverage of the open-source options, with good AWS rules. Runs as a dedicated workflow on infrastructure changes only — avoids running it on every markdown edit. |
| **GitHub `dependency-review-action`** | New vulnerable dependencies added in a PR | Runs only on PRs, shows exactly which dependency was added/updated and what CVEs it introduces. A forcing function for "do not merge a PR that adds a known-vulnerable package." |

The tools are deliberately boring. All are open-source, all are well-maintained in 2026, all run without paid subscriptions. The security value is in the tuning and the policy, not in the tool choice.

Tools explicitly not in this baseline:

- **Commercial SAST suites.** They are worth the money at enterprise scale, but the value depends heavily on tuning. Adopt after the baseline is stable and you know what problem the commercial tool solves that Semgrep does not.
- **Container image scanning.** It belongs in the pipeline, but in a dedicated workflow triggered on container builds — not on every code change. Trivy or Grype are the right starting point.
- **Runtime application self-protection (RASP).** Different problem space. RASP catches what the build-time pipeline missed; it is not a substitute for build-time controls.

---

## Files in This Folder

| File | Purpose |
| --- | --- |
| [`.github/workflows/appsec-pipeline.yml`](./.github/workflows/appsec-pipeline.yml) | The main workflow. Runs on every PR and every push to `main`. Jobs: secrets-scan, sast, sca-python, sca-javascript, iac-scan (thin wrapper), dependency-review, summary. |
| [`.github/workflows/iac-scan.yml`](./.github/workflows/iac-scan.yml) | A dedicated IaC security workflow. Runs only on changes under `infrastructure/`, `terraform/`, `k8s/`, or other IaC-flagged paths. Uploads SARIF to the GitHub Security tab. |
| [`semgrep-rules/custom-rules.yaml`](./semgrep-rules/custom-rules.yaml) | Five hand-authored Semgrep rules covering organization-specific patterns: Flask debug mode, MD5/SHA-1 for passwords, hardcoded AWS access keys, `eval()` of user input in JS, and Flask routes missing authentication decorators. |
| [`policy-as-code/break-build-policy.md`](./policy-as-code/break-build-policy.md) | The rules-of-engagement document. What breaks the build, what the exception process is, how risk acceptances are requested and tracked. |

---

## How to Adopt This in an Existing Repo

1. Copy `.github/workflows/appsec-pipeline.yml` into your repo's `.github/workflows/` directory. Run it in a draft PR. Expect noise on the first run — baseline the false positives before enabling break-build.

2. Start with every job set to `continue-on-error: true`. Let the pipeline run for a week. Review the findings with the team. Suppress or tune the rules that produce noise.

3. Turn `continue-on-error` off for the secrets-scan job first. It is the highest-precision gate and the most dangerous thing to miss. Keep the others in observe mode.

4. Tune Semgrep next. Enable the rules that fire correctly on your code; disable the rest with a justified comment. Only after you have a clean run on the default branch should Semgrep be allowed to break the build.

5. Turn on SCA gating when you have triaged the existing vulnerable dependencies to zero. A pipeline that fails on a 4-year-old transitive dependency with a fix nobody will backport is a pipeline the team will disable.

6. Roll out the policy document at the same time as enabling break-build on Semgrep. Developers need to know the rules of the game before they are graded on them.

The entire rollout is typically 2-4 weeks for a single-service team, 8-12 weeks for a larger organization where tuning must happen per-language and per-team.
