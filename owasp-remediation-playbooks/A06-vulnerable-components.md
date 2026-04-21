# A06 — Vulnerable and Outdated Components

## What it is

Vulnerable and outdated components are third-party libraries, runtime versions, operating system packages, and base container images that contain known security defects. Your application may be written perfectly; the 472 packages in your dependency tree, and the 3,200 transitive dependencies they pull in, are authored by people who are not on your team and whose quality controls you do not enforce. One of those packages will ship a critical vulnerability this quarter. Whether your application is exposed depends on what the dependency does, how your code uses it, and how quickly you patch.

The category is less about individual bugs and more about process: is there a pipeline that tells you when a dependency has a new CVE, is there a policy that decides how fast you upgrade, and is there a control that prevents a vulnerable dependency from being added to the codebase in the first place. OWASP moved this category up from A09 in 2017 to A06 in 2021 because the industry collectively got worse at it.

## Why it matters

A concrete exploit: a SaaS platform runs a Java application that depends on Log4j 2.14. On December 9, 2021, CVE-2021-44228 (Log4Shell) is disclosed — every Log4j version from 2.0-beta9 to 2.14.1 allows remote code execution via a crafted log message. Attackers begin scanning the internet within hours. The platform's application logs request paths and user-agent strings, so every HTTP request is a potential exploit delivery. The fix is a dependency upgrade that takes one pull request and ~30 minutes; the question is whether the team finds out before the attackers do, and whether the upgrade process can ship an emergency patch in under 24 hours. Teams with a working SCA pipeline, a documented patch SLA, and a production deploy that can ship in an hour did fine. Teams without those things spent the next three weeks in incident mode.

Other common shapes:

- **A dependency with a critical CVE, fix available, never upgraded** — the scanner flags it every week, the ticket sits in the backlog.
- **A dependency with a critical CVE, no fix available (abandoned package)** — requires replacing the package or forking.
- **A transitive dependency pinned by a direct dependency that cannot be upgraded** — dependency-tree hell; resolved by overrides, forks, or replacing the direct dependency.
- **A base container image with dozens of OS-level CVEs** — a Node.js app on a 2023 Alpine image with `openssl` CVEs from eight months ago.
- **An outdated runtime** — Node 16 after EOL, Python 3.8 after EOL, Java 8 with no patches.
- **A typosquatted package** — `requests-util` where you meant `requests`, or a look-alike npm package; supply-chain compromise vector.

## How to find it

**Manual review indicators.** On every PR that adds or upgrades a dependency, check: is the new package actively maintained (release within 12 months, active GitHub activity), does it have known CVEs (check the advisory database), and is it the right package (not a typosquat). On periodic reviews: inventory all direct dependencies, flag anything on an EOL runtime, anything unmaintained, anything with a critical CVE unresolved for more than 30 days.

**Automated signals.** This is the category where scanners shine.

- **pip-audit** (Python) — native, reads lockfile, checks PyPI and OSV.
- **npm audit** / **yarn audit** / **pnpm audit** — native package-manager SCA.
- **GitHub Dependabot alerts + dependency-review-action** — PR-level blocking of new vulnerable dependencies.
- **Snyk** (SaaS) — strong at deep dependency trees, exploitable-path analysis.
- **OSV-Scanner** — cross-ecosystem OSS scanner, reads lockfiles across Python/Node/Go/Rust/Java.
- **Trivy** — image and filesystem scanning; also covers OS packages and IaC.
- **GitHub Advanced Security** — Dependabot + secret scanning + code scanning in one.

What to watch for beyond scanners:

- A package's GitHub repo archived or marked "no longer maintained."
- Single-maintainer packages in security-critical positions (crypto, auth, parsing).
- Packages with >1% of your supply chain concentrated in them — a single compromise, a big blast radius.

## How to fix it — Python

**Vulnerable.**
```python
# requirements.txt with known-vulnerable pins.
#
#   requests==2.19.0            # CVE-2018-18074 — credential leak
#   urllib3==1.24.1             # CVE-2020-26137 — header injection
#   pyyaml==5.1                 # CVE-2020-14343 — unsafe load
#   django==2.2                 # EOL, no security patches
```

```python
# Code that amplifies the blast radius: using the dependency in ways
# that expose it to untrusted input.
import yaml

def parse_config(user_upload: bytes):
    return yaml.load(user_upload)          # CVE-2020-14343 arbitrary code exec
```

**Secure.**
```
# requirements.txt pinned to current, actively-maintained versions.
#
#   requests==2.32.*
#   urllib3==2.*
#   pyyaml==6.*
#   Django==5.*

# pyproject.toml with explicit constraints, reproducible lockfile
# committed (poetry.lock, uv.lock, or pip-compile output).
#
#   [project]
#   dependencies = [
#     "requests~=2.32",
#     "pyyaml>=6,<7",
#     "Django>=5,<6",
#   ]
```

```python
import yaml

def parse_config(user_upload: bytes):
    # Never yaml.load on untrusted input; yaml.safe_load only handles
    # YAML 1.1 scalars/sequences/mappings — no arbitrary class construction.
    return yaml.safe_load(user_upload)
```

For the automation side, a minimal CI step that catches new vulnerable dependencies:

```yaml
# .github/workflows/dependency-gate.yml — run on every PR.
jobs:
  pip-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install pip-audit
      - run: pip-audit --strict --format=json --output=audit.json
      - run: |
          high=$(jq '[.dependencies[]?.vulns[]?.severity // "" | ascii_upcase
                     | select(IN("HIGH","CRITICAL"))] | length' audit.json)
          if [ "$high" -gt 0 ]; then
            echo "::error::$high high/critical dependency findings"
            exit 1
          fi
```

## How to fix it — JavaScript

**Vulnerable.**
```json
// package.json with outdated, vulnerable pins.
{
  "dependencies": {
    "express": "4.16.0",
    "lodash": "4.17.10",
    "jsonwebtoken": "7.0.0",
    "node-fetch": "2.6.0"
  }
}
```

```javascript
// Code that uses a vulnerable pattern — this is lodash.merge on user
// input, which hits CVE-2019-10744 (prototype pollution) on <4.17.12.
const _ = require("lodash");
app.post("/preferences", (req, res) => {
  const merged = _.merge({}, req.body);
  req.user.preferences = merged;
  res.json({ ok: true });
});
```

**Secure.**
```json
// package.json pinned to current versions, with explicit override of
// a transitive dependency that would otherwise drag in a vulnerable
// version. package-lock.json committed.
{
  "dependencies": {
    "express": "^4.19.2",
    "jsonwebtoken": "^9.0.2",
    "undici": "^6.19.8"
  },
  "overrides": {
    "tough-cookie": "^4.1.3"
  },
  "engines": {
    "node": ">=20.0.0"
  }
}
```

```javascript
// Avoid lodash.merge on user input entirely. Use a validated schema
// + flat assignment — same result, no prototype pollution surface.
const { z } = require("zod");
const PrefsSchema = z.object({
  theme: z.enum(["light", "dark"]).optional(),
  language: z.string().regex(/^[a-z]{2}(-[A-Z]{2})?$/).optional(),
}).strict();

app.post("/preferences", async (req, res) => {
  const parsed = PrefsSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid prefs" });
  req.user.preferences = { ...req.user.preferences, ...parsed.data };
  await req.user.save();
  res.json({ ok: true });
});
```

And the pipeline side:

```yaml
jobs:
  npm-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: "20" }
      - run: npm ci
      - run: npm audit --audit-level=high --omit=dev

  dependency-review:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    steps:
      - uses: actions/checkout@v4
      - uses: actions/dependency-review-action@v4
        with: { fail-on-severity: high }
```

## How to test the fix

Two kinds of tests here: tests that assert the pipeline enforces the policy, and tests that assert specific known-bad dependencies are not present.

**pytest (Python).**
```python
import subprocess, json

def test_no_critical_cves_in_dependencies():
    result = subprocess.run(
        ["pip-audit", "--format=json"],
        capture_output=True, text=True, check=False,
    )
    report = json.loads(result.stdout or "{}")
    critical = []
    for dep in report.get("dependencies", []):
        for vuln in dep.get("vulns", []) or []:
            sev = (vuln.get("severity") or "").upper()
            if sev in {"CRITICAL", "HIGH"}:
                critical.append((dep["name"], vuln.get("id"), sev))
    assert critical == [], f"Unresolved high/critical CVEs: {critical}"

def test_runtime_is_supported():
    import sys
    # Python 3.11+ — 3.8 and 3.9 are EOL.
    assert sys.version_info >= (3, 11), f"Upgrade Python; on {sys.version}"
```

**Jest (JavaScript).**
```javascript
const { execSync } = require("child_process");

describe("dependency hygiene", () => {
  it("reports no high/critical vulnerabilities from npm audit", () => {
    let report;
    try {
      const out = execSync("npm audit --json --omit=dev", { stdio: ["ignore", "pipe", "ignore"] });
      report = JSON.parse(out.toString());
    } catch (err) {
      report = JSON.parse(err.stdout.toString());
    }
    const counts = report.metadata?.vulnerabilities || {};
    expect(counts.high || 0).toBe(0);
    expect(counts.critical || 0).toBe(0);
  });

  it("runs on a supported Node version", () => {
    const major = parseInt(process.versions.node.split(".")[0], 10);
    expect(major).toBeGreaterThanOrEqual(20);
  });

  it("does not pin lodash < 4.17.21", () => {
    const pkg = require("../package-lock.json");
    const lodash = pkg.packages?.["node_modules/lodash"];
    if (lodash) {
      const [maj, min, patch] = lodash.version.split(".").map(Number);
      expect([maj, min, patch] >= [4, 17, 21]).toBe(true);
    }
  });
});
```

## Compliance mapping

| Framework | Control | Relevance |
| --- | --- | --- |
| **HIPAA Security Rule** | §164.308(a)(5)(ii)(B) — Protection from Malicious Software | Patch management for components handling ePHI is in-scope. |
| **HIPAA Security Rule** | §164.308(a)(8) — Evaluation | Periodic technical evaluation in response to environmental or operational changes — including new vulnerabilities in dependencies. |
| **SOC 2 Trust Services Criteria** | CC7.1 — Detection and Monitoring of System Vulnerabilities | SCA tooling is the realization of this detective control. |
| **SOC 2 Trust Services Criteria** | CC7.2 — Security Incidents | Critical CVE in a dependency is a security event; response is in-scope. |
| **SOC 2 Trust Services Criteria** | CC8.1 — Change Management | Patches are changes; change management process applies. |
| **NIST CSF 2.0** | ID.RA-01 — Vulnerabilities in assets are identified, validated, and recorded | Dependency CVEs are asset vulnerabilities. |
| **NIST CSF 2.0** | ID.SC — Cybersecurity Supply Chain Risk Management | Third-party components are the supply chain; management is in-scope. |
| **NIST CSF 2.0** | PR.PS-02 — Software is maintained, replaced, and removed | Patching cadence, EOL runtime replacement, package retirement. |
| **NIST CSF 2.0** | RS.MA-02 — Incident reports are triaged and validated | CVE disclosures are the external trigger for incident triage. |

For PCI-DSS v4, this maps to Requirement 6.3 (security vulnerabilities are identified and addressed) and Requirement 6.3.3 (all system components are protected from known vulnerabilities by installing applicable security patches/updates within one month of release for critical vulnerabilities).
