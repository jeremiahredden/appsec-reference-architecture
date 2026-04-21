# Demo Application — Intentionally Vulnerable Target

> **EDUCATIONAL USE ONLY** — This application contains intentional security vulnerabilities for demonstration purposes. Never deploy this code in any environment. Do not run against production data. Do not expose to the public internet. Do not reuse any "secrets" in this folder.

This demo app exists as a scan target for the DevSecOps pipeline defined in [`../devsecops-pipeline/`](../devsecops-pipeline/). It gives the pipeline something real to find: vulnerable code paired with a secured counterpart, so a reader can see what the tooling flags, what the fixes look like, and how the two line up.

Every vulnerability below is commented inline with the pattern:

```
# VULNERABILITY: <class> — intentional for pipeline demonstration
```

Secure counterparts live alongside each vulnerable file: `python-api/secure_app.py` and `node-api/secure_app.js`. Read the two side-by-side to see the delta the pipeline is trying to enforce.

---

## Python API (Flask)

`python-api/app.py` is a single-file Flask application that demonstrates ten common web vulnerabilities. `python-api/secure_app.py` is the hardened version.

### Run locally

```bash
cd demo-app/python-api
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# vulnerable build (do not expose):
python app.py

# hardened build:
export JWT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export FETCH_ALLOWLIST="api.internal.example.com,metadata.internal.example.com"
python secure_app.py
```

---

## Node.js API (Express)

`node-api/app.js` is the vulnerable Express counterpart. `node-api/secure_app.js` is the hardened version.

### Run locally

```bash
cd demo-app/node-api
npm install

# vulnerable build (do not expose):
node app.js

# hardened build:
export JWT_PUBLIC_KEY="$(cat jwt-public.pem)"
export PROXY_ALLOWLIST="api.internal.example.com,metadata.internal.example.com"
node secure_app.js
```

---

## What the pipeline finds

The pipeline in `.github/workflows/appsec-pipeline.yml` runs Semgrep, gitleaks, pip-audit, npm audit, and Checkov. Running it against this folder produces the following expected findings. If you add a vulnerability to the demo app and the pipeline does not catch it, that is a gap worth a ticket.

### Python (`python-api/app.py`)

| # | Vulnerability | Caught by | Rule / indicator |
|---|---|---|---|
| 1 | SQL injection via f-string | Semgrep | `python.flask.security.tainted-sql-string` + custom rule |
| 2 | Hardcoded JWT secret | Semgrep + gitleaks | `python.jwt.hardcoded-secret` + generic-api-key heuristic |
| 3 | `debug=True` on Flask run | Semgrep | `custom-rules.flask-debug-enabled` |
| 4 | Missing authentication on `/admin` | Semgrep (custom) | `custom-rules.flask-route-missing-auth` |
| 5 | Command injection via `os.system` | Semgrep | `python.lang.security.audit.dangerous-system-call` |
| 6 | Insecure deserialization via `pickle.loads` | Semgrep | `python.lang.security.audit.avoid-pickle` |
| 7 | SSRF via unvalidated `requests.get` | Semgrep | `python.requests.security.disabled-cert-validation` family + custom |
| 8 | Weak hash (MD5) | Semgrep | `python.lang.security.audit.md5-used-as-password` |
| 9 | Path traversal in `/file` | Semgrep | `python.lang.security.audit.path-traversal-open` |
| 10 | Missing rate limiting | Manual review | architectural — no rule flags this directly; fixed in secure version |

### Node.js (`node-api/app.js`)

| # | Vulnerability | Caught by | Rule / indicator |
|---|---|---|---|
| 1 | SQL injection via string concat | Semgrep | `javascript.mysql.security.audit.sql-injection` |
| 2 | NoSQL injection via `req.body` | Semgrep | `javascript.mongoose.security.injection` |
| 3 | Hardcoded weak JWT secret | Semgrep + gitleaks | `javascript.jwt.hardcoded-secret` |
| 4 | Command injection via `exec` | Semgrep | `javascript.lang.security.audit.child-process.exec` |
| 5 | Prototype pollution via recursive merge | Semgrep | `javascript.lang.security.audit.prototype-pollution` |
| 6 | Reflected XSS via unescaped HTML | Semgrep | `javascript.express.security.audit.xss` |
| 7 | SSRF via axios to user URL | Semgrep | `javascript.express.security.audit.ssrf` |
| 8 | Missing security headers (no `helmet()`) | Semgrep | `javascript.express.security.audit.helmet-missing` |
| 9 | Permissive CORS `origin: '*'` | Semgrep | `javascript.express.security.audit.permissive-cors` |
| 10 | JWT verify without algorithm | Semgrep | `javascript.jwt.security.audit.jwt-none-alg` |

Any dependency CVE — transient or direct — will surface through `pip-audit` and `npm audit` regardless of the code. The pinned versions above intentionally include some aged minor releases so dependency scanners have something to flag on first run.

---

## Adding a new vulnerability

1. Add the vulnerable pattern to `app.py` / `app.js`. Comment it with `# VULNERABILITY: <class> — intentional for pipeline demonstration`.
2. Add the secure counterpart to `secure_app.py` / `secure_app.js`.
3. Run the pipeline locally against the folder. If it does not flag the new finding, either add a custom rule to `devsecops-pipeline/semgrep-rules/custom-rules.yaml` or document the gap in the table above.
4. Update the table in this README.

That loop — vulnerability → expected finding → rule or documented gap — is how the pipeline stays honest.
