# A09 — Security Logging and Monitoring Failures

## What it is

Security logging and monitoring failures are the gaps that let an attacker operate inside a system undetected. The other OWASP categories prevent compromise; A09 is about what happens after one. If an application logs nothing of security value, logs locally with no aggregation, logs data that cannot be correlated to a user or request, or logs secrets into a less-protected system, then the mean time to detect a breach is however long it takes an external party to notice — often months, sometimes never.

The 2021 revision added the word "security" to the category name to distinguish it from application logging generally. An application that produces gigabytes of debug logs with no authentication events, no authorization denials, no administrative actions, and no anomaly alerts is exactly as blind to an intrusion as one that logs nothing at all.

## Why it matters

A concrete exploit: an attacker uses credential stuffing against a company's login endpoint over four days. The login endpoint logs successful logins only. There is no logging of failed attempts, no alerting on rates of failures per IP, and the WAF is in "learning mode" with no enforcement. On day five, the attacker finds a valid credential, logs in, exfiltrates 40,000 customer records over the normal API (no data-volume alert), and logs out. The next security-relevant event is a ransom email received by the CEO 11 weeks later.

The fix is a set of small controls that compound: log failed authentication attempts with user, IP, and user-agent; alert when failures-per-IP crosses a threshold; log every access to sensitive data with a request ID that ties back to the user; alert when a user pulls more than 10× their historical daily record volume; ship all of this to a SIEM that retains it for a year. None of these is sophisticated. The failure mode is that no one wrote them.

Other common shapes:

- **Log everything, structure nothing** — plaintext `print` statements that grep can find but no tool can query.
- **Logs that contain secrets** — `Authorization` headers, password-reset tokens, session cookies written to log aggregation that has wider access than the primary application.
- **Logs that drop user identity** — the log has `user_id=12345` on the login event and nothing on the next 500 events that user triggered.
- **No alert on authorization denials** — a 403 rate spike is the signature of an attacker testing scopes; nobody watches.
- **Logs deleted on schedule shorter than the breach-detection window** — 7 days of retention means a 90-day-dormant attacker is forensically invisible.

## How to find it

**Manual review indicators.** Open the login handler — does it log successful and failed attempts, with IP and user agent, at an appropriate level? Open a resource handler — does the log line include request ID, user ID, and action? Look at the logging configuration — is there a secrets-redaction filter? Look at alerting — is there a rule for repeated auth failures, for privilege escalation attempts, for data exfiltration volumes?

**Automated signals.**

- Code search for `print(`, `console.log(`, `logger.debug(`, then inspect what they emit — prints in handlers often mean no structured logging.
- Grep for `req.headers.authorization`, `password`, `cookie`, `session_id`, `api_key` inside log statements — these are logs-with-secrets smells.
- Semgrep: `python.flask.security.audit.debug-enabled`, `javascript.express.security.audit.audit-express-morgan-combined-logging` — some frameworks log too little, others too much.
- Observability: Grafana dashboards, OpenTelemetry traces, Loki or Elasticsearch for log aggregation. Whatever you use, the question is: can an on-call engineer answer "show me every action by user X in the last hour" in under 60 seconds?
- Incident-response readiness: run a tabletop exercise that assumes credentials were stolen on day D-7; determine how long it takes to list every action the compromised account took. If nobody can, logging is broken.

## How to fix it — Python

**Vulnerable.**
```python
# Unstructured logs that leak secrets, drop identity, and print user
# input uncritically.
import logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger()

@app.post("/login")
def login():
    body = request.get_json()
    log.debug(f"login attempt: {body}")                 # Logs password plaintext.
    user = User.query.filter_by(email=body["email"]).first()
    if not user or not user.verify_password(body["password"]):
        return {"error": "invalid"}, 401                # No failed-login log.
    session["user_id"] = user.id
    log.info(f"logged in {user.email}")                 # No IP, no request id.
    return {"ok": True}
```

**Secure.**
```python
# Structured JSON logging with per-request context, explicit event
# names, and a redaction filter that drops known-sensitive keys.
import logging, json, time, uuid
from flask import g, request

class RedactFilter(logging.Filter):
    REDACT = {"password", "authorization", "cookie", "set-cookie", "token", "api_key"}

    def filter(self, record):
        if isinstance(record.args, dict):
            record.args = {k: ("[REDACTED]" if k.lower() in self.REDACT else v)
                           for k, v in record.args.items()}
        return True

class JSONFormatter(logging.Formatter):
    def format(self, record):
        base = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "msg": record.getMessage(),
            "event": getattr(record, "event", None),
            "request_id": getattr(g, "request_id", None) if request else None,
            "user_id": getattr(g, "user_id", None) if request else None,
            "ip": request.remote_addr if request else None,
        }
        # Merge any structured kwargs the caller attached.
        extra = getattr(record, "ctx", {}) or {}
        base.update(extra)
        return json.dumps(base)

handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
handler.addFilter(RedactFilter())
logging.basicConfig(level=logging.INFO, handlers=[handler])
log = logging.getLogger("app")

@app.before_request
def attach_request_context():
    g.request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    g.started = time.monotonic()

@app.post("/login")
def login():
    body = request.get_json() or {}
    email = body.get("email")
    user = User.query.filter_by(email=email).first()
    if not user or not user.verify_password(body.get("password", "")):
        log.warning("login_failed", extra={"event": "login_failed",
                                           "ctx": {"email": email}})
        return {"error": "invalid"}, 401

    g.user_id = user.id
    log.info("login_success", extra={"event": "login_success",
                                     "ctx": {"user_id": user.id}})
    session["user_id"] = user.id
    return {"ok": True}

# Sensitive-resource access — always logged, always attributable.
@app.get("/patients/<int:patient_id>")
@require_role("clinician")
def patient_detail(patient_id: int):
    record = Patient.query.get_or_404(patient_id)
    log.info("phi_access", extra={
        "event": "phi_access",
        "ctx": {"patient_id": patient_id, "reason": request.args.get("reason")},
    })
    return jsonify(record.to_dict())
```

## How to fix it — JavaScript

**Vulnerable.**
```javascript
// Unstructured, secret-leaking, user-less logs.
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url} auth=${req.headers.authorization}`);
  next();
});

app.post("/login", async (req, res) => {
  console.log("login body", req.body);                 // Logs password.
  const user = await User.findOne({ email: req.body.email });
  if (!user || !(await user.verifyPassword(req.body.password))) {
    return res.status(401).json({ error: "invalid" }); // No failure log.
  }
  req.session.userId = user.id;
  res.json({ ok: true });
});
```

**Secure.**
```javascript
// pino with per-request child logger, redaction, and an explicit
// event vocabulary. Log lines are JSON that the SIEM can query.
const pino = require("pino");
const pinoHttp = require("pino-http");
const { randomUUID } = require("crypto");

const logger = pino({
  level: process.env.LOG_LEVEL || "info",
  redact: {
    paths: [
      "req.headers.authorization",
      "req.headers.cookie",
      "req.body.password",
      "req.body.token",
      "res.headers['set-cookie']",
    ],
    censor: "[REDACTED]",
  },
  formatters: {
    level: (label) => ({ level: label }),
  },
});

app.use(pinoHttp({
  logger,
  genReqId: (req) => req.headers["x-request-id"] || randomUUID(),
  customLogLevel: (req, res, err) => {
    if (err || res.statusCode >= 500) return "error";
    if (res.statusCode >= 400) return "warn";
    return "info";
  },
}));

app.post("/login", async (req, res) => {
  const email = (req.body?.email || "").toLowerCase();
  const user = await User.findOne({ email }).select("+passwordHash");
  const ok = user && (await argon2.verify(user.passwordHash, req.body.password));
  if (!ok) {
    req.log.warn({ event: "login_failed", email, ip: req.ip }, "login failed");
    return res.status(401).json({ error: "invalid" });
  }
  req.log.info({ event: "login_success", userId: user.id, ip: req.ip }, "login");
  req.session.regenerate(() => {
    req.session.userId = user.id;
    res.json({ ok: true });
  });
});

// Sensitive-resource access — one line per access, tied to request id
// and user id by the pinoHttp context.
app.get("/patients/:id", requireRole("clinician"), async (req, res) => {
  const patient = await Patient.findById(req.params.id);
  if (!patient) return res.status(404).end();
  req.log.info({
    event: "phi_access",
    patientId: patient.id,
    reason: req.query.reason || null,
    userId: req.session.userId,
  }, "phi access");
  res.json(patient);
});
```

For the alerting side — the logs you write are only useful if something reads them:

```yaml
# grafana-alert-rules.yaml (excerpt) — runs against Loki logs.
groups:
  - name: auth-anomalies
    rules:
      - alert: AuthFailureSpike
        expr: |
          sum by (ip) (rate({app="api"} |= "login_failed" [5m])) > 2
        for: 5m
        annotations:
          summary: "High rate of failed logins from {{ $labels.ip }}"
      - alert: PHIAccessVolumeAnomaly
        expr: |
          sum by (user_id) (rate({app="api"} |= "phi_access" [1h]))
            > on(user_id) (avg_over_time({app="api"} |= "phi_access" [30d]) * 10)
        annotations:
          summary: "User {{ $labels.user_id }} accessed 10× the historical PHI volume"
```

## How to test the fix

**pytest (Python).**
```python
import json, logging

def test_login_failure_is_logged_with_event_name(caplog, client):
    with caplog.at_level(logging.WARNING):
        client.post("/login", json={"email": "nobody@example.com", "password": "x"})
    entries = [json.loads(r.message) if r.message.startswith("{") else r
               for r in caplog.records]
    events = [e.event if hasattr(e, "event") else None for e in entries]
    assert "login_failed" in events or any(
        getattr(r, "event", None) == "login_failed" for r in caplog.records
    )

def test_passwords_are_not_logged(caplog, client):
    with caplog.at_level(logging.DEBUG):
        client.post("/login", json={"email": "a@b.test", "password": "s3cret!"})
    for record in caplog.records:
        assert "s3cret!" not in record.getMessage()

def test_phi_access_is_logged_with_patient_and_user(caplog, client, clinician, patient):
    with caplog.at_level(logging.INFO):
        client.get(f"/patients/{patient.id}",
                   headers=auth_headers(clinician),
                   query_string={"reason": "scheduled visit"})
    phi = [r for r in caplog.records if getattr(r, "event", None) == "phi_access"]
    assert phi, "phi_access event not logged"
    assert phi[0].ctx["patient_id"] == patient.id
```

**Jest (JavaScript).**
```javascript
describe("security logging", () => {
  it("emits a login_failed event on wrong password", async () => {
    const sink = captureLogs(logger);
    await request(app).post("/login").send({ email: "a@b.test", password: "wrong" });
    const events = sink.records().map((r) => r.event);
    expect(events).toContain("login_failed");
  });

  it("does not log the password field", async () => {
    const sink = captureLogs(logger);
    await request(app).post("/login").send({ email: "a@b.test", password: "s3cret!" });
    for (const r of sink.records()) {
      expect(JSON.stringify(r)).not.toContain("s3cret!");
    }
  });

  it("redacts the Authorization header", async () => {
    const sink = captureLogs(logger);
    await request(app).get("/healthz").set("authorization", "Bearer leaked-token");
    for (const r of sink.records()) {
      expect(JSON.stringify(r)).not.toContain("leaked-token");
    }
  });

  it("logs phi_access with patient and user ids", async () => {
    const sink = captureLogs(logger);
    await request(app)
      .get(`/patients/${patient.id}`)
      .set("Authorization", `Bearer ${tokenFor(clinician)}`);
    const phi = sink.records().find((r) => r.event === "phi_access");
    expect(phi).toBeTruthy();
    expect(phi.patientId).toBe(patient.id);
    expect(phi.userId).toBe(clinician.id);
  });
});
```

## Compliance mapping

| Framework | Control | Relevance |
| --- | --- | --- |
| **HIPAA Security Rule** | §164.312(b) — Audit Controls | "Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use electronic protected health information." Structured audit logs are the direct realization. |
| **HIPAA Security Rule** | §164.308(a)(1)(ii)(D) — Information System Activity Review | Regular review of audit logs, access reports, and security incident tracking reports. |
| **HIPAA Security Rule** | §164.308(a)(5)(ii)(C) — Log-in Monitoring | Procedures for monitoring log-in attempts and reporting discrepancies. |
| **SOC 2 Trust Services Criteria** | CC7.2 — System Monitoring for Anomalies | Monitoring for anomalies that indicate malicious intent; alerting rules on auth failure rates and data volume anomalies. |
| **SOC 2 Trust Services Criteria** | CC7.3 — Evaluation of Security Events | Once an anomaly is detected, evaluation and escalation are in scope. |
| **SOC 2 Trust Services Criteria** | CC7.4 — Incident Response | Log retention must meet the RTO for forensics — typically ≥12 months. |
| **NIST CSF 2.0** | DE.CM-01 — Networks and network services are monitored to find potentially adverse events | Application-layer logs feed the detection function. |
| **NIST CSF 2.0** | DE.CM-09 — Computing hardware and software, runtime environments, and their data are monitored to find potentially adverse events | Application logs and runtime telemetry. |
| **NIST CSF 2.0** | DE.AE-02 — Potentially adverse events are analyzed to better understand associated activities | SIEM queries, threat-hunting, retrospective analysis. |
| **NIST CSF 2.0** | RS.AN-03 — Analysis is performed to establish what has taken place during an incident | Log retention and queryability are the substrate. |

For PCI-DSS v4, this maps to Requirement 10 in its entirety — audit logs exist, are protected, cover the required events (access to CHD, administrative actions, authentication events), are time-synchronized (10.6), are reviewed daily for CDE systems (10.4), and are retained for at least 12 months with 3 months immediately available (10.5.1).
