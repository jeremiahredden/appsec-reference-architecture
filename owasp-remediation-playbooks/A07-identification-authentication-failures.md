# A07 — Identification and Authentication Failures

## What it is

Identification and authentication failures are bugs in how an application proves who a user is. The category covers the full lifecycle: initial enrollment, credential storage (overlap with A02), login flow, session issuance and validation, session revocation, and account recovery. When any stage is weak, an attacker either bypasses authentication outright or steals a valid session.

The name changed from "Broken Authentication" in 2021 to emphasize that identification (knowing *which* account the request is for) and authentication (proving the request is from the account owner) are distinct concerns. A system that authenticates correctly but mis-identifies — for example, by looking up a user by a client-supplied tenant header without verifying the user belongs to that tenant — has an A07 defect even when the password check passes.

## Why it matters

A concrete exploit: a B2B SaaS issues JWTs signed with RS256, with the signing key published at `/.well-known/jwks.json`. The JWT validation library is configured with `algorithms=["RS256", "HS256"]` "for future flexibility." An attacker fetches the public key, constructs a token with `alg: HS256`, and signs it with the public key bytes as the HMAC secret. The validator sees `alg: HS256`, uses the RSA public key as an HMAC secret, and the signature verifies. The attacker has forged a token for any user — including the service's own admin role — using only information the service publishes.

The fix is one line: `algorithms=["RS256"]`. The vulnerability is caused by the library being asked to trust the `alg` header of the token it is trying to validate — a classic "the attacker chose the algorithm" failure.

Other common shapes:

- **JWT `alg: none` accepted** — the token is unsigned and the validator accepts it.
- **Session fixation** — the session ID does not rotate on login, so a pre-login session ID the attacker planted remains valid post-login.
- **Credential stuffing with no rate limit** — attackers can try millions of password combinations per hour against the login endpoint.
- **Password reset that leaks account existence** — "Email sent" vs. "No account with that email" turns the reset flow into an enumeration oracle.
- **MFA-bypass on a secondary flow** — the primary login requires MFA, but the mobile OAuth grant does not.
- **Remember-me tokens that are non-expiring** — a stolen laptop retains access indefinitely.

## How to find it

**Manual review indicators.** In the authentication code, look for JWT validators accepting multiple algorithms, validators that trust the `alg` header, validators that do not verify `iss` / `aud` / `exp`. Look for session cookies without `HttpOnly`, `Secure`, and `SameSite` attributes. Look for password reset flows that return different messages or HTTP statuses depending on whether the account exists. Look for login endpoints without rate limiting, with no account lockout, and without logging of failed attempts. Look for remember-me or API tokens without expiration.

**Automated signals.**

- Semgrep: `python.jwt.security.audit.jwt-none-alg`, `python.jwt.security.jwt-hardcoded-secret`.
- Semgrep: `javascript.jsonwebtoken.security.jwt-none-alg`, `javascript.express.security.audit.express-session-hardcoded-secret`.
- Semgrep custom rule: `flask-route-missing-auth` (this repo — flags unauthenticated Flask routes that look sensitive).
- Bandit: `B105` (hardcoded password strings), `B107` (hardcoded password function defaults).
- Snyk Code: `javascript/HardcodedSecret`, `javascript/JwtSignatureVerification`, `javascript/InsecureRandomness`.
- DAST: ZAP/Burp active scan for session-fixation, credential-stuffing, and enumeration issues.

## How to fix it — Python

**Vulnerable.**
```python
# JWT validator that accepts multiple algorithms and trusts the token's
# own alg header — the "RS256/HS256 confusion" vulnerability.
import jwt

PUBLIC_KEY = open("jwt.pub").read()

def get_user_from_token(token: str):
    payload = jwt.decode(
        token,
        PUBLIC_KEY,
        algorithms=["RS256", "HS256"],  # Trusting the alg header.
    )
    return payload["sub"]

# Flask login without rate limiting, with user-enumeration messages,
# and without session rotation on successful login.
@app.post("/login")
def login():
    email = request.form["email"]
    password = request.form["password"]
    user = User.query.filter_by(email=email).first()
    if not user:
        return "No account with that email", 404     # Enumeration oracle.
    if not user.verify_password(password):
        return "Wrong password", 401                 # Oracle again.
    session["user_id"] = user.id                     # No session rotation.
    return redirect("/dashboard")

# Password reset that confirms whether the email is registered.
@app.post("/reset")
def reset():
    email = request.form["email"]
    user = User.query.filter_by(email=email).first()
    if not user:
        return "No account with that email", 404    # Enumeration oracle.
    send_reset_email(user)
    return "Reset email sent", 200
```

**Secure.**
```python
# JWT validator with a single algorithm, explicit issuer/audience,
# and the leeway on exp kept tight. algorithm is hard-coded, NOT read
# from the token.
import jwt
from jwt import InvalidTokenError

def get_user_from_token(token: str):
    try:
        payload = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            issuer="https://auth.example.com",
            audience="api.example.com",
            leeway=30,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except InvalidTokenError:
        abort(401)
    return payload["sub"]

# Flask login with rate limiting per email + IP, uniform error messages
# (no enumeration), session rotation on successful login, and secure
# cookie attributes at the app level.
from flask_limiter import Limiter
limiter = Limiter(app=app, key_func=lambda: f"{request.remote_addr}:{request.form.get('email','')}")

@app.post("/login")
@limiter.limit("10/hour; 50/day")
def login():
    email = request.form["email"]
    password = request.form["password"]
    user = User.query.filter_by(email=email).first()
    if user is None or not user.verify_password(password):
        # Same message, same status, constant time (verify_password
        # runs argon2 even when the user is missing, below).
        return "Invalid email or password", 401
    session.clear()                     # Rotate session on login.
    session["user_id"] = user.id
    session.permanent = True
    return redirect("/dashboard")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)

# Reset flow that always returns the same response — the email is only
# sent if the account exists, but the caller cannot distinguish.
@app.post("/reset")
@limiter.limit("5/hour")
def reset():
    email = request.form["email"]
    user = User.query.filter_by(email=email).first()
    if user is not None:
        send_reset_email(user)
    return "If that email is registered, a reset link has been sent.", 200
```

## How to fix it — JavaScript

**Vulnerable.**
```javascript
// JWT validator with the library defaults that accept multiple
// algorithms, including HS256 signed with the RSA public key.
const jwt = require("jsonwebtoken");
const publicKey = fs.readFileSync("jwt.pub");

function getUser(token) {
  const payload = jwt.verify(token, publicKey);   // algorithm not pinned
  return payload.sub;
}

// Express login with no rate limit, user-enumeration messages, and
// a session secret that defaults to a constant when env is missing.
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ error: "No such user" });
  if (!(await user.verifyPassword(password))) {
    return res.status(401).json({ error: "Wrong password" });
  }
  req.session.userId = user.id;                   // No regenerate.
  res.json({ ok: true });
});

app.use(session({
  secret: process.env.SESSION_SECRET || "dev-secret",
  resave: false,
  saveUninitialized: true,
}));
```

**Secure.**
```javascript
// JWT validator pinned to RS256, with issuer/audience/required claims
// enforced, and a JWKS client that caches keys for rotation.
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");

const client = jwksClient({
  jwksUri: "https://auth.example.com/.well-known/jwks.json",
  cache: true,
  cacheMaxEntries: 5,
  cacheMaxAge: 10 * 60 * 1000,
});

function getKey(header, cb) {
  client.getSigningKey(header.kid, (err, key) => {
    cb(err, key?.getPublicKey());
  });
}

function verifyToken(token) {
  return new Promise((resolve, reject) => {
    jwt.verify(
      token,
      getKey,
      {
        algorithms: ["RS256"],
        issuer: "https://auth.example.com",
        audience: "api.example.com",
        clockTolerance: 30,
      },
      (err, payload) => (err ? reject(err) : resolve(payload)),
    );
  });
}

// Rate-limited login, uniform errors, session regeneration, secure
// cookies, fail-fast secret config.
const rateLimit = require("express-rate-limit");
const loginLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  keyGenerator: (req) => `${req.ip}:${(req.body?.email || "").toLowerCase()}`,
});

app.post("/login", loginLimiter, async (req, res) => {
  const parsed = LoginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid" });
  const { email, password } = parsed.data;

  const user = await User.findOne({ email: email.toLowerCase() }).select("+passwordHash");
  const ok = user && (await argon2.verify(user.passwordHash, password));
  if (!ok) {
    // Burn the password against a dummy hash when the user is absent
    // so the timing does not leak existence.
    if (!user) await argon2.verify(DUMMY_ARGON2_HASH, password).catch(() => {});
    return res.status(401).json({ error: "Invalid email or password" });
  }

  req.session.regenerate((err) => {                // Rotate session id.
    if (err) return res.status(500).json({ error: "session" });
    req.session.userId = user.id;
    res.json({ ok: true });
  });
});

if (!process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET is required");   // Fail fast at boot.
}

app.use(session({
  secret: process.env.SESSION_SECRET,
  name: "sid",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: 12 * 60 * 60 * 1000,
  },
}));
```

## How to test the fix

**pytest (Python).**
```python
import jwt

def test_rs256_hs256_confusion_is_rejected(public_key_pem):
    # Sign a token with HS256 using the RSA public key bytes as the
    # HMAC secret — the classic algorithm-confusion attack.
    forged = jwt.encode({"sub": "admin"}, public_key_pem, algorithm="HS256")
    with pytest.raises(Exception):
        get_user_from_token(forged)

def test_login_is_rate_limited(client):
    for _ in range(10):
        client.post("/login", data={"email": "a@b.test", "password": "wrong"})
    resp = client.post("/login", data={"email": "a@b.test", "password": "wrong"})
    assert resp.status_code == 429

def test_login_does_not_enumerate(client, user_factory):
    known = user_factory(email="real@example.com")
    r1 = client.post("/login", data={"email": "real@example.com", "password": "wrong"})
    r2 = client.post("/login", data={"email": "nobody@example.com", "password": "wrong"})
    assert r1.status_code == r2.status_code == 401
    assert r1.data == r2.data   # Same body — no oracle.

def test_session_rotates_on_login(client, user_factory):
    user = user_factory(password="hunter2")
    with client.session_transaction() as s:
        s["csrf_token"] = "pre-login"
    pre = client.get_cookie("session").value
    client.post("/login", data={"email": user.email, "password": "hunter2"})
    post = client.get_cookie("session").value
    assert pre != post
```

**Jest (JavaScript).**
```javascript
describe("authentication", () => {
  it("rejects a token signed with the wrong algorithm", async () => {
    const forged = jwt.sign({ sub: "admin" }, PUBLIC_KEY_PEM, { algorithm: "HS256" });
    await expect(verifyToken(forged)).rejects.toThrow();
  });

  it("rate-limits login attempts per email+IP", async () => {
    for (let i = 0; i < 10; i++) {
      await request(app).post("/login").send({ email: "a@b.test", password: "x" });
    }
    const res = await request(app).post("/login").send({ email: "a@b.test", password: "x" });
    expect(res.status).toBe(429);
  });

  it("returns the same response for unknown and wrong-password accounts", async () => {
    const a = await request(app).post("/login").send({ email: "nobody@example.com", password: "x" });
    const b = await request(app).post("/login").send({ email: "real@example.com", password: "wrong" });
    expect(a.status).toBe(b.status);
    expect(a.body).toEqual(b.body);
  });

  it("regenerates the session cookie on successful login", async () => {
    const agent = request.agent(app);
    await agent.get("/");                                          // issues a sid
    const pre = agent.jar.getCookie("sid", { path: "/" })?.value;
    await agent.post("/login").send({ email: "real@example.com", password: "correct" });
    const post = agent.jar.getCookie("sid", { path: "/" })?.value;
    expect(pre).not.toBe(post);
  });
});
```

## Compliance mapping

| Framework | Control | Relevance |
| --- | --- | --- |
| **HIPAA Security Rule** | §164.312(a)(1) — Access Control | Unique user identification and authentication for ePHI access. |
| **HIPAA Security Rule** | §164.312(d) — Person or Entity Authentication | Verify that persons or entities seeking access to ePHI are who they claim to be. |
| **HIPAA Security Rule** | §164.308(a)(5)(ii)(D) — Password Management | Procedures for creating, changing, and safeguarding passwords. |
| **SOC 2 Trust Services Criteria** | CC6.1 — Logical Access Controls | Authentication is the gate on logical access. |
| **SOC 2 Trust Services Criteria** | CC6.2 — Registration and Authorization of New Users | Enrollment flow, initial credential issuance, identity proofing. |
| **SOC 2 Trust Services Criteria** | CC6.3 — Access Removal | Session revocation on role change or termination. |
| **NIST CSF 2.0** | PR.AA-01 — Identities and credentials are issued, managed, verified, revoked, and audited | Full credential lifecycle. |
| **NIST CSF 2.0** | PR.AA-02 — Identities are proofed and bound to credentials | Enrollment identity proofing. |
| **NIST CSF 2.0** | PR.AA-03 — Users, services, and hardware are authenticated | The core control. |
| **NIST CSF 2.0** | PR.AA-05 — Access permissions, entitlements, and authorizations are defined, managed, enforced, and reviewed | Authorization depends on correct authentication. |

For PCI-DSS v4, this maps to Requirement 8 (identify users and authenticate access to system components), including 8.3 (strong authentication), 8.3.6 (minimum password complexity where passwords are used as the sole factor), 8.4 (MFA for non-console admin access and all remote access into the CDE), and 8.5 (MFA implemented securely — no bypasses).
