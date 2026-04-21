/**
 * Hardened counterpart to app.js.
 *
 * Every endpoint from app.js is implemented here with the vulnerability
 * removed. Read the two files side-by-side to see the exact shape of each
 * fix. This is what the pipeline should flag as clean (modulo dependency
 * CVEs, which the SCA stage handles separately).
 */

const express = require('express');
const mongoose = require('mongoose');
const mongoSanitize = require('express-mongo-sanitize');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { execFile } = require('child_process');
const net = require('net');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');

const app = express();
app.use(express.json({ limit: '100kb' }));

// FIX: missing-security-headers → helmet() mounted before any route handler.
// Sets X-Content-Type-Options, Referrer-Policy, HSTS, frameguard, etc.
app.use(helmet());

// FIX: permissive-cors → explicit origin allowlist from env.
const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      return cb(new Error('origin not allowed'));
    },
    credentials: true,
  }),
);

// FIX: nosql-injection (defense-in-depth) → strip `$` and `.` keys at ingress.
// Per-route validation still enforces exact shape; this is a second layer.
app.use(mongoSanitize());

// Conservative default rate limit. Tighter caps are applied on sensitive routes.
const defaultLimiter = rateLimit({ windowMs: 60_000, max: 60 });
app.use(defaultLimiter);

// FIX: hardcoded-secret → public key sourced from env, algorithm pinned below.
const JWT_PUBLIC_KEY = process.env.JWT_PUBLIC_KEY;
const JWT_PRIVATE_KEY = process.env.JWT_PRIVATE_KEY;
const JWT_ISSUER = process.env.JWT_ISSUER || 'demo-api';
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || 'demo-clients';
if (!JWT_PUBLIC_KEY || !JWT_PRIVATE_KEY) {
  throw new Error('JWT_PUBLIC_KEY and JWT_PRIVATE_KEY are required');
}

// FIX: ssrf → explicit proxy allowlist, populated from env and normalized once.
const ALLOWED_PROXY_HOSTS = new Set(
  (process.env.PROXY_ALLOWLIST || '')
    .split(',')
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean),
);

const db = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  connectionLimit: 10,
});

const UserSchema = new mongoose.Schema({ username: String, email: String, role: String });
const User = mongoose.model('User', UserSchema);

function requireAdmin(req, res, next) {
  // FIX: missing-authentication → bearer JWT required, admin role enforced.
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'unauthorized' });
  try {
    const claims = jwt.verify(auth.slice(7), JWT_PUBLIC_KEY, {
      algorithms: ['RS256'],
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });
    if (!Array.isArray(claims.roles) || !claims.roles.includes('admin')) {
      return res.status(403).json({ error: 'forbidden' });
    }
    req.claims = claims;
    return next();
  } catch {
    return res.status(401).json({ error: 'unauthorized' });
  }
}

app.get('/users', (req, res) => {
  // FIX: sql-injection → parameterized query.
  const { username } = req.query;
  if (typeof username !== 'string' || username.length > 64) {
    return res.status(400).json({ error: 'invalid username' });
  }
  db.query(
    'SELECT id, username, email FROM users WHERE username = ?',
    [username],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'query failed' });
      res.json(rows);
    },
  );
});

const SearchSchema = z.object({ username: z.string().min(1).max(64) }).strict();

app.post('/search', async (req, res) => {
  // FIX: nosql-injection → strict Zod schema; only the exact shape passes.
  const parsed = SearchSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid body' });
  const results = await User.find({ username: parsed.data.username });
  res.json(results);
});

const pingLimiter = rateLimit({ windowMs: 60_000, max: 5 });
app.get('/ping', pingLimiter, (req, res) => {
  // FIX: command-injection → execFile with an argv list, strict host validation.
  const { host } = req.query;
  if (typeof host !== 'string' || !net.isIP(host)) {
    return res.status(400).json({ error: 'invalid host' });
  }
  execFile('ping', ['-c', '1', host], { timeout: 5000 }, (err, stdout) => {
    if (err) return res.status(500).json({ error: 'ping failed' });
    res.type('text/plain').send(stdout);
  });
});

const FORBIDDEN_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

function safeMerge(target, source) {
  // FIX: prototype-pollution → skip reserved keys, enforce own-property check,
  // and never recurse into arrays or non-plain objects.
  for (const key of Object.keys(source)) {
    if (FORBIDDEN_KEYS.has(key)) continue;
    if (!Object.prototype.hasOwnProperty.call(source, key)) continue;
    const value = source[key];
    if (value && typeof value === 'object' && value.constructor === Object) {
      target[key] = safeMerge(target[key] && target[key].constructor === Object ? target[key] : {}, value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

app.post('/merge', (req, res) => {
  if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
    return res.status(400).json({ error: 'object body required' });
  }
  res.json(safeMerge({}, req.body));
});

function escapeHtml(s) {
  // FIX: xss → escape the five HTML-significant characters on reflection.
  return String(s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

app.get('/render', (req, res) => {
  const name = escapeHtml(req.query.name || 'guest');
  res
    .type('html')
    .send(`<!doctype html><html><body><h1>Hello, ${name}!</h1></body></html>`);
});

app.get('/proxy', async (req, res) => {
  // FIX: ssrf → scheme check, host allowlist, no redirects followed.
  let parsed;
  try {
    parsed = new URL(req.query.url);
  } catch {
    return res.status(400).json({ error: 'invalid url' });
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return res.status(400).json({ error: 'scheme not allowed' });
  }
  if (!ALLOWED_PROXY_HOSTS.has(parsed.hostname.toLowerCase())) {
    return res.status(400).json({ error: 'host not on allowlist' });
  }
  try {
    const r = await axios.get(parsed.toString(), {
      timeout: 5000,
      maxRedirects: 0,
      validateStatus: () => true,
    });
    res.json({ status: r.status, body: String(r.data).slice(0, 200) });
  } catch {
    res.status(502).json({ error: 'fetch failed' });
  }
});

app.post('/verify', (req, res) => {
  // FIX: jwt-alg-confusion → pin RS256, assert issuer + audience.
  const { token } = req.body || {};
  if (typeof token !== 'string') return res.status(400).json({ error: 'token required' });
  try {
    const claims = jwt.verify(token, JWT_PUBLIC_KEY, {
      algorithms: ['RS256'],
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });
    res.json({ claims });
  } catch {
    res.status(401).json({ error: 'invalid token' });
  }
});

app.post('/token', (req, res) => {
  const token = jwt.sign(
    { sub: 'demo-user' },
    JWT_PRIVATE_KEY,
    { algorithm: 'RS256', issuer: JWT_ISSUER, audience: JWT_AUDIENCE, expiresIn: '15m' },
  );
  res.json({ token });
});

app.get('/admin', requireAdmin, (req, res) => {
  res.json({ users: ['alice', 'bob'] });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '127.0.0.1', () => {
  // eslint-disable-next-line no-console
  console.log(`Hardened demo API listening on 127.0.0.1:${PORT}`);
});
