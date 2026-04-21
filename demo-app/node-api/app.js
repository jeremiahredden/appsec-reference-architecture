/**
 * Intentionally vulnerable Express API — pipeline scan target.
 *
 * EDUCATIONAL USE ONLY. Do not deploy. Do not run against production data.
 * Every vulnerability below is marked with:
 *     // VULNERABILITY: <class> — intentional for pipeline demonstration
 *
 * The secure counterpart for each handler is commented directly below it so
 * a reader can see the delta without flipping files. See secure_app.js for
 * the consolidated hardened build the pipeline should flag as clean.
 */

const express = require('express');
const mongoose = require('mongoose');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { exec } = require('child_process');
const cors = require('cors');

const app = express();
app.use(express.json());

// VULNERABILITY: permissive-cors — intentional for pipeline demonstration
// `origin: '*'` with credentials allowed on routes downstream is the worst
// combination — any site can call the API from a user's browser.
// Secure counterpart: explicit origin allowlist.
app.use(cors({ origin: '*', credentials: true }));
// SECURE:
// const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS || '').split(',').filter(Boolean);
// app.use(cors({ origin: ALLOWED_ORIGINS, credentials: true }));

// VULNERABILITY: missing-security-headers — intentional for pipeline demonstration
// No helmet(). Responses ship without X-Content-Type-Options, CSP, HSTS, etc.
// Secure counterpart: helmet() mounted before any route handler.
// SECURE:
// const helmet = require('helmet');
// app.use(helmet());

// VULNERABILITY: hardcoded-secret — intentional for pipeline demonstration
// Static string in source, same across every environment.
// Secure counterpart: env-sourced, algorithm pinned.
const JWT_SECRET = 'weakpassword';
// SECURE:
// const JWT_PUBLIC_KEY = process.env.JWT_PUBLIC_KEY;   // RS256 public key
// if (!JWT_PUBLIC_KEY) { throw new Error('JWT_PUBLIC_KEY is required'); }

// MySQL connection used by the SQL-injection demo. The vulnerability is in
// how queries are assembled, not the driver itself.
const db = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'demo',
  password: process.env.DB_PASS || 'demo',
  database: process.env.DB_NAME || 'demo',
});

// Mongo model for the NoSQL-injection demo.
const UserSchema = new mongoose.Schema({ username: String, email: String, role: String });
const User = mongoose.model('User', UserSchema);

app.get('/users', (req, res) => {
  // VULNERABILITY: sql-injection — intentional for pipeline demonstration
  // `?username=' OR 1=1 --` dumps the table. Concatenated into the SQL body.
  const { username } = req.query;
  const query = `SELECT id, username, email FROM users WHERE username = '${username}'`;
  db.query(query, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});
// SECURE:
// app.get('/users', (req, res) => {
//   const { username } = req.query;
//   db.query(
//     'SELECT id, username, email FROM users WHERE username = ?',
//     [username],
//     (err, rows) => {
//       if (err) return res.status(500).json({ error: 'query failed' });
//       res.json(rows);
//     },
//   );
// });

app.post('/search', async (req, res) => {
  // VULNERABILITY: nosql-injection — intentional for pipeline demonstration
  // Passing req.body straight into find() lets a client send
  // `{"username": {"$ne": null}}` and enumerate every user.
  const results = await User.find(req.body);
  res.json(results);
});
// SECURE:
// const mongoSanitize = require('express-mongo-sanitize');
// app.use(mongoSanitize());
// app.post('/search', async (req, res) => {
//   const schema = z.object({ username: z.string().min(1).max(64) }).strict();
//   const parsed = schema.safeParse(req.body);
//   if (!parsed.success) return res.status(400).json({ error: 'invalid body' });
//   const results = await User.find({ username: parsed.data.username });
//   res.json(results);
// });

app.get('/ping', (req, res) => {
  // VULNERABILITY: command-injection — intentional for pipeline demonstration
  // `?host=8.8.8.8; cat /etc/passwd` executes both commands via the shell.
  const { host } = req.query;
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    if (err) return res.status(500).json({ error: err.message });
    res.type('text/plain').send(stdout);
  });
});
// SECURE:
// const { execFile } = require('child_process');
// const net = require('net');
// app.get('/ping', (req, res) => {
//   const { host } = req.query;
//   if (!net.isIP(host)) return res.status(400).json({ error: 'invalid host' });
//   execFile('ping', ['-c', '1', host], { timeout: 5000 }, (err, stdout) => {
//     if (err) return res.status(500).json({ error: 'ping failed' });
//     res.type('text/plain').send(stdout);
//   });
// });

app.post('/merge', (req, res) => {
  // VULNERABILITY: prototype-pollution — intentional for pipeline demonstration
  // Recursive merge without hasOwnProperty checks — a payload like
  // `{"__proto__": {"isAdmin": true}}` pollutes Object.prototype.
  const merge = (target, source) => {
    for (const key in source) {
      if (typeof source[key] === 'object' && source[key] !== null) {
        target[key] = target[key] || {};
        merge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
    return target;
  };
  const result = merge({}, req.body);
  res.json(result);
});
// SECURE:
// const FORBIDDEN = new Set(['__proto__', 'prototype', 'constructor']);
// const safeMerge = (target, source) => {
//   for (const key of Object.keys(source)) {
//     if (FORBIDDEN.has(key)) continue;
//     if (!Object.prototype.hasOwnProperty.call(source, key)) continue;
//     const value = source[key];
//     if (value && typeof value === 'object' && !Array.isArray(value)) {
//       target[key] = safeMerge(target[key] || {}, value);
//     } else {
//       target[key] = value;
//     }
//   }
//   return target;
// };

app.get('/render', (req, res) => {
  // VULNERABILITY: xss — intentional for pipeline demonstration
  // Reflected HTML with no encoding — `?name=<script>alert(1)</script>` fires.
  const { name } = req.query;
  res.send(`<html><body><h1>Hello, ${name}!</h1></body></html>`);
});
// SECURE:
// const escapeHtml = (s) => String(s).replace(/[&<>"'/]/g, (c) => ({
//   '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '/': '&#47;',
// }[c]));
// app.get('/render', (req, res) => {
//   const name = escapeHtml(req.query.name || 'guest');
//   res.type('html').send(`<!doctype html><html><body><h1>Hello, ${name}!</h1></body></html>`);
// });

app.get('/proxy', async (req, res) => {
  // VULNERABILITY: ssrf — intentional for pipeline demonstration
  // Unvalidated outbound fetch — cloud metadata, internal admin panels,
  // localhost services. No scheme check, no host allowlist.
  const { url } = req.query;
  try {
    const r = await axios.get(url, { timeout: 5000 });
    res.json({ status: r.status, body: String(r.data).slice(0, 200) });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});
// SECURE:
// const ALLOWED_PROXY_HOSTS = new Set(
//   (process.env.PROXY_ALLOWLIST || '').split(',').map((h) => h.trim().toLowerCase()).filter(Boolean),
// );
// app.get('/proxy', async (req, res) => {
//   let parsed;
//   try { parsed = new URL(req.query.url); } catch { return res.status(400).json({ error: 'invalid url' }); }
//   if (!['http:', 'https:'].includes(parsed.protocol)) return res.status(400).json({ error: 'scheme not allowed' });
//   if (!ALLOWED_PROXY_HOSTS.has(parsed.hostname.toLowerCase())) return res.status(400).json({ error: 'host not on allowlist' });
//   const r = await axios.get(parsed.toString(), { timeout: 5000, maxRedirects: 0, validateStatus: () => true });
//   res.json({ status: r.status, body: String(r.data).slice(0, 200) });
// });

app.post('/verify', (req, res) => {
  // VULNERABILITY: jwt-alg-confusion — intentional for pipeline demonstration
  // Calling verify() without { algorithms } lets an attacker hand-craft a
  // token with `alg: none` (or HS256 against an RS256 public key) and win.
  const { token } = req.body;
  try {
    const claims = jwt.verify(token, JWT_SECRET);
    res.json({ claims });
  } catch (e) {
    res.status(401).json({ error: 'invalid token' });
  }
});
// SECURE:
// app.post('/verify', (req, res) => {
//   const { token } = req.body;
//   try {
//     const claims = jwt.verify(token, JWT_PUBLIC_KEY, {
//       algorithms: ['RS256'],
//       issuer: process.env.JWT_ISSUER,
//       audience: process.env.JWT_AUDIENCE,
//     });
//     res.json({ claims });
//   } catch {
//     res.status(401).json({ error: 'invalid token' });
//   }
// });

app.post('/token', (req, res) => {
  // Uses the hardcoded secret above — keeps the gitleaks / Semgrep finding
  // tied to a real use site rather than a dead constant.
  const token = jwt.sign({ sub: 'demo-user' }, JWT_SECRET);
  res.json({ token });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`Vulnerable demo API listening on :${PORT}`);
});
