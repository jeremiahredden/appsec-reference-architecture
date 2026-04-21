/**
 * NoSQL Injection — vulnerable and secure variants, side by side.
 *
 * Scenario: an Express + Mongoose login endpoint. The endpoint looks
 * up a user by email, verifies the password, and issues a session
 * token. The handler receives a JSON body and passes fields from it
 * directly into a Mongoose query.
 *
 * MongoDB accepts objects as query values (e.g., { $gt: "" } means
 * "greater than empty string"). If an attacker can submit an object
 * as a field where the code expects a string, the query engine
 * evaluates the object as a query operator. This is operator
 * injection — the most common NoSQL injection pattern in Node.js
 * applications.
 *
 * The classic payload converts "find a user with this password" into
 * "find any user." On a real login endpoint, that is authentication
 * bypass on any account whose email is known.
 */

const express = require("express");
const mongoose = require("mongoose");
const mongoSanitize = require("express-mongo-sanitize");
const argon2 = require("argon2");
const { z } = require("zod");

const User = mongoose.model(
  "User",
  new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true, select: false },
    role: { type: String, default: "user" },
  })
);

// ===========================================================================
// VULNERABLE app — accepts arbitrary JSON shapes into the query.
// ===========================================================================
function buildVulnerableApp() {
  const app = express();
  app.use(express.json());

  app.post("/login", async (req, res) => {
    // The attacker sends:
    //   { "email": "victim@example.com",
    //     "password": { "$ne": null } }
    //
    // Mongoose forwards the shape directly to MongoDB:
    //   db.users.findOne({
    //     email: "victim@example.com",
    //     passwordHash: { $ne: null }
    //   })
    //
    // Which matches the victim because their passwordHash is not null.
    // The attacker logs in without knowing the password.
    //
    // Variations that bypass email targeting entirely:
    //   { "email": { "$ne": null }, "password": { "$ne": null } }
    //   → returns the first user in the collection, usually an admin
    //     seeded during bootstrap.
    //
    //   { "email": { "$regex": "^admin" }, "password": { "$ne": null } }
    //   → returns admin@example.com or similar.
    const user = await User.findOne({
      email: req.body.email,
      passwordHash: req.body.password, // ← treated as a query operator
    });

    if (!user) return res.status(401).json({ error: "invalid credentials" });
    return res.json({ token: "vulnerable-session-token" });
  });

  return app;
}

// ===========================================================================
// SECURE app — layered defenses that each independently block the bug.
// ===========================================================================
function buildSecureApp() {
  const app = express();
  app.use(express.json({ limit: "10kb" }));

  // Layer 1: strip operator-style keys application-wide. This is the
  // belt-and-suspenders protection; even a handler that forgets to
  // validate will have `$ne`, `$gt`, `$regex` etc. stripped before it
  // ever runs. Keys containing `.` are also stripped (to prevent
  // dot-path traversal into nested documents).
  app.use(mongoSanitize({
    replaceWith: "_",
    onSanitize: ({ req, key }) => {
      // Log every sanitization event. Frequent triggers from a single
      // source is a reconnaissance signal.
      req.log?.warn({ reqId: req.id, key }, "mongo operator stripped");
    },
  }));

  // Layer 2: strict per-endpoint schema validation. Rejects any body
  // whose shape is not exactly `{ email: string, password: string }`.
  const LoginSchema = z.object({
    email: z.string().trim().toLowerCase().email().max(255),
    password: z.string().min(1).max(256),
  }).strict();

  app.post("/login", async (req, res) => {
    const parsed = LoginSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "invalid request" });
    }
    const { email, password } = parsed.data;

    // Layer 3: look up the user by email only, then explicitly verify
    // the password hash. The password never appears inside the query
    // filter, so operator injection cannot influence row selection.
    const user = await User.findOne({ email }).select("+passwordHash");
    if (!user || !(await argon2.verify(user.passwordHash, password))) {
      // Constant-response + constant-time comparison below — do NOT
      // branch the message between "no such user" and "wrong password."
      return res.status(401).json({ error: "invalid credentials" });
    }

    return res.json({ token: issueSessionToken(user) });
  });

  return app;
}

function issueSessionToken(_user) {
  // In a real app this signs a JWT; see javascript/auth/jwt_validation.js.
  return "secure-session-token";
}

// ===========================================================================
// Review notes:
//
// - The same pattern exists in other NoSQL stores and query
//   languages. DynamoDB queries that accept `FilterExpression`
//   strings with user-concatenated values. Elasticsearch queries that
//   accept a raw `query` object from the client. Treat every NoSQL
//   driver's query-object interface as equivalent to a SQL query —
//   user input goes in as values, never as operators or field names.
//
// - Input type checking alone (`typeof req.body.password === "string"`)
//   is sufficient in principle but brittle in practice; an async
//   middleware mutation, a JSON reviver, or a recursive parser can
//   reintroduce the problem. Schema validation with a library like zod
//   is not just type-checking — it is exhaustively shaped checking.
//
// - The mongo-sanitize middleware is a safety net, not the primary
//   control. Primary control is schema validation at the handler.
//   Define your defenses to be independent so that a failure of any
//   single layer still leaves the system safe.
//
// - Do not rely on Mongoose `String` schema types to save you.
//   Mongoose casts `{ $ne: null }` to a string in some contexts and
//   leaves it alone in others depending on version and options. Never
//   trust implicit casting for a security property.
// ===========================================================================

module.exports = { buildVulnerableApp, buildSecureApp };
