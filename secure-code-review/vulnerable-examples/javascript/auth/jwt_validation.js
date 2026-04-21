/**
 * Insecure JWT Validation in Express — vulnerable and secure variants.
 *
 * Scenario: an Express middleware that extracts the current user from
 * the `Authorization: Bearer <jwt>` header. Every protected route
 * depends on it. Errors here are full-compromise bugs.
 *
 * Failure modes demonstrated:
 *
 *   1. jwt.decode() used as a validation step. It does not validate
 *      — it only decodes. Any attacker-controlled payload is accepted
 *      as truth.
 *
 *   2. jwt.verify() without an explicit `algorithms` option. In
 *      older jsonwebtoken versions (and still reachable in some
 *      misconfigurations), this enables the classic
 *      RS256-as-HS256 algorithm-confusion attack: the attacker
 *      signs the token with the server's PUBLIC key using HS256,
 *      and the server — configured with the public key as the HMAC
 *      secret — accepts it.
 *
 *   3. No expiry check, so a 90-day-old stolen token is still valid.
 *
 *   4. `kid` header trusted blindly — the server fetches a key from
 *      whatever URL the `kid` points at, creating an arbitrary-key
 *      validation oracle.
 *
 * The secure version uses RS256 with JWKS lookup constrained to the
 * authorization server, pins algorithm and issuer and audience,
 * enforces expiry, tolerates small clock skew, and returns a sanitized
 * error to the client while logging the real reason server-side.
 */

const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");

const EXPECTED_ISSUER = "https://auth.example.com/";
const EXPECTED_AUDIENCE = "api.example.com";

// ===========================================================================
// VULNERABLE middleware
// ===========================================================================

function authVulnerable(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.replace(/^Bearer /, "");

  // BUG 1: jwt.decode does NOT verify the signature. Any attacker-
  // constructed token with a valid shape is accepted.
  const payload = jwt.decode(token);
  if (!payload) return res.status(401).json({ error: "missing token" });

  // BUG 2: `role` is trusted verbatim from the token with no
  // validation that the token was signed by the authorization server.
  req.user = {
    id: payload.sub,
    role: payload.role,
    tenantId: payload.tenant_id,
  };
  next();
}

// Equally common variation — jwt.verify with no algorithms option.
//
//   jwt.verify(token, SHARED_SECRET, (err, decoded) => { ... });
//
// Against a library version that defaults to permissive algorithms,
// an attacker can craft an HS256-signed token using the server's
// RSA public key and the server validates it because it thinks the
// "secret" IS the public key.

// ===========================================================================
// SECURE middleware — layered defenses against each failure mode.
// ===========================================================================

// JWKS client constrained to the authorization server's jwks_uri.
// Caching reduces the chance of upstream dependence during a spike;
// rate limiting prevents an attacker from exhausting the cache with
// random `kid` values.
const keyClient = jwksClient({
  jwksUri: `${EXPECTED_ISSUER}.well-known/jwks.json`,
  cache: true,
  cacheMaxAge: 10 * 60 * 1000,
  rateLimit: true,
  jwksRequestsPerMinute: 10,
  timeout: 3000,
});

function getSigningKey(header, cb) {
  // `kid` must be a non-empty string; refuse anything else.
  if (!header.kid || typeof header.kid !== "string") {
    return cb(new Error("missing kid"));
  }
  keyClient.getSigningKey(header.kid, (err, key) => {
    if (err) return cb(err);
    cb(null, key.getPublicKey());
  });
}

function authSecure(req, res, next) {
  const header = req.headers.authorization || "";
  const match = /^Bearer (.+)$/.exec(header);
  if (!match) {
    return res.status(401).json({ error: "missing token" });
  }
  const token = match[1];

  jwt.verify(
    token,
    getSigningKey,
    {
      algorithms: ["RS256"],          // explicit allowlist — kills
                                      // alg=none and RS256-as-HS256
      issuer: EXPECTED_ISSUER,        // rejects tokens from other IdPs
      audience: EXPECTED_AUDIENCE,    // rejects tokens for other services
      clockTolerance: 30,             // seconds — absorb normal drift,
                                      // not a replay window
      complete: false,
    },
    (err, decoded) => {
      if (err) {
        // Log the real error server-side for debugging and detection.
        req.log?.warn(
          { reqId: req.id, err: err.message },
          "jwt rejected"
        );
        // Return a generic message to the client — no leak of whether
        // expiry, signature, or structure failed.
        return res.status(401).json({ error: "invalid token" });
      }

      // Additional application-specific invariants.
      if (!decoded.sub) {
        return res.status(401).json({ error: "invalid token" });
      }

      // Minimal, whitelisted fields. `role` is trusted at this level
      // only for non-privileged decisions; high-impact authorization
      // re-fetches the current role from the identity service.
      req.user = {
        id: decoded.sub,
        role: decoded.role ?? "user",
        tenantId: decoded.tenant_id,
        issuedAt: decoded.iat,
        expiresAt: decoded.exp,
      };

      next();
    }
  );
}

// ===========================================================================
// A per-route scope/role check, since authentication alone is not
// authorization. The reviewer's rule: every protected handler
// explicitly states what role or scope is required — never inferred
// from "the user is logged in."
// ===========================================================================

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "unauthenticated" });
    if (req.user.role !== role) {
      req.log?.info(
        { reqId: req.id, userId: req.user.id, required: role, actual: req.user.role },
        "forbidden"
      );
      return res.status(403).json({ error: "forbidden" });
    }
    next();
  };
}

// Usage:
//   app.use(authSecure);
//   app.post("/admin/users", requireRole("admin"), adminHandler);

// ===========================================================================
// Common patterns that look secure but are not, worth calling out in
// review:
//
// - `jwt.verify(token, getKeyFromKid, {...})` where `getKeyFromKid`
//   follows the URL embedded in the `kid` claim. This is an
//   arbitrary-key oracle — attacker controls which key you validate
//   against. Always pull keys from a fixed JWKS URI, not from the
//   token itself.
//
// - Trusting the `role` claim for high-privilege operations. The JWT
//   was issued minutes or hours ago; the user's entitlements may have
//   changed. For admin actions, re-check authorization against the
//   identity service at the moment of the action.
//
// - "We only use this behind the API gateway which already validated
//   the JWT." Until someone makes the service reachable from another
//   path — a cron job, a test harness, a migration script. Validate
//   on every entry point.
//
// - jwt.verify without `audience` and `issuer`. A token issued for a
//   different service in the same IdP passes signature validation.
//   You now accept another team's tokens.
// ===========================================================================

module.exports = { authVulnerable, authSecure, requireRole };
