/**
 * Hardcoded Secrets — vulnerable and secure patterns, side by side.
 *
 * Scenario: a Node.js service that charges cards via Stripe and
 * writes transaction records to Postgres. It needs two credentials:
 * the Stripe secret key and the Postgres connection string.
 *
 * The vulnerable version is the pattern `gitleaks` flags every day.
 * The secure version is the progression: dotenv-safe for local dev,
 * a secrets manager abstraction for production, one config module
 * that validates the loaded values and fails fast on startup.
 *
 * Reminder: if you find committed secrets during review, treat them
 * as compromised. Removing the line does not un-leak them — they
 * are in git history, on every developer's machine, in every CI
 * cache, and very possibly in training data for some LLM.
 */

// ===========================================================================
// VULNERABLE — do not do any of this.
// ===========================================================================

// Bug 1: a literal secret in source. gitleaks catches this on commit,
// but only if the hook is installed. Lives in git history either way.
const STRIPE_SECRET = "sk_live_EXAMPLE_NOT_A_REAL_KEY // example format

// Bug 2: credentials embedded in a connection URL, committed.
const DATABASE_URL =
  "postgres://svc_payments:S3cretP@ssw0rd@prod-db.internal:5432/payments";

// Bug 3: "defensive" fallback default that is itself a live secret.
// Reads plausible — ships a real credential if the env var is missing.
const DATADOG_API_KEY =
  process.env.DATADOG_API_KEY || "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";

// Bug 4: test fixture with real-shaped credentials that grep-bait the
// scanner into false positives, so the real leak hides in the noise.
// (Yes, I have seen this used intentionally. It is a bad pattern.)
const TEST_STRIPE_KEY = "sk_test_FAKE0000000000000000000000";

async function chargeVulnerable(amountCents, sourceToken) {
  const Stripe = require("stripe");
  const stripe = new Stripe(STRIPE_SECRET);
  return stripe.charges.create({ amount: amountCents, source: sourceToken, currency: "usd" });
}


// ===========================================================================
// SECURE — one config module, fail-fast validation, pluggable source.
// ===========================================================================
//
// Directory convention:
//
//   .env.example      — committed. Lists the variable NAMES with
//                       placeholder values. dotenv-safe uses this as
//                       the "required keys" contract.
//
//   .env              — NOT committed (in .gitignore). Real values
//                       for local development only.
//
//   Production        — env vars come from the platform's secret
//                       store (AWS Secrets Manager via a
//                       pre-deploy hook, HashiCorp Vault agent,
//                       Kubernetes externalSecrets, etc.). The
//                       application code is unchanged — it reads
//                       from process.env either way.
//
// ---------------------------------------------------------------------------
// .env.example (committed, no real values) — lists required vars:
//
//   NODE_ENV=
//   STRIPE_SECRET=
//   DATABASE_URL=
//   DATADOG_API_KEY=
//
// ---------------------------------------------------------------------------

const { z } = require("zod");

// In CI / prod, `.env` does not exist — dotenv-safe is a no-op
// because real env vars are already populated. Locally it ensures
// every required key is present and yells if one is missing.
require("dotenv-safe").config({
  allowEmptyValues: false,
  example: ".env.example",
});

// Schema-driven validation: every environment variable is declared
// with the type + constraints it must satisfy. If something is
// missing or malformed, the process crashes on startup with a clear
// error — not three hours later when a customer hits a broken code
// path.
const EnvSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]),

  // Format hint catches swapped keys (live vs test) and typos.
  STRIPE_SECRET: z
    .string()
    .regex(/^sk_(live|test)_[A-Za-z0-9]{16,}$/, "invalid Stripe secret format"),

  DATABASE_URL: z.string().url(),

  // Hex, exactly 32 chars — catches truncated or malformed keys.
  DATADOG_API_KEY: z.string().regex(/^[0-9a-f]{32}$/),
});

let env;
try {
  env = EnvSchema.parse(process.env);
} catch (err) {
  // Fail fast with the clearest possible diagnostic.
  console.error("Environment validation failed:");
  for (const issue of err.errors ?? []) {
    console.error(`  - ${issue.path.join(".")}: ${issue.message}`);
  }
  process.exit(1);
}

// Guardrail: in production, refuse to run if a Stripe test key is
// loaded, or vice versa. Catches deploy-time config mixups.
if (env.NODE_ENV === "production" && env.STRIPE_SECRET.startsWith("sk_test_")) {
  console.error("Refusing to start: Stripe TEST key loaded in production");
  process.exit(1);
}

module.exports.env = env;


// ===========================================================================
// Secrets-manager abstraction — optional, and preferred over raw env
// vars for high-value secrets that should be rotatable without a
// redeploy.
// ===========================================================================

class SecretsProvider {
  constructor(environment) {
    this.environment = environment;
    this.cache = new Map();
    if (environment === "production") {
      const {
        SecretsManagerClient,
        GetSecretValueCommand,
      } = require("@aws-sdk/client-secrets-manager");
      this.client = new SecretsManagerClient({});
      this.GetSecretValueCommand = GetSecretValueCommand;
    }
  }

  async get(name) {
    if (this.cache.has(name)) return this.cache.get(name);

    let value;
    if (this.environment === "production") {
      const resp = await this.client.send(
        new this.GetSecretValueCommand({ SecretId: `/payments/prod/${name}` })
      );
      value = resp.SecretString;
      if (!value) {
        throw new Error(`secret ${name} is empty or binary`);
      }
    } else {
      const envName = name.toUpperCase();
      value = process.env[envName];
      if (!value) {
        throw new Error(
          `secret ${name} missing; set ${envName} in your .env file`
        );
      }
    }
    this.cache.set(name, value);
    return value;
  }
}

const secrets = new SecretsProvider(env.NODE_ENV);

async function chargeSecure(amountCents, sourceToken) {
  const Stripe = require("stripe");

  // Lazy fetch — prod hits Secrets Manager once, then cache.
  const stripe = new Stripe(await secrets.get("stripe_secret"));
  return stripe.charges.create({
    amount: amountCents,
    source: sourceToken,
    currency: "usd",
  });
}


// ===========================================================================
// If you inherit a repo with committed secrets, this is the response:
//
//   1. Treat every committed secret as compromised. Removing the line
//      is not remediation.
//
//   2. Rotate the credential at its source (Stripe dashboard, AWS
//      IAM, DB user) and put the new value in the secrets manager.
//
//   3. Audit usage in the log window before rotation. Unknown callers
//      or anomalous patterns = incident.
//
//   4. Purge from history after rotation, with git-filter-repo or BFG,
//      coordinating a force-push with the whole team.
//
//   5. Install gitleaks (or equivalent) as a pre-commit hook and as a
//      CI step on the default branch. The next developer's mistake is
//      then caught before the credential is ever pushed.
// ===========================================================================

module.exports.chargeSecure = chargeSecure;
module.exports.secrets = secrets;
