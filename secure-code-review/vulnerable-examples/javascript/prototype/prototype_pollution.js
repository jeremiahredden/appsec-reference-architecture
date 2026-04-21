/**
 * Prototype Pollution — vulnerable and secure variants, side by side.
 *
 * Scenario: a user-preferences endpoint that merges an update payload
 * into the current user's preferences. The vulnerable implementation
 * uses a recursive merge helper, which is the canonical pattern
 * behind CVE-2019-10744 (lodash.merge), CVE-2018-16487 (lodash.mergeWith),
 * CVE-2018-3721 (lodash 4.x at large), and dozens of downstream
 * packages.
 *
 * Prototype pollution matters because it is a supply-chain-scale bug:
 * polluting Object.prototype changes the default value of a property
 * on every object in the process. A vulnerable merge in an obscure
 * preferences endpoint gives the attacker the ability to set
 * `isAdmin: true` on every object the application subsequently
 * checks, for the rest of the process lifetime.
 */

// ===========================================================================
// VULNERABLE — naive recursive merge.
// ===========================================================================
function mergeVulnerable(target, source) {
  for (const key in source) {
    if (
      source[key] !== null &&
      typeof source[key] === "object" &&
      !Array.isArray(source[key])
    ) {
      // The bug: when `key` is "__proto__" (or "constructor.prototype"),
      // `target[key]` resolves to Object.prototype, and the recursive
      // assignment writes to it. Every object in the process now has
      // the attacker's keys on its prototype chain.
      target[key] = target[key] || {};
      mergeVulnerable(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// The exploit, demonstrated end-to-end:
//
//   const attackerInput = JSON.parse(
//     '{"__proto__": {"isAdmin": true, "role": "admin"}}'
//   );
//   mergeVulnerable({}, attackerInput);
//
//   // After this call:
//   ({}).isAdmin  // → true
//   ({}).role     // → "admin"
//
//   // Any downstream authorization check like:
//   if (user.isAdmin) { /* grant admin */ }
//   // ...passes for EVERY user object, because `isAdmin` is inherited
//   // from the polluted prototype.
//
// Worse: the pollution persists for the life of the Node process.
// A single unauthenticated request can escalate privileges for every
// subsequent request handled by the same process.


// ===========================================================================
// SECURE — schema validation + null-prototype merge + key allowlist.
// ===========================================================================
const { z } = require("zod");

// Layer 1: explicit, strict schema for the update. zod's `.strict()`
// rejects any key that is not in the schema — including `__proto__`,
// `constructor`, and `prototype`.
const PrefsSchema = z
  .object({
    theme: z.enum(["light", "dark", "system"]).optional(),
    density: z.enum(["compact", "comfortable"]).optional(),
    language: z.string().regex(/^[a-z]{2}(-[A-Z]{2})?$/).optional(),
    notifications: z
      .object({
        email: z.boolean().optional(),
        sms: z.boolean().optional(),
      })
      .strict()
      .optional(),
  })
  .strict();

// Layer 2: a safe merge helper that rejects dangerous keys by name
// and uses a null-prototype result so the merged object does not
// inherit from Object.prototype at all.
const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function safeMerge(base, update) {
  // Null-prototype object: no inherited keys, no accidental exposure
  // of the Object.prototype chain through the merged result.
  const out = Object.create(null);

  for (const key of Object.keys(base)) {
    if (DANGEROUS_KEYS.has(key)) continue;
    out[key] = base[key];
  }

  for (const key of Object.keys(update)) {
    if (DANGEROUS_KEYS.has(key)) continue;
    if (!Object.prototype.hasOwnProperty.call(update, key)) continue;

    const val = update[key];
    if (val !== null && typeof val === "object" && !Array.isArray(val)) {
      // Recursive merge — but each recursion level creates a fresh
      // null-prototype object, so pollution cannot propagate.
      out[key] = safeMerge(out[key] ?? Object.create(null), val);
    } else {
      out[key] = val;
    }
  }

  return out;
}

// The secure handler. Three independent layers of defense, so a
// failure of any one still leaves the system safe.
function updatePreferencesSecure(currentPrefs, updatePayload) {
  // Layer 1: schema validation at the handler boundary.
  const parsed = PrefsSchema.safeParse(updatePayload);
  if (!parsed.success) {
    throw new Error("invalid prefs");
  }

  // Layer 2+3: safe merge, null prototype, key allowlist.
  return safeMerge(currentPrefs, parsed.data);
}


// ===========================================================================
// Defense-in-depth options worth considering at the process level:
//
// - Node 20+ flag: `--disable-proto=delete`. Removes the `__proto__`
//   setter entirely (`__proto__` becomes a regular own property, not
//   a special accessor). This kills a large fraction of prototype-
//   pollution gadgets across the whole process without code changes.
//
// - Object.freeze(Object.prototype): freezes Object.prototype at
//   process start. Any later write to it throws (in strict mode) or
//   is silently dropped (in sloppy mode). Some libraries genuinely
//   write to Object.prototype, so test this one carefully.
//
// - Map instead of plain object, wherever possible. A Map does not
//   have a prototype chain for string keys — it is a structurally
//   safer data structure for user-controlled key-value storage.
//
// None of these replace schema validation at the boundary. Validation
// is the primary control; the process-level flags are a mitigation
// for code you do not control (dependencies).
// ===========================================================================

// ===========================================================================
// Review checklist for prototype-pollution risk in a PR:
//
//   □ Any recursive merge / deep-clone that iterates keys from untrusted
//     input?
//   □ Any use of `lodash.merge`, `lodash.mergeWith`, `lodash.set`,
//     `lodash.defaultsDeep`? Check versions against the relevant CVEs.
//   □ Any dynamic property assignment `obj[key] = value` where `key`
//     comes from user input without an allowlist check?
//   □ Any JSON parse with a reviver that constructs objects by
//     attacker-controlled key names?
//   □ Does the code set keys on a plain `{}` object, or on a
//     `Object.create(null)` / `Map` / typed class? The former is
//     pollutable; the latter two are not.
// ===========================================================================

module.exports = {
  mergeVulnerable,
  safeMerge,
  updatePreferencesSecure,
  PrefsSchema,
};
