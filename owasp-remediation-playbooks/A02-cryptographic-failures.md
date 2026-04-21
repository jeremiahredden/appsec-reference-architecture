# A02 — Cryptographic Failures

## What it is

Cryptographic failures are the set of bugs where data that should be confidential, authentic, or tamper-evident is not — because the wrong primitive was used, the right primitive was used the wrong way, a key was handled carelessly, or encryption was skipped on a path the author assumed was safe. The category was renamed from "Sensitive Data Exposure" in the 2021 revision to emphasize that the root cause is almost always a cryptographic choice, not a data-handling choice.

Most cryptographic failures are not "they used RC4." They are "they used AES-GCM with a reused IV," "they used MD5 for password storage," or "they used `Math.random()` to generate a session token." The primitives are right; the usage is wrong.

## Why it matters

A concrete exploit: a Node.js service stores customer passwords hashed with `crypto.createHash('sha256').update(password).digest('hex')`. An attacker dumps the database through a separate SQL injection. SHA-256 is a fast hash; the attacker runs `hashcat` with a 2-billion-word dictionary, cracks 78% of the passwords in 90 minutes on a single consumer GPU, and credential-stuffs the cracked passwords against the company's email provider and banking partners. Many users reused the same password.

The fix is `argon2.hash(password)`. The difference is a 10^9 slowdown for an attacker and no user-visible impact. The cost of getting this wrong is a credential-stuffing campaign that affects users on platforms the company does not control.

Other common shapes:

- **TLS missing or optional**: an API accepts HTTP as well as HTTPS for historical reasons; a downgrade attack strips TLS entirely.
- **Weak random for tokens**: session IDs, password reset tokens, API keys generated with `random` or `Math.random` — recoverable state, not secret.
- **Hard-coded signing keys**: JWT `HS256` with a secret that is in the repo, rotated never.
- **Unauthenticated encryption**: AES-CBC without an HMAC, vulnerable to padding-oracle bit-flipping.
- **Secrets in logs**: Authorization headers, session cookies, or request bodies captured in log aggregation with broader access than the primary data store.

## How to find it

**Manual review indicators.** In storage code, look for any use of `hashlib.md5`, `hashlib.sha1`, `hashlib.sha256`, or raw `crypto.createHash` being used to hash passwords. Any symmetric encryption that uses AES-CBC without an accompanying HMAC is suspicious; any AES-GCM implementation that sets a fixed or plaintext-derived IV is broken. Any JWT signed with HS256 using a secret loaded from an environment variable shared with other services is over-trusted. Any TLS configuration that supports TLS 1.0 or 1.1, or allows RC4 or 3DES cipher suites, is out of date.

**Automated signals.**

- Semgrep: `python.cryptography.security.insecure-hash-algorithms` (MD5, SHA-1 uses).
- Semgrep custom rule: `weak-password-hash` (this repo — catches MD5/SHA-1 on anything named like a password).
- Semgrep: `python.lang.security.audit.insecure-pycrypto` (use of the unmaintained `pycrypto` — migrate to `cryptography`).
- Semgrep: `javascript.lang.security.audit.math-random-security-sensitive` (`Math.random()` in security-sensitive contexts).
- Bandit: `B303` (MD5 use), `B305` (DES/insecure cipher), `B324` (insecure hash), `B501` (requests with `verify=False`).
- Snyk Code: `javascript/WeakCryptoAlgorithm`, `javascript/HardcodedSecret`.
- TLS scanning with `testssl.sh` or `sslyze` against deployed endpoints.

## How to fix it — Python

**Vulnerable.**
```python
import hashlib
import random
import string

# Password stored as a fast hash — crackable in minutes.
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# Session token from Mersenne Twister — state is recoverable from output.
def generate_session_token(length: int = 32) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))

# JWT with a weak, shared, never-rotated secret.
JWT_SECRET = "production-jwt-secret-2019"

def sign_token(payload: dict) -> str:
    import jwt
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")
```

**Secure.**
```python
import secrets
from argon2 import PasswordHasher, exceptions as argon2_exc
from cryptography.hazmat.primitives import serialization

# Argon2id with tuned parameters — ~50 ms per verification on target
# hardware. Revisit the parameters annually; a slowdown an attacker
# sees is the security property, so "too slow for us" is a red flag
# but "as fast as SHA-256" is a broken deployment.
_ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

def hash_password(password: str) -> str:
    return _ph.hash(password)

def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _ph.verify(stored_hash, password)
    except argon2_exc.VerifyMismatchError:
        return False

# 32 bytes → 256 bits of entropy from the OS CSPRNG, URL-safe encoding.
def generate_session_token() -> str:
    return secrets.token_urlsafe(32)

# JWT signed with RS256 using a private key loaded at boot. The
# verifiers have only the public key — even if an app host is
# compromised, new tokens cannot be minted without the authorization
# server's private key.
def _load_private_key():
    import os
    pem = os.environ["JWT_PRIVATE_KEY_PEM"].encode()
    return serialization.load_pem_private_key(pem, password=None)

def sign_token(payload: dict) -> str:
    import jwt
    return jwt.encode(payload, _load_private_key(), algorithm="RS256")
```

## How to fix it — JavaScript

**Vulnerable.**
```javascript
const crypto = require("crypto");

function hashPassword(password) {
  // SHA-1, no salt, fast. Cracked in seconds at billions of guesses per sec.
  return crypto.createHash("sha1").update(password).digest("hex");
}

function generateSessionToken() {
  // Math.random is a PRNG with recoverable state, not cryptographic.
  return Math.random().toString(36).slice(2);
}

// Plaintext logging of the full Authorization header.
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path} auth=${req.headers.authorization}`);
  next();
});
```

**Secure.**
```javascript
const crypto = require("crypto");
const argon2 = require("argon2");

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

function generateSessionToken() {
  // OS CSPRNG, 256 bits of entropy, URL-safe base64.
  return crypto.randomBytes(32).toString("base64url");
}

// Log without the Authorization header. Log request ID and path; the
// full request context goes to a separate stream with stricter access.
app.use((req, res, next) => {
  req.log.info({ method: req.method, path: req.path, reqId: req.id }, "request");
  next();
});
```

For transport security, the Node service should set `strictSSL: true` on any outbound client, and `helmet()` at the app level to emit `Strict-Transport-Security` with a long max-age and `includeSubDomains; preload`. Terminate TLS with TLS 1.2+ only; disable RC4, 3DES, and export ciphers at the load balancer.

## How to test the fix

**pytest (Python).**
```python
import re

def test_password_hash_is_argon2id(user_factory):
    user = user_factory(password="correct horse battery staple")
    # Argon2 hashes start with $argon2id$ and include cost parameters.
    assert user.password_hash.startswith("$argon2id$")
    assert re.match(r"^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$", user.password_hash)

def test_session_token_has_sufficient_entropy():
    from myapp.tokens import generate_session_token
    token = generate_session_token()
    assert len(token) >= 43          # 32 bytes base64url ≈ 43 chars
    # No ascii-printable repetition that would indicate weak generation.
    assert len(set(token)) > 15

def test_jwt_uses_rs256_not_hs256():
    import base64, json
    from myapp.auth import sign_token
    token = sign_token({"sub": "u-1"})
    header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
    assert header["alg"] == "RS256"
```

**Jest (JavaScript).**
```javascript
describe("cryptographic hygiene", () => {
  it("stores password as argon2id", async () => {
    const user = await userFactory({ password: "correct horse battery staple" });
    expect(user.passwordHash).toMatch(/^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$/);
  });

  it("generates session tokens with ≥256 bits of entropy", () => {
    const { generateSessionToken } = require("../auth/tokens");
    const a = generateSessionToken();
    const b = generateSessionToken();
    expect(a).not.toBe(b);
    expect(a.length).toBeGreaterThanOrEqual(43); // 32 bytes base64url
  });

  it("signs JWTs with RS256", () => {
    const { signToken } = require("../auth/jwt");
    const token = signToken({ sub: "u-1" });
    const header = JSON.parse(Buffer.from(token.split(".")[0], "base64url"));
    expect(header.alg).toBe("RS256");
  });
});
```

## Compliance mapping

| Framework | Control | Relevance |
| --- | --- | --- |
| **HIPAA Security Rule** | §164.312(a)(2)(iv) — Encryption and Decryption | "Implement a mechanism to encrypt and decrypt electronic protected health information." Addressable standard; in practice, NIST-recognized algorithms at current-era strength are the baseline. |
| **HIPAA Security Rule** | §164.312(e)(1) — Transmission Security | Integrity and encryption controls on ePHI in transit; TLS 1.2+ with strong cipher suites. |
| **HIPAA Security Rule** | §164.312(c)(1) — Integrity | Protect ePHI from improper alteration or destruction; authenticated encryption (AEAD) addresses this at rest. |
| **SOC 2 Trust Services Criteria** | CC6.1 — Logical Access Controls | Includes protection of data in transit and at rest as part of access control. |
| **SOC 2 Trust Services Criteria** | CC6.6 — Transmission of Sensitive Information | Encrypt transmission of sensitive information over public networks. |
| **SOC 2 Trust Services Criteria** | CC6.7 — Restriction of Physical and Logical Access | Key management is part of controlling access to the cryptographic material that protects data. |
| **NIST CSF 2.0** | PR.DS-01 — Data-at-rest is protected | AES-GCM or AES-CCM at storage layer, with keys in a KMS. |
| **NIST CSF 2.0** | PR.DS-02 — Data-in-transit is protected | TLS 1.2+ across every external boundary; mTLS for service-to-service. |
| **NIST CSF 2.0** | PR.DS-11 — Backups of data are created, protected, maintained, and tested | Backups encrypted with a separate key scope from the primary data. |
| **NIST CSF 2.0** | PR.PS-01 — Configuration management practices are applied | Cryptographic configuration is part of this — pinned TLS versions, pinned cipher lists, key rotation cadence. |

For PCI-DSS v4 environments, this maps to Requirement 3 (protect stored account data) and Requirement 4 (protect cardholder data with strong cryptography during transmission).
