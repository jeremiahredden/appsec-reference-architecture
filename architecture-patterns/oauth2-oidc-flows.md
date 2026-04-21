# OAuth2 / OIDC Flows — A Practitioner's Guide

## The opinion up front

Most applications should use **Authorization Code + PKCE** for user-facing login and **Client Credentials** for service-to-service. Those two flows cover probably 90% of real implementations. **Device Flow** handles the input-constrained cases (CLIs, smart TVs, IoT onboarding). **Implicit flow** should not be used in new designs. **Resource Owner Password Credentials** should not be used in new designs. **Hybrid flow** is a holdover from OIDC's early compromises and is rarely the right answer today.

OAuth2 is an authorization framework; OIDC is an authentication layer built on top of it. If you need to know *who* the user is (most login flows), you need OIDC, not plain OAuth2. The `id_token` is an OIDC thing; the `access_token` is an OAuth2 thing. An access token proves *authorization* (this bearer can call this API); an ID token proves *authentication* (this user signed in at this IdP at this time).

## Terminology reference

| Term | Meaning |
| --- | --- |
| **Resource Owner** | The human user (or, in CC, the machine principal). |
| **Client** | The application requesting access. "Public" if it cannot safely store a secret (SPA, mobile, CLI); "confidential" if it can (backend service). |
| **Authorization Server (AS)** | The IdP — issues tokens. Okta, Auth0, Entra, Keycloak, your own. |
| **Resource Server (RS)** | The API the access token lets you call. |
| **Access token** | Bearer token for the RS. Usually a JWT signed by the AS; sometimes opaque + introspection. |
| **ID token** | JWT containing claims about the authenticated user, for the client's consumption. |
| **Refresh token** | Long-lived token the client uses to obtain new access tokens without user interaction. Rotate on use. |
| **Scope** | What the token is allowed to do (`invoices:read`, `users:write`). |
| **Audience (`aud`)** | Which RS the token is for. Must be validated. |
| **Issuer (`iss`)** | Which AS minted the token. Must be validated. |

---

## 1. Authorization Code + PKCE

### When to use

- First-party web apps (SPA or server-rendered).
- First-party mobile apps (iOS, Android).
- Third-party integrations that need delegated access to a user's data.
- Essentially, any flow where a real user is at a browser or on a device.

### Sequence

```
 User         Client (browser)        Authorization Server        Resource Server
  │                │                          │                          │
  │   click login  │                          │                          │
  │───────────────▶│                          │                          │
  │                │  generate code_verifier, │                          │
  │                │  hash → code_challenge   │                          │
  │                │                          │                          │
  │                │  /authorize?             │                          │
  │                │    response_type=code    │                          │
  │                │    client_id=...         │                          │
  │                │    redirect_uri=...      │                          │
  │                │    scope=openid profile  │                          │
  │                │    code_challenge=...    │                          │
  │                │    code_challenge_method=│                          │
  │                │    S256                  │                          │
  │                │    state=<CSRF nonce>    │                          │
  │                │    nonce=<ID-token nonce>│                          │
  │                │─────────────────────────▶│                          │
  │                │                          │                          │
  │   auth UI      │                          │                          │
  │◀──────────────────────────────────────────│                          │
  │   consent      │                          │                          │
  │──────────────────────────────────────────▶│                          │
  │                │                          │                          │
  │                │   302 to redirect_uri    │                          │
  │                │   ?code=<auth code>      │                          │
  │                │   &state=<nonce>         │                          │
  │                │◀─────────────────────────│                          │
  │                │                          │                          │
  │                │  POST /token             │                          │
  │                │    grant_type=           │                          │
  │                │      authorization_code  │                          │
  │                │    code=...              │                          │
  │                │    code_verifier=...     │                          │
  │                │    redirect_uri=...      │                          │
  │                │    client_id=...         │                          │
  │                │─────────────────────────▶│                          │
  │                │                          │                          │
  │                │   { access_token,        │                          │
  │                │     id_token,            │                          │
  │                │     refresh_token }      │                          │
  │                │◀─────────────────────────│                          │
  │                │                          │                          │
  │                │  Authorization: Bearer <access_token>               │
  │                │────────────────────────────────────────────────────▶│
  │                │                                       verify sig,  │
  │                │                                       iss, aud,    │
  │                │                                       exp, scopes  │
  │                │   200 { data }                                      │
  │                │◀────────────────────────────────────────────────────│
```

### Security properties

- **PKCE** (`code_challenge` / `code_verifier`) binds the code exchange to the same client instance that requested it. An attacker who intercepts the code cannot exchange it without the `code_verifier`, which never leaves the client. Originally designed for mobile; now recommended for *every* client type including confidential clients.
- **`state`** is a per-request random nonce the client stores (usually in a signed cookie) and verifies on the callback. It is a CSRF guard for the redirect; without it, an attacker can start a flow in their browser and trick the user's browser into completing it with the attacker's code.
- **`nonce`** is an OIDC ID-token binding. The client stores it, sends it on `/authorize`, and the AS embeds it in the issued ID token. The client verifies it matches on return. Prevents ID-token replay.
- **Redirect URI** must be pre-registered exactly and validated. No wildcards. No "localhost" in production registrations.
- **Short-lived access tokens** (5–60 minutes). **Refresh tokens** live longer but must be stored securely (HttpOnly cookie for browser, secure storage for mobile) and **rotated on use** — the AS issues a new refresh token each time and invalidates the old one.

### Python — Authlib (server-rendered client)

```python
from authlib.integrations.flask_client import OAuth
from flask import Flask, redirect, session, url_for, request
import secrets

app = Flask(__name__)
oauth = OAuth(app)

oauth.register(
    name="idp",
    server_metadata_url="https://auth.example.com/.well-known/openid-configuration",
    client_id=app.config["OIDC_CLIENT_ID"],
    client_secret=app.config["OIDC_CLIENT_SECRET"],
    client_kwargs={
        "scope": "openid profile email invoices:read",
        "code_challenge_method": "S256",
    },
)

@app.get("/login")
def login():
    # Authlib generates state, nonce, and PKCE verifier automatically.
    redirect_uri = url_for("auth_callback", _external=True, _scheme="https")
    return oauth.idp.authorize_redirect(redirect_uri)

@app.get("/auth/callback")
def auth_callback():
    token = oauth.idp.authorize_access_token()    # Exchanges code + verifier.
    # Authlib has already verified state, nonce, signature, iss, aud, exp.
    user_info = token["userinfo"]
    session["sub"] = user_info["sub"]
    session["access_token"] = token["access_token"]
    session["refresh_token"] = token.get("refresh_token")
    return redirect("/")

@app.post("/logout")
def logout():
    session.clear()
    # RP-initiated logout if the IdP supports it.
    return redirect("https://auth.example.com/v1/logout")
```

Authlib handles the cryptographic details — do not hand-roll any of the signature, nonce, or PKCE verification. The one thing *you* still must do: validate `aud` and `iss` on access tokens at the resource server.

### JavaScript — `openid-client` (backend-for-frontend pattern)

```javascript
const { Issuer, generators } = require("openid-client");
const express = require("express");
const session = require("express-session");

const app = express();
app.use(session({ /* secure session config */ }));

let client;
(async () => {
  const issuer = await Issuer.discover("https://auth.example.com");
  client = new issuer.Client({
    client_id: process.env.OIDC_CLIENT_ID,
    client_secret: process.env.OIDC_CLIENT_SECRET,
    redirect_uris: ["https://app.example.com/auth/callback"],
    response_types: ["code"],
  });
})();

app.get("/login", (req, res) => {
  const code_verifier = generators.codeVerifier();
  const code_challenge = generators.codeChallenge(code_verifier);
  const state = generators.state();
  const nonce = generators.nonce();

  req.session.pkce = { code_verifier, state, nonce };

  res.redirect(client.authorizationUrl({
    scope: "openid profile email invoices:read",
    code_challenge,
    code_challenge_method: "S256",
    state,
    nonce,
  }));
});

app.get("/auth/callback", async (req, res, next) => {
  try {
    const params = client.callbackParams(req);
    const { code_verifier, state, nonce } = req.session.pkce || {};
    const tokenSet = await client.callback(
      "https://app.example.com/auth/callback",
      params,
      { code_verifier, state, nonce },
    );
    // tokenSet.claims() runs ID-token validation.
    req.session.user = tokenSet.claims();
    req.session.accessToken = tokenSet.access_token;
    req.session.refreshToken = tokenSet.refresh_token;
    res.redirect("/");
  } catch (err) {
    next(err);
  }
});
```

### Common implementation mistakes

- **Storing access tokens in `localStorage`.** Accessible to any script on the origin; XSS reads the token. Use an HttpOnly cookie via a backend-for-frontend, or keep the token only in memory.
- **Not verifying `aud`, `iss`, `exp`, `nbf`.** The library will not do these unless configured; check the defaults.
- **Accepting multiple algorithms on token validation.** Pin to one (typically `RS256` or `ES256`). See `A07-identification-authentication-failures.md` in this repo.
- **Long-lived refresh tokens without rotation.** Rotate on use; if the AS returns the same refresh token, it is misconfigured.
- **Using the ID token as an access token.** The ID token is for the client; it is not meant for the resource server. Send the access token to the RS.
- **Open redirects on the `redirect_uri`.** Pre-register exact URIs. A wildcard registration turns your IdP into a phishing vehicle.

---

## 2. Client Credentials

### When to use

- Service-to-service calls where the *service itself* is the principal.
- Batch jobs, schedulers, server-to-server webhook consumers inside one org.
- Never for user-facing flows.

### Sequence

```
 Service                    Authorization Server                    Resource Server
    │                                │                                      │
    │  POST /token                   │                                      │
    │    grant_type=client_credentials                                      │
    │    client_id=...                                                      │
    │    client_secret=... (or client assertion JWT)                        │
    │    scope=orders:write                                                 │
    │───────────────────────────────▶│                                      │
    │                                │                                      │
    │   { access_token, expires_in } │                                      │
    │◀───────────────────────────────│                                      │
    │                                │                                      │
    │  Authorization: Bearer <access_token>                                 │
    │──────────────────────────────────────────────────────────────────────▶│
    │                                                    verify sig, iss,   │
    │                                                    aud, exp, scope    │
    │   200 { ... }                                                         │
    │◀──────────────────────────────────────────────────────────────────────│
```

### Security properties

- **No user is involved.** The token's subject is the service account.
- **Client authentication to the AS matters.** Options: client_secret_post/basic (a shared secret), **private_key_jwt** (the client signs a JWT with its private key and the AS verifies with the public key), or **tls_client_auth** (mTLS to the AS). Prefer private_key_jwt or tls_client_auth in regulated environments.
- **Workload identity federation is the modern pattern.** AWS IAM Roles Anywhere, GitHub OIDC → IdP, GCP workload identity — the client authenticates to the AS with an ambient credential issued by the workload platform. No secret to rotate.
- **Short-lived access tokens (5–15 minutes).** No refresh tokens in CC — the client re-authenticates for each new access token.

### Python — Authlib client

```python
from authlib.integrations.httpx_client import OAuth2Client

client = OAuth2Client(
    client_id=os.environ["CLIENT_ID"],
    client_secret=os.environ["CLIENT_SECRET"],
    scope="orders:write",
    token_endpoint_auth_method="client_secret_basic",
)

token = client.fetch_token(
    "https://auth.example.com/oauth/token",
    grant_type="client_credentials",
)

# Authlib attaches the access token automatically on subsequent calls.
resp = client.post("https://api.example.com/v1/orders", json=order)
```

For private_key_jwt:

```python
client = OAuth2Client(
    client_id=os.environ["CLIENT_ID"],
    token_endpoint_auth_method="private_key_jwt",
    client_kwargs={"jwks": {"keys": [PRIVATE_JWK]}},
    scope="orders:write",
)
```

### JavaScript — openid-client

```javascript
const tokenSet = await client.grant({
  grant_type: "client_credentials",
  scope: "orders:write",
});
// tokenSet.access_token → call RS.
```

### Common implementation mistakes

- **Sharing client secrets across services.** One secret per service; rotation blast radius stays local.
- **Storing secrets in environment variables read from git.** Use a secrets manager. Emit the secret into the environment at pod start.
- **Treating the CC token as a user context.** A CC token has no user. Do not use it to make "act on behalf of user X" decisions.

---

## 3. Device Flow

### When to use

- CLI tools.
- Smart TVs, consoles, IoT devices with no browser or no keyboard.
- Headless backends that need a human to approve access once (e.g., first-time onboarding of a GitHub CLI).

### Sequence

```
 Device                Authorization Server                 User on another device
   │                          │                                      │
   │ POST /device_authorization                                       │
   │───────────────────────────▶│                                      │
   │                          │                                      │
   │ { device_code,           │                                      │
   │   user_code,             │                                      │
   │   verification_uri,      │                                      │
   │   interval, expires_in } │                                      │
   │◀───────────────────────────│                                      │
   │                          │                                      │
   │ Display: "visit          │                                      │
   │   verification_uri and   │                                      │
   │   enter user_code"       │                                      │
   │                          │                                      │
   │                          │   GET verification_uri, enter code   │
   │                          │◀─────────────────────────────────────│
   │                          │                                      │
   │                          │   auth + consent                     │
   │                          │◀─────────────────────────────────────│
   │                          │                                      │
   │ Poll POST /token         │                                      │
   │   grant_type=            │                                      │
   │   urn:ietf:params:       │                                      │
   │   oauth:grant-type:      │                                      │
   │   device_code            │                                      │
   │   device_code=...        │                                      │
   │───────────────────────────▶│                                      │
   │                          │                                      │
   │ { access_token,          │                                      │
   │   refresh_token }        │                                      │
   │◀───────────────────────────│                                      │
```

### Security properties

- **User authorizes on a trusted device**, not the device with weak input.
- **`user_code` is short and human-friendly** (`ABCD-1234`); **`device_code` is long and opaque.** The user sees the short one; the device transmits the long one.
- **Phishing risk.** An attacker who controls an imitation device can try to get a user to authorize; rate-limit and display the target device's identity on the consent screen.
- **Polling interval matters.** Devices must respect `interval` to avoid being throttled by the AS.

### Common implementation mistakes

- **Treating the `user_code` as secret.** It is short and guessable by construction; the security relies on binding to a specific device flow session, not on secrecy.
- **Not expiring device codes.** Implement `expires_in`; abandoned flows must eventually fail.

---

## 4. When NOT to use Implicit flow

**Implicit flow** (`response_type=token` or `response_type=id_token token`) returns the access token directly in the redirect URL fragment, with no code-exchange step. It existed because early SPAs could not safely store a client secret, so the spec designers skipped the code exchange.

Modern guidance (OAuth 2.1 drafts, IETF Best Current Practice RFC 9700, 2025) deprecates it. Reasons:

- **Tokens appear in browser history, server logs, and HTTP Referer headers.** The access token in `#access_token=...` is leaked by every intermediary the redirect touches.
- **No client authentication.** PKCE was designed to restore that binding.
- **No refresh token issuance** (spec). Workarounds re-run the flow in an iframe, which reintroduces cookie / SameSite complexity.
- **Authorization Code + PKCE does the same job better.** Modern browser APIs (fetch, CORS) let an SPA exchange a code for a token at the token endpoint exactly as a backend client would.

**Do not use Implicit in new designs.** If you inherit it, migrate to Auth Code + PKCE.

**Do not use Resource Owner Password Credentials (ROPC).** It requires the client to collect the user's password and send it to the AS — a pattern OAuth2 was designed to eliminate. Legacy systems with no other option are the only justification; those should still have a migration plan.

---

## 5. JWT best practices

Access and ID tokens are typically JWTs. Validation is easy to get wrong. The rules below cover what every resource server must do.

### Signature algorithm

- **Pin one algorithm.** `RS256` or `ES256` for public/private; `EdDSA` if the library supports it. Never accept `none`. Never allow `HS256` and `RS256` on the same validator — the algorithm-confusion attack lets an attacker forge tokens with the public key. See `A07-identification-authentication-failures.md`.
- **Validate with the algorithm you expect**, not the one the token claims. If your library takes `algorithms=[...]`, pass exactly one value.

### Key management

- **Rotate signing keys on a schedule** (quarterly to annually, depending on exposure).
- **Publish public keys at `/.well-known/jwks.json`** keyed by `kid`. The RS fetches, caches, and looks up by `kid`.
- **Keep the private key in a KMS or HSM.** The AS should sign with a key it cannot export.
- **Overlap old and new keys.** When rotating, publish both old and new JWKS entries for at least one token lifetime so in-flight tokens remain valid.

### Claims

The RS must validate, on every token:

| Claim | Validation |
| --- | --- |
| `iss` | Exact match to the expected issuer URL. |
| `aud` | Exact match to this resource server's identifier. |
| `exp` | Now < `exp`, with a small clock skew tolerance (≤ 60 s). |
| `nbf` | Now ≥ `nbf`, same clock skew. |
| `iat` | Not in the future. Optional to enforce age limits. |
| `sub` | Required to exist. |
| `scope` / `scp` | Contains the scope needed for this operation. |

For ID tokens additionally:

| Claim | Validation |
| --- | --- |
| `nonce` | Matches the `nonce` the client sent. |
| `azp` | If multiple audiences, validate the authorized party. |
| `auth_time` | If `max_age` was requested, check it. |

### Lifetime

- **Access tokens: 5–60 minutes.** Shorter is better; the tradeoff is AS load.
- **ID tokens: short** (they are consumed immediately by the client). Do not reuse an ID token as an access token.
- **Refresh tokens: hours to days.** Rotate on use; one-time tokens tie compromise to a single detection window.

### Revocation

JWTs are self-contained and hard to revoke before `exp`. Options:

1. **Short-lived access tokens + long-lived refresh tokens with server-side revocation** is the standard combo. An attacker has at most one access-token lifetime of validity after revocation.
2. **Token introspection (RFC 7662)** — the RS calls the AS for every token. Gives perfect revocation at the cost of a call per request; cache aggressively.
3. **Session-version claims** — every token carries a session-version counter; incrementing the counter on the user record invalidates all outstanding tokens. Works well when the RS has DB access to the session store.

### Example — RS validation in Python

```python
import jwt
from jwt import PyJWKClient, InvalidTokenError

JWKS = PyJWKClient("https://auth.example.com/.well-known/jwks.json")
ISSUER = "https://auth.example.com/"
AUDIENCE = "https://api.example.com"

def validate_access_token(raw: str, required_scope: str):
    try:
        unverified_header = jwt.get_unverified_header(raw)
        if unverified_header.get("alg") != "RS256":
            raise InvalidTokenError("unexpected algorithm")
        signing_key = JWKS.get_signing_key_from_jwt(raw).key
        payload = jwt.decode(
            raw,
            signing_key,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            leeway=30,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except InvalidTokenError as e:
        raise HTTPException(401, detail="invalid token") from e

    scopes = set((payload.get("scope") or "").split())
    if required_scope not in scopes:
        raise HTTPException(403, detail="insufficient scope")
    return payload
```

### Example — RS validation in JavaScript

```javascript
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");

const client = jwksClient({
  jwksUri: "https://auth.example.com/.well-known/jwks.json",
  cache: true,
  cacheMaxAge: 10 * 60 * 1000,
});

function getKey(header, cb) {
  client.getSigningKey(header.kid, (err, key) =>
    cb(err, key?.getPublicKey()));
}

function requireScope(scope) {
  return (req, res, next) => {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
    if (!token) return res.status(401).end();

    jwt.verify(
      token,
      getKey,
      {
        algorithms: ["RS256"],
        issuer: "https://auth.example.com/",
        audience: "https://api.example.com",
        clockTolerance: 30,
      },
      (err, payload) => {
        if (err) return res.status(401).end();
        const scopes = (payload.scope || "").split(" ");
        if (!scopes.includes(scope)) return res.status(403).end();
        req.user = payload;
        next();
      },
    );
  };
}
```

## Summary — picking the flow

| Client | Flow | Notes |
| --- | --- | --- |
| First-party web (server-rendered) | Authorization Code + PKCE | Store tokens server-side, pass identity to the browser via signed session cookie. |
| First-party SPA | Authorization Code + PKCE | Via a backend-for-frontend; do not put tokens in localStorage. |
| First-party mobile | Authorization Code + PKCE | Use the platform's secure storage for refresh tokens. |
| Third-party integration (delegated access) | Authorization Code + PKCE | With a public client profile if no backend; otherwise confidential. |
| Service-to-service, one org | Client Credentials (with workload identity if available) | Scope narrowly per caller. |
| Service-to-service, federated trust | Client Credentials with private_key_jwt or tls_client_auth | Prefer over shared secrets in regulated environments. |
| CLI / TV / IoT | Device Flow | User authorizes on another device. |
| Legacy username/password | ROPC (only as a stopgap) | Migrate out. |
| Anything else | Start from Authorization Code + PKCE | If you cannot make it fit, reconsider the design. |

## Further reading

- [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) — The OAuth 2.0 Authorization Framework.
- [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) — PKCE.
- [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628) — Device Authorization Grant.
- [RFC 9700](https://datatracker.ietf.org/doc/html/rfc9700) — OAuth 2.0 Security Best Current Practice.
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html).
- [OAuth 2.1 draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1) — consolidates BCP into the core spec.
