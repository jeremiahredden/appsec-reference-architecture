# Secure REST API Design

## The opinion up front

A secure REST API is one whose defaults are safe and whose surface area is boring. The design choices that matter are (1) strict, schema-driven input validation at the boundary, (2) a single authentication method that is right for the client type, (3) authorization that is always enforced at the data layer and not only at the gateway, (4) rate limits that are stricter than you think you need, (5) error handling that reveals nothing about the stack, and (6) headers that make the browser the second line of defense.

JSON request bodies, UTF-8, versioned via URL path (`/v1/`, `/v2/`), hyphenated resource names, RFC 7807 `application/problem+json` errors. No XML, no RPC-over-REST, no GraphQL for external APIs. These defaults eliminate a long list of attacks simply by not accepting the inputs that enable them.

## Reference architecture

```
                                                 ┌─────────────────────────────┐
                                                 │  WAF / CDN (AWS WAF,        │
                                                 │  CloudFront, Cloudflare)    │
  ┌──────────────┐       HTTPS (TLS 1.3)         │  · Managed rule sets        │
  │  Client      │  ────────────────────────▶    │  · Bot mitigation           │
  │  (Web/Mobile)│                               │  · Rate limit (IP, ASN)     │
  └──────────────┘                               └──────────────┬──────────────┘
                                                                │
                                                 ┌──────────────▼──────────────┐
                                                 │  API Gateway                │
                                                 │  · TLS termination          │
                                                 │  · OAuth2 introspect / JWT  │
                                                 │    signature + claims       │
                                                 │  · Per-client rate limit    │
                                                 │  · Request-ID propagation   │
                                                 │  · Request-schema envelope  │
                                                 └──────────────┬──────────────┘
                                                                │ mTLS (mesh)
                                                 ┌──────────────▼──────────────┐
                                                 │  Service (FastAPI/Express)  │
                                                 │  · Schema validation        │
                                                 │  · Authorization (scope +   │
                                                 │    resource ownership)      │
                                                 │  · Business logic           │
                                                 │  · Structured audit log     │
                                                 └──────────────┬──────────────┘
                                                                │ parameterized
                                                 ┌──────────────▼──────────────┐
                                                 │  Data tier (Postgres, S3)   │
                                                 │  · Row-level security       │
                                                 │  · KMS-encrypted at rest    │
                                                 └─────────────────────────────┘
```

The key property of this shape is that every hop is an independent control. If the WAF is bypassed, the gateway still authenticates. If the gateway lets a malformed request through, the service still validates. If the service forgets a scope check, the database's row-level security still enforces tenancy. Each layer is designed to fail independently; none of them is load-bearing alone.

## 1. Input validation

The baseline is "parse, don't validate" — build a typed representation at the boundary and never operate on raw strings past that point. Pydantic (Python) and Zod (JavaScript) make this a one-line commitment.

### Rules

- **Allowlist, never denylist.** A denylist is trying to enumerate every bad input. Attackers will find one you missed. An allowlist enumerates what is valid; everything else is rejected.
- **Enforce maximum length on every string.** Unbounded strings are denial-of-service surface and, often, injection surface.
- **Reject unknown fields.** `strict` mode in Zod / Pydantic. If the client sent `admin: true`, you want the request to fail, not to silently ignore.
- **Constrain types precisely.** Not "a number" — an integer between 1 and 1000. Not "a string" — a UUID v4, or a 2-letter country code, or an email address that parses.
- **Validate after trimming.** Trim once, then validate. Do not trim inside business logic.

### Python — Pydantic v2

```python
from pydantic import BaseModel, EmailStr, Field, ConfigDict, field_validator
from typing import Annotated, Literal
from uuid import UUID

class CreateInvoiceRequest(BaseModel):
    # strict=True rejects unknown keys; revalidate_instances forces
    # re-validation when a model is constructed from a model.
    model_config = ConfigDict(extra="forbid", revalidate_instances="always")

    customer_id: UUID
    currency: Literal["USD", "EUR", "GBP", "JPY"]
    amount_cents: Annotated[int, Field(ge=1, le=1_000_000_00)]
    memo: Annotated[str, Field(min_length=0, max_length=500)] = ""
    due_date: str   # Validated below, not here.

    @field_validator("memo")
    @classmethod
    def no_control_chars(cls, v: str) -> str:
        if any(ord(c) < 0x20 and c not in "\n\r\t" for c in v):
            raise ValueError("memo contains control characters")
        return v.strip()

    @field_validator("due_date")
    @classmethod
    def iso_date(cls, v: str) -> str:
        from datetime import date
        try:
            date.fromisoformat(v)
        except ValueError:
            raise ValueError("due_date must be YYYY-MM-DD")
        return v
```

In FastAPI the model is the handler signature; no explicit validation call is needed:

```python
@app.post("/v1/invoices", status_code=201)
def create_invoice(
    payload: CreateInvoiceRequest,
    user: User = Depends(require_scope("invoices:write")),
):
    ...
```

Any request that does not match the schema returns a 422 with a machine-readable error — the handler body never sees the invalid input.

### JavaScript — Zod

```javascript
import { z } from "zod";

const CreateInvoiceRequest = z.object({
  customerId: z.string().uuid(),
  currency: z.enum(["USD", "EUR", "GBP", "JPY"]),
  amountCents: z.number().int().min(1).max(100_000_000),
  memo: z.string().max(500).default(""),
  dueDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
}).strict();

app.post("/v1/invoices", requireScope("invoices:write"), async (req, res) => {
  const parsed = CreateInvoiceRequest.safeParse(req.body);
  if (!parsed.success) {
    return res.status(422).json({
      type: "https://errors.example.com/validation",
      title: "Invalid request",
      errors: parsed.error.issues,
    });
  }
  const data = parsed.data;
  // ...
});
```

`.strict()` rejects unknown fields. `refine` / `superRefine` cover cross-field constraints (e.g. "if `currency === 'JPY'`, `amountCents` must be ≥ 100"). Never assign `req.body` into a model directly — pass the parsed object only.

### A note on structural validation vs. semantic validation

Schema validation handles structure (type, format, length, enumerated values). Semantic validation — "the customer exists and belongs to the caller's tenant," "the invoice is not in a closed period" — has to happen inside the handler, because it depends on database state. Both are required; neither is sufficient. A common bug is stopping after schema validation and assuming the rest is someone else's problem.

## 2. Authentication patterns

Pick one primary authentication method per client type. Multiple methods on the same endpoint multiply the attack surface.

| Client type | Method | Why |
| --- | --- | --- |
| First-party web / mobile | OAuth2 Authorization Code + PKCE → short-lived access tokens | Industry standard, works with modern IdPs, PKCE protects against code interception. |
| Third-party apps (delegated access to user data) | OAuth2 Authorization Code + PKCE | Same; scopes enumerate what the third party can do. |
| Service-to-service within one org | mTLS with mesh-issued SPIFFE identities | The identity is cryptographic, not a shared secret. Rotation is automatic. |
| Service-to-service across orgs (webhook in / out) | Signed requests (HMAC) + optional mTLS | Signing with a shared secret is simpler than OAuth2 CC for one-way webhooks. |
| Machine users inside one org (scripts, CI) | OAuth2 Client Credentials | Short-lived tokens; rotation is automatic if the client uses workload identity. |
| Public read-only APIs (data dumps, status) | API key or unauthenticated | API keys are fine when the resource is low-sensitivity and the rate-limit tier matters more than identity. |

### What to avoid

- **HTTP Basic Auth outside of local development.** Base64 is not encryption. The only time Basic Auth is acceptable is as a stopgap for internal tooling, and even then rotate quickly to a real auth method.
- **Custom auth protocols.** If you invented it this quarter, an attacker will break it next quarter. Use OAuth2, OIDC, SAML, or mTLS. The cases where those do not fit are rarer than engineers think.
- **Long-lived bearer tokens in URLs, email, or logs.** A token in a URL path is in every access log, proxy log, and browser history. Move it to a header.
- **Implicit flow for new OAuth2 integrations.** See `oauth2-oidc-flows.md` for the long version. Short version: Authorization Code + PKCE is strictly better.

### API key storage — if you must issue them

- Store `hash(key)`, never the key itself. Generate 32 bytes from a CSPRNG, return the raw key once to the user, store the SHA-256 hash.
- Tie every key to a principal (user, service account) and scope it to an allowlist of operations.
- Include a stable prefix that identifies the key type and environment (`sk_live_...`, `pk_test_...`) so leaked keys can be detected by secret scanners.

## 3. Authorization — RBAC vs. ABAC, and where to enforce

### RBAC vs. ABAC

**RBAC** (role-based) assigns users to roles and grants permissions to roles. It is the right model when the access decision depends only on who the user is: `admin` can delete accounts, `analyst` can read reports, `viewer` can read dashboards. RBAC scales badly when permissions depend on attributes of the *resource* — "user can read invoices only for customers in their territory."

**ABAC** (attribute-based) evaluates a policy over attributes of the user, the resource, and the environment: `allow if user.team == resource.team AND request.time in business_hours`. ABAC is more powerful and more expensive — you need a policy engine and a way to ship attributes to it. Use ABAC when resource-scoped rules are the norm.

**Practical recommendation.** Start with RBAC for coarse role gates (admin, user, service), and layer on a small number of ABAC checks for resource ownership (`resource.owner_id == user.id`) and tenancy (`resource.tenant_id == user.tenant_id`). Reserve a full ABAC engine (OPA, Cedar) for systems that need policy-level separation — multi-tenant SaaS with complex sharing, or highly regulated workloads.

### Gateway vs. service enforcement

The gateway enforces **authentication** and **coarse authorization** (does this token have a scope that allows this endpoint). That is necessary but not sufficient.

Authorization at the **service layer** enforces resource-level rules: *this* user can access *this* invoice because they own it, belong to its tenant, or have been granted a share. This check must happen with the data — typically as a WHERE clause or a row-level security policy — because the service is the only layer that knows the resource's owner.

**Anti-pattern.** Checking only at the gateway. The gateway sees the URL and the token; it does not know that invoice `42` belongs to tenant `B`. An attacker with a valid token for tenant `A` can hit `GET /v1/invoices/42` and if the service does not re-check ownership, they get tenant `B`'s data. This is the IDOR pattern — see OWASP A01.

### Example — resource-scoped query

```python
# Always. Every. Time.
def get_invoice(session, invoice_id: UUID, user: User) -> Invoice:
    invoice = session.query(Invoice).filter(
        Invoice.id == invoice_id,
        Invoice.tenant_id == user.tenant_id,
    ).first()
    if invoice is None:
        # 404 not 403 — do not confirm existence across tenants.
        raise HTTPException(404)
    return invoice
```

Postgres Row-Level Security policies are a belt-and-suspenders reinforcement for this pattern; the WHERE clause enforces it in the application, the RLS policy enforces it in the database even if the app forgets.

## 4. Rate limiting and throttling

### Principles

- **Limit at two layers.** Coarse (per-IP, per-ASN) at the edge (WAF / CDN), and fine (per-client, per-endpoint, per-user) at the API gateway or service.
- **Different limits per endpoint class.** Authenticated read-only endpoints can be ~10x the limit of write endpoints; password-reset and login are ~1/100th.
- **Default to 429 with `Retry-After`.** Give well-behaved clients enough information to back off. Malicious clients get dropped at the edge.
- **Track rate-limit hits as a security signal.** A client sustainedly hitting 429 is either a broken client or a reconnaissance attempt; route the metric to the SIEM.

### Token bucket, because the algorithm matters

Sliding-window counters are fine for coarse IP rate limits but produce unfriendly behavior under normal bursty traffic (a user refreshing a page hits 10 endpoints in 50 ms). Token bucket smooths the burstiness: each client has a bucket of capacity `N` that refills at rate `R`. A request consumes one token; if the bucket is empty the request is rejected. Capacity handles bursts; rate handles sustained load.

### Python — Flask / FastAPI with `slowapi` (token bucket via Redis)

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(
    key_func=lambda: get_remote_address() + ":" + (get_user_id() or "anon"),
    storage_uri="redis://redis:6379",
    strategy="moving-window",
)

@app.post("/v1/invoices")
@limiter.limit("60/minute; 10/second")
def create_invoice(...):
    ...

@app.post("/v1/auth/login")
@limiter.limit("5/minute; 50/hour", key_func=lambda: request.form["email"].lower())
def login():
    ...
```

### JavaScript — Express with `rate-limiter-flexible` (Redis-backed token bucket)

```javascript
const { RateLimiterRedis } = require("rate-limiter-flexible");

const writeLimiter = new RateLimiterRedis({
  storeClient: redis,
  keyPrefix: "rl:write",
  points: 60,            // 60 requests
  duration: 60,          // per 60 seconds
  blockDuration: 60,
});

app.use("/v1/*", async (req, res, next) => {
  if (req.method === "GET") return next();
  try {
    await writeLimiter.consume(req.user?.id || req.ip);
    next();
  } catch (rej) {
    res.set("Retry-After", Math.ceil(rej.msBeforeNext / 1000));
    res.status(429).json({ type: "about:blank", title: "Too many requests" });
  }
});
```

## 5. Error handling that leaks nothing

The goal is one canonical error response shape per API — `application/problem+json` (RFC 7807) — with error messages that are actionable for legitimate clients and useless for attackers.

### Rules

- **Never include stack traces, SQL fragments, filesystem paths, or internal service names in responses.** Those belong in logs, not responses.
- **Return the same error for "not found" and "not authorized," unless you have an explicit reason to distinguish.** A 404 for both avoids confirming resource existence to an attacker who lacks authorization.
- **Log the full error context with a request ID; return the request ID in the response.** The caller can ask for help by request ID; the operator can find the log without the caller revealing sensitive data.
- **Rate-limit error-generating endpoints.** Repeated 400s from the same client are a signal.

### Example response

```json
{
  "type": "https://errors.example.com/not-found",
  "title": "Resource not found",
  "status": 404,
  "requestId": "01HS3K1T6KB8V2GJ9A7YQWN3RF"
}
```

### Python — FastAPI error handler

```python
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    # Log the full story with the request ID.
    logger.warning("http_error", extra={
        "event": "http_error",
        "ctx": {"status": exc.status_code, "detail": str(exc.detail)},
    })
    # Return only the sanitized shape to the client.
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "type": f"https://errors.example.com/{exc.status_code}",
            "title": _title_for(exc.status_code),
            "status": exc.status_code,
            "requestId": request.state.request_id,
        },
    )

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("unhandled_exception", extra={"ctx": {"request_id": request.state.request_id}})
    return JSONResponse(
        status_code=500,
        content={
            "type": "https://errors.example.com/internal",
            "title": "Internal server error",
            "status": 500,
            "requestId": request.state.request_id,
        },
    )
```

### JavaScript — Express error middleware (last in the chain)

```javascript
app.use((err, req, res, _next) => {
  req.log.error({ err, reqId: req.id }, "unhandled_exception");
  const status = err.status || 500;
  res.status(status).type("application/problem+json").json({
    type: `https://errors.example.com/${status}`,
    title: status === 500 ? "Internal server error" : (err.title || "Error"),
    status,
    requestId: req.id,
  });
});
```

Never install `express-errorhandler` or similar "pretty error page" middleware in production; they ship stack traces to clients by default.

## 6. Security headers

The browser is the second-line defender. The headers below turn it on. Emit them on every response from any endpoint that can return HTML, and most are safe on API-only endpoints too.

| Header | Value (example) | What it does |
| --- | --- | --- |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Forces HTTPS for 2 years, including subdomains, eligible for the HSTS preload list. |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'` | Restricts the sources the browser will load; kills most XSS delivery paths. |
| `X-Content-Type-Options` | `nosniff` | Browser respects the declared content type; prevents MIME sniffing into XSS. |
| `X-Frame-Options` | `DENY` | Legacy header; pair with `frame-ancestors 'none'` above. |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Don't leak full URLs (which may contain tokens) in the Referer header. |
| `Permissions-Policy` | `geolocation=(), camera=(), microphone=()` | Disable browser features the app does not use. |
| `Cross-Origin-Opener-Policy` | `same-origin` | Isolates the browsing context; mitigates Spectre-class side channels. |
| `Cross-Origin-Resource-Policy` | `same-origin` | Prevents other origins from embedding this resource. |

### Python — FastAPI with a tiny middleware

```python
@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; object-src 'none'; "
        "frame-ancestors 'none'; base-uri 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    return response
```

### JavaScript — Express with `helmet`

```javascript
const helmet = require("helmet");

app.use(helmet({
  hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
    },
  },
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  crossOriginOpenerPolicy: { policy: "same-origin" },
  crossOriginResourcePolicy: { policy: "same-origin" },
}));
```

Do not set `X-XSS-Protection` — it has been deprecated and can introduce vulnerabilities. Do not set `Server:` with a version string.

## 7. Versioning and deprecation without breaking security controls

### Rules

- **Version in the URL path.** `/v1/invoices`, `/v2/invoices`. Header-based versioning (`Accept: application/vnd.acme.v2+json`) is correct in a purist sense and operationally harder — routing, WAF rules, and rate limits all key off the URL.
- **Never mutate a released version.** Once `/v1/invoices` ships, its contract is frozen. Breaking changes go to `/v2`.
- **Deprecate, don't delete, until usage drops to agreed thresholds.** Publish a deprecation date; emit a `Deprecation: date` and `Sunset: date` header on every response from the deprecated version.
- **Security fixes ship to every supported version.** If a bug allows an IDOR in `/v1/invoices`, fix it in `/v1/invoices`; do not tell customers "upgrade to v2 to get the security fix." That is a backdoor for attackers who learn which versions are frozen.
- **When retiring a version, retire its rate limits and WAF rules last.** Attackers enumerate old versions. Keep the gates up until the endpoint itself is gone.

### Deprecation headers

```
Deprecation: Sun, 01 Jun 2026 00:00:00 GMT
Sunset: Tue, 01 Dec 2026 00:00:00 GMT
Link: <https://developer.example.com/v2/migration>; rel="successor-version"
```

## Testing the design

A design is only as good as the tests that hold it in place. At minimum, every API should have:

- **Schema tests.** Fuzz each endpoint with invalid bodies and assert 4xx with no server-side effect.
- **IDOR tests.** For every resource endpoint, create two tenants and assert that tenant A cannot read / modify tenant B's resources. 404 on cross-tenant access.
- **Rate-limit tests.** Assert the configured limit is enforced and that `Retry-After` is present on 429.
- **Header tests.** Assert the full set of security headers is present on at least one representative response per service.
- **Error-shape tests.** Assert every 4xx / 5xx returns `application/problem+json` and does not contain `Traceback`, stack frames, or SQL snippets.

These tests live in the same CI pipeline as unit tests. Regressions in security defaults are regressions in the product, not optional concerns.

## Further reading

- [OWASP API Security Top 10](https://owasp.org/API-Security/) — the class-by-class threat list for APIs specifically.
- [RFC 7807 — Problem Details for HTTP APIs](https://datatracker.ietf.org/doc/html/rfc7807) — the error-shape standard.
- [RFC 9457](https://datatracker.ietf.org/doc/html/rfc9457) — the 2023 update to 7807.
- OWASP Cheat Sheet Series: [REST Security](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html), [Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html), [HTTP Security Response Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html).
