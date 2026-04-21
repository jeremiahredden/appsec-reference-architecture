# Secure Code Review — Process Guide

A practical guide for conducting a manual secure code review that produces findings developers will actually fix. Written for security engineers who have the scanner output in one window and the pull request in another, and are trying to decide what to look at next.

---

## When Automated Scanning Is Not Enough

Static analysis is necessary and insufficient. Every team should run SAST (Semgrep, CodeQL, Bandit, ESLint security plugins), SCA (Dependabot, Snyk, Trivy), secrets scanning (gitleaks, TruffleHog), and IaC scanning (Checkov, tfsec) on every pull request. Those tools catch the low-hanging fruit. They also miss most of the bugs that matter.

Manual review is required when:

- **The bug class cannot be expressed as a pattern.** Scanners match syntax; auditors reason about intent. Authorization logic that calls the right function on the right object for the wrong user is invisible to a scanner because the code looks correct. Business logic flaws — "the refund endpoint trusts a signed URL that the user's browser generated" — have no signature.
- **The system crosses trust boundaries that the scanner cannot see.** A scanner reading one service does not know that the `user_id` being passed in as a trusted parameter was originally a URL path segment in a different service. Trust boundary violations are the single largest source of real exploitable bugs, and they almost always span multiple repositories.
- **Cryptography is involved.** Scanners catch `MD5` and `pickle.loads`. They do not catch "this HMAC is computed over the wrong bytes," "this JWT validates signature but trusts a claim it should not," or "this AES-GCM uses a deterministic IV derived from the plaintext." Crypto bugs require human attention.
- **A regulated data class is handled.** HIPAA, PCI-DSS, SOX, and 42 CFR Part 2 introduce requirements that are not code smells — they are legal obligations. A manual reviewer confirms audit log retention, consent capture, and break-glass logging. A scanner does not.
- **The code was written by an LLM, or with heavy LLM assistance.** This is the 2026 reality. LLM-generated code passes syntactic checks and pattern matchers at a rate that does not reflect its actual quality. LLM-generated auth code in particular has a high rate of confidently-wrong patterns — correct-looking JWT validation that silently accepts `alg: none`, correct-looking password reset flows with no token binding, correct-looking RBAC checks that check the role but not the resource. Spend your manual review budget disproportionately on LLM-assisted code.
- **The change touches money, credentials, or personal data.** Payment flows, authentication, PII handling, and administrative tooling are always worth a human pass, regardless of what the scanner says.

If the change is none of the above — a UI tweak, a logging refactor, a developer-tooling update — trust the scanners and move on. Your manual review time is finite; spend it where it matters.

---

## What to Focus On

The six categories below are where I spend >90% of my manual review attention. Read every PR through these lenses in roughly this order.

### 1. Business Logic Flaws

Business logic bugs are the hardest to find and the most likely to cost money. Ask: "What is this feature supposed to prevent?" Then: "What can I do as a user that it does not prevent?"

Canonical examples:
- A promotional discount code that is validated server-side but applied against a total the client submits.
- An account-linking flow that trusts an email address without a challenge to the current owner of that address.
- A refund endpoint that processes any `refund_id` as long as it exists, rather than checking it belongs to the requesting merchant.
- A "transfer funds between my accounts" endpoint that validates the source account but not the destination account.

No scanner will find these. You find them by building an attacker's model of the feature and asking what the feature's assumptions are.

### 2. Authentication and Authorization Gaps

Authorization bugs outnumber authentication bugs in real-world codebases by roughly 10:1. Authentication is "who are you" and is usually centralized (you check the JWT once at the gateway). Authorization is "are you allowed to do this specific thing to this specific resource" and is usually decentralized across every handler — which is why it is the number-one source of IDOR and horizontal privilege escalation.

On every protected endpoint, ask three questions:
- **Identity:** Is the authenticated user ID derived from a token the user cannot modify? (Not a header. Not a form field.)
- **Ownership:** Does the resource being accessed belong to that user, and is the ownership check enforced *at the data layer*, not just in the URL routing?
- **Capability:** Does the user's role or scope permit this operation on this class of resource? Is this check server-side, not "the frontend hides the button"?

If a handler reads any identifier (user_id, tenant_id, account_id, document_id, record_id) from the URL or request body and uses it to scope a query, verify that it is cross-checked against the authenticated identity. This is where most of the Critical findings in my engagements come from.

### 3. Cryptographic Misuse

Most cryptographic bugs are not "they used RC4"; they are "they used a good primitive the wrong way." Look for:

- **Algorithm confusion:** JWT libraries that accept `alg` from the token itself and dispatch to the corresponding verifier — a Critical bug class (CVE-2015-9235 and its 50+ siblings). Always pin the expected algorithm.
- **Custom crypto:** Any hand-rolled MAC, any hand-rolled KDF, any "encrypt then concatenate" pattern that omits the authentication tag. Use AEAD (AES-GCM, ChaCha20-Poly1305, libsodium) and nothing else.
- **Weak sources of randomness:** `random.random()` in Python, `Math.random()` in JavaScript for anything security-relevant. Use `secrets` (Python) or `crypto.randomBytes` (Node.js). Session tokens, password reset tokens, API keys, CSRF tokens, all must come from a CSPRNG.
- **Hash functions used as passwords:** MD5, SHA-1, SHA-256, SHA-512 are not password hashing functions. Use Argon2id (preferred), bcrypt, or scrypt. Check the cost factor — an Argon2 with default parameters on a 2026 machine is often too weak.
- **Fixed IVs / nonces:** AES-GCM with a reused nonce and the same key is catastrophic. Check that nonces are random (or counter-based with strict monotonic guarantees) and that the nonce space is not narrow enough to repeat.
- **Missing authenticity:** Cookies signed with a "signature" that is just HMAC over part of the payload, with the rest unsigned. Signed URLs that do not sign the query string. JWTs with no signature at all (`alg: none`) — still observed in the wild.

### 4. Trust Boundary Violations

A trust boundary is a line in the system where the level of trust changes — external to internal, one tenant to another, user input to internal consumer, one service to another. Validation at a boundary is non-negotiable.

On review, find the trust boundaries in the changed code. Then ask:
- What validation happens as data crosses the boundary?
- What assumptions does the downstream code make about data that has "already been validated"?
- Is there a point in the data flow where the input regains full attacker control because it was logged, re-serialized, or stored and later re-fetched?

The last question is where SSRF, second-order SQL injection, and stored XSS live. The attacker's input is validated on ingress, then stored, then fetched later by code that has forgotten it was ever attacker-controlled.

### 5. Race Conditions and State

Concurrency bugs are underrepresented in scanner output and overrepresented in real exploits. The classic examples:
- **TOCTOU on authorization:** Check the user can perform the action, then perform it, without atomic guarantees. User cancels the permission in between and the action still happens.
- **Double-spend on credits/balance:** Fetch balance, check sufficient, deduct. Two requests in parallel both pass the check and both deduct.
- **Signup race:** Two requests sign up the same email simultaneously, creating two accounts that the uniqueness constraint should have prevented, because the constraint is not at the database layer.
- **File write races:** Temp file created with predictable name, security check run against it, then the file is opened — an attacker can swap the file between check and open.

Look for `SELECT ... then UPDATE` patterns without `SELECT FOR UPDATE` or a database-level constraint. Look for "check then act" code that crosses a non-atomic boundary. Look for filesystem operations that trust a name rather than a file descriptor.

### 6. Error Handling and Information Disclosure

What does the system say to an attacker who sends it malformed input? What does it log? What ends up in the error response? Two common failure modes:

- **Detailed errors returned to the client:** Stack traces, database error text, internal service names, query fragments. These provide a reconnaissance windfall to an attacker. Every production service should have a single error-handling middleware that maps internal exceptions to sanitized client responses.
- **Sensitive data in logs:** Full request bodies including passwords, tokens in query strings, PHI in search queries. Logs are usually stored with less stringent access control than the primary data store — sensitive data in logs is a data-classification violation.

---

## How to Scope a Review Efficiently

A targeted review follows the data, not the file tree. The order that works:

### Step 1: Find the Entry Points (10-20% of time)

List every way external input reaches this code. HTTP handlers, message queue consumers, scheduled jobs that pull from external sources, file upload handlers, webhook receivers. Make a concrete list — a PR that adds three new HTTP endpoints has three entry points, not "the API."

### Step 2: Map the Trust Boundaries (10-15% of time)

For each entry point, identify where validated input becomes "trusted." Where does the code stop validating? This is usually a function signature or a data structure that presents itself as "already cleaned up." Trust boundaries are also where data crosses service boundaries, writes to a data store, or flows into external systems.

### Step 3: Follow the Data Flows (50-60% of time)

This is where you spend most of your review time. For each piece of attacker-controlled input:
- Where does it go? (What queries does it participate in? What files does it name? What URLs does it construct?)
- What does the code do with it along the way? (Sanitize? Encode? Reformat? Trust?)
- Where does it end up? (Rendered back in a response? Stored? Passed to a downstream service?)

Taint tracking in your head is tedious but effective. Modern reviewers use `rg` / `ripgrep` heavily: find every reference to the inbound variable name, follow the assignments, keep notes.

### Step 4: Validate the Controls You Expect to See (15-20% of time)

Once you understand the data flow, check that the protections you would design into this code actually exist. Is there a parameterized query at the edge? Is authorization checked before the query runs, not after? Is the response filtered to the fields the user is allowed to see?

Absence of a control is a finding. Present-but-broken control is also a finding. Trust nothing you have not verified.

---

## How to Write Findings Developers Will Act On

A secure code review produces a list of findings. A finding that gets fixed has six properties. A finding without them is a comment, not a ticket.

**1. File and line.** Always. `src/api/users.py:147`. A finding without a location is not actionable. If the finding spans a function, cite the function entry and the specific problem lines.

**2. The exploit scenario in plain language.** Not "user input is not validated." Write the exploit as a two-sentence narrative: "An authenticated user sends a PATCH request to `/users/{id}` with a body containing `{\"role\": \"admin\"}`. The handler passes the body directly to the ORM's `update()` method, which writes all fields including the role column. The attacker now has admin on the platform."

A developer reading the exploit narrative should be able to reproduce it themselves with `curl` in 30 seconds. If they cannot, the narrative is too abstract.

**3. The concrete code-level fix.** Not "add input validation." Show the code. If the fix is a three-line change, paste the three lines. If the fix requires a structural change, paste the shape of the structural change. The recommendation must be specific enough that a competent engineer, reading only the finding, can produce a PR.

**4. A test that verifies the fix.** This is the property most finding-writers skip. Every finding should come with a test: the request that currently exploits the bug and should fail after the fix, or the unit test that exercises the broken invariant. Reviewers like tests because the test is a verifier; developers like tests because they prove the fix worked.

**5. Severity with justification.** "High" is not a justification. "High: authenticated user can escalate to admin without requiring any additional compromise; impact is full tenant takeover" is a justification. Tie severity to the exploit narrative, not to a vague rubric.

**6. An owner and a target sprint.** Findings without owners are findings that will not be fixed. Coordinate with the engineering lead at the point of review — do not throw findings over the wall and hope they land.

---

## Review Checklist by Category

Use this as a working checklist on every review. For language-specific versions with code, see the `checklists/` folder.

### Input Handling

- [ ] Every entry point identified and noted.
- [ ] Every external input is validated against a strict schema at the boundary (length, type, character class, allowed values).
- [ ] Output encoding is applied at the point of output, not at the point of input (prevents stored XSS).
- [ ] No raw string concatenation into SQL, shell commands, XPath, LDAP filters, or URL construction.
- [ ] File paths derived from user input are resolved and verified to be within the expected directory.
- [ ] URLs derived from user input go through an allowlist, never a denylist.

### Authentication and Session Management

- [ ] Every endpoint that accesses protected data requires a valid, unexpired token.
- [ ] JWT validation pins the expected algorithm, issuer, and audience.
- [ ] Session tokens come from a CSPRNG and have meaningful entropy (≥128 bits).
- [ ] Password reset tokens are single-use, time-limited, and bound to the originating account.
- [ ] Step-up / MFA assertions are bound to the operation being authorized, not to a global session.
- [ ] Logout invalidates the session server-side (not just client-side cookie clearing).

### Authorization

- [ ] Every handler that accepts a resource ID verifies the authenticated user has access to *that* resource, not just *a* resource.
- [ ] Role checks validate the role *and* the resource scope.
- [ ] Authorization is enforced at the data layer (query filter, RLS, service-level check), not just at the URL routing.
- [ ] Administrative endpoints have additional scoping (tenant, geography, business unit) beyond "is admin."

### Cryptography

- [ ] No use of MD5 or SHA-1 for anything security-relevant.
- [ ] Passwords hashed with Argon2id, bcrypt, or scrypt, with current-era cost parameters.
- [ ] All symmetric encryption uses AEAD (AES-GCM, ChaCha20-Poly1305). No CBC without authenticated MAC.
- [ ] Random values for tokens and keys come from `secrets` (Python) or `crypto.randomBytes` (Node).
- [ ] No hand-rolled crypto. No "XOR with a key" patterns.
- [ ] Signing keys are per-environment, KMS-managed, rotatable.

### Error Handling and Logging

- [ ] Exceptions are caught at a single top-level handler and mapped to sanitized responses.
- [ ] No stack traces or database error text in production responses.
- [ ] Audit log events are emitted for all privileged actions, with actor, target, timestamp, and request ID.
- [ ] Sensitive data (passwords, tokens, PII, PHI) is not logged. Verified against logger calls in the changed code.
- [ ] Logs go to an immutable store for regulated-action auditing.

### Secrets Management

- [ ] No hardcoded credentials, API keys, or tokens anywhere in the repo (including test files and fixtures).
- [ ] Secrets loaded from environment, secrets manager, or KMS. Never from a committed config file.
- [ ] The `.env` files committed (if any) are examples only — verify no real secrets.
- [ ] Secrets scanning runs on every PR and on the default branch; gitleaks history scan current.

### Dependency Safety

- [ ] No new dependency added in this PR that has known high/critical CVEs.
- [ ] Lockfile is updated and committed.
- [ ] New dependency is maintained (last release within 12 months, active repo).
- [ ] No transitive dependencies from abandoned or single-maintainer packages handling security-critical functionality.

### Business Logic

- [ ] The feature's implicit assumptions are documented or explicit in code.
- [ ] Every state transition has been considered: what happens in each intermediate state?
- [ ] Every "impossible" path has an assertion or an explicit rejection.
- [ ] Financial operations are idempotent (same request submitted twice produces one side effect).
- [ ] Rate limits and quotas are enforced at the operation level, not just at the endpoint level.
