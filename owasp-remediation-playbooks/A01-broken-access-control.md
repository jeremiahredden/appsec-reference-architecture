# A01 — Broken Access Control

## What it is

Broken access control is any bug that lets a user do something the application was supposed to prevent: view another tenant's data, modify a record they do not own, escalate to an administrative role, or bypass a workflow step. Authentication asks "who are you"; authorization asks "are you allowed to do this specific thing to this specific resource." A broken authorization check is the most common class of bug in real-world applications, and it is responsible for more Critical findings in my engagements than any other category.

## Why it matters

A concrete exploit: a consumer SaaS platform exposes an endpoint `GET /api/v1/invoices/{invoice_id}` that checks the requester is authenticated but does not verify the invoice belongs to them. An attacker signs up for a free account, generates one invoice to learn the ID format (sequential integers), then writes a two-line loop that enumerates every invoice in the system. Twenty minutes later they have every customer's billing address, itemized purchase history, and partial card data.

The fix is one line — a `WHERE customer_id = $current_user` clause. The impact is total customer-data exposure and a GDPR notification. This is the archetypal IDOR (Insecure Direct Object Reference) bug, and it ships to production every week somewhere in the industry.

Other common shapes:

- **Horizontal privilege escalation**: any authenticated user can act on any other user's records.
- **Vertical privilege escalation**: a standard user reaches an admin endpoint because the role check was on the frontend only.
- **Missing function-level authorization**: the endpoint requires a JWT, but does not check that the JWT's scope permits the operation.
- **Path/parameter tampering**: `?user_id=123` trusted verbatim without cross-referencing the authenticated session.

## How to find it

**Manual review indicators.** On every handler that accepts a resource ID in the URL, query string, or body: trace the ID into the database query. If the query filters only by the ID and not by the authenticated user's identity (or the user's tenant, or a join against an ownership table), it is an IDOR. Any admin endpoint that relies on "the frontend hides the button" is broken. Any endpoint whose authorization is a single `if user.role == 'admin'` without resource scoping is broken when an admin is cross-tenant.

**Automated signals.** Scanner coverage for this category is weaker than for injection or crypto because "is this user allowed to access this resource" is a semantic question. What automation can catch:

- Semgrep: `python.flask.security.audit.route-without-login-required` (Flask routes missing `@login_required`).
- Semgrep custom rule: `flask-route-missing-auth` (in this repo's `devsecops-pipeline/semgrep-rules/custom-rules.yaml`).
- Semgrep: `javascript.express.security.audit.express-route-without-auth` (Express routes with no middleware).
- Snyk Code: `javascript/InsecureDirectObjectReference` (heuristic — tune before trusting).
- Checkov: `CKV_AWS_111` (S3 bucket policy too permissive) — infrastructure-level broken access control.

Put the weight on integration tests. Every protected endpoint should have a test that asserts a different user's resource ID returns 404 (not 403 — do not confirm existence).

## How to fix it — Python

**Vulnerable.**
```python
# FastAPI — authenticated but not authorized.
@app.get("/invoices/{invoice_id}")
def get_invoice(invoice_id: int, user = Depends(current_user)):
    # Checks authentication (via the dependency) but not ownership.
    invoice = db.query(Invoice).filter(Invoice.id == invoice_id).one_or_none()
    if not invoice:
        raise HTTPException(404)
    return invoice
```

**Secure.**
```python
@app.get("/invoices/{invoice_id}")
def get_invoice(invoice_id: int, user = Depends(current_user)):
    # Scope the query by BOTH the resource ID and the owner's customer_id.
    # If the invoice exists but belongs to someone else, .one_or_none()
    # returns None and the attacker gets a 404 — we do NOT return 403,
    # which would confirm the invoice exists.
    invoice = db.query(Invoice).filter(
        Invoice.id == invoice_id,
        Invoice.customer_id == user.customer_id,
    ).one_or_none()
    if not invoice:
        raise HTTPException(404)
    return invoice


# For a multi-table / aggregate endpoint, push the authorization into
# a shared helper so individual handlers cannot forget it.
def get_invoice_for_user(db, invoice_id: int, user) -> Invoice:
    invoice = db.query(Invoice).filter(
        Invoice.id == invoice_id,
        Invoice.customer_id == user.customer_id,
    ).one_or_none()
    if not invoice:
        raise HTTPException(404)
    return invoice


# For the Django crowd, this is also where row-level security or a
# custom manager pays off: never let a handler query Invoice.objects
# directly; force every query through a user-scoped manager.
```

## How to fix it — JavaScript

**Vulnerable.**
```javascript
// Express — authenticated middleware runs, but no ownership check.
app.get("/invoices/:invoiceId", requireAuth, async (req, res) => {
  const invoice = await Invoice.findById(req.params.invoiceId);
  if (!invoice) return res.status(404).json({ error: "not found" });
  res.json(invoice);
});
```

**Secure.**
```javascript
// Ownership enforced at the query layer. A missing resource and a
// resource-you-don't-own both return 404, so the endpoint does not
// leak existence.
app.get("/invoices/:invoiceId", requireAuth, async (req, res) => {
  const invoice = await Invoice.findOne({
    _id: req.params.invoiceId,
    customerId: req.user.customerId,
  });
  if (!invoice) return res.status(404).json({ error: "not found" });
  res.json(invoice);
});


// Reusable authorization helper — every handler that needs an invoice
// goes through this function, so the filter cannot be forgotten.
async function getInvoiceForUser(invoiceId, user) {
  const invoice = await Invoice.findOne({
    _id: invoiceId,
    customerId: user.customerId,
  });
  if (!invoice) {
    const err = new Error("not found");
    err.status = 404;
    throw err;
  }
  return invoice;
}


// For the admin case: role check AND tenant scoping, together.
function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "forbidden" });
  next();
}

app.get("/admin/invoices/:invoiceId",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    // An admin can read invoices — but only in their own tenant.
    // Platform super-admins use a different endpoint with additional checks.
    const invoice = await Invoice.findOne({
      _id: req.params.invoiceId,
      tenantId: req.user.tenantId,
    });
    if (!invoice) return res.status(404).json({ error: "not found" });
    res.json(invoice);
  },
);
```

## How to test the fix

**pytest (Python).**
```python
def test_user_cannot_read_other_users_invoice(client, db, user_factory, invoice_factory):
    alice = user_factory(customer_id="c-alice")
    bob = user_factory(customer_id="c-bob")
    bobs_invoice = invoice_factory(customer_id="c-bob")

    # Authenticated as alice, asking for bob's invoice ID.
    resp = client.get(
        f"/invoices/{bobs_invoice.id}",
        headers=auth_headers(alice),
    )

    # Expect 404 — not 403 — so the endpoint does not confirm existence.
    assert resp.status_code == 404
    # And alice's own invoice is still reachable.
    alices_invoice = invoice_factory(customer_id="c-alice")
    ok = client.get(f"/invoices/{alices_invoice.id}", headers=auth_headers(alice))
    assert ok.status_code == 200
```

**Jest (JavaScript).**
```javascript
describe("GET /invoices/:invoiceId authorization", () => {
  it("returns 404 when the invoice belongs to a different customer", async () => {
    const alice = await userFactory({ customerId: "c-alice" });
    const bob = await userFactory({ customerId: "c-bob" });
    const bobsInvoice = await invoiceFactory({ customerId: "c-bob" });

    const res = await request(app)
      .get(`/invoices/${bobsInvoice._id}`)
      .set("Authorization", `Bearer ${signTokenFor(alice)}`);

    expect(res.status).toBe(404);
  });

  it("returns 200 for the user's own invoice", async () => {
    const alice = await userFactory({ customerId: "c-alice" });
    const alicesInvoice = await invoiceFactory({ customerId: "c-alice" });

    const res = await request(app)
      .get(`/invoices/${alicesInvoice._id}`)
      .set("Authorization", `Bearer ${signTokenFor(alice)}`);

    expect(res.status).toBe(200);
    expect(res.body._id).toBe(alicesInvoice._id.toString());
  });
});
```

Both tests fail against the vulnerable implementation (alice reads bob's invoice) and pass against the fix. Ship the test with the fix.

## Compliance mapping

| Framework | Control | Relevance |
| --- | --- | --- |
| **HIPAA Security Rule** | §164.312(a)(1) — Access Control | Implementing technical policies and procedures that allow only authorized persons to access ePHI. IDOR and horizontal privilege escalation are direct violations. |
| **HIPAA Security Rule** | §164.312(a)(2)(i) — Unique User Identification | Every access must be attributable to a specific user; broken access control undermines attributability. |
| **HIPAA Security Rule** | §164.312(b) — Audit Controls | Authorization failures must be logged for forensic review. |
| **SOC 2 Trust Services Criteria** | CC6.1 — Logical and Physical Access Controls | The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events. |
| **SOC 2 Trust Services Criteria** | CC6.3 — User Access Management | Access is authorized, modified, or removed based on roles and responsibilities; function-level and resource-level authorization enforcement is part of this control. |
| **NIST CSF 2.0** | PR.AA-05 — Access permissions, entitlements, and authorizations | Permissions are defined, managed, and enforced — resource-level authorization is the engineering realization of this subcategory. |
| **NIST CSF 2.0** | PR.AA-03 — Users, services, and hardware are authenticated | Authentication is prerequisite to authorization; both must be enforced together. |
| **NIST CSF 2.0** | DE.CM-01 — Continuous monitoring | Unauthorized access attempts must be detectable in logs. |

For PCI-DSS v4 environments, this also maps to Requirement 7 ("Restrict access to cardholder data by business need-to-know") and Requirement 8.2.1 (strong authentication with per-user attribution).
