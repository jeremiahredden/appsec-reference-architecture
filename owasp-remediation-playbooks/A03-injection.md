# A03 — Injection

## What it is

Injection is any bug where attacker-controlled input is interpolated into a string that is then parsed and executed by an interpreter — a SQL engine, a shell, an LDAP directory, an XPath/XQuery engine, an ORM's raw-query escape hatch, a MongoDB query, a template renderer. The interpreter cannot distinguish code from data because the application handed it a single blended string, so the attacker's input becomes instructions. OWASP merged several historically-separate bugs (cross-site scripting included) into the A03 category in 2021 because the underlying defect is the same: data and code shared a channel.

The fix is always the same shape: keep data and code in separate channels. Parameterized queries, argument lists for subprocesses, DOM APIs that take text rather than markup, and schema-validated structured data all apply that principle. The fix is simpler than the bug — which is why injection has been at or near the top of the OWASP list for two decades.

## Why it matters

A concrete exploit: a reporting dashboard allows authenticated users to filter by customer name. The backend builds the query with an f-string:

```python
query = f"SELECT * FROM transactions WHERE customer = '{name}'"
```

An attacker submits `' UNION SELECT email, password_hash, null FROM users --` as the customer name. The UNION query returns the `users` table through the transactions endpoint. The dashboard renders the rows as normal "transactions," and the attacker now has every email and password hash in the system. If password hashing was weak (see A02), the attacker has every password within the hour.

The fix is parameterization: `WHERE customer = :name` with `{"name": name}` passed as a bind parameter. The attacker's entire payload becomes a single string value — not syntax — and the query returns zero rows.

Other common shapes:

- **NoSQL operator injection**: MongoDB accepts `{"$ne": null}` as a query value, and Node apps that pass `req.body.password` directly into the query get "find any user" for free.
- **Command injection**: `subprocess.run(f"convert {filename} out.jpg", shell=True)` — filename with a semicolon becomes RCE.
- **Template injection (SSTI)**: Jinja2 or Handlebars templates rendered with user-supplied template strings — full RCE in most template engines.
- **XSS**: user input interpolated into HTML without encoding — historically A07, now absorbed into A03.
- **Log injection**: unvalidated input containing newline characters that forge log lines.
- **Header injection / CRLF injection**: user input in an HTTP response header that contains CR/LF, splitting the response.

## How to find it

**Manual review indicators.** Any f-string, `.format()`, or `%`-interpolation that builds a SQL, shell command, LDAP filter, or XPath query. Any `exec()`, `eval()`, `os.system()`, or `subprocess` call with `shell=True`. Any template engine rendered with a user-supplied template body. Any ORM `raw()`, `text()`, `execute()` with an interpolated string. Any NoSQL driver receiving `{...req.body}` as a query. Any response that renders user input into HTML without a templating engine's auto-escape or an explicit `escape()`.

**Automated signals.**

- Semgrep: `python.lang.security.audit.formatted-sql-query`, `python.django.security.audit.raw-query`, `python.sqlalchemy.security.sqlalchemy-execute-raw-query`, `python.subprocess-shell-true`.
- Semgrep: `javascript.lang.security.audit.detect-child-process`, `javascript.express.security.audit.xss-serialize-javascript`, `typescript.react.security.audit.react-dangerouslysetinnerhtml`.
- Semgrep custom rule: `eval-on-request-input` (this repo — catches `eval()` / `new Function()` on Express request data).
- Bandit: `B601` (shell injection via paramiko), `B602` (subprocess shell=True), `B608` (SQL injection via string concat).
- Snyk Code: `javascript/Sqli`, `javascript/CodeInjection`, `javascript/CommandInjection`.
- Runtime: dependency on a WAF / RASP as a defense-in-depth, never as the primary control.

## How to fix it — Python

**Vulnerable.**
```python
# SQL injection via f-string.
def search_transactions(session, customer_name: str):
    query = f"SELECT * FROM transactions WHERE customer = '{customer_name}'"
    return session.execute(query).fetchall()

# Command injection via shell=True.
def convert_image(filename: str):
    subprocess.run(f"convert {filename} output.jpg", shell=True, check=True)

# Template injection — user controls the template, not just the data.
def render_email(template_src: str, context: dict) -> str:
    return Template(template_src).render(**context)
```

**Secure.**
```python
from sqlalchemy import text

# Parameterized query — bind values, not string interpolation.
def search_transactions(session, customer_name: str):
    return session.execute(
        text("SELECT * FROM transactions WHERE customer = :name"),
        {"name": customer_name},
    ).fetchall()

# Or, preferred, the ORM — parameterized by construction.
def search_transactions_orm(session, customer_name: str):
    return session.query(Transaction).filter(Transaction.customer == customer_name).all()

# Argument list, no shell, with path validation.
def convert_image(filename: str):
    source = (UPLOADS_DIR / filename).resolve()
    if UPLOADS_DIR not in source.parents:
        raise ValueError("path traversal")
    subprocess.run(
        ["convert", str(source), "output.jpg"],
        shell=False, check=True, timeout=30,
    )

# User supplies CONTEXT, not the template. Templates are authored by
# the application, loaded from a trusted location, and autoescape is on.
env = Environment(
    loader=FileSystemLoader("templates"),
    autoescape=select_autoescape(["html", "xml"]),
)

def render_email(template_name: str, context: dict) -> str:
    return env.get_template(template_name).render(**context)
```

## How to fix it — JavaScript

**Vulnerable.**
```javascript
// SQL injection via template literal.
async function searchTransactions(conn, customerName) {
  const [rows] = await conn.query(
    `SELECT * FROM transactions WHERE customer = '${customerName}'`
  );
  return rows;
}

// NoSQL operator injection.
app.post("/login", async (req, res) => {
  const user = await User.findOne({
    email: req.body.email,
    password: req.body.password, // { "$ne": null } → authentication bypass
  });
  if (!user) return res.status(401).json({ error: "invalid" });
  res.json({ token: issueToken(user) });
});

// XSS via dangerouslySetInnerHTML with user content.
function Comment({ body }) {
  return <div dangerouslySetInnerHTML={{ __html: body }} />;
}
```

**Secure.**
```javascript
// Parameterized query with placeholders.
async function searchTransactions(conn, customerName) {
  const [rows] = await conn.execute(
    "SELECT * FROM transactions WHERE customer = ?",
    [customerName],
  );
  return rows;
}

// NoSQL — schema validation + lookup by email, then explicit hash verify.
const mongoSanitize = require("express-mongo-sanitize");
app.use(mongoSanitize());

const LoginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1).max(256),
}).strict();

app.post("/login", async (req, res) => {
  const parsed = LoginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid" });

  const user = await User.findOne({ email: parsed.data.email }).select("+passwordHash");
  if (!user || !(await argon2.verify(user.passwordHash, parsed.data.password))) {
    return res.status(401).json({ error: "invalid credentials" });
  }
  res.json({ token: issueToken(user) });
});

// XSS — React escapes by default. Use it.
function Comment({ body }) {
  return <div>{body}</div>;
}

// When you MUST render HTML — markdown-authored content, for example —
// sanitize with a strict allowlist of tags and attributes.
import DOMPurify from "dompurify";
function MarkdownComment({ rawHtml }) {
  const clean = DOMPurify.sanitize(rawHtml, {
    ALLOWED_TAGS: ["p", "a", "em", "strong", "code", "pre", "ul", "ol", "li"],
    ALLOWED_ATTR: ["href", "title"],
    ALLOWED_URI_REGEXP: /^(https?:|mailto:)/i,
  });
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
```

## How to test the fix

**pytest (Python).**
```python
@pytest.mark.parametrize("payload", [
    "' OR '1'='1",
    "' UNION SELECT email, password_hash, null FROM users --",
    "'; DROP TABLE transactions; --",
])
def test_sql_injection_payloads_return_empty(client, payload, db, user_factory):
    user = user_factory()
    resp = client.get(
        "/transactions",
        params={"customer": payload},
        headers=auth_headers(user),
    )
    assert resp.status_code == 200
    assert resp.json() == []   # No rows matched; no syntax error leaked.

def test_command_injection_payload_is_treated_as_filename(tmp_path):
    # The injection characters are treated as filename bytes, so the
    # call fails with FileNotFoundError rather than running a shell.
    with pytest.raises(ValueError):
        convert_image("photo.png; curl evil.example.com")
```

**Jest (JavaScript).**
```javascript
describe("SQL + NoSQL injection", () => {
  it.each([
    "' OR '1'='1",
    "' UNION SELECT email,password_hash FROM users --",
    "'; DROP TABLE transactions; --",
  ])("returns empty results for payload %s", async (payload) => {
    const res = await request(app)
      .get("/transactions")
      .query({ customer: payload })
      .set("Authorization", `Bearer ${signTokenFor(alice)}`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual([]);
  });

  it("rejects Mongo operator injection on login", async () => {
    const res = await request(app)
      .post("/login")
      .send({ email: "victim@example.com", password: { $ne: null } });
    expect(res.status).toBe(400);
  });
});

describe("XSS", () => {
  it("does not render script tags from comment body", () => {
    const { container } = render(<Comment body="<script>alert(1)</script>" />);
    expect(container.querySelector("script")).toBeNull();
    expect(container.textContent).toContain("<script>alert(1)</script>");
  });
});
```

## Compliance mapping

| Framework | Control | Relevance |
| --- | --- | --- |
| **HIPAA Security Rule** | §164.312(c)(1) — Integrity | Injection that modifies or deletes PHI is an integrity violation; controls that prevent unauthorized writes are in-scope. |
| **HIPAA Security Rule** | §164.308(a)(1)(ii)(B) — Risk Management | Reducing known risks to a reasonable and appropriate level; injection is a known, addressable risk. |
| **SOC 2 Trust Services Criteria** | CC6.1 — Logical Access Controls | Injection that bypasses query-level access controls is a logical access failure. |
| **SOC 2 Trust Services Criteria** | CC8.1 — Change Management | Controls to prevent unauthorized changes to data; parameterized queries prevent injected writes. |
| **NIST CSF 2.0** | PR.DS-10 — The confidentiality, integrity, and availability of data-in-use are protected | Data being processed (query inputs, template contexts) is protected from tampering. |
| **NIST CSF 2.0** | PR.PS-06 — Secure software development practices are integrated | Injection-safe APIs (parameterized queries, argument lists, safe templating) are the SDLC realization. |

For PCI-DSS v4, this maps to Requirement 6.2.4 (software engineered to prevent common software attacks, including injection) and Requirement 6.4.2 (review application code or use automated tools to identify and address coding vulnerabilities).
