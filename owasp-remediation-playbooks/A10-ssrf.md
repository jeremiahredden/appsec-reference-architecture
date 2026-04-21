# A10 — Server-Side Request Forgery

## What it is

Server-side request forgery (SSRF) is a bug where an application fetches a URL, and an attacker controls, in whole or in part, what URL gets fetched. The application is the request originator, so the request comes from inside the network and bypasses whatever boundary controls the perimeter applied. SSRF is the category that most often ends in cloud-metadata-service theft — the attacker uses the application as a proxy to read the IMDS endpoint (`http://169.254.169.254/`) and obtain the instance's IAM credentials.

SSRF was promoted to its own OWASP category in 2021 after a decade of being filed under "various injection." The promotion reflects the cloud-era reality: a server that can reach `169.254.169.254` and is willing to fetch arbitrary URLs on behalf of a user is a short path from "fetch this image URL" to "exfiltrate an AWS role."

## Why it matters

A concrete exploit: a content-aggregator app accepts a URL from users, fetches the page, and renders a preview (title, description, og:image). The fetcher uses `requests.get(url)` with no allowlist, no protocol restriction, and no DNS-pin. An attacker submits `http://169.254.169.254/latest/meta-data/iam/security-credentials/app-role`. The service fetches the IMDS endpoint from inside the VPC, the response contains the temporary IAM credentials for the EC2 instance's role, and the credentials are rendered back to the attacker as the "preview." Those credentials have `s3:GetObject` on the production bucket. The breach notification letters go out two weeks later.

This specific shape of SSRF was the root cause of the 2019 Capital One incident, where a misconfigured WAF was exploited to hit IMDS and exfiltrate AWS credentials. IMDSv2 (token-bound requests) shuts this specific attack down; it does not stop SSRF against internal services that lack equivalent protection.

Other common shapes:

- **Internal network scanning** — the attacker submits `http://10.0.0.1`, `http://10.0.0.2`, ... and learns the internal topology from response timing / status codes.
- **DNS rebinding** — the URL resolves to a public IP on first check and to `127.0.0.1` on the actual request; allowlist-by-hostname defeated.
- **Protocol smuggling** — `gopher://`, `file://`, `dict://` used to reach services that speak different protocols on the same port (Redis, memcached, SMTP).
- **Blind SSRF** — the response is not shown to the attacker, but side effects (admin API calls, credential rotation) still happen.
- **SSRF via redirect** — the attacker's URL is on the allowlist and redirects to an internal target; the HTTP client follows.

## How to find it

**Manual review indicators.** Any code path that takes a URL (or a fragment that becomes a URL) from a request and calls `requests.get`, `urllib.request.urlopen`, `httpx.get`, `fetch`, `axios`, `http.get`, `got`, `node-fetch`, `curl`, or a webhook-delivery helper. Any integration that accepts a customer-configurable webhook URL. Any image/file fetcher that takes a URL parameter. Any oEmbed / open-graph preview generator. Any SAML/OIDC metadata loader that accepts a URL.

**Automated signals.**

- Semgrep: `python.requests.security.audit.ssrf-requests-library`, `python.urllib.security.audit.urlopen-ssrf`.
- Semgrep: `javascript.lang.security.detect-non-literal-require`, `javascript.lang.security.audit.audit-node-fetch-ssrf`.
- Bandit: `B310` (urllib urlopen with user input), `B113` (requests with no timeout, which is an availability and SSRF-timing signal).
- Snyk Code: `javascript/Ssrf`, `javascript/UrlRedirection`.
- DAST: Burp Collaborator / interactsh — feed an out-of-band URL into every user-controllable URL parameter and watch what connects.
- Cloud-side: require IMDSv2 on every EC2 instance, block egress from pod networks to the IMDS IP, run an egress proxy that enforces an allowlist.

## How to fix it — Python

**Vulnerable.**
```python
# Preview generator that fetches any URL the user supplies.
import requests
from urllib.parse import urlparse

@app.post("/preview")
def preview():
    url = request.json["url"]
    r = requests.get(url, timeout=10)          # SSRF.
    return {"title": _extract_title(r.text)}

# Webhook deliverer that follows redirects and accepts any scheme.
def deliver_webhook(endpoint: str, payload: dict):
    requests.post(endpoint, json=payload, timeout=15,
                  allow_redirects=True)        # Redirect can land on IMDS.
```

**Secure.**
```python
# Validate the URL structure, resolve DNS ourselves, reject private /
# link-local / loopback targets, disable redirects, and route through
# an egress proxy that enforces a second layer of controls.
import ipaddress, socket
from urllib.parse import urlparse
import requests

ALLOWED_SCHEMES = {"http", "https"}
BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),    # IMDS.
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def _is_blocked(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in BLOCKED_NETWORKS)

def _resolve_allowed(hostname: str) -> str:
    # Resolve, check every returned address. Prevents DNS rebinding by
    # using the resolved IP below, not the hostname.
    infos = socket.getaddrinfo(hostname, None)
    addresses = {info[4][0] for info in infos}
    if not addresses or any(_is_blocked(a) for a in addresses):
        raise ValueError(f"destination not allowed: {hostname}")
    return next(iter(addresses))

def safe_fetch(url: str, *, max_bytes: int = 2 * 1024 * 1024) -> bytes:
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError("scheme not allowed")
    if not parsed.hostname:
        raise ValueError("hostname required")

    resolved = _resolve_allowed(parsed.hostname)
    # Connect to the resolved IP but send the original Host header, so
    # TLS / virtual hosting still work and rebinding cannot flip us.
    session = requests.Session()
    session.mount("http://", _PinnedHTTPAdapter(resolved))
    session.mount("https://", _PinnedHTTPAdapter(resolved))

    with session.get(
        url,
        timeout=(3, 10),
        allow_redirects=False,       # Handle redirects manually, re-validating each hop.
        stream=True,
    ) as r:
        r.raise_for_status()
        body = r.raw.read(max_bytes + 1, decode_content=True)
        if len(body) > max_bytes:
            raise ValueError("response too large")
        return body
```

`_PinnedHTTPAdapter` is an adapter that overrides `get_connection` to use the resolved IP instead of re-resolving the hostname at connect time, so DNS rebinding cannot move the target between the check and the connect.

For webhook delivery specifically, use an allowlist of hostnames / domains when possible (many SaaS products publish explicit egress destinations), and route through an egress proxy that caps concurrency and enforces the same IP checks a second time.

## How to fix it — JavaScript

**Vulnerable.**
```javascript
// Preview generator with no URL validation.
const fetch = require("node-fetch");

app.post("/preview", async (req, res) => {
  const r = await fetch(req.body.url);     // SSRF.
  const html = await r.text();
  res.json({ title: extractTitle(html) });
});

// Webhook deliverer that follows redirects.
async function deliverWebhook(url, payload) {
  await fetch(url, {
    method: "POST",
    body: JSON.stringify(payload),
    redirect: "follow",                    // Can land on IMDS.
  });
}
```

**Secure.**
```javascript
// URL validator + pinned-IP agent. On Node we use a custom lookup
// function on the HTTP agent to resolve and validate every connection.
const { URL } = require("url");
const dns = require("dns/promises");
const net = require("net");
const http = require("http");
const https = require("https");
const ipaddr = require("ipaddr.js");

const BLOCKED_RANGES = [
  ["10.0.0.0", 8],
  ["172.16.0.0", 12],
  ["192.168.0.0", 16],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["::1", 128],
  ["fc00::", 7],
  ["fe80::", 10],
];

function isBlocked(ip) {
  const parsed = ipaddr.parse(ip);
  return BLOCKED_RANGES.some(([range, bits]) =>
    parsed.kind() === ipaddr.parse(range).kind() &&
    parsed.match(ipaddr.parse(range), bits),
  );
}

async function safeLookup(hostname, options, cb) {
  try {
    const records = await dns.lookup(hostname, { all: true, family: 0 });
    for (const r of records) {
      if (isBlocked(r.address)) {
        return cb(new Error(`blocked address: ${r.address}`));
      }
    }
    const first = records[0];
    cb(null, first.address, first.family);
  } catch (err) {
    cb(err);
  }
}

const safeHttpAgent = new http.Agent({ lookup: safeLookup });
const safeHttpsAgent = new https.Agent({ lookup: safeLookup });

async function safeFetch(rawUrl, { maxBytes = 2 * 1024 * 1024 } = {}) {
  const url = new URL(rawUrl);
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("scheme not allowed");
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  try {
    const res = await fetch(rawUrl, {
      redirect: "manual",               // Re-validate redirects manually.
      agent: url.protocol === "https:" ? safeHttpsAgent : safeHttpAgent,
      signal: controller.signal,
    });
    if ([301, 302, 303, 307, 308].includes(res.status)) {
      throw new Error("redirects not allowed on this endpoint");
    }
    const reader = res.body;
    const chunks = [];
    let total = 0;
    for await (const chunk of reader) {
      total += chunk.length;
      if (total > maxBytes) throw new Error("response too large");
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  } finally {
    clearTimeout(timer);
  }
}

app.post("/preview", async (req, res) => {
  try {
    const body = await safeFetch(req.body.url);
    res.json({ title: extractTitle(body.toString("utf8")) });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});
```

## How to test the fix

**pytest (Python).**
```python
@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",       # AWS IMDS
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://127.0.0.1/admin",
    "http://[::1]/",
    "http://10.0.0.5/",
    "http://localhost/",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",
])
def test_safe_fetch_rejects_internal_and_non_http_targets(url):
    with pytest.raises(ValueError):
        safe_fetch(url)

def test_safe_fetch_rejects_redirect_to_internal(httpserver):
    httpserver.expect_request("/redir").respond_with_data(
        "", status=302, headers={"Location": "http://169.254.169.254/"},
    )
    with pytest.raises(Exception):
        safe_fetch(httpserver.url_for("/redir"))

def test_safe_fetch_enforces_max_bytes(httpserver):
    httpserver.expect_request("/big").respond_with_data("A" * (3 * 1024 * 1024))
    with pytest.raises(ValueError):
        safe_fetch(httpserver.url_for("/big"), max_bytes=1 * 1024 * 1024)
```

**Jest (JavaScript).**
```javascript
describe("SSRF protections", () => {
  it.each([
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1/admin",
    "http://[::1]/",
    "http://10.0.0.5/",
    "http://localhost/",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",
  ])("rejects %s", async (url) => {
    await expect(safeFetch(url)).rejects.toThrow();
  });

  it("rejects HTTP redirects to internal addresses", async () => {
    // Start a short-lived server that returns a 302 → IMDS.
    const server = http.createServer((req, res) => {
      res.writeHead(302, { Location: "http://169.254.169.254/" });
      res.end();
    });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    const { port } = server.address();
    await expect(safeFetch(`http://127.0.0.1:${port}/`)).rejects.toThrow();
    server.close();
  });

  it("enforces max response size", async () => {
    const big = "A".repeat(3 * 1024 * 1024);
    nock("https://example.com").get("/big").reply(200, big);
    await expect(safeFetch("https://example.com/big", { maxBytes: 1 * 1024 * 1024 }))
      .rejects.toThrow(/too large/);
  });
});
```

## Compliance mapping

| Framework | Control | Relevance |
| --- | --- | --- |
| **HIPAA Security Rule** | §164.312(a)(1) — Access Control | SSRF that reaches internal services bypasses intended access boundaries around ePHI. |
| **HIPAA Security Rule** | §164.312(e)(1) — Transmission Security | Controls on data transmission; SSRF is an unauthorized transmission originating from the server. |
| **HIPAA Security Rule** | §164.308(a)(1)(ii)(A) — Risk Analysis | SSRF is a known risk to systems that fetch URLs; risk analysis must account for it. |
| **SOC 2 Trust Services Criteria** | CC6.1 — Logical Access Controls | Egress controls on outbound application traffic, IP allowlists, and IMDS hardening. |
| **SOC 2 Trust Services Criteria** | CC6.6 — Transmission of Information | Protecting confidentiality of information transmitted, including blocking unauthorized outbound destinations. |
| **SOC 2 Trust Services Criteria** | CC6.8 — Prevention and Detection of Unauthorized Software and Malicious Acts | SSRF is exploited as an unauthorized act; detection via egress proxy logging is a control. |
| **NIST CSF 2.0** | PR.IR-01 — Networks and environments are protected from unauthorized logical access and usage | Egress network segmentation, IMDSv2 enforcement, pod-level egress firewalls. |
| **NIST CSF 2.0** | PR.DS-02 — Data-in-transit is protected | Includes preventing unintended transmissions. |
| **NIST CSF 2.0** | DE.CM-01 — Networks are monitored to find potentially adverse events | Egress proxy logging detects SSRF attempts. |

For PCI-DSS v4, this maps to Requirement 1.4 (controls between trusted and untrusted networks), Requirement 6.2.4 (software engineered to prevent common attacks, including SSRF), and Requirement 1.4.5 (disclosure of internal IP addresses is prevented). For AWS environments specifically, IMDSv2 enforcement and metadata hop-limit of 1 are the baseline mitigations that should be validated continuously (AWS Config rule `ec2-imdsv2-check`).
