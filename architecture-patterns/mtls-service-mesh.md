# mTLS with a Service Mesh — A Practitioner's Guide

## The opinion up front

Mutual TLS is an **identity** control first and an **encryption** control second. Plain TLS encrypts the channel and authenticates the server; mTLS additionally authenticates the client. In a service mesh, that client authentication is what lets you make authorization decisions based on who is calling, not where the call came from. If you take mTLS out of a zero-trust design, you lose the ability to enforce "only service A can call service B" without falling back to network-layer controls that are weaker and fail open when a subnet is misconfigured.

Practical recommendation: adopt a mesh (Istio or Linkerd), enable **STRICT** mTLS everywhere, use the mesh's built-in certificate authority with short-lived certificates (24h or less) rotated automatically, and enforce authorization with SPIFFE-identity-based policies. Do not hand-roll mTLS with self-managed certificates outside the mesh unless you have a specific constraint that justifies the operational overhead — I have not seen one that held up over time.

## Why mTLS, not just TLS

| Concern | TLS | mTLS |
| --- | --- | --- |
| Encrypts traffic in flight | Yes | Yes |
| Authenticates the server | Yes | Yes |
| Authenticates the client | No | Yes |
| Enforces "only service A can call service B" | No (needs separate auth) | Yes, at the transport layer |
| Survives subnet/firewall misconfiguration | No (attacker on same subnet reads clear auth tokens) | Yes (attacker cannot complete handshake without valid client cert) |
| Binds identity to the transport | No | Yes — identity is cryptographic, not bearer |

The last row is the one that matters most. With plain TLS, a client proves who it is by presenting a bearer token — which is only as secure as the storage on the client. Anyone who steals the token is the client. With mTLS issued from the mesh's CA, the identity is tied to a cryptographic key pair that the workload proves possession of; stealing the token-equivalent requires exfiltrating a key from a running pod, which is a materially higher bar.

mTLS does not replace application-layer authorization. A service still needs to decide whether a given caller is allowed to perform a given operation. mTLS gives that decision a trustworthy input — "this caller is the `orders` service" — rather than one inferred from network location.

## Certificate lifecycle

Certificates are the source of identity in mTLS. The lifecycle has four stages: issuance, rotation, revocation, and retirement. Get these wrong and every benefit of mTLS becomes a liability.

### Issuance

- **Issuing CA is the trust anchor.** In a mesh, this is typically Istio's `istiod` or Linkerd's `identity` component. The CA key should live in a KMS or HSM; never ship it in a ConfigMap, never commit it to git.
- **Identity format: SPIFFE.** Identities look like `spiffe://cluster.local/ns/checkout/sa/checkout` — encoding cluster, namespace, and service account. That structure is what makes policy writeable.
- **Proof of possession.** The workload's sidecar proxy generates a keypair and requests a cert; the CA verifies the workload's Kubernetes service-account token (or equivalent identity signal) before signing. The private key never leaves the pod.
- **TTL: short.** 24 hours is typical; some deployments go to 1 hour. Short TTLs limit the window for abuse of a stolen key and eliminate most revocation concerns — the cert expires before anyone needs to revoke it.

### Rotation

- **Automatic.** The proxy requests a new cert before the old one expires; there is no human in the loop.
- **Overlapping validity.** New cert is issued before the old one expires; there is a brief window when both are valid to prevent connection drops.
- **Monitor for rotation failures.** If a workload fails to rotate (e.g., its service account was deleted), its existing cert will expire and all its connections will fail. A rotation-failure alert must be in place.

### Revocation

- **Rare for short-lived certs.** A 1-hour cert that expires in 30 minutes is not worth revoking; you wait it out.
- **When it matters.** Long-lived CA certs, compromised workload keys that need immediate denial of access, or a CA rotation.
- **Mechanisms.** Push a new CRL to the mesh control plane, or rotate the intermediate CA such that any cert signed by the old intermediate becomes invalid. OCSP is rarely used inside meshes because the control plane is already online.

### Retirement

- **CA retirement is the hardest case.** Plan a CA rotation before you need one. Istio and Linkerd both support intermediate CA rotation; test it in a non-production cluster first. Budget a multi-day rollout.

## Istio — annotated example configs

The examples below assume a standard Istio install with `meshConfig.accessLogFile` enabled and Envoy sidecars injected into all namespaces the mesh manages. Each config targets the `orders` service.

### 1. Enforce STRICT mTLS

```yaml
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: orders
spec:
  # STRICT: mTLS required on every incoming connection.
  # PERMISSIVE (the install default): accept both plaintext and mTLS.
  # DISABLE: never accept mTLS. Do not use.
  mtls:
    mode: STRICT
```

**What this does.** Envoy sidecars in the `orders` namespace reject any inbound connection that does not present a valid peer certificate signed by the mesh CA. Anything trying to bypass the mesh — a direct pod-to-pod connection that skipped the sidecar, a scrape from a monitoring tool not integrated with the mesh — is rejected at the transport layer.

**Common mistake.** Leaving the mesh in `PERMISSIVE` mode forever. Permissive exists to allow a phased rollout where existing plaintext callers continue working while you migrate them; it is not a steady state. Set a deadline, migrate everything, then flip to STRICT. A mesh in permanent permissive is an mTLS deployment in name only.

### 2. Restrict who can call the service

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: orders-callers
  namespace: orders
spec:
  selector:
    matchLabels:
      app: orders
  action: ALLOW
  rules:
    # Allow the checkout service to POST to /internal/orders/*.
    - from:
        - source:
            principals:
              - "cluster.local/ns/checkout/sa/checkout"
      to:
        - operation:
            methods: ["POST"]
            paths: ["/internal/orders", "/internal/orders/*"]

    # Allow the admin service to GET the same paths for read-only audit.
    - from:
        - source:
            principals:
              - "cluster.local/ns/admin/sa/admin"
      to:
        - operation:
            methods: ["GET"]
            paths: ["/internal/orders/*"]
```

**What this does.** Only connections whose peer SPIFFE principal matches one of the listed identities are allowed. An attacker who compromises a pod in another namespace cannot call the orders service even if they have network reach to it.

**Default-deny.** If any `AuthorizationPolicy` with `action: ALLOW` targets a workload, every non-matching request is denied. That is the behavior you want; the "default allow" pattern where missing policies permit everything is an anti-pattern. When in doubt, add an explicit deny-all policy at the namespace level:

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: deny-all
  namespace: orders
spec:
  action: DENY
  rules:
    - {}
```

Then add `ALLOW` policies that open specific paths.

### 3. Require a user JWT with specific claims

```yaml
apiVersion: security.istio.io/v1
kind: RequestAuthentication
metadata:
  name: orders-jwt
  namespace: orders
spec:
  selector:
    matchLabels:
      app: orders
  jwtRules:
    - issuer: "https://auth.example.com/"
      audiences: ["https://api.example.com"]
      jwksUri: "https://auth.example.com/.well-known/jwks.json"
      forwardOriginalToken: true
---
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: orders-scope
  namespace: orders
spec:
  selector:
    matchLabels:
      app: orders
  action: ALLOW
  rules:
    - when:
        - key: request.auth.claims[iss]
          values: ["https://auth.example.com/"]
        - key: request.auth.claims[scope]
          values: ["*orders:write*"]
```

**What this does.** Combines workload identity (from mTLS) with user identity (from the forwarded JWT). The orders service sees a request only if both the calling workload is allowed and the forwarded user token has the required scope. This is the core zero-trust pattern — authorization depends on who the service is *and* who the user is *and* what the user's token authorizes.

### 4. ServiceEntry for external dependencies

A `ServiceEntry` registers an external service (outside the mesh) so the sidecar can apply policy and telemetry to calls to it.

```yaml
apiVersion: networking.istio.io/v1
kind: ServiceEntry
metadata:
  name: stripe-api
  namespace: checkout
spec:
  hosts:
    - api.stripe.com
  ports:
    - number: 443
      name: https
      protocol: TLS
  resolution: DNS
  location: MESH_EXTERNAL
```

Without a `ServiceEntry`, calls to external hostnames bypass the mesh's egress policy. With one, the egress gateway can enforce TLS version, cipher suites, and destination allowlisting.

### 5. DestinationRule for outbound TLS settings

```yaml
apiVersion: networking.istio.io/v1
kind: DestinationRule
metadata:
  name: stripe-tls
  namespace: checkout
spec:
  host: api.stripe.com
  trafficPolicy:
    tls:
      mode: SIMPLE
      sni: api.stripe.com
      # Pin the CA bundle to a known set; do not accept random CAs.
      caCertificates: /etc/ssl/certs/stripe-ca.pem
```

**What this does.** Forces the sidecar to validate Stripe's certificate against a pinned CA bundle. If Stripe rotates to a CA you don't trust, the connection fails; that's the correct outcome. (In practice, pin to a well-known root bundle that Stripe publishes, not to their leaf cert.)

## Certificate pinning vs. CA trust chains — tradeoffs

**Certificate pinning** is the practice of hardcoding the expected certificate (or its public key, or its CA) in the client. A connection is only accepted if the server's cert matches. Pinning originated in mobile apps talking to their backend APIs, where the threat was a malicious CA issuing a fake cert for the app's backend and MITM'ing the traffic.

**Do pin** when:
- The client is distributed and out of your control (mobile app, desktop app, IoT device) and you need protection against rogue public CAs.
- The connection is high-value and the peer is stable (e.g., your mobile app to your backend).
- You have tooling to rotate pins without bricking old clients.

**Do not pin** inside a service mesh. The mesh already pins to its own CA — every workload trusts the mesh CA, only the mesh CA. Adding per-peer pinning on top creates brittle coupling that breaks on any CA rotation. The mesh CA is your pin; that's sufficient.

**Do not pin** to a leaf certificate (the end cert, not the CA). Leaf certs rotate; your pin breaks every time. If you must pin in a mesh boundary (e.g., to an external vendor), pin to the vendor's CA or an SPKI hash of their intermediate, not to the leaf.

**Wildcard certs in service mesh — avoid.** A wildcard `*.orders.svc.cluster.local` cert shared across workloads in a namespace undermines the per-workload identity property mTLS is supposed to provide. If two workloads share a cert, the mesh cannot tell them apart at the transport layer. The mesh-issued, per-workload SPIFFE cert is what makes policy work; wildcards defeat that design.

## Compromised certificate — revocation and rotation runbook

Scenario: you believe a workload's private key has been exfiltrated (e.g., a container image with debug tools leaked, a pod was compromised and the key read from memory, a developer exported `/etc/certs` from a running pod). The cert is short-lived, but you want it invalidated now.

### Step 1 — Contain

- Scale the compromised workload to 0 replicas. This terminates the pods holding the key.
- Block the SPIFFE identity at the mesh policy layer:

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: deny-compromised-workload
  namespace: orders
spec:
  action: DENY
  rules:
    - from:
        - source:
            principals:
              - "cluster.local/ns/orders/sa/orders-worker"
```

This denies any caller presenting the compromised identity, even if they reuse the cert before it expires.

### Step 2 — Rotate the identity

- Delete and recreate the Kubernetes service account under a new name (or rotate the binding). The mesh will issue certs for the new identity; the old identity becomes obsolete.
- Update any `AuthorizationPolicy` rules that reference the old identity.

### Step 3 — Revoke at the CA if warranted

- For short-lived certs (≤ 24h), waiting for expiry plus the containment policy above is usually sufficient.
- For longer-lived certs, use the mesh's CA to issue a CRL or rotate the intermediate.

### Step 4 — Root-cause the exfiltration

- How did the key leave the pod? Unnecessary debug tooling in the image? Pod allowed to expose `/etc/certs` via a vulnerable endpoint? Compromised node?
- Fix the root cause. Reissuing certs without fixing the source means the new certs are exfiltrated next week.

### Step 5 — Post-incident

- Audit what the compromised identity was allowed to access. Assume the attacker exercised everything in-scope.
- Invalidate downstream sessions, rotate tokens the workload could have accessed, revisit the blast radius of the policy grant — the workload had too much access if the incident has broad impact.

## Common misconfigurations

### 1. Permissive mode left on

**Symptom.** `PeerAuthentication: PERMISSIVE` configured during the initial rollout, never flipped to `STRICT`.
**Impact.** The mesh accepts both mTLS and plaintext. Any attacker with pod-to-pod network reach can bypass mTLS entirely.
**Fix.** Scheduled audit: `kubectl get peerauthentication -A -o json | jq '.items[] | select(.spec.mtls.mode != "STRICT")'` should return empty in production. Alert if not.

### 2. Certificate expiry not monitored

**Symptom.** Workload rotation silently fails; certificates expire; connections drop.
**Impact.** Production outage with an obscure root cause ("why is everything timing out?").
**Fix.** Export Envoy cert-lifetime metrics (`envoy_server_days_until_first_cert_expiring`) to Prometheus; alert at 7 days remaining on any cert. Additionally alert on rotation failures from the mesh control plane.

### 3. Wildcard certs in service mesh

**Symptom.** Operators issued a `*.svc.cluster.local` cert to "simplify" mesh bootstrapping.
**Impact.** Per-workload identity is lost; authorization policies cannot distinguish callers.
**Fix.** Let the mesh issue per-workload SPIFFE certs. If a wildcard was imported during migration, schedule its retirement.

### 4. CA key in a ConfigMap

**Symptom.** Initial Istio install used `istiod`'s auto-generated CA, then someone "backed it up" into a ConfigMap or Helm values file.
**Impact.** Anyone with cluster read access now has the CA key and can mint certs for any identity.
**Fix.** Rotate to a new CA (mesh-managed, KMS-backed if available). Delete the old CA material. Audit where it might have been copied.

### 5. AuthorizationPolicy with empty rules

**Symptom.** An `AuthorizationPolicy` written as `spec: { action: ALLOW, rules: [{}] }` — an empty rule matches everything.
**Impact.** "Allow everything from everyone" — the mesh's authorization layer is effectively disabled for that workload.
**Fix.** Never ship a policy with empty rules. Linting via OPA or `istioctl analyze` catches this.

### 6. Missing egress controls

**Symptom.** Workloads can reach any external IP/hostname because no `ServiceEntry` or egress gateway policy constrains them.
**Impact.** SSRF attacks, data exfiltration, C2 beaconing all go unobstructed.
**Fix.** Deploy an egress gateway; require workloads to route all external calls through it; allowlist by hostname.

### 7. mTLS on the mesh but plaintext on the ingress

**Symptom.** Mesh is STRICT internally, but the ingress gateway accepts plaintext HTTP from the load balancer to its own listener.
**Impact.** Anything on the network between the LB and the ingress pod can read traffic.
**Fix.** Require TLS on the ingress listener; terminate TLS at the ingress gateway, not at the LB, if you need end-to-end encryption.

### 8. Forwarding the original token without validating it

**Symptom.** `RequestAuthentication` issues forward the JWT, but backend services do not re-validate `iss` / `aud` / `exp`.
**Impact.** A leaked token remains usable past its intended audience; confusion across APIs that share a token.
**Fix.** Every service that receives a forwarded token re-validates it. The mesh validates at the edge; services validate at their boundary.

## Rollout playbook

| Week | Action | Success criterion |
| --- | --- | --- |
| 1 | Install mesh; inject sidecars into one non-critical namespace | All pods in that namespace show mesh sidecars. |
| 2 | Enable `PeerAuthentication: PERMISSIVE` in that namespace | Mesh records the traffic mix; you see what is and isn't yet mTLS. |
| 3–4 | Migrate all callers of that namespace to route through the mesh | Traffic is 100% mTLS. |
| 5 | Flip `PeerAuthentication: STRICT` | No connection failures; alerts clean. |
| 6–8 | Repeat for remaining namespaces | Production namespaces all STRICT. |
| 9 | Add `AuthorizationPolicy` for one critical service | Unauthorized callers get 403; metrics show the denials. |
| 10 | Roll out authorization policies across the mesh, namespace by namespace | All critical services have explicit caller allowlists. |
| 11 | Add JWT-based authorization policies on user-facing services | Forwarded tokens drive scope decisions. |
| 12 | Turn on egress policy; remove any catchall egress allow rules | All external calls are registered via `ServiceEntry`. |

On greenfield, the full rollout takes weeks. On brownfield, it takes months — most of the work is migrating callers that assumed plaintext.

## Further reading

- [Istio Security docs](https://istio.io/latest/docs/concepts/security/) — reference for the resource kinds used above.
- [Linkerd mTLS docs](https://linkerd.io/2/features/automatic-mtls/) — simpler alternative to Istio with narrower feature surface.
- [SPIFFE / SPIRE](https://spiffe.io/) — workload identity standard, independent of mesh.
- [RFC 8705 — OAuth 2.0 Mutual-TLS Client Authentication](https://datatracker.ietf.org/doc/html/rfc8705) — mTLS beyond service-to-service (for AS / RS).
- CNCF Service Mesh Landscape for current implementations and tradeoffs.
