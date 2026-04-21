# Architecture Patterns

## What this folder is

A small library of opinionated reference designs for the architectural decisions that recur across modern SaaS and enterprise application builds: how to shape a secure REST API, how to pick the right OAuth2 / OIDC flow, what a zero-trust SaaS stack looks like when it is drawn on a whiteboard, and how mTLS actually gets deployed through a service mesh without leaving the cluster in permissive mode for the next three years.

These are designs I would ship. They are not vendor-neutral surveys and they do not enumerate every alternative. For each decision I note the tradeoffs briefly and then pick one, because a reference architecture that does not commit to a choice is an essay, not an architecture.

## What "opinionated" means here

Every document in this folder makes a call that other reasonable architects would make differently. For example:

- **API design.** I default to JSON-only, versioned via URL path, and reject SOAP / GraphQL / gRPC for external APIs unless the team has an explicit reason that justifies the additional surface area. GraphQL is fine inside a trust boundary; for an external API it hands the attacker a query planner.
- **OAuth2 flows.** I recommend Authorization Code + PKCE as the default for first-party web and mobile clients. I say Implicit flow should not be used in new designs, even with nonce, because the attack surface is not worth the simplicity.
- **Zero trust.** I treat "zero trust" as an architectural commitment, not a product. Buying a vendor's "zero trust network access" appliance does not make a system zero trust; removing network-perimeter trust assumptions from the authorization model does.
- **mTLS.** I prefer mesh-managed short-lived certificates with SPIFFE identities over long-lived certificates with CA trust chains, and I reject certificate pinning for service-to-service inside the mesh as operationally brittle.

Each document states its opinion up front so that the reader can disagree productively. If your constraints lead you to a different choice, the document's structure still helps — the tradeoff analysis and the failure modes section transfer even when the recommendation does not.

## Documents

- **[secure-api-design.md](./secure-api-design.md)** — Input validation, authentication patterns, authorization (RBAC vs. ABAC), rate limiting, error handling, security headers, versioning. Includes an ASCII diagram of a secure API gateway pattern.
- **[oauth2-oidc-flows.md](./oauth2-oidc-flows.md)** — Authorization Code + PKCE, Client Credentials, Device Flow, and why to avoid Implicit. Sequence diagrams, security properties, common mistakes, and Python (Authlib) + JavaScript (openid-client) code.
- **[zero-trust-saas.md](./zero-trust-saas.md)** — Full-stack reference diagram, seven zero-trust principles applied to SaaS, continuous verification, service-mesh micro-segmentation, production access management, telemetry requirements for detecting lateral movement.
- **[mtls-service-mesh.md](./mtls-service-mesh.md)** — Why mTLS (identity, not just encryption), certificate lifecycle, Istio config examples, pinning vs. CA trust, revocation runbook, common misconfigurations.

## How to use these documents

**As a starting template.** Fork the architecture into your ADR (Architecture Decision Record) or design-review tooling, change the vendor-specific pieces (IdP, mesh, cloud, WAF) to match your stack, delete the options you will not ship, and run the document through a design review. The opinionated shape means a two-hour review is enough; a vendor-neutral survey would take two days.

**As a pre-read for security reviews.** When a team asks for a security review of a new service, share the relevant document before the meeting so the discussion is about divergences from the baseline, not re-deriving the baseline.

**As an interview-and-onboarding artifact.** Senior hires can skim these and know the engineering baseline on day one. Disagreement is welcome; re-deriving baselines from scratch per engineer is not.

## What these documents are not

- **A vendor-neutral market survey.** I do not enumerate every WAF / IdP / mesh; I pick one in each category that I have shipped in production, note the substitutes, and move on.
- **A beginner's introduction to each topic.** The documents assume you can read a sequence diagram, understand TLS basics, and know the difference between authentication and authorization. If you are brand new, read the OWASP Cheat Sheet Series first.
- **A compliance artifact.** Pair these with the **[compliance-control-mapping/](../compliance-control-mapping/)** documents if you need to produce evidence that the architecture satisfies a specific HIPAA, SOC 2, or NIST CSF control.
