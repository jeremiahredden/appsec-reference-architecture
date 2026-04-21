# AI / LLM Security

## What this folder is

A working library of threat models, architectural patterns, and remediation playbooks for the security problems that appear when an application uses a large language model — whether as a chat assistant, a RAG pipeline, an autonomous agent, or embedded in a workflow. The content here is the shape I would put in front of an engineering team building such a system, with enough specificity that it can be acted on in a sprint rather than a roadmap.

## Why a separate section

AI / LLM security is a distinct discipline from traditional AppSec, and the difference is not cosmetic. Three properties make the attack surface new:

1. **Instructions and data share one channel.** An LLM is told what to do in the same prompt window that contains user input, retrieved documents, and tool outputs. The classical injection defense — parameterize queries so code and data never mix — has no direct equivalent. Mitigations are probabilistic, not structural.
2. **Outputs feed downstream actions.** Agentic systems take model output and turn it into tool calls, API requests, code execution, or database writes. A model that hallucinates a URL causes an SSRF; a model that emits a tool call triggered by a poisoned document causes an unintended action. The blast radius of a wrong output is proportional to the authority the agent has been granted.
3. **The model itself is an attack surface.** Training-data poisoning, model inversion, prompt leakage through embedding spaces, and supply-chain risk on model artifacts are classes of attack that do not exist when your "model" is a hand-written function.

Classical AppSec controls still apply — input validation, output encoding, auth, authz, transport security, audit logs — but they are insufficient. The new controls that belong alongside them: prompt-injection-resistant system design, agent permission tiers, human-in-the-loop gates, output filtering, RAG access control, and model / data provenance.

## Primary frameworks referenced

| Framework | Use |
| --- | --- |
| **[OWASP LLM Top 10 (2025 edition)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)** | Class-by-class threat taxonomy and baseline control set. The owasp-llm-top10-playbooks.md file in this folder is organized against it. |
| **[MITRE ATLAS](https://atlas.mitre.org/)** | Adversarial tactics, techniques, and case studies against AI systems. Use for threat modeling and red-team exercise design. Maps to MITRE ATT&CK where relevant. |
| **[NIST AI Risk Management Framework (AI RMF 1.0)](https://www.nist.gov/itl/ai-risk-management-framework)** | Governance framing for AI systems. Sits above the technical controls and addresses organizational accountability. |
| **[OWASP ML Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)** | Complements the LLM list; covers ML attacks generally (evasion, poisoning, model extraction). Relevant to any system with a trained model, not just LLMs. |
| **[Google Secure AI Framework (SAIF)](https://safety.google/cybersecurity-advancements/saif/)** | Engineering-flavored controls; overlaps with OWASP LLM with more emphasis on ecosystem-level controls. |

These are stable-enough references as of 2026. The space moves quickly; expect the OWASP LLM list to rev again within the year, and expect regulatory frameworks (EU AI Act, NIST profiles) to continue refining what "high risk" means. Treat this folder as a living document, not a set of settled truths.

## Documents

- **[threat-model-llm-api.md](./threat-model-llm-api.md)** — Full STRIDE threat model for a healthcare-assistant LLM application with a RAG pipeline over medical records. ASCII DFD, threats per STRIDE category, LLM-specific attack scenarios (prompt injection as spoofing, training poisoning as tampering, model inversion as information disclosure, token exhaustion as DoS, indirect injection as privilege escalation), risk ratings, remediation owners.
- **[prompt-injection-defense.md](./prompt-injection-defense.md)** — Defense-in-depth for prompt injection: direct vs. indirect, why sanitization alone is insufficient, layered pattern (input validation → prompt hardening → output validation → privilege separation), Python and JavaScript hardened examples, structured-output enforcement, human-in-the-loop gates, anomaly detection.
- **[agent-isolation-patterns.md](./agent-isolation-patterns.md)** — Agent attack surface, isolation principles, permission tiers (read-only / write-with-approval / never-allowed), human-in-the-loop checkpoints with LangGraph, multi-agent trust boundaries, memory scoping, secure-agent-platform diagram.
- **[rag-pipeline-security.md](./rag-pipeline-security.md)** — Ingestion security, vector-database access control, document-level retrieval authorization, context-injection risk, output filtering for PII and hallucinations, audit logging, hardened Python RAG implementation.
- **[owasp-llm-top10-playbooks.md](./owasp-llm-top10-playbooks.md)** — Remediation playbooks for LLM01 through LLM10, same seven-section structure as the AppSec OWASP playbooks in this repo.

## How to use this section

**If you are designing a new LLM feature** — start with `threat-model-llm-api.md`. Run the same STRIDE exercise against your service, substituting your data flows. The threats are the same; the details differ.

**If you are building an agentic system** — `agent-isolation-patterns.md` is the reference. The single biggest mistake teams make is giving an agent more authority than it needs, and the second biggest is trusting other agents. Both are structural; neither has a good runtime fix.

**If you are integrating RAG over regulated data (PHI, PCI, internal confidential)** — `rag-pipeline-security.md` is not optional. A naive RAG pipeline over regulated data is a compliance violation waiting to be audited; the patterns in that document are what makes RAG auditable.

**If a prompt-injection incident has already happened** — read `prompt-injection-defense.md` and implement at least the output validation and privilege separation patterns. Input sanitization alone is not enough.

**If you are answering an audit question about AI** — reference NIST AI RMF alongside the OWASP mappings; auditors in 2026 increasingly expect both.

## What this section is not

- **A model-evaluation guide.** Bias, fairness, accuracy, and explainability are outside AppSec scope. They belong in ML governance and model-evaluation tooling.
- **A tutorial on using LangChain / LlamaIndex / OpenAI SDK.** The examples assume basic familiarity with these libraries.
- **A guide to training or fine-tuning models.** The threats unique to model training are covered briefly (poisoning, supply chain) but the operational guidance on how to train securely is out of scope. See MLSecOps resources for that.
- **Complete.** The space moves fast. Treat every recommendation as the best current answer, subject to revision as attacks evolve.

## A note on scope

The content here assumes you are calling a hosted model (OpenAI, Azure OpenAI, Anthropic, Bedrock, Vertex) or running a self-hosted model you did not train from scratch. That covers the large majority of real deployments. If you are training models from raw data, additional concerns apply that are not in scope here — data curation security, training-pipeline integrity, model-artifact signing, reproducible-training attestations — and the resources above (MITRE ATLAS, OWASP ML Top 10) are the right starting points.
