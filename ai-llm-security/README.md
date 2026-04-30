# AI / LLM Security — moved

The AI/LLM security material that lived in this folder has moved to its own dedicated repository, where it is being expanded into a full reference architecture covering LLM application security, agent security, MLOps security, AI governance, AI infrastructure security, AI detection and response, AI privacy, and defensive AI.

**New location:** [github.com/jeremiahredden/ai-security-reference-architecture](https://github.com/jeremiahredden/ai-security-reference-architecture)

The original five documents live in the new repo's `llm-application-security/` folder:

- **[threat-model-llm-api.md](https://github.com/jeremiahredden/ai-security-reference-architecture/blob/main/llm-application-security/threat-model-llm-api.md)** — STRIDE threat model for a healthcare-assistant LLM application with a RAG pipeline over medical records
- **[prompt-injection-defense.md](https://github.com/jeremiahredden/ai-security-reference-architecture/blob/main/llm-application-security/prompt-injection-defense.md)** — Defense-in-depth for direct and indirect prompt injection
- **[agent-isolation-patterns.md](https://github.com/jeremiahredden/ai-security-reference-architecture/blob/main/llm-application-security/agent-isolation-patterns.md)** — Permission tiers, HITL checkpoints, multi-agent trust boundaries
- **[rag-pipeline-security.md](https://github.com/jeremiahredden/ai-security-reference-architecture/blob/main/llm-application-security/rag-pipeline-security.md)** — Ingestion, retrieval authorization, output filtering, audit logging
- **[owasp-llm-top10-playbooks.md](https://github.com/jeremiahredden/ai-security-reference-architecture/blob/main/llm-application-security/owasp-llm-top10-playbooks.md)** — LLM01–LLM10 remediation playbooks

## Why the split

This repository (`appsec-reference-architecture`) covers traditional application security — threat modeling, secure code review, OWASP remediation, DevSecOps pipelines, cloud security, and compliance mapping. The companion repo covers the controls that begin where AppSec ends: prompt-injection-resistant design, agent permission models, MCP server hardening, code-execution sandboxes, MLOps pipeline integrity, AI governance, AI-specific detection and response, AI privacy, and the use of AI in defensive workflows.

Use this repo for the controls every modern application still needs. Use the [AI security repo](https://github.com/jeremiahredden/ai-security-reference-architecture) for the controls that only an AI-bearing application needs.
