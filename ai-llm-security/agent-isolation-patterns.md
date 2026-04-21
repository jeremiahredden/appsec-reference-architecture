# Agent Isolation Patterns

## The opinion up front

An agentic AI system is a program whose control flow is decided by an LLM. That's the whole reason the attack surface is different. A traditional service has a control flow you can reason about statically; an agent's control flow is decided at runtime by a non-deterministic model that was partially shaped by whatever data flows into the prompt. The control flow is therefore an untrusted input, and the entire design discipline of agent security follows from taking that observation seriously.

The practical consequence: **give agents the smallest possible set of tools, the smallest possible permission per tool, the shortest possible memory, and the most explicit possible boundaries between agents.** If your agent platform has one agent with broad tool access and unbounded memory across sessions, you do not have a security boundary; you have an impression of one.

## What's different from a traditional application

| Property | Traditional app | Agentic system |
| --- | --- | --- |
| Control flow | Deterministic, written by a developer | Decided by an LLM at runtime |
| Inputs | Request body, identity | Request body, identity, **retrieved documents, tool outputs, other agents' messages, long-term memory** |
| Trust of inputs | External input is untrusted | **Every input is potentially untrusted**, including inputs from other agents and from the system's own memory |
| Action space | Finite set of routes | Potentially unbounded combinations of tool calls |
| Side effects | Known at code-review time | Emerge from tool use at runtime |
| Failure modes | Well-understood (errors, timeouts) | Include: hallucinated actions, injected actions from retrieved content, loops, runaway tool-call chains |

The last row is the operational story: agent failures look different from app failures. A hung loop where the agent repeatedly calls `search_web` → reads → calls `search_web` → reads is not a bug in any tool; it is a bug in the control flow the model chose. A traditional observability stack will see "high cost" or "long latency" but will not flag the loop as a security incident. Agent-specific telemetry is required.

## Agent attack surface

Four sources make agentic systems uniquely exposed:

1. **Autonomous action.** The agent decides to call tools without per-call human review (this is the point of "agentic"). Any authority delegated to the agent is exercised by whatever content steers the model.
2. **Chained tool calls.** One tool's output becomes another tool's input. A poisoned document retrieved by tool A is fed to tool B, which acts on its contents. Injection hops across tools.
3. **Persistent memory.** Agents often maintain long-term memory across sessions. Data written into memory by one session — potentially an attacker session — is read and acted on in later sessions with other users' identity.
4. **Multiple instruction sources.** System prompt, user prompt, retrieved content, tool outputs, memory, other-agent messages — all compete for interpretation. The model cannot reliably distinguish which is authoritative.

Treat every one of these as the attacker's entry point. The mitigations in this document are organized around them.

## Isolation principles

### 1. Least privilege, per tool and per agent

- Every tool is registered with an explicit scope: what resource, what operation, under whose authority.
- An agent is configured with the minimum set of tools it needs for its role. There is no "general-purpose agent" with the full tool catalog; specialized agents with narrow tool lists are the norm.
- Tool arguments are rewritten by a wrapper to include the real caller's identity, not whatever the LLM said. `get_customer(customer_id=X)` is silently transformed to `get_customer(customer_id=X, tenant_id=caller.tenant_id)` with a rejection if `X` does not belong to `caller.tenant_id`.

### 2. Memory scope boundaries

- **Session memory** lives for the duration of one user conversation, then is discarded.
- **User long-term memory** is scoped to a single user identity; never shared across users.
- **Shared memory** (cross-user) is read-only and curated — the system can retrieve from a KB, but the KB is not written to by agents acting under user prompts.
- **No memory written by one user is ever surfaced into another user's session** except through explicit, audited sharing flows.

### 3. Session isolation

- Each conversation is a fresh process-level context. A compromised session cannot read state from a concurrent session.
- Session IDs are cryptographic randoms. Memory and tool state keyed by `(user_id, session_id)`.
- Session termination flushes in-memory state and rotates any short-lived credentials issued for the session.

### 4. Output sandboxing

- Anything the agent produces — especially text, code, or tool proposals — is treated as untrusted output.
- If the agent emits code (a common pattern for "code interpreter" style tools), the code runs in an isolated sandbox: a separate container or microVM, no network except to explicitly allowed endpoints, no access to the host filesystem, resource limits.
- If the agent emits markdown or HTML, it is sanitized before rendering; images and links are validated against allowlists.

### 5. Deterministic guardrails above the model

- The LLM proposes; a deterministic layer decides.
- Tool-call arguments are schema-validated before execution.
- Tool outputs are schema-validated before being placed back into the model's context.
- Policy checks (allowlists, budgets, quotas, rate limits) live in the deterministic layer.

## Permission tiers

Not all tools are equal. Classify tools by impact and gate them accordingly.

### Tier 1 — Read-only, auto-approved

Tools that retrieve information the caller is already authorized to access.

- Examples: search the user's own emails, read the user's calendar, fetch a public document, query a knowledge base scoped to the user.
- Policy: the agent may call without approval. Arguments are still sanitized and tenant-scoped.
- Risk: information disclosure via injection. Mitigations: retrieval filters, output validation.

### Tier 2 — Write, auto-approved within scope

Writes that the caller has authority to make directly and whose impact is bounded.

- Examples: update the user's own profile, add a task to the user's own task list, save a draft email to the user's drafts folder.
- Policy: auto-approved if within a defined envelope (size limits, rate limits, scope limits). Anything outside the envelope escalates to Tier 3.
- Risk: injected writes that degrade the user's own data or create content the user did not intend. Mitigations: soft-commit with undo window, diff-before-commit in the UI, rate limits.

### Tier 3 — Write, requires human approval

Writes with real-world impact, or writes that cross tenant or trust boundaries.

- Examples: send an email, make a payment, post to a public channel, call a third-party API with write semantics, update shared / team data.
- Policy: the agent proposes; a human approves. The human sees the full proposal (tool, arguments, rendered preview if applicable, the reasoning the model gave).
- Risk: injection-driven mis-action; reputational, financial, or legal consequences. Mitigations: human review, reversibility where possible.

### Tier 4 — Never allowed

Actions that are out of scope entirely.

- Examples: rotate production credentials, alter audit logs, deploy code, access cross-tenant data, act as another user.
- Policy: not registered as a tool. The model has no way to propose them because the tool does not exist in the agent's tool list.
- Risk: any appearance of such a tool in an agent's configuration is itself the incident. Alert on configuration drift.

**The dominant mistake** is putting a tool at Tier 1 or Tier 2 that belongs at Tier 3. "The agent can send emails on behalf of the user; the user's email is the user's own data; that's auto-approved" fails because the email goes to **other people** who then act on its contents. Almost any outbound communication is Tier 3.

## Human-in-the-loop with LangGraph

LangGraph models an agent as a state machine whose transitions include explicit interrupts. Interrupts are the concrete mechanism for Tier 3 approval.

```python
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from typing import TypedDict, Annotated
from langchain_core.messages import BaseMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field, ValidationError

class AgentState(TypedDict):
    messages: list[BaseMessage]
    pending_action: dict | None
    caller_user_id: str

class ProposedAction(BaseModel):
    tool: str = Field(pattern=r"^(search_kb|send_email|update_task)$")
    arguments: dict = Field(default_factory=dict)
    reasoning: str = Field(max_length=1000)

TIER1 = {"search_kb"}
TIER2 = {"update_task"}
TIER3 = {"send_email"}

def llm_propose(state: AgentState) -> AgentState:
    llm = ChatOpenAI(
        model="gpt-4o",
        temperature=0,
        model_kwargs={"response_format": {"type": "json_object"}},
    )
    response = llm.invoke(state["messages"])
    try:
        proposal = ProposedAction.model_validate_json(response.content)
    except ValidationError:
        return {**state, "pending_action": None}
    return {**state, "pending_action": proposal.model_dump()}

def route_on_tier(state: AgentState) -> str:
    action = state.get("pending_action")
    if action is None:
        return "end"
    tool = action["tool"]
    if tool in TIER1 or tool in TIER2:
        return "execute"
    if tool in TIER3:
        return "await_approval"
    return "end"

def await_approval(state: AgentState) -> AgentState:
    # This node signals an interrupt. The graph pauses here; an
    # approver-facing UI reads the pending action from the checkpoint,
    # records a decision, and resumes the graph with the outcome.
    return state

def execute(state: AgentState) -> AgentState:
    action = state["pending_action"]
    args = {**action["arguments"], "tenant_id": _tenant_of(state["caller_user_id"])}
    result = TOOLS[action["tool"]](**args)
    audit_log(event="tool_executed", caller=state["caller_user_id"], tool=action["tool"])
    return {**state, "messages": state["messages"] + [result], "pending_action": None}

builder = StateGraph(AgentState)
builder.add_node("propose", llm_propose)
builder.add_node("await_approval", await_approval)
builder.add_node("execute", execute)
builder.set_entry_point("propose")
builder.add_conditional_edges("propose", route_on_tier, {
    "execute": "execute",
    "await_approval": "await_approval",
    "end": END,
})
builder.add_edge("await_approval", "execute")   # after approval resumes
builder.add_edge("execute", "propose")

# The checkpointer persists state across the interrupt. A production
# deployment uses Redis or Postgres, not MemorySaver.
graph = builder.compile(
    checkpointer=MemorySaver(),
    interrupt_before=["await_approval"],   # pause here, external actor resumes
)
```

**Key properties.**
- The agent state is checkpointed; the interrupt pauses the graph without losing context.
- A separate UI surfaces pending proposals, captures approval or rejection (with an identity claim and reason), and resumes the graph.
- Every executed action is audit-logged with caller, tool, and arguments. The LLM's chain-of-thought ("reasoning") is logged but is **not** treated as authoritative — audit trusts the arguments and the approval record, not the model's prose.

## Human-in-the-loop in JavaScript

LangGraph.js supports the same pattern; an alternative for simpler cases is an explicit two-phase orchestrator:

```javascript
const { z } = require("zod");

const ProposedAction = z.object({
  tool: z.enum(["search_kb", "send_email", "update_task"]),
  arguments: z.record(z.unknown()),
  reasoning: z.string().max(1000),
});

const TIER = {
  search_kb: "tier1",
  update_task: "tier2",
  send_email: "tier3",
};

async function propose(userInput, caller) {
  const completion = await openai.chat.completions.create({
    model: "gpt-4o",
    temperature: 0,
    response_format: { type: "json_object" },
    messages: buildMessages(userInput, caller),
  });
  return ProposedAction.parse(JSON.parse(completion.choices[0].message.content));
}

async function handle(userInput, caller) {
  const action = await propose(userInput, caller);
  const tier = TIER[action.tool];

  if (tier === "tier1" || tier === "tier2") {
    return execute(action, caller);
  }

  if (tier === "tier3") {
    const ticket = await approvals.create({ action, caller });
    return { status: "pending_approval", ticketId: ticket.id };
  }

  return { status: "denied", reason: "unknown_tool" };
}

app.post("/approvals/:id/resolve", requireRole("approver"), async (req, res) => {
  const { id } = req.params;
  const { decision, note } = req.body;
  const { action, caller } = await approvals.load(id);

  if (decision !== "approve") {
    await approvals.close(id, { approver: req.user.id, decision, note });
    return res.json({ status: "rejected" });
  }

  const result = await execute(action, caller);
  await audit.log({
    event: "tool_executed_with_approval",
    approverId: req.user.id,
    callerId: caller.id,
    tool: action.tool,
    argumentsHash: sha256(JSON.stringify(action.arguments)),
    note,
  });
  res.json({ status: "executed", result });
});
```

## Multi-agent trust

In multi-agent systems, one agent's output becomes another agent's input. The receiving agent must treat the sender's messages with the same suspicion it would give a user — possibly more, because (a) the sending agent may itself have been injected via its retrieval, and (b) the messages carry implicit authority signals ("as agent X, I authorize…") that the receiving agent may credit.

### Rules

- **Agents do not trust each other.** An agent receiving a message from another agent treats it as tagged `agent-output`, no more trusted than `user-direct` input.
- **Explicit capability transfer, not ambient authority.** If agent A must trigger action X via agent B, the runtime — not agent A — checks that the triggering user has permission for X. Agent B does not take agent A's word for it.
- **Audit identity at every hop.** The original user's identity flows through every agent in the chain; the executing tool sees the user identity and the full agent path, and logs it.
- **No privilege escalation via delegation.** An agent does not acquire capabilities by being called by a higher-privileged agent. Capabilities are attached to the original user, not to the calling agent.

### Failure mode to avoid

```
User (tenant A)
   │
   ▼
 Agent A (has tool: read_tenant_data)
   │  "please summarize this customer's activity"
   ▼
 Agent B (has tool: send_email, trusts Agent A)
```

If Agent B trusts Agent A's framing ("this is a summary for the customer"), an injection in Agent A's retrieved content can steer Agent B to email anyone Agent A names. The fix is not to trust Agent A's framing; Agent B must re-authorize against the original user's identity and scope.

## Memory boundary controls

### What should persist

- The user's declared preferences ("call me by my nickname Jamie").
- Persistent facts the user has asserted ("I work at Acme").
- Task state the user expects to carry forward ("my TODO list").

### What should NOT persist

- Anything derived from retrieved content without explicit user confirmation.
- Tool outputs from Tier 3 actions (keep the audit trail of *what was done*; don't feed the tool's response body into future prompts as authoritative fact).
- Content from other users' sessions (obvious, easy to violate by accident).
- Model reasoning or "thoughts" — these are not facts.

### Enforcement

- **Typed memory.** Memory is a structured store (key-value or schema-scoped), not a free-text blob. Each entry has a source, a timestamp, a TTL, and an owner.
- **Write on explicit intent.** Writing to long-term memory is itself a tool call, subject to Tier 2 approval; the user sees "I'd like to remember that you prefer X" and confirms.
- **Read by scope.** Memory reads are filtered by `(user_id, session_id)` — or `(user_id, None)` for user-scoped long-term memory — before being handed to the model.
- **Forget.** A user-facing "forget that" is a required feature, not an extra; it satisfies both trust and compliance obligations (GDPR right to erasure, for instance).

## Secure agent platform — reference diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           TRUST ZONE: PUBLIC                                 │
│                                                                              │
│  ┌──────────────────┐                                                        │
│  │  User / Clinician│                                                        │
│  └────────┬─────────┘                                                        │
│           │ HTTPS + OIDC                                                     │
└───────────┼──────────────────────────────────────────────────────────────────┘
            │
┌───────────▼──────────────────────────────────────────────────────────────────┐
│                         TRUST ZONE: EDGE                                     │
│                                                                              │
│   ┌──────────────────────────────────────────────────────────────────────┐   │
│   │  API Gateway / WAF — JWT validation, rate limits, identity propagation│   │
│   └───────────────────────────────┬──────────────────────────────────────┘   │
└───────────────────────────────────┼──────────────────────────────────────────┘
                                    │ mTLS
┌───────────────────────────────────▼──────────────────────────────────────────┐
│                   TRUST ZONE: AGENT ORCHESTRATION                            │
│                                                                              │
│   ┌──────────────────────────────────────────────────────────────────────┐   │
│   │  Orchestrator (LangGraph / custom)                                   │   │
│   │  · Enforces permission tiers                                         │   │
│   │  · Runs input / output guardrails                                    │   │
│   │  · Holds deterministic policy (allowlists, budgets)                  │   │
│   │  · Emits audit events                                                │   │
│   └────┬──────────────────────────────────────────────────────────┬─────┘   │
│        │                                                          │         │
│        │ LLM call                                                  │         │
│   ┌────▼──────────────┐         ┌──────────────────────────┐      │         │
│   │  LLM Provider     │         │  Approval Service        │      │         │
│   │  (Azure OpenAI,   │         │  · Queues Tier-3 actions │◀─────┘         │
│   │   Bedrock, etc.)  │         │  · Human UI              │                │
│   └───────────────────┘         │  · 2-person on Sev-1     │                │
│                                 └────────────┬─────────────┘                │
└──────────────────────────────────────────────┼──────────────────────────────┘
                                               │ mesh mTLS
┌──────────────────────────────────────────────▼──────────────────────────────┐
│                    TRUST ZONE: TOOL EXECUTION (SANDBOXED)                   │
│                                                                             │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────────┐   │
│  │ Tier-1 Tools     │  │ Tier-2 Tools     │  │ Tier-3 Tools             │   │
│  │ · Read-only,     │  │ · Scoped writes  │  │ · External API writes    │   │
│  │   auto-approved  │  │ · Rate-limited   │  │ · Email / payment        │   │
│  │ · Retrieval,     │  │ · Own-data only  │  │ · Approval required      │   │
│  │   KB search      │  │                  │  │                          │   │
│  └────────┬─────────┘  └────────┬─────────┘  └───────────┬──────────────┘   │
│           │                     │                         │                  │
│           │                     │                         │                  │
│  ┌────────▼─────────┐  ┌────────▼─────────┐  ┌───────────▼──────────────┐   │
│  │  Vector DB       │  │  Per-user data   │  │  External service        │   │
│  │  (per-tenant)    │  │  (scoped by      │  │  · mTLS / OAuth2 CC       │   │
│  │                  │  │   caller)        │  │  · Egress allowlist       │   │
│  └──────────────────┘  └──────────────────┘  └──────────────────────────┘   │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Code Execution Sandbox (if applicable)                              │   │
│  │  · Isolated container / microVM (gVisor / Firecracker)                │   │
│  │  · No network except allowlist                                       │   │
│  │  · No host mount, no privileged caps                                 │   │
│  │  · CPU / memory / time budget                                        │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│               TRUST ZONE: TELEMETRY (ISOLATED FROM AGENTS)                  │
│                                                                              │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────────┐   │
│  │  Audit log       │  │  SIEM            │  │  Detection rules         │   │
│  │  (append-only)   │  │  · Tool calls    │  │  · Injection attempts    │   │
│  │  · Proposals     │  │  · Approvals     │  │  · Loops                 │   │
│  │  · Approvals     │  │  · Retrievals    │  │  · Scope violations      │   │
│  │  · Executions    │  │  · Errors        │  │  · Budget breaches       │   │
│  └──────────────────┘  └──────────────────┘  └──────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Properties of this design

- **Trust zones have hard boundaries.** The agent orchestrator sits between edge and tool execution; it cannot be bypassed by an agent "choosing to skip" a guardrail because the guardrails are deterministic code, not model behavior.
- **Each tier's tool surface is a separate service.** An injection that steers the model to call a Tier-3 tool reaches the Approval Service, not the tool's execution. The executing code is behind the approval gate.
- **Telemetry is isolated.** Agents have no write access to the audit log. An agent cannot self-cover by writing fake "approved" entries.
- **Code execution runs in a separate sandbox.** If the agent has a "run this code" tool, the code runs with no access to the orchestrator's secrets, no access to other tenants' data, and no network beyond the allowlist.

## Operational discipline

- **Budget per user per time window** for LLM calls, tool calls, and total cost. An agent stuck in a loop hits the budget and stops; the user sees a message; the operator sees the loop metric.
- **Step count bounds.** No agent run exceeds N (say, 10) tool-call iterations without a human checkpoint.
- **Per-session tool budget.** A session that proposes 50 tool calls gets inspected; that's not normal for any legitimate workflow.
- **Decay of trust.** A session that produces repeated policy blocks, schema failures, or rejected approvals is de-prioritized and eventually terminated.

## What not to build

- **A single "god agent" with every tool.** Split into specialized agents. A scheduling agent has scheduling tools; a customer-service agent has support tools; they do not share tool lists.
- **Agents that can register new tools at runtime.** The tool catalog is part of the deploy; new tools ship via code review and threat modeling.
- **Free-text inter-agent protocols.** Use a structured message schema with explicit fields (`requesting_agent`, `intended_action`, `user_identity`). Prose is interpretable; schemas are not.
- **Long-lived shared memory written by agents.** If a fact is worth keeping, the user confirms it and the write is tiered.

## Further reading

- OWASP LLM Top 10 — LLM08 Excessive Agency and LLM06 Sensitive Information Disclosure.
- MITRE ATLAS — tactics and techniques for AI systems, including cases relevant to multi-step agent exploitation.
- Simon Willison — "The 'dual LLM' pattern for building AI assistants that can resist prompt injection" (2023) — the architectural spine of Tier 3 approval.
- LangGraph documentation — practical patterns for checkpointed interrupts and stateful graphs.
- Anthropic's "Computer Use" safety research — a recent, concrete discussion of the risks of giving an agent broad action capability.
