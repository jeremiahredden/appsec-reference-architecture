# Threat Modeling Facilitation Guide

How to run a STRIDE threat modeling session with an engineering team such that (a) they find it useful, (b) the output lands as tickets in their sprint, and (c) they agree to do it again. The goal is not to produce a document. The goal is to change the system.

---

## Before You Facilitate Your First Session

A few mental models to carry in with you.

**You are not the expert on this system.** The engineers in the room are. Your expertise is in threat enumeration, trust boundary reasoning, and risk prioritization — not in how their service actually works. The moment you start telling them what their system does, you have lost the room. Ask questions. Let them explain. When someone says "X authenticates via Y," write it down, then ask "what happens if Y is unavailable?" That is where threats live.

**The session is a facilitated working meeting, not a presentation.** If you walk in with 40 slides, you are doing it wrong. Walk in with a shared document, a diagram canvas, and a STRIDE template. Fill them in together. People own what they help create.

**Engineers defend designs they built.** This is not a character flaw. It is a professional reflex. Your facilitation job is to create the psychological safety where surfacing a design weakness is a contribution, not an attack. The language you use matters — see the facilitation tactics section below.

**Threats are cheaper to prevent in the design phase than in prod.** You will occasionally model a system that is already in production and find that the right fix is a 6-month rearchitecture. That is a hard conversation. It does not mean you skip the finding. It means you document it, propose an interim compensating control, and have the architectural conversation with leadership separately.

---

## Pre-Meeting Checklist

Complete this the week before the session, not the morning of.

### Materials to Gather

- [ ] **A data flow diagram.** Even a whiteboard photo. If the team does not have one, ask them to sketch one before the meeting. If they cannot, you will spend the first 30 minutes of the session drawing it with them. That is fine, but adjust the total session time to 90-105 minutes.
- [ ] **The system's data classification.** Not "sensitive." Specifically: what regulated data classes are handled (PHI, PCI, FTI, PII, export-controlled, ITAR, FERPA), and what the organization's internal classification framework calls them.
- [ ] **The authentication model in one paragraph.** Who authenticates how, what tokens are issued, how they are validated, what the session model is.
- [ ] **The list of external integrations.** Every outbound call the service makes, with what credentials, what data flows each direction, and what the business relationship is with the counterparty.
- [ ] **Any known prior incidents.** Security bugs, postmortems, pen test findings from the last 18 months. You are not re-litigating them; you are making sure the threat model does not miss the class of bug that has already hit this team.
- [ ] **The deploy pipeline.** Where code goes from commit to production, what automated checks run, who has what permissions along the way. Many of the highest-risk findings come from the pipeline, not the running application.
- [ ] **The previous threat model, if one exists.** Read it. Do not start from scratch if a competent predecessor has already done half the work.

### People to Invite

The right attendee list is 5-7 people. More than 7 and the introverts stop talking. Fewer than 4 and you miss perspectives.

**Required:**
- The **tech lead** or most senior engineer on the service.
- One **senior IC** who has touched most of the code recently.
- The **SRE or platform engineer** who owns the deploy and runtime environment.

**Recommended:**
- A **product manager**, specifically if the session will surface questions about data handling, consent, or feature scoping that need product input.
- A **compliance analyst**, for regulated-data systems (HIPAA, PCI, etc.). They will catch regulatory-specific threats engineers miss.
- **One other security engineer**, as a scribe and second brain. On your first few sessions, this is important. By your tenth, you can facilitate solo.

**Do not invite:**
- Managers who do not work on the code, unless they are specifically the decision-maker for an open question you need to resolve live.
- Executives. Their presence changes what engineers are willing to say.
- More than one product manager.

### Meeting Logistics

- **Schedule 90 minutes.** You will usually finish in 60-75 minutes, but if you schedule 60 you will hit the hard stop mid-enumeration. A 90-minute block with an early finish is generous to the team's calendar.
- **In-person if possible; hybrid works; fully remote is fine but harder.** The single most important thing in a remote session is that the shared document and diagram are visible to everyone, and that one person is clearly facilitating.
- **Share the template ahead of time.** Let the team fill in the metadata block before the meeting. They will arrive already oriented.
- **Do not send slides.** Send the template and the DFD prep request.

---

## Session Agenda

**Total: 60-90 minutes.** The agenda below assumes 90 minutes with a DFD already in hand. Adjust intro and DFD walkthrough if you are drawing the diagram live.

### 0:00 - 0:05 — Intro and Framing (5 min)

Your opening should hit three notes. In practice, something close to this:

> "We are going to spend 90 minutes looking at the system together, category by category, asking the question: what could go wrong? I am not here to audit the code or to grade your design. I am here to help surface threats early, while they are cheap to fix. The output of this session is not a document — it is a set of tickets that go into your sprint with owners. If we find something that makes the design harder to defend, that is a win, not a failure. If we find a design that already handles a class of threats well, we will write that down too, because it helps us make the case for doing this more broadly. Any questions before we start?"

Do not skip this. It pays back 10x in the next 85 minutes. It establishes that the session is collaborative, that the output is ticketed, and that finding problems is the point.

### 0:05 - 0:20 — Data Flow Diagram Walkthrough (15 min)

Put the DFD on the shared screen. Ask the tech lead to walk through it end to end. You are listening for two things: (1) trust boundary crossings, which are where threats concentrate, and (2) components or flows that are missing from the diagram. Missing flows are always there. Ask explicitly: "What is not on this diagram that should be? Cron jobs? Async queues? Admin tools? Migration scripts? Breakglass access paths?"

As they walk through it, annotate the diagram with the trust boundaries. This is usually where you earn your keep as a facilitator — the team often has a DFD but has not thought of it in trust-boundary terms.

### 0:20 - 1:00 — STRIDE Enumeration (40 min)

Go through the six STRIDE categories in order. Spend roughly 6-7 minutes per category. The order matters: Spoofing first because it warms the room up on a familiar concept (authentication), Elevation of Privilege last because it is often the most architecturally complex.

**For each category, do this:**

1. State the category in one sentence. Not the Wikipedia definition — your working definition. For Spoofing: "Is there a way for someone to impersonate a user, a service, or a system component?"
2. Walk the DFD, component by component, asking the question. Write down every threat the team surfaces, even if it turns out later to be already mitigated. You are casting a wide net.
3. For each threat, ask: "What stops this today?" Write down the current mitigation. If the answer is "nothing," that is a finding. If the answer is "we validate X," probe the edges: "What if X is empty? What if X is twice the expected length? What if an attacker controls the upstream that produces X?"
4. Flag the risk rating as you go. Do not debate ratings mid-enumeration — note your instinct and keep moving. You will re-rank in the prioritization phase.

**Facilitation hints for this phase:**

- Do not let one person dominate. If the tech lead is doing all the talking, ask a junior IC directly: "From your perspective working in the code, where does this concern you?"
- Ride the energy. If the team is on a roll in one category, let them run 2 extra minutes. If they are dry in another, skip ahead and come back.
- Park architectural disputes. If two engineers start debating whether to use OAuth2 vs mTLS between two services, write it down as an open question and move on. That conversation is a 45-minute side quest that does not belong in this session.

### 1:00 - 1:10 — Risk Prioritization (10 min)

Put the threat list on screen. Walk through each threat and assign Likelihood (1-4) and Impact (1-4) scores. Let the team score, not you — you might propose a number, but ask the team to push back if they disagree. The scoring rubric is in the STRIDE template.

Do not spend more than 45 seconds per row. These are directional ratings, not a formal risk assessment. The purpose is to sort the list into Critical / High / Medium / Low so the team knows where to start.

### 1:10 - 1:20 — Ownership and Ticketing (10 min)

This is the most important 10 minutes of the entire session. Do not let anyone leave before it is done.

For every Critical and High finding, answer three questions:

1. **Who owns the fix?** Not a team — a person. "The Rx team" is not an owner. "Sam, on the Rx team, will pick up the ticket tomorrow" is an owner.
2. **What is the acceptance criterion?** Specifically enough that the ticket reviewer can verify the fix. "Improve JWT validation" is not an acceptance criterion. "Validate `iss` and `aud` claims and add an integration test that rejects tokens with mismatched issuers" is an acceptance criterion.
3. **What sprint does it land in?** If the team cannot commit to a sprint live, set a deadline for the tech lead to schedule it within 3 business days and send you the ticket links.

Create the tickets live, in the team's JIRA (or Linear, or GitHub Issues — whatever they use). Copy the threat description, the recommended control, the owner, and the sprint. Link back to the committed threat model in the repo.

Medium findings get tickets too, but with a softer commitment — they can sit in the backlog with a target quarter rather than a specific sprint.

### 1:20 - 1:30 — Wrap-Up (10 min)

Three things to cover:

1. **Summarize the top 3 findings verbally.** Not the full list — the three that matter most. This is what people will remember when they describe the session to their manager.
2. **Confirm next steps.** Who is committing the threat model to the repo (usually the tech lead). Who is sending the JIRA links to the group (usually you). When you will check in on progress (usually two weeks out for a quick review of the Critical findings).
3. **Ask for session feedback.** "What should I do differently next time?" You will get useful answers, and the act of asking signals that this was a collaboration.

---

## Facilitation Tactics That Actually Work

A handful of moves that consistently help.

**"Pretend you are an attacker who just got a developer's laptop."** Framing threats from a concrete attacker position is far more productive than abstract "what could go wrong?" questions. Cycle through attacker positions: laptop-compromised developer, phished customer, malicious insider in a partner team, compromised third-party vendor, compromised CI runner.

**"What would it take to detect this if it happened?"** A powerful follow-up to any surfaced threat. Sometimes the answer is "we would not" — which is itself a finding. And sometimes the answer reveals that the threat is manageable because the team already has strong detection, which changes your prioritization.

**"If a junior engineer joined next week, where would they introduce this vulnerability?"** Engineers will protect their own designs from criticism but will happily describe the ways a hypothetical junior could misuse their system. Weaponize this. Most of the best findings come from this question.

**Repeat back what you heard in STRIDE terms.** When an engineer says "well, someone could technically re-use a session token if they stole the cookie," you say: "OK, so that is a Spoofing concern at the session-token component — the cookie has no binding to client context. Is that accurate?" This does three things: it teaches the STRIDE vocabulary by example, it confirms you understood correctly, and it makes the engineer feel like a co-author rather than a target.

**Treat silence as data.** If the room goes quiet when you ask about a component, it is almost always because nobody fully understands it. That is itself a finding — the component has bus-factor risk, and the threats against it are not understood. Write it down.

**Do not let "we can fix that in a future release" close a finding.** You will hear this repeatedly. Your response: "Great, let us create the ticket for it now so we do not lose it." If a finding is real, it needs a ticket. "Future release" without a ticket is a finding that dies the moment the meeting ends.

---

## Anti-Patterns to Avoid

These are the failure modes I have seen kill threat modeling programs. Steer around them.

**Scope creep.** "While we're here, could we also look at the authentication in the mobile app, and the data warehouse, and the internal admin tool?" No. One system, one session. Scope creep produces superficial coverage of everything and deep coverage of nothing. Schedule separate sessions for separate systems.

**Perfectionism.** Trying to enumerate every possible threat exhausts the room and produces a document nobody reads. Aim for the top 80% of meaningful threats in 90 minutes. The long tail can be caught in the next model or by code review.

**Treating the session as an audit.** If you walk in with a finding pre-loaded ("I already know you have SQLi in the reports endpoint, let us discuss"), the team correctly perceives this as an audit and clams up. Save pre-identified findings for a separate code review. The threat modeling session is forward-looking.

**Overweighting exotic threats.** Nation-state supply chain attacks are fascinating but rarely the right place to spend sprint time on a consumer SaaS product. Calibrate the threat surface to the actual adversary model. A B2C app's adversary model is credential stuffers, fraudsters, and bored opportunists with automated tooling — not the SVR.

**Producing a Word document that goes into SharePoint.** The moment the output lives outside the engineering team's working tools, the threat model is dead. Commit the threat model to the service's Git repository, alongside the code. Create the JIRA tickets in their actual project. If the output does not live where the team works, you have produced a deliverable, not a change.

**Doing it once and never again.** Threat models go stale. Every new vendor integration, new data class, or major architectural change should trigger a refresh. Annual re-modeling at minimum for regulated systems. If you are not budgeted for maintenance, you have not closed the contract correctly.

**Treating the DFD as ground truth without challenging it.** Data flow diagrams produced by the team often reflect the system as the team wishes it were, not as it is. Probe. Ask about migration scripts, backup paths, admin tools, the flow that runs every 90 days, the cron job that nobody touches. That is where the threats are.

---

## How to Write Findings That Actually Get Fixed

The difference between a threat modeling program that changes systems and one that produces PDFs is in how the findings are written. A finding that lands in a sprint backlog has five properties.

1. **Specific to a file, component, or behavior.** "Improve input validation" is a failure. "The `/patients/search` endpoint accepts a `last_name` parameter that is passed to a `LIKE '%x%'` query without a minimum-length constraint; a zero-length or one-character query returns tens of thousands of rows and exhausts the connection pool" is a ticket.

2. **Actionable by the owner without further research.** If the engineer receiving the ticket has to do two hours of investigation to understand what you meant, you have underspecified. State the recommended control specifically: "Require minimum 3-character prefix; add a GIN trigram index on `last_name`; enforce per-user concurrent-query limit via semaphore." Let them decide whether your specific recommendation is right, but give them something concrete to react to.

3. **Sized to one sprint or less.** If a fix is larger than a sprint, split it. Write the ticket for the 80% fix that ships now, and write a separate ticket for the architectural investment that ships later. Do not bundle them.

4. **Verifiable.** The acceptance criterion must include the test or observation that proves the fix works. "Integration test that exercises cross-patient access and must fail with a 404." "A deploy with the prior vulnerable code is rejected by the added pre-commit hook."

5. **Owned.** Every open finding has a name next to it. Not a team, a name. When the team reshuffles, the facilitator or tech lead updates the owner. An owner-less finding is a finding that will not be fixed.

Write every finding to that standard. You will find that the deliverables you produce start to travel — other teams will ask for the template, managers will ask to have a session for their own systems, and the threat modeling program becomes something engineers request rather than tolerate.
