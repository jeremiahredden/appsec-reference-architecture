# Threat Modeling

A practitioner's approach to threat modeling that engineering teams will actually sit through — and act on.

---

## The Approach in One Paragraph

I run lightweight, facilitated STRIDE sessions timeboxed to 60-90 minutes, anchored on a data flow diagram the team produces (not one I produce for them), ending with owned findings in the team's existing ticket system before anyone leaves the room. I do not ship threat modeling documents as deliverables. I ship a JIRA epic with prioritized, estimable tickets and a living diagram checked into the repo. The STRIDE document is a byproduct of the session; the backlog is the actual output.

---

## Why STRIDE (and When Not To)

STRIDE is the right default for the vast majority of engagements. It is easy to teach to a team in five minutes, it forces coverage across six categories that humans tend to forget under time pressure, and its output maps cleanly to engineering controls. The alternatives each have narrower fits:

- **PASTA** is the better fit when the client has a formal risk management function that will consume business-impact scoring, or when the target system carries direct financial exposure (trading systems, payment rails). It takes 3-5x longer to run.
- **LINDDUN** is the better fit when privacy is the primary concern — EU consumer products, health data processors, regulated markets with specific data subject rights. Use it alongside STRIDE, not instead of it, for healthcare and fintech.
- **Attack Trees** are the better fit for a specific high-value asset where you have already identified the crown jewel and need to enumerate adversary paths. They are a bad fit for "model the whole service."
- **Kill Chains / MITRE ATT&CK mapping** are the right tool for detection engineering, not design-time threat modeling. Do not confuse the two.

For any system I have not seen before, I start with STRIDE. If the system warrants deeper analysis, I layer a second methodology after the first pass.

---

## Templates in This Folder

| File | When to Use |
| --- | --- |
| [`stride-template.md`](./stride-template.md) | The baseline STRIDE template I start every engagement with. Fork it into your engagement workspace and overwrite the example rows with the system under analysis. |
| [`worked-example-rest-api.md`](./worked-example-rest-api.md) | A completed threat model for a realistic healthcare data REST API. Read this before facilitating your first session — it shows the level of specificity you are aiming for. |
| [`facilitation-guide.md`](./facilitation-guide.md) | How to run the session. Covers pre-meeting prep, the agenda, facilitation tactics for getting engineers to surface threats, anti-patterns to avoid, and how to close the session with findings in the backlog. |

---

## How to Run a Session (The Short Version)

The detailed playbook is in [`facilitation-guide.md`](./facilitation-guide.md). The short version:

1. **Before the meeting**, get a data flow diagram from the team — even a whiteboard photo. If they cannot produce one, the first 30 minutes of your session is drawing it. Also gather: the system's data classification, its authentication model, its upstream/downstream dependencies, and any known prior incidents.
2. **Invite the right people**: the tech lead, one senior IC who built most of it, the SRE/platform contact, and the product owner if data handling decisions need business input. Keep it to 5-7 people. More than that and the introverts stop talking.
3. **Run the 60-90 minute session** per the agenda in the facilitation guide. Use the STRIDE template live — share your screen, fill in rows as threats surface, show the team their own output in real time.
4. **Before anyone leaves**, assign owners and create tickets. Not JIRA epics to be decomposed later — actual tickets with acceptance criteria. The 10 minutes at the end of the session is the difference between threat modeling that changes code and threat modeling that changes nothing.
5. **Commit the output**: check the completed threat model into the service's repository under `/docs/security/threat-model.md`. It should live next to the code, not in a separate document management system where it will go stale.

---

## When to Re-Run a Threat Model

A threat model is a snapshot of a system's risk posture at a moment in time. Re-run it when:

- A new trust boundary is introduced (new external integration, new tenant model, new data classification handled).
- The authentication or authorization model changes.
- A new class of data is processed (first time handling PHI, PCI, or regulated data).
- A significant incident occurs that the existing model did not anticipate — the model missed something, and you need to understand why.
- Annually, at minimum, for any system handling regulated data.

Do not re-run a full threat model for every feature release. That is how threat modeling gets a reputation as a tax. Use lightweight security design reviews for incremental changes and reserve the full STRIDE session for architectural inflection points.

---

## Common Objections (And My Answers)

**"We already have penetration tests."** Pen tests find bugs in what you built. Threat models find problems in what you are about to build, before the bug exists. They are complementary, not substitutes. A pen test two weeks before launch that finds a broken authorization model costs 10x a threat model that prevents it.

**"Our system is too small / too new / too early-stage."** The earliest-stage systems benefit most, because design decisions are still cheap to change. A threat model of a two-week-old prototype takes 45 minutes and often reshapes the authentication model before the team has written the code they would otherwise throw away.

**"We do not have a diagram."** Then we will draw one in the first 30 minutes of the session. If a team cannot describe their system's data flows on a whiteboard, that is itself a finding.

**"Our threat model from last year is still good."** Possibly. Read it. If the system has added a new external integration, a new data type, or a new tenant model since then, it is not still good.
