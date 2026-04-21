# NIST CSF 2.0 → AppSec Program Mapping

## Scope

This document maps the NIST Cybersecurity Framework 2.0 (published February 2024) to the activities of a mature application security program. CSF 2.0 introduced the new **Govern (GV)** function and reorganized subcategories across **Identify (ID), Protect (PR), Detect (DE), Respond (RS),** and **Recover (RC)**. Every subcategory here has at least one AppSec-relevant touchpoint; subcategories that are purely physical, organizational, or financial are omitted.

The mapping is accompanied by a **maturity model** per functional area with four levels:

- **Level 1 — Initial.** The control exists ad hoc; one or two engineers know how it works; there is no systematic evidence.
- **Level 2 — Managed.** The control has an owner, a documented process, and produces artifacts on a repeatable cadence. Most teams follow it; exceptions are exceptions.
- **Level 3 — Defined.** The control is automated wherever feasible, integrated into the software development lifecycle, and the evidence it produces is retained in audit-ready form.
- **Level 4 — Optimized.** The control is continuously improved from outcome data (incident trends, false-positive rates, MTTD/MTTR), and feeds back into architecture and design.

A realistic mature program is roughly Level 3 across most subcategories with a few Level 2 and a few Level 4. A program uniformly at Level 4 is usually over-claiming or has stopped adding features.

## GV — Govern

CSF 2.0's new function covers the governance context that surrounds all the others. AppSec's contribution is smaller here than in Protect or Detect, but the governance decisions drive what controls get built.

| Subcategory | Meaning | AppSec Contribution |
| --- | --- | --- |
| **GV.OC-01** — Organizational mission is understood and informs cybersecurity risk management | Context for security decisions. | Threat models reference the business mission (PHI handling, payment processing) when prioritizing risks. |
| **GV.RM-01** — Risk management objectives are established and agreed to by organizational stakeholders | Risk appetite. | AppSec severity SLAs (Critical: 7 days, High: 30 days, Medium: 90 days) tied to an agreed appetite. |
| **GV.SC-01** — A cybersecurity supply chain risk management program is established | Supply chain governance. | Vendor security review process, SBOM requirement in contracts, subprocessor registry. |
| **GV.SC-04** — Suppliers are known and prioritized by criticality | Critical-dependency awareness. | Dependency inventory (Snyk / Dependabot) tiered by criticality to the app. |
| **GV.PO-01** — Policy for managing cybersecurity risks is established | The policy layer. | AppSec policy documents (secure coding standard, break-build policy, incident response) that engineering actually references. |

### Maturity — Govern

| Level | What it looks like |
| --- | --- |
| Initial | Policies exist in a wiki, rarely referenced; no formal risk appetite. |
| Managed | Policies owned by a named accountable individual, reviewed annually; severity SLAs agreed with engineering. |
| Defined | Policies are short, linked from the pipeline documentation, and revised when incidents expose gaps; supply-chain inventory automated. |
| Optimized | Policy coverage metrics tracked (which teams follow which policy), drift detected automatically, policy decisions informed by incident trend data. |

## ID — Identify

### AppSec-relevant subcategories

| Subcategory | Meaning | AppSec Contribution |
| --- | --- | --- |
| **ID.AM-02** — Software platforms and applications are inventoried | Asset inventory. | CMDB entry per service; auto-discovered via GitHub / container registry / load balancer inventory. |
| **ID.AM-03** — Organizational communication and data flows are mapped | DFDs. | Every threat model produces a DFD that becomes the data-flow source of truth for the service. |
| **ID.AM-08** — Systems, hardware, software, services, and data are managed throughout their life cycles | Service lifecycle. | Decommissioning checklist that includes credential rotation, log archival, DNS cleanup. |
| **ID.RA-01** — Vulnerabilities in assets are identified, validated, and recorded | Vulnerability management. | SAST / SCA / DAST findings in a single tracker; triage SLA; trend dashboard. |
| **ID.RA-02** — Cyber threat intelligence is received from information sharing forums and sources | Threat intel consumption. | Subscribe to ISAC feeds for the industry; CVE mailing lists; dependency maintainer announcements. |
| **ID.RA-05** — Threats, vulnerabilities, likelihoods, and impacts are used to determine inherent risk and prioritize responses | Risk-weighted triage. | STRIDE risk rubric (L × I), CVSS scores, exploitability context drive the queue order. |
| **ID.RA-06** — Risk responses are chosen, prioritized, planned, tracked, and communicated | Remediation program. | Findings tracked in JIRA with severity-based SLAs; weekly review of slippage. |
| **ID.SC-01** (2.0 equivalents in GV.SC) — Supply chain risk management | SBOM, image signing, signed commits. |
| **ID.IM-01** — Improvements are identified from evaluations | Retro inputs. | Post-incident reviews and pen-test reports produce backlog items tagged `security-improvement`. |

### Maturity — Identify

| Level | What it looks like |
| --- | --- |
| Initial | Asset inventory lives in spreadsheets; threat models exist for a few services; vulnerability findings in per-tool silos. |
| Managed | Single vulnerability tracker across SAST/SCA/DAST/manual; every new service goes through a threat model before launch. |
| Defined | Asset inventory auto-populated; every threat model has an owner and a review cadence; findings have severity-based SLAs tracked against actual close times. |
| Optimized | Threat intel feeds drive targeted threat-hunting; asset criticality is input to vulnerability prioritization; risk scoring is measurable and calibrated against incident data. |

## PR — Protect

This is where most AppSec controls live. The subcategories mirror the control classes the earlier OWASP playbooks in this repository address.

### AppSec-relevant subcategories

| Subcategory | Meaning | AppSec Contribution |
| --- | --- | --- |
| **PR.AA-01** — Identities and credentials are issued, managed, verified, revoked, and audited | Identity lifecycle. | IdP-driven provisioning and deprovisioning; quarterly access review; audit log of every permission mutation. |
| **PR.AA-02** — Identities are proofed and bound to credentials | Enrollment identity proofing. | Employee enrollment through HR-verified identity; customer enrollment with verified email + MFA. |
| **PR.AA-03** — Users, services, and hardware are authenticated | Authentication. | SSO for users, workload identities (IAM roles, OIDC federation) for services, device attestation where applicable. |
| **PR.AA-05** — Access permissions, entitlements, and authorizations are defined, managed, enforced, and reviewed | Authorization. | Resource-scoped authorization checks; least-privilege IAM; quarterly reviews. |
| **PR.AA-06** — Physical access is managed | Physical — inherited from cloud provider. |
| **PR.AT-01** — Personnel are provided with awareness and training | Security training. | Annual training + secure coding training for engineers specifically. |
| **PR.DS-01** — Data-at-rest is protected | Encryption at rest. | AES-GCM / AES-CCM at storage layer, KMS-managed keys, column-level encryption on PHI/PII. |
| **PR.DS-02** — Data-in-transit is protected | Encryption in transit. | TLS 1.2+, mTLS for service-to-service, HSTS with preload, egress controls. |
| **PR.DS-10** — Data-in-use is protected | Data in use. | Memory-safe languages where feasible; secret redaction in logs; selective use of confidential computing where justified. |
| **PR.DS-11** — Backups are created, protected, maintained, and tested | Backups. | Separate key scope for backups, periodic restore tests, offline copy on long intervals. |
| **PR.PS-01** — Configuration management practices are applied | Config management. | IaC-enforced infrastructure; environment-variable validation at boot; drift detection via Terraform plan on a schedule. |
| **PR.PS-02** — Software is maintained, replaced, and removed | Dependency lifecycle. | Dependency upgrade cadence; EOL-runtime detection; decommissioning process. |
| **PR.PS-03** — Hardware is maintained, replaced, and removed | Hardware — inherited. |
| **PR.PS-05** — Installation and execution of unauthorized software is prevented | Execution control. | Signed image admission, allowlisted package registries, code signing on binaries. |
| **PR.PS-06** — Secure software development practices are integrated | SDLC. | Threat modeling, secure code review, SAST/SCA/DAST in CI, security champions program. |
| **PR.IR-01** — Networks and environments are protected from unauthorized logical access | Network segmentation. | VPC boundaries, mesh policies, egress allowlists, IMDSv2 enforcement. |
| **PR.IR-02** — The organization's technology assets are protected from environmental threats | Environmental — inherited. |
| **PR.IR-03** — Mechanisms are implemented to achieve resilience requirements | Resilience. | Circuit breakers, timeouts, rate limits, bulkheads in application code. |

### Maturity — Protect

| Level | What it looks like |
| --- | --- |
| Initial | Some encryption, some TLS, some auth; secure coding is a convention not enforced; dependencies upgraded reactively. |
| Managed | Encryption at rest and in transit standard; SSO enforced; CI pipeline includes SAST and SCA with a published severity threshold; secure coding standard documented. |
| Defined | Every new service goes through threat modeling; break-build policy enforced; KMS with separation of duties; runtime protections (WAF, RASP, egress proxy); dependency upgrades on a cadence with SLA; security champions in every team. |
| Optimized | Security controls measurably reduce incident rates; engineers opt into stricter profiles (e.g., hardened containers, stricter CSP); automated remediation for common findings; dependencies upgraded with minimal human touch via tested PR automation. |

## DE — Detect

### AppSec-relevant subcategories

| Subcategory | Meaning | AppSec Contribution |
| --- | --- | --- |
| **DE.CM-01** — Networks and network services are monitored | Network telemetry. | Egress proxy logs; VPC flow logs; service-mesh metrics and access logs. |
| **DE.CM-02** — The physical environment is monitored | Physical — inherited. |
| **DE.CM-03** — Personnel activity and technology usage are monitored | Insider-threat monitoring. | Auth logs, privileged-action logs, anomalous-access alerting. |
| **DE.CM-06** — External service provider activities and services are monitored | Third-party telemetry. | SaaS vendor admin logs ingested where available; supply-chain compromise indicators. |
| **DE.CM-09** — Computing hardware and software, runtime environments, and their data are monitored | Application telemetry. | Structured application logs, APM, SIEM rules on security-relevant events. |
| **DE.AE-02** — Potentially adverse events are analyzed to understand associated activities | Threat hunting. | Periodic hunts over log data; detection engineering backlog. |
| **DE.AE-03** — Information is correlated from multiple sources | Correlation. | SIEM joins identity, network, application, and cloud control-plane events on a common request / trace ID. |
| **DE.AE-04** — Estimated impact and scope of adverse events are understood | Scope assessment. | Incident-responder runbooks include scope-assessment queries; blast-radius reasoning in post-incident reviews. |
| **DE.AE-06** — Information on adverse events is provided to authorized staff and tools | Routing. | PagerDuty / Slack channels; documented routing matrix. |
| **DE.AE-07** — Cyber threat intelligence and other contextual information are integrated into the analysis | Intel integration. | IoC enrichment on SIEM rules; intel feeds drive proactive rule creation. |
| **DE.AE-08** — Incidents are declared when adverse events meet the defined incident criteria | Incident declaration. | Severity rubric with unambiguous declaration thresholds. |

### Maturity — Detect

| Level | What it looks like |
| --- | --- |
| Initial | Unstructured logs to local disk; occasional SSH-in-and-grep for investigation; no centralized SIEM. |
| Managed | Central log aggregation; structured application logs with request ID and user ID; basic alert rules on auth failures and error rates. |
| Defined | Detection engineering backlog with named owner; alert rules mapped to MITRE ATT&CK; tabletop exercises test log queryability; mean time to detect tracked. |
| Optimized | Alert tuning driven by false-positive rate data; purple-team exercises drive new detections; detections tested in CI against attack-simulation scripts; MTTD trending down across successive audits. |

## RS — Respond

### AppSec-relevant subcategories

| Subcategory | Meaning | AppSec Contribution |
| --- | --- | --- |
| **RS.MA-01** — The incident response plan is executed with stakeholders once an incident is declared | IR execution. | On-call rotation, incident commander role, documented playbooks. |
| **RS.MA-02** — Incident reports are triaged and validated | Triage. | Sev assignment within 15 minutes; duplicate / false-alarm handling documented. |
| **RS.MA-03** — Incidents are categorized and prioritized | Categorization. | Taxonomy of incident classes: credential compromise, data exfiltration, availability, supply chain, etc. |
| **RS.AN-03** — Analysis is performed to establish what has taken place during an incident and the root cause | Forensic analysis. | Log retention meets the forensic window; immutable log store where possible; runbooks for common root-cause analyses. |
| **RS.AN-06** — Actions performed during an investigation are recorded and the record's integrity and provenance are preserved | Chain of custody. | Incident timeline as an append-only document; tool-generated artifacts stored in an evidence bucket with tamper-evident hashing. |
| **RS.CO-02** — Internal and external stakeholders are notified of incidents | Notification. | Breach-notification runbook with counsel, regulatory, and customer communication templates. |
| **RS.MI-01** — Incidents are contained | Containment. | Credential rotation playbook, IP blocklisting via WAF, emergency kill-switch feature flags. |
| **RS.MI-02** — Incidents are eradicated | Eradication. | Malicious-dependency removal, forced session revocation, image redeployment with hashes verified. |

### Maturity — Respond

| Level | What it looks like |
| --- | --- |
| Initial | Incidents handled by whoever is on the Slack channel; post-incident reviews are occasional and freeform. |
| Managed | On-call rotation with a documented incident commander role; severity rubric in use; post-incident reviews on a template within 5 business days. |
| Defined | Runbooks per incident class, versioned and exercised in tabletops; evidence-handling procedures documented; internal and external notification templates pre-drafted with legal review. |
| Optimized | Game days quarterly; incident trends drive preventive backlog; MTTR tracked and trending down; regulatory notifications rehearsed for jurisdictions the business operates in. |

## RC — Recover

### AppSec-relevant subcategories

| Subcategory | Meaning | AppSec Contribution |
| --- | --- | --- |
| **RC.RP-01** — The recovery portion of the incident response plan is executed once initiated from the incident response process | Recovery execution. | Documented recovery playbook invoked after containment; recovery distinct from eradication. |
| **RC.RP-02** — Recovery actions are selected, scoped, prioritized, and performed | Recovery scoping. | Prioritize restoration of customer-facing services; defer non-essential integrations. |
| **RC.RP-03** — The integrity of backups and other restoration assets is verified before using them for restoration | Backup integrity. | Restore tests on a schedule; HMAC or signature verification on backup artifacts; separate key scope so an attacker who compromises production keys cannot also compromise backups. |
| **RC.RP-04** — Critical mission functions and cybersecurity risk management are considered in restoration planning | Risk-aware restoration. | Restoration plan considers whether the root cause is eliminated before restoring access. |
| **RC.RP-05** — The integrity of restored assets is verified, systems and services are restored, and normal operating status is confirmed | Post-restore verification. | Post-recovery smoke tests that include security checks (encryption on, WAF engaged, auth working). |
| **RC.CO-03** — Recovery activities and progress in restoring operational capabilities are communicated | Communication. | Status page updates, internal status calls, customer communications timed to confirmed milestones. |

### Maturity — Recover

| Level | What it looks like |
| --- | --- |
| Initial | Backups exist; restores have been attempted occasionally; recovery procedures ad hoc. |
| Managed | Scheduled restore drills; backup retention and encryption policies documented; status page used for customer communication. |
| Defined | Recovery distinct from eradication; restore validated with security tests; status page templates and internal / external comms pre-drafted; recovery exercised quarterly. |
| Optimized | Recovery time continually decreasing from data-driven improvements; chaos engineering includes security-recovery scenarios; failover to secondary region tested under load. |

## How to use this document

**As a program roadmap.** Print the maturity tables, mark where you are honestly, and propose a target state one level up. The jump from Initial to Managed is usually "establish the owner and the cadence"; the jump from Managed to Defined is usually "automate it and integrate it into CI"; the jump from Defined to Optimized is usually "measure outcomes and tune from data."

**As an audit pre-read.** CSF is not itself an audit framework, but assessors using ISO 27001, HITRUST, FedRAMP, or sector-specific frameworks often cross-walk to CSF. A mature CSF mapping gives the assessor a fast way to understand your posture before they get into control-specific fieldwork.

**As a gap analysis for executive reporting.** The CSF function taxonomy is a natural reporting structure for a CISO report to a board. A heatmap of functions by maturity, with delta arrows from last quarter, communicates posture at the right altitude — the board does not want the Semgrep rule count; they want to know whether Detect is moving toward Optimized.

## What this document does not replace

- **A formal NIST CSF Profile or Tier assessment** — that is a guided exercise, typically with an external assessor, that produces a current-state and target-state profile. This document is input to such an assessment, not a substitute.
- **A risk register** — CSF identifies categories of risk; it does not quantify specific risks to your organization. Pair this mapping with a FAIR or similar quantitative risk model for the top-tier threats.
- **The other compliance mappings in this folder** — CSF is voluntary and outcome-focused; HIPAA and SOC 2 are prescriptive and evidence-driven. Use CSF to plan and prioritize; use HIPAA / SOC 2 mappings to respond to specific audit requests.
