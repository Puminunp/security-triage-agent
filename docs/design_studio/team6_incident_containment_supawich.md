# Week 3 Design Studio: Team 6, Incident Containment

> In-class worksheet (CYBERSEC 590 design lab, Google Doc tab "Team 6"), copied as submitted by the team. Supawich Puengdang was a member of this team. Included because the lab instructions require each student to attach their team's completed worksheet to this assignment. Lessons we carried into Assignment 3 are in `revised_worksheet_assignment3.md`.

# Incident Containment

**Scenario brief  |  Read this page, then complete the worksheet**

### Scenario

EDR has flagged ransomware precursors at a manufacturing firm: shadow-copy deletion on two workstations and suspicious SMB fan-out from a server that also runs the shipping line's scheduling. The on-call responder has a 15-minute decision window. Design an agent system that assembles the picture, proposes containment, and executes approved actions quickly without breaking the business.

### Stakeholder

Incident commander. 

### Design scope

Focus on the decision to isolate the shipping scheduling server. Use the supplied incident facts as the starting input and show the evidence, approval, and rollback record needed for that decision.

### Example of Available tools

|  |  |
| :-: | :-: |
| **Tool** | **Input → output** |
| EDR host isolation | host → network-isolated (reversible, but disruptive while active) |
| AD account disable | account → disabled |
| Firewall block | IOC → blocked at egress |
| Blast-radius lookup | host → dependent systems, business function, downtime cost |
| Backup status check | host → last good backup, estimated restore time |
| Comms drafter | incident facts → stakeholder notification draft |
| Action log | every action → timestamped, attributable entry |

  

### Constraints to preserve

  - Isolating the scheduling server stops the shipping line; that decision needs a named human approval.
  - The decision window is 15 minutes; the agent must surface the hard choice, not bury it.
  - Isolations and disabled accounts must be tracked for rollback.
  - The after-action review will read the action log; completeness matters.

  
  
  
  
  
  
  
  
  
  
  
  
  
  
  

# Team 6 Worksheet  

# Worksheet Team 6

  

**Team Number:**   Team 6

**Team Scenario Title::**  Incident Containment

**Team members:**   Dan Hendricks, Justin Abraham, Supawich Puengdang, Kangyu(Sera) Tan

  

**Complete the following questions for your team’s assigned scenario**

1.  **## **System contract****

State the task in one sentence. What does your system need to do? (This is not a trick question).  Then identify the input and the output format with its key fields.  If you are unfamiliar with the scenario, feel free to research the topic.

The agent must identify and categorize incident indicators based on business impact, recommend remediation, obtain human approval for high-impact remediation decisions, execute approved actions, maintain action traces for logging and rollback, and preserve the availability of critical infrastructure.   
  
**Input Format**

A structured incident report containing:

**Incident indicators:** type, affected host, severity, timestamp

**Business impact:** affected service, system criticality, estimated downtime

**Network activity:** suspicious connections, IOCs, affected systems

**Backup status:** last known-good backup and estimated recovery time

**Available actions:** isolation, account disablement, firewall blocking

**Decision deadline:** time remaining to make the containment decision  
  

**Output Format**

A structured containment decision record containing:

**Incident assessment:** identified threats and severity

**Recommendation:** proposed remediation action and rationale

**Business impact:** expected operational disruption

**Human approval:** approver, approval status, and timestamp

**Execution status:** approved action, execution time, and executor

**Rollback plan:** reversal action and conditions

**Action log:** timestamped record of all decisions and actions

  

1.  **## **Workflow and human role****

Draw a system diagram that shows the agent design. Make sure to choose a design pattern and explain why you chose that pattern. Label each component and where LLM, code, tools, or humans. Identify any actions that require approval and what triggers it.

<https://excalidraw.com/#room=4ec5cbb13fa5c7e81093,679QsyEKx8puKeT2OiYOnQ>

•

Separation of judgment from execution: the component that recommends (LLM) is never the component that is authorized to isolate a host or disable an account (code, tool-calling only). A single fused agent makes it harder to guarantee the gate can't be reasoned around.

• Parallelizable evidence gathering: blast-radius lookup and backup-status check don't depend on each other, so an orchestrator can fire both at once — a linear single-agent loop would serialize them and burn the 15-minute window.

• Clean audit boundaries: each worker's output is independently logged, so the after-action review can see exactly which component produced which fact, recommendation, or action — not just a single LLM transcript.

• Low-risk actions don't wait on the gate: isolating the two already-compromised workstations and blocking the IOC proceed under standing pre-authorization in parallel with the human decision on the scheduling server, so the orchestrator pattern lets urgent-but-safe actions and the one urgent-and-risky action move on separate tracks simultaneously.

  
  

1.  **## **Select Tools****

Choose only the essential tools for the task. For each, specify input → output and what happens on failure

  

|  |  |  |
| :-: | :-: | :-: |
| **Tool** | **Input → output** | what happens on failure |
| EDR host isolation | host → network-isolated (reversible, but disruptive while active) | Verify status, retry once, and escalate. |
| Firewall block | IOC → blocked at egress | Log the failure and use alternative containment methods. |
| Blast-radius lookup | host → dependent systems, business function, downtime cost | Mark impact as unknown, retry once and require human approval. |
| Backup status check | host → last good backup, estimated restore time | Mark recovery as unknown. |
| Action log | every action → timestamped, attributable entry | Stop high-impact automated actions until the log is restored. |

  
  

1.  **## **Failure walkthrough and trace****

Create a failure scenario (e.g. What happens if the tool use returns empty, or timeout?  What if the request is off topic?) and then describe how the system should handle that (i.e. What would you put in place? Guardrails, retry/stop limits). 

If the Blast-radius lookup timeout or returns empty,  the system can not confirm the server’s dependent systems.

The agent should not assume that missing data means low impact, it needs to present the confirmed security evidence and impact to the commander. Blocking  malicious indicators or isolating workstations can be processed while waiting for human approval to isolate the server.  Because  the incident has a 15 minutee decision window,  so the retry is limited (only once).

### Trace of what the system does?

•     Evidence Agent calls Blast-Radius Lookup on the scheduling server; the call times out at 5s.

•     Orchestrator retries once (single retry, short backoff). Timeout again.

•     Guardrail fires: unknown business impact defaults to "treat as production-critical." This is a fail-safe default set in code, not left to the Recommendation Agent to infer — the agent cannot conclude "probably fine to isolate" from missing data.

•     Recommendation Agent is required to state the degraded condition explicitly in the decision package shown to the Incident Commander: "Impact data unavailable — proceeding on worst-case (production-critical) assumption." The gap is surfaced, never silently filled in.

•     Approval Gate still triggers (worst-case default forces it), so the human decision still happens inside the 15-minute window rather than stalling on the failed tool call.

•     Action Log records the tool failure, the retry, the fallback-to-worst-case decision, and the fact that the approver was told — each as its own entry, so the after-action review can see the degraded-data path was followed correctly.

  
  

1.  **## **Success Metrics****

Choose one metric and a proposed target. Describe a small test set and who or what supplies the expected answers. Include the failure case above.

  

Metric: Correct containment  decision rate

Target:>= 90% 

Test set:  15 simulated incident cases(eg. Blast-radius timeout case, low-impact workstations..)

Who or what: based on incident response policy and instructor-provided requirements. 

Failure case above: mark impact as unknown, retry once then ask for human approval before isolating the server.

  
  

### Report in 45 seconds

  

State your workflow and pattern choice, then identify the worst failure and the mitigating control.

  

**Keep your completed worksheet and submit with the next assignment.**

