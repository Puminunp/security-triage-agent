# Design Studio worksheet, revised for Assignment 3

**Scenario:** Security triage agent, CVE-2026-85880 against Northbridge Services
**Team members:** Paul Prommark (pp273), Supawich Puengdang (sp803)

The in-class worksheets are kept unchanged in this folder:
`team3_vulnerability_prioritization_puminun.md` (Paul, Team 3) and `team6_incident_containment_supawich.md` (Supawich, Team 6). This page answers the same five questions for the system we built. The full design is in `docs/architecture.md`.

## Lessons carried over from the in-class activity

| From | Lesson | Where it shows up in Assignment 3 |
|---|---|---|
| Team 3 | Missing KEV data must never silently become "not KEV"; unknown routes to review | `lookup_kev` says absence ≠ safe; KEV unknown → no modifier, confidence Low, flagged in the rule (`src/policy.py`) |
| Team 3 | Parsing and scoring in deterministic code; the LLM only drafts justifications | The policy is code (`src/policy.py`); the LLM gathers evidence and drafts actions, never rates |
| Team 3 | Fail safe, not silent; audit every failed lookup | Every tool result, retry, cache fallback and stop is in `trace.jsonl` and `tool_results.json` |
| Team 6 | Separate the component that recommends from the one that decides | The model submits facts; a validator checks them; code applies the policy |
| Team 6 | Missing impact data must not be read as "low impact" | Unknown decisive facts → INSUFFICIENT_EVIDENCE; unknown data protection counts as unprotected (policy section 3) |
| Team 6 | Retry once, then surface the degraded state to the human | External lookups retry once, then use the cache, which is labeled `cached` and lowers confidence |
| Both | A named human signs off before anything is acted on | `human_review.status: pending` in every assessment; `docs/evidence_review.md` |

## 1. System contract

**Task:** Given one CVE, decide for every Northbridge asset that runs an affected product whether the CVE is High, Medium or Low local risk under our policy, or say INSUFFICIENT_EVIDENCE, with cited evidence and a next step.

**Input:** CVE ID (e.g. `CVE-2026-85880`) and an environment snapshot (`environment/northbridge-v1.1.json`).

**Output:** `assessment.json`, one entry per affected asset record:
`asset` (ID, instance, role, zone, locator) · `decision` · `status` (rated / needs_analyst_review) · `rationale` (applicability level and facts, priority and reason, severity band, KEV and Partial modifiers, policy rule) · `evidence` (R#, tool, source/locator, retrieved_at, live/cached/simulated) · `assumptions` · `unknowns` (decisive / non-decisive) · `confidence` · `action` (recommended action, evidence that would change it) · run metadata (model, code version, snapshot hash).

## 2. Workflow and human role

Pattern: **one tool-using agent inside deterministic code, with an evaluator gate** (diagram: `docs/workflow.png`).

`Intake (code)` → `Evidence loop (LLM picks tool + query → code runs and validates it → result back to LLM)` → `submit_findings (LLM)` → `Validator (code; errors back to LLM, at most 2 corrections)` → `Policy (code)` → `Action text (LLM)` → `Save (code)` → `Analyst review (human)`.

Why this pattern: the decision path is short and the same every time (look up the threat, find the assets, compare, rate). The only part that needs judgment is choosing what to look up and reading the results, so one agent is enough. Parallel workers would add cost with no benefit for a single CVE. The evaluator gate is there because the model's first submission was incomplete in our first live runs.

**Human approval:** this system recommends; it does not patch or isolate anything. A human must (a) review every run before acting on it, and (b) resolve every INSUFFICIENT_EVIDENCE asset. A Conflict result always names both sources so the human knows what to check.

## 3. Essential tools

| Tool | Input → output | On failure |
|---|---|---|
| `lookup_vulnerability` (NVD) | CVE ID → CVSS, affected products, fixed builds | Retry once → cache (`cached`, confidence ≤ Medium) → no cache: **stop, INSUFFICIENT_EVIDENCE**, names the lookup |
| `lookup_kev` (CISA) | CVE ID → listed?, dateAdded, dueDate, requiredAction | Retry once → cache → NVD's KEV fields → unknown: no modifier, confidence Low |
| `lookup_environment` (snapshot) | action + query → asset records, evidence S01–S08, flows, absences | `not_found` says "does not prove absence"; nulls listed as unknown, never guessed |
| `submit_findings` (code gate) | facts per asset → accepted, or errors to fix | 3 attempts, then unverified assets → INSUFFICIENT_EVIDENCE |

Deferred: EPSS (the policy doesn't use it), MSRC page (not machine-readable; saved by hand as a PDF to cross-check NVD), web search (NVD and KEV are the primary sources).

## 4. Failure walkthrough and trace

**Case:** NVD is unreachable and there is no cached copy.
**Guardrail and where enforced:** `src/sources/_fetch.py` retries once; `src/agent.py` stops the loop as soon as `lookup_vulnerability` returns `error`.
**Expected response:** no per-asset rating; overall INSUFFICIENT_EVIDENCE; stop reason names `lookup_vulnerability` and the error; the model is not allowed to fill in fixed builds from memory (the validator rejects any fixed build when no NVD data exists).
**Trace fields:** `run_id`, `faults`, tool-call `ref`, `tool`, `args`, `status`, `source_mode`, `error`, `stop.status`, `stop.reason`, `code_version`, `snapshot_sha256`.

Second case, checked offline: the model calls a tool that doesn't exist three times → each call rejected with the list of real tools → the run stops with `stopped_rejected_calls`, no rating.

## 5. Success test

**Metric and target:** 100% agreement between the agent's decision for W15 and the group's pre-registered expected decision on all five snapshot checks, plus the expected behavior on every controlled failure (`tests/expected_results.json`, set from the policy before any run).

**Test cases and source of expected answers:** base snapshot (High), applicability change (Low), impact change (Medium), missing build (INSUFFICIENT_EVIDENCE), conflicting evidence (INSUFFICIENT_EVIDENCE), NVD down with cache (High, confidence ≤ Medium), NVD down without cache (stop, INSUFFICIENT_EVIDENCE), invalid tool (rejected, run continues). Expected answers come from Student A's written policy and its reference implementation, agreed at the group consensus meeting. Results: `docs/test_results.md`.

## Report in 45 seconds

One agent, wrapped in code. The model decides what to look up (NVD, KEV, the environment) and extracts the facts. Code checks every fact against the tool data and applies the group's applicability-and-impact policy, and a human reviews the output. **Worst failure:** the model invents or misreads a decisive fact (a build number) and a vulnerable server is rated Low. **Control:** the model never rates. The validator rejects any fact that differs from the tool data, unknowns become INSUFFICIENT_EVIDENCE instead of a guess, and a run with coverage gaps can never come out as "Low".
