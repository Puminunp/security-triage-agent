# Security Triage Agent: Agentic CTI Risk Triage for Northbridge Services

An agentic cyber threat intelligence (CTI) risk-triage system that rates a CVE against a fictional Windows enterprise, Northbridge Services. Given only a CVE ID, the agent decides which lookups to run, collects vulnerability evidence (NVD, CISA KEV), finds the affected assets in an environment snapshot of the organization, and applies a documented applicability-and-impact rating policy to produce a High / Medium / Low rating per asset, or INSUFFICIENT_EVIDENCE when a decisive fact is missing or conflicting. Results are compared against expected results set before any run and against a baseline.

## Group members

| Member | Role | Contributions |
|---|---|---|
| Paul Prommark (pp273) | A: case and policy | Case selection and sources, environment v1.1 and test variants, rating policy, expected results |
| Paul Prommark (pp273) | B: tools | NVD and KEV clients, cache and failure fallback, environment lookups, tool registry, tool tests and contracts |
| Supawich Puengdang (sp803) | C: agent | Agent loop, prompts, output validation, policy code, assessment and report output |
| Supawich Puengdang (sp803) | D: design and testing | Architecture and workflow diagram, test suite, live checks and controlled failures, evidence review checklist, baseline |

Both members: consensus rating, review of the final assessment and its citations, video demo.

## Repository layout

```
inputs/        Selected CVE, source list, transcribed and raw NVD / KEV data
environment/   Northbridge environment snapshot (v1.1), change log, test variants and generator
docs/          Architecture and workflow diagram, rating policy, threat prerequisites, tool contracts,
               expected and actual test results, evidence review, design-studio worksheets
reference/     Runnable reference implementation of the rating policy (Role A's spec)
config/        settings.yaml: snapshot path, source URLs, model settings, agent limits (no secrets)
src/sources/   NVD and CISA KEV clients, file cache                          (Role B)
src/tools/     Environment lookups and the tool registry the agent calls     (Role B)
src/agent.py   Orchestration: intake, tool loop, validation gate, policy, actions, save (Role C)
src/llm.py     Ollama Cloud client                                            (Role C)
src/prompts.py System prompt, submit_findings schema, action prompt          (Role C)
src/validation.py  Checks the model's facts against the tool results         (Role C)
src/evidence.py    Evidence ledger, citations, blinding of test-variant names (Role C)
src/policy.py  Rating policy as code                                         (Role C)
src/report.py  assessment.json and report.md                                 (Role C)
src/faults.py  Controlled failures for testing                               (Role D)
src/run_checks.py  Live policy checks + failures vs expected results         (Role D)
tests/         pytest: tools (B); policy parity, agent, validation (D); expected_results.json
cache/         Cached NVD and KEV responses, used when a live lookup fails
outputs/       Saved runs: outputs/checks_<timestamp>/ has every live check run
baseline/      Frozen Assignment 3 baseline for Assignment 4 (inputs, config, code version, outputs)
```

**Where each concern lives** (the assignment asks for these to be separately identifiable): source access `src/sources/`; tools `src/tools/`; model settings `config/settings.yaml` (`llm:`) and `src/llm.py`; orchestration `src/agent.py`; rating logic `src/policy.py`; validation `src/validation.py`.

## Setup

Tested with Python 3.13.5 on macOS (3.10 or later should work). Dependencies are pinned in `requirements.txt`: requests 2.32.3, PyYAML 6.0.2, python-dotenv 1.1.0, pytest 8.3.4. No agent framework is used.

macOS or Linux:

```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Windows (PowerShell):

```
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Then open `.env` and put your Ollama Cloud key in `OLLAMA_API_KEY`. Create a key at https://ollama.com/settings/keys (free account). The agent needs this key; the tests do not.

`.env` is ignored by git and must never be committed. `NVD_API_KEY` is optional: the NVD lookup works without it at a lower rate limit.

**Model:** `gpt-oss:120b` on [Ollama Cloud](https://docs.ollama.com/cloud) (free tier), temperature 0, seed 42, `think: medium`. Change it in `config/settings.yaml` or with `LLM_MODEL` in `.env`. The model must support tool calling.

## Running the complete workflow

```
python -m src.main
```

This assesses CVE-2026-85880 against `environment/northbridge-v1.1.json`, prints the non-Low decisions, and saves `outputs/<run_id>/` with `assessment.json`, `report.md`, `trace.jsonl`, `tool_results.json`, `messages.json` and `config.json`. A run takes about 30–60 seconds.

Options: `--cve`, `--snapshot environment/variants/env_patched.json`, `--fault nvd-down` (also `nvd-down-no-cache`, `kev-down`, `bad-tool`, `llm-down`), `--label`, `--out`.

To run every policy check and controlled failure with the live model and compare them with the expected results:

```
python -m src.run_checks
```

This writes `outputs/checks_<timestamp>/summary.md` (expected vs actual) and one run folder per check.

## Running the tests

```
python -m pytest
```

The tests use no LLM and no network. NVD and KEV responses are replayed from the raw files in `inputs/`, and a scripted model stands in for the LLM. To also call the real NVD and KEV services, set the environment variable `RUN_LIVE=1`.

To check Role A's policy reference against the snapshot and variants:

```
python reference/policy_reference.py environment/northbridge-v1.1.json
python reference/policy_reference.py environment/variants/env_patched.json W15
```

## Results at a glance

| Document | What it contains |
|---|---|
| `docs/architecture.md` | Design: risk question, workflow diagram, model/code/tool/human steps, tool contracts, evidence flow, failure paths, acceptance test, design-vs-implementation changes |
| `docs/workflow.png` | Workflow diagram (source `docs/workflow.mmd`) |
| `docs/rating_policy.md` | The applicability-and-impact policy with justifications |
| `docs/test_results.md` | Expected vs actual for the three policy checks and the controlled failures, demonstration checklist, limitations |
| `docs/evidence_review.md` | Human review of the final assessment and its citations |
| `docs/design_studio/` | In-class worksheets (Team 3, Team 6) and the revised worksheet for this project |
| `baseline/` | Frozen Assignment 3 baseline |

## Role A sections

### Selected case

We assess **CVE-2026-85880**, a heap-based buffer overflow in Windows ALPC that lets a low-privileged local attacker become SYSTEM (CVSS v3.1 7.8, High). CISA added it to KEV on 2026-09-08. Microsoft fixed it in the September 2026 cumulative update.

**Risk question:** What is the risk that CVE-2026-85880 is exploited on Northbridge Services assets, given the environment snapshot as of 2026-10-01?

The main asset is **W15**, the legacy finance servers (Windows Server 2016, July 2026 patch level), which hold payroll and banking data for 1,000 employees. Sources are listed in `inputs/SOURCES.md`.

### Environment

We adapted the course-supplied Northbridge Services scenario (v1.0) into `environment/northbridge-v1.1.json`. The original is unchanged. We added data classification, data protection, exposure, priority overrides, a low-privilege access field, and OS builds and software versions using real vendor release numbers. All records are labeled `source_mode: simulated`. Every change and assumption (A1–A15) is listed in `environment/CHANGES.md`, and cited through evidence records S07 and S08.

### Rating policy (summary)

The rating is computed by code in five steps. The model never chooses it.

1. **Applicability gate:** not applicable → Low; unknown or conflicting decisive fact → INSUFFICIENT_EVIDENCE.
2. **Machine priority (impact):** data sensitivity × exposure → P1–P3 (matrix 1), with P1 overrides.
3. **Severity:** CVSS v3.1 band (Critical 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9).
4. **Final matrix:** machine priority × vulnerability severity → High / Medium / Low (matrix 2).
5. **Modifiers:** KEV +1, then Partial −1. The result never goes above High or below Low.

**Matrix 1: machine priority = data sensitivity × exposure**

| Data \ Exposure | Internet | Intranet | Internal only |
|---|---|---|---|
| **PII without protection** | P1 | P1 | P2 |
| **PII with protection** | P1 | P2 | P3 |
| **No PII** | P2 | P3 | P3 |

Unknown protection counts as "without protection". Three kinds of asset are always P1 whatever the matrix says: Tier-0 identity, control planes and remote-access gateways, and services with a 4-hour recovery target.

**Matrix 2: rating = machine priority × vulnerability severity**

| Priority \ Severity | Critical | High | Medium | Low |
|---|---|---|---|---|
| **P1** | High | High | Medium | Medium |
| **P2** | High | Medium | Medium | Low |
| **P3** | Medium | Low | Low | Low |

**How CVE-2026-85880 (severity High, in KEV) moves through the matrices:**

| Asset | Matrix 1 | Matrix 2 | Modifiers | Rating |
|---|---|---|---|---|
| W15 legacy finance servers | PII without protection × Intranet = P1 | P1 × High = High | KEV +1 (already at the top) | **High** |
| W15 in the impact-change variant | No PII × Internal only = P3 | P3 × High = Low | KEV +1 | **Medium** |
| W02 offline root CA | P1 by override (Tier-0 identity) | P1 × High = High | KEV +1, then Partial −1 | **Medium** |

CVSS describes technical severity; the rating describes local risk. The full policy, with the justification for every cell, is in `docs/rating_policy.md`.

### Limitations (environment and policy)

- The priority matrix measures confidentiality (PII) and exposure, not availability. Overrides cover the most important availability cases (identity, ERP).
- Logs are not treated as PII (assumption A8).
- Versions and assumptions are simulated additions to a fictional scenario; real environments would need verified asset data.
- The low-privilege access path on W15 (A15) is an assumption, which lowers confidence in the main result to Medium.
- Severity uses CVSS v3.1 only. CVSS v4.0 and EPSS were not used.
- The NVD and KEV inputs were first transcribed through a web-reading tool. The raw files have since been saved and compared (`inputs/SOURCES.md`); no fact used by the policy differed.

### Contributions: Role A

Case selection and source collection; environment adaptation (v1.1), assumptions and change log; test variants and generator script; rating policy design and justification; threat prerequisites; expected results; reference policy implementation for checking expected results.

### AI assistance

Claude (Anthropic) helped Puminun (Role A) select the CVE, look up current vendor version numbers, draft the policy and change log, and write the snapshot, variant generator and reference policy scripts. Puminun reviewed and edited all output; the group verified the policy at the consensus meeting.

## Role B sections

### Tools

The agent has three tools. The model sees their schemas in `registry.TOOL_SCHEMAS`, and code runs each call through `registry.execute()`, which validates the call first. Tools return evidence only; they never choose the rating.

| Tool | Source | What it supplies |
|---|---|---|
| `lookup_vulnerability` | NVD CVE API 2.0 (live) | Description, CVSS v3.1 score and vector, CWEs, affected products with the first fixed build (`versionEndExcluding`), KEV fields, references |
| `lookup_kev` | CISA KEV JSON feed (live) | Whether the CVE is listed, `dateAdded`, `dueDate`, required action |
| `lookup_environment` | Northbridge snapshot (simulated) | Asset records, evidence records S01 to S08, network flows, documented absences, business services |

```python
from src.tools import registry

result = registry.execute("lookup_environment", {"action": "get_asset", "query": "W15"})
```

Every call returns the same wrapper: `tool`, `args`, `status` (`live`, `cached`, `ok`, `not_found` or `error`), `source`, `retrieved_at`, `source_mode` (`live`, `cached` or `simulated`), `data`, `unknown_fields` and `error`. The full contract, with a real example request and response for each tool, is in `docs/tool_contracts.md`.

### Unknowns and failures

- A `null` in the snapshot is returned as `null` and its path is listed in `unknown_fields` (for example `assets[17].os.build`). Nothing is guessed.
- A lookup with no match returns `not_found` and says that no match does not prove absence. Only `check_absence`, which reads the snapshot's documented absences, can establish that a product is not used.
- A CVE that is not in KEV returns `in_kev: false` with the note that absence from KEV does not establish safety.
- A failed external lookup is retried once. Then the cached copy is returned with `status: cached`. If there is no cache, the result is `status: error` with no data. This follows section 8 of `docs/rating_policy.md`.
- Unknown tools, missing or wrong arguments, and CVE IDs that do not match `CVE-YYYY-NNNN` are rejected before anything runs.

### Raw source data

The raw NVD response and KEV entry for CVE-2026-85880 are saved as `inputs/CVE-2026-85880_nvd_raw.json` and `inputs/CVE-2026-85880_kev_raw.json` (retrieved 2026-10-12 UTC; KEV catalog version 2026.10.08). Compared field by field with Role A's transcribed files, they show no difference in any fact the policy uses: CVSS 7.8, KEV dates and every fixed build match. The differences in wording and extra fields are listed in `inputs/SOURCES.md`.

### Limitations (tools)

- NVD's CPE data has no fixed build for Windows Server 2012 and 2012 R2. The tool reports it as unknown and gives the vendor's numbers separately (`cna_affected`). Northbridge has no Server 2012.
- The CVSS score is the Microsoft CNA score, because NVD has not published its own for this CVE. The tool records which score it used.
- The MSRC advisory (source T3) is not fetched by a tool; the page needs a browser.
- `search_assets` is plain text matching, so it can miss a product that is named differently in the snapshot.
- Every null is listed in `unknown_fields`, including `priority_override` and `business_service`, which are null by design on most assets.
- Tool results include the snapshot file name and ID. For the test variants these name the test, which the model can see.
- The cached KEV feed is a snapshot in time; a `cached` answer can be out of date.

### Contributions: Role B

NVD and KEV clients; file cache and retry-then-cache fallback; environment lookup functions; tool schemas and the validating registry; settings file; raw source data and the raw-versus-transcribed comparison; tool tests; tool contract documentation.

### AI assistance

Claude (Anthropic) helped Puminun (Role B) write the source clients, environment tools, registry, tests and tool contract documentation, fetch the raw NVD and KEV data, and compare it with the transcribed files. Puminun reviewed the output; the tests were run before each commit.

## Role C sections

### Agent design

The agent takes only a CVE ID. A `gpt-oss:120b` model on Ollama Cloud decides which tools to call and with what arguments. It looks up the CVE in NVD and KEV, searches the environment for every affected product, fetches the evidence records each candidate asset cites, and then calls `submit_findings` with the facts for each asset. Code then takes over:

1. **Validation** (`src/validation.py`). Every submitted fact (OS build, affected product, fixed build, the build comparison, low-privilege access, conflicts) is compared with the tool result it came from. The validator also checks that every affected product was searched for in the environment, that every asset running one is included, and that its cited evidence was fetched. Errors go back to the model, which gets two chances to fix them. An asset whose facts still don't match is rated INSUFFICIENT_EVIDENCE. A run with open coverage gaps can never come out as "Low".
2. **Policy** (`src/policy.py`). Applies `docs/rating_policy.md` to the validated **tool data** and returns the decision, the rule that fired and the confidence. The model never chooses a rating.
3. **Action text.** The model drafts the recommended action and the evidence that would change the decision for non-Low assets (labeled `drafted_by: model`). Low assets get a fixed template.
4. **Save.** The assessment, a readable report, the full trace, every raw tool result, the model conversation and the configuration are saved.

The model sees a **blinded** copy of each tool result: the snapshot's file name and ID are replaced with neutral labels, so a test variant such as `env_conflict.json` cannot hint at the expected answer. Citations in the saved assessment use the real locators.

### Assessment format

`outputs/<run>/assessment.json` has one entry per affected asset record:

- **Asset and threat:** asset ID, instance, role, zone, locator
- **Decision and status:** `rated` or `needs_analyst_review`
- **Rationale:** applicability level and facts, priority and reason, severity band, KEV and Partial modifiers, the policy rule that fired
- **Evidence:** each citation has a ref, source ID (T1, T2, S0x), tool, URL or locator, `retrieved_at`, and `live`, `cached` or `simulated`
- **Uncertainty:** assumptions (A1–A15 that apply), decisive and non-decisive unknowns, confidence and why
- **Action:** recommended next step and the evidence that would change the decision

Top-level sections cover the threat, the overall result, product coverage, the external lookups, agent activity and human review status.

## Role D sections

### Testing

- **Offline** (`python -m pytest`, 111 tests, no LLM or network):
  - `src/policy.py` gives the same applicability, priority and decision as Role A's reference on all 48 asset records of the base snapshot and all four variants.
  - With a scripted model, the agent produces the expected result for all five checks.
  - Every controlled failure behaves as designed: NVD down with and without cache, KEV down, 3 invalid tool calls, model outage, text-only replies.
  - The validator catches a made-up build and a fixed build "from memory".
  - The model never sees a variant's name.
- **Live** (`python -m src.run_checks`): the same checks against the real model and the real NVD and KEV, compared with `tests/expected_results.json`. That file was copied from `docs/expected_results.md`, which was set before any run.

Expected vs actual results, the demonstration checklist and limitations are in `docs/test_results.md`. The human evidence review is in `docs/evidence_review.md`. The frozen baseline for Assignment 4 is in `baseline/`.

### Limitations (agent and tests)

- **The model is not fully deterministic.** Ollama Cloud doesn't guarantee that the same seed gives the same output. Tool choices and the number of correction rounds vary between runs. The decision doesn't vary, because code computes it from validated tool data.
- **Coverage is measured against the snapshot.** "Every affected asset found" means every asset record the agent's searches returned. A product named differently in the snapshot could be missed, the same limitation as `search_assets`.
- **Coverage checks can use not_found searches.** A complete search with no matches counts toward coverage ("we looked"), not as proof that the product is absent.
- **Conflict detection is narrow.** Code detects conflicts with the same rule as the reference: an evidence fact `<asset_id>: ...` that states a different build. Other kinds of disagreement are caught only if the model reports them.
- **The invalid-tool failure is induced.** It is triggered by an instruction in the task message, because a real model rarely asks for a non-existent tool on its own. The 3-rejection stop is shown with a scripted model.
- **Confidence is coarse.** It follows the policy's three rules, so almost every applicable result is Medium: the builds and the access path come from group-simulated evidence (S07, S08).

### AI assistance (Roles C and D)

Claude (Anthropic) helped Supawich write the agent loop, prompts, validator, policy code, report output, tests, check runner, diagram and documentation. It also ran the live checks. Supawich reviewed the design decisions (model provider, scope, framework, workflow) and the outputs. The group reviewed the final assessment and its citations (`docs/evidence_review.md`).
