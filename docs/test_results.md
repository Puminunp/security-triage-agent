# Test results: expected vs actual

**Expected results** were set from the written policy **before any agent run** (`docs/expected_results.md`, Student A). They were copied unchanged into `tests/expected_results.json`, which `src/run_checks.py` compares against.

**Actual results** below come from the final live run of `python -m src.run_checks`:

| Item | Value |
|---|---|
| Run folder | `outputs/checks_20261012T185021Z` (2026-10-12, every check passed on its first attempt) |
| Code commit | `8600907` (`860090785513dace0642dd033c87df5b0fd7b998`, no uncommitted changes in `src/`, `config/` or `environment/`) |
| Model | `gpt-oss:120b` (Ollama Cloud), temperature 0, seed 42, think medium |
| Sources | live NVD and CISA KEV unless a fault says otherwise; environment simulated |

The machine-generated table is in `outputs/checks_20261012T185021Z/summary.md`. Each check's run folder holds `assessment.json`, `report.md`, `trace.jsonl`, `tool_results.json`, `messages.json` and `config.json`.

## 1. Policy checks (focus asset W15)

| # | Check | Input | What changes | Expected (applicability / priority / decision) | Actual | Rule that fired | Pass |
|---|---|---|---|---|---|---|---|
| 0 | Main run | `northbridge-v1.1.json` | — | Confirmed / P1 / **High** | Confirmed / P1 / **High** | `P1 x High = High; KEV +1 -> High` | ✅ |
| 1 | **Applicability change** | `variants/env_patched.json` | W15 at fixed build 9512 | Not applicable / P1 / **Low** | Not applicable / P1 / **Low** | `gate: not applicable -> Low` (build 10.0.14393.9512 >= fixed 10.0.14393.9512) | ✅ |
| 2 | **Impact change** | `variants/env_low_priority.json` | W15 no PII, internal only | Confirmed / P3 / **Medium** | Confirmed / P3 / **Medium** | `P3 x High = Low; KEV +1 -> Medium` | ✅ |
| 3a | **Missing evidence** | `variants/env_missing.json` | W15 build null | Unknown / P1 / **INSUFFICIENT_EVIDENCE** | Unknown / P1 / **INSUFFICIENT_EVIDENCE** | Gate: "OS build unknown (decisive)"; no build guessed | ✅ |
| 3b | **Conflicting evidence** | `variants/env_conflict.json` | S08 says September 9512, record says July 9339 | Conflict / P1 / **INSUFFICIENT_EVIDENCE**, both sources named | Conflict / P1 / **INSUFFICIENT_EVIDENCE** | "S08 says 'W15: ... build 10.0.14393.9512 (September 2026 update) per patch report dated 2026-09-30' but the asset record (env_conflict.json#assets[17]) says build 10.0.14393.9339" | ✅ |

Run folders: `outputs/checks_20261012T185021Z/<timestamp>_check0` … `_check3b`. Each check changed exactly one thing, and only the expected part of the decision moved.

The three required policy checks:
- **applicability change** (check 1): only the build changes, so only applicability moves (P1 stays P1)
- **impact change** (check 2): only data and exposure change, so only priority moves (Confirmed stays Confirmed)
- **missing / conflicting evidence** (checks 3a and 3b)

## 2. Controlled failures

| # | Failure (trigger) | Expected behavior | Actual | Pass |
|---|---|---|---|---|
| 4a | NVD unreachable, cache present (`--fault nvd-down`: NVD URL → closed port 127.0.0.1:9) | One retry, then cached NVD record labeled `cached`; rating still **High**; confidence ≤ Medium | `lookup_vulnerability` status `cached` after 2 attempts (connection refused); KEV live; W15 **High**, confidence **Medium** ("cached fallback used for lookup_vulnerability") | ✅ |
| 4b | NVD unreachable, no cache (`--fault nvd-down-no-cache`: closed port + empty cache dir) | Stop with **INSUFFICIENT_EVIDENCE**, naming the failed lookup | `stopped_decisive_lookup_failed` after 1 tool call (2.6 s); overall **INSUFFICIENT_EVIDENCE**; stop reason: "lookup_vulnerability failed (… Connection refused … no cached copy); affected products and fixed builds are unknown". No per-asset rating, nothing filled from memory | ✅ |
| 4c | Model requests a tool that doesn't exist (`--fault bad-tool`: the model's first call `lookup_vulnerability` is replaced by `scan_network {"target": "W15"}`) | Call rejected with an error; model continues with valid tools; run completes | Rejected: "unknown tool: 'scan_network'. Available tools: …". The model called `lookup_vulnerability` next and finished normally: 20 tool calls, W15 **High** | ✅ |

**Invalid tool requests the model made on its own** in the same final run, all rejected by the registry, after which the model recovered:
- check 0: `search_assets` with `limit: "invalid"`
- check 1: an unknown tool `lookup_evidence?`
- check 3a: `get_evidence` with `target` instead of `query`

No run came near the 3-rejection stop. That stop is shown offline in `tests/test_agent.py::test_4c_three_rejected_calls_stop_without_rating`.

**Validation gate in practice.** In 7 of 7 completed live runs, the model's first `submit_findings` failed validation and was corrected. Typical gaps: missing Windows Server 2022 records, Windows 10 not searched, cited evidence not fetched, a finding without a locator. Six runs passed on the second submission and one (check 2) on the third. No run reached a decision with unverified facts.

Also covered offline by `python -m pytest`, with a scripted model, no network:
- 3 rejected tool calls → `stopped_rejected_calls`, no rating
- KEV down → cached feed used
- model outage → `stopped_model_error`, no rating
- text-only replies → stop
- a made-up build → sent back and corrected
- a fact that never validates → that asset INSUFFICIENT_EVIDENCE
- a fixed build "from memory" with no environment lookup → rejected, and the overall result can't be "Low"

## 3. Secondary scan: every asset, base snapshot

Expected (from `docs/expected_results.md` section 4): W15 High, W02 CA-ROOT01 Medium, E02 stale-sensor devices INSUFFICIENT_EVIDENCE, everything else Low.

Actual (check 0, 23 asset records assessed):
- W15 FINLEG01–02 **High**
- W02 CA-ROOT01 **Medium** (Partial: build 10.0.20348.5256 < 5622, but isolated with no low-privilege access; `P1 x High = High; KEV +1 -> High; Partial -1 -> Medium`)
- E02 stale sensors **INSUFFICIENT_EVIDENCE** (OS build unknown)
- 20 others **Low** (Windows Server 2022 at 5622 = fixed; E02 healthy at 19045.7725 = fixed)

Windows Server 2012 and 2019 were searched (no match) and are on the snapshot's documented absences list. ✅

## 4. Complete-run demonstration checklist (main run, check 0)

| Requirement (assignment Step 2.2) | Evidence | Status |
|---|---|---|
| Intake loads the selected threat and the correct environment snapshot | `assessment.json` → `intake` (CVE, snapshot path, `snapshot_id`, SHA-256); trace event 1 `intake` | ✅ CVE-2026-85880, `environment/northbridge-v1.1.json`, snapshot_id `northbridge-v1.1`, SHA-256 recorded |
| The model requests an allowed tool with valid arguments; code executes it and returns attributed evidence to the model | `messages.json` (model tool calls and tool replies carrying `ref`, `source`, `source_mode`); `trace.jsonl` `tool_call` events | ✅ 15 model-chosen tool calls (e.g. `search_assets "Windows Server 2016"`, `get_evidence S08`); 1 invalid call rejected and recovered |
| Environment lookup and at least one external lookup execute and contribute to the assessment | W15 evidence lists `lookup_environment` (simulated), `lookup_vulnerability` (T1, live) and `lookup_kev` (T2, live) | ✅ R1 NVD (live), R2 KEV (live), R3/R8/R9/R11/R12 snapshot (simulated), all cited on W15 |
| The agent compares threat prerequisites with environment facts, keeps unknowns, applies the policy, and produces a supported rating or explicit insufficient-evidence status with an action | W15: `rationale.applicability.facts` (build vs fixed build, access path), `unknowns`, `policy_rule`, `action`; E02 stale sensors → INSUFFICIENT_EVIDENCE | ✅ W15 High with rule, unknowns and action; E02 stale INSUFFICIENT_EVIDENCE |
| A group member verifies the assessment and its cited evidence | `docs/evidence_review.md` | **Pending human sign-off** |
| Inputs, configuration, tool results and output preserved; live lookups used and fallbacks labeled | `baseline/` (inputs, snapshot, config, code version, all outputs); `source_mode` on every citation; check 4a shows `cached` | ✅ `baseline/` frozen from this run; 4a shows a labeled `cached` fallback |

## 5. Comparison with the group consensus

`docs/expected_results.md` section 1 proposes **High** for W15. The live output is **High**, by rule `P1 x High = High; KEV +1 -> High`, which matches the policy. Both members ticked "Agree: High" there on 2026-10-14. The expected rating itself was written on 2026-10-11, before the agent existed.

## 6. Observations from development runs

These runs were made before the final code and are not part of the results above. They are recorded because they shaped the design (`docs/architecture.md` section 10).

| Observation | What we changed |
|---|---|
| The first live run called `get_evidence` as if it were a tool, three times, and hit the 3-rejection stop. The stop rule worked as designed | Prompt now says which names are tools and which are `lookup_environment` actions |
| In every live run so far, the model's first `submit_findings` was incomplete: it left out the 20 Windows Server 2022 records, or forgot to search Windows 10. The validator returned the gaps and the second submission passed | None needed: this is what the validator is for |
| Ollama Cloud returned intermittent HTTP 500s late in long conversations. The same request succeeded on replay | 5 retries with backoff; compact tool results for the model. The run stops cleanly (`stopped_model_error`) if the service stays down |
| The model ignored an instruction in the task message to call a non-existent tool | Fault 4c now replaces the model's first tool call instead |
| In one run the model sent `cve_id: "CVE-202c?"` (garbled). Registry validation rejected it and the model retried correctly | None: a natural example of the invalid-request path |
| The model's drafted action came back as a list and once included a made-up requirement | Action text is normalized to one string; the prompt forbids invented requirements (prompt v1.1). The rating is unaffected because code computes it |

## 7. Limitations

- **Simulated environment.** Builds, data classes, access paths and assumptions A1–A15 are group additions to a fictional scenario. That is why confidence is Medium on every applicable result.
- **Non-deterministic model.** Tool order, number of calls and number of validation rounds differ between runs. The decisions did not differ, because they are computed by code from validated tool data. We tested one model only.
- **Coverage is measured against the snapshot.** A product named differently in the inventory could be missed (plain-text `search_assets`).
- **Conflict detection in code is narrow.** It catches a differing build statement in an evidence record. Other disagreements depend on the model reporting them.
- **The live invalid-tool failure is injected,** not produced by the model on its own. The 3-rejection stop is shown offline.
- **Sources.** CVSS v3.1 only (Microsoft CNA score; NVD has no primary score). No EPSS. The MSRC advisory (T3) is not fetched by the agent; it was saved by hand and its fixed builds match NVD. A cached KEV feed may be out of date.
- **Free-tier model service.** Ollama Cloud availability affects run time; a long outage stops the run without a rating.
- **No action is executed.** The agent only recommends; patching and access changes are left to people.
