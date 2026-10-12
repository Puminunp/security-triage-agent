# Video demo script (about 8–10 minutes)

The assignment asks the video to show: **the design, the complete workflow, tool calls, rating rationale, evidence, and limitations.** Suggested split: Puminun covers parts 1–2 (case, environment, policy, tools), Supawich covers parts 3–6 (agent, run, tests, limitations).

Before recording:
- `source .venv/bin/activate`
- check `.env` has `OLLAMA_API_KEY`
- run `python -m pytest -q` once so the terminal is warm
- open in tabs: `docs/workflow.png`, `docs/rating_policy.md`, the newest `outputs/<run>/report.md`, `docs/test_results.md`

## 1. The problem (Puminun, ~1.5 min)

- Introduce yourselves and your roles (A+B Puminun, C+D Supawich).
- **Risk question:** "Does CVE-2026-85880 matter for Northbridge, which machines, how bad for us, and what do we do?"
- **The CVE:** Windows ALPC privilege escalation (low-privileged local user → SYSTEM). CVSS 7.8, in CISA KEV since 2026-09-08, fixed in the September 2026 update.
- **Severity ≠ risk:** CVSS is the same for everyone; our rating is local risk.
- **Environment:** the course's Northbridge scenario, adapted to v1.1 with builds, data classes and an access path (show `environment/CHANGES.md` briefly). Everything local is simulated.

## 2. Policy and tools (Puminun, ~2 min)

- Show the policy overview in `docs/rating_policy.md` section 1:
  - applicability gate
  - machine priority (data × exposure, overrides)
  - CVSS band
  - matrix
  - KEV +1 / Partial −1
  - unknown or conflict → INSUFFICIENT_EVIDENCE
- Walk the W15 worked example (section 9).
- The three tools and what each contributes (`docs/tool_contracts.md`). Retry → cache → error. "No match doesn't prove absence."

## 3. Architecture (Supawich, ~1.5 min)

- Show `docs/workflow.png`. Colors: purple = LLM, blue = code, green = tools, orange = human, red = stop.
- **Key point:** the model chooses tools and builds queries, and extracts facts. Code validates every fact against the tool data, then applies the policy. **The model never picks the rating.**
- **Blinding:** the model never sees the test-variant file name.

## 4. Live run (Supawich, ~2.5 min)

```
python -m src.main --label demo
```

While it runs (~40 s), explain what is happening. Then open `outputs/<run>/trace.jsonl` or `messages.json` and point at:
- the model's **own** tool choices: `search_assets "Windows Server 2016"`, `"Windows 10"`, the `get_evidence S08` calls
- a **validation round**, if one happened: "the model left out 20 servers, code sent it back, it fixed it"

Then open `report.md`:
- **W15 High.** Rule `P1 x High = High; KEV +1 -> High`. Confidence Medium because the build and access path come from simulated evidence S07/S08.
- **Citations:** R# with live NVD/KEV and the simulated snapshot locators.
- **Assumptions** A6 and A15, the recommended action, and "what would change the decision".
- **CA-ROOT01 Medium** (Partial: powered off, no low-privilege access).
- **Stale-sensor laptops INSUFFICIENT_EVIDENCE**: build unknown, so a human must check. We don't guess.
- Everything else Low (patched).

## 5. Testing (Supawich, ~2 min)

- Show `docs/test_results.md`, the expected vs actual table.
  - **Applicability change** (patched W15) → Low
  - **Impact change** (no PII, internal only) → Medium
  - **Missing build** → INSUFFICIENT_EVIDENCE
  - **Conflict** (S08 says September, record says July) → INSUFFICIENT_EVIDENCE, naming both sources
- **Controlled failure, live:**

  ```
  python -m src.main --fault nvd-down-no-cache --label demo_fail
  ```

  It stops with INSUFFICIENT_EVIDENCE and names `lookup_vulnerability`. Mention `nvd-down` (cache used, still High, confidence Medium) and `bad-tool` (rejected, model recovers).
- `python -m pytest -q`: 112 offline tests, including policy parity with the reference on every asset.
- **Human review:** show the signed `docs/evidence_review.md`.

## 6. Limitations and next steps (either, ~1 min)

- The environment is simulated. Real use needs a live asset inventory and patch data.
- The model is not deterministic. Tool choices vary, but the rating is computed by code from validated data, so it doesn't.
- Conflict detection is narrow (build statements only).
- Confidence is coarse. CVSS v3.1 only; no EPSS. The MSRC page is not fetched.
- Ollama Cloud's free tier gives intermittent HTTP 500s; we retry with backoff and stop cleanly if it stays down.
- `baseline/` is saved for Assignment 4 (tracing and evaluation).
