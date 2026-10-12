# Expected results and group consensus

Expected results were set **from the written policy before any agent run**, and checked with `reference/policy_reference.py`. Student D fills in the "Actual" columns after running the agent. If a result doesn't match, record whether the bug is in the code, the policy or the expectation. Don't change an expected value after the run.

## 1. Group consensus rating (main case)

> **Fill this in at a group meeting before running the agent.** The proposed answer below comes from the policy; the group must agree or record its disagreement.

| Item | Value |
|---|---|
| Case | CVE-2026-85880 on W15 (FINLEG01–02), snapshot `northbridge-v1.1` |
| Proposed rating | **High** |
| Reasoning | Vulnerable build (9339 < 9512), non-admin logon path exists, payroll/banking PII for 1,000 employees, reachable from the USERS zone, actively exploited (KEV), KEV due date already passed |
| Group consensus | ☐ Agree: High ☐ Disagree: ______ |
| If disagreeing, why | |
| Members present and date | |

## 2. Policy checks

| # | Test | Input file | What changes | Expected applicability | Expected priority | Expected decision | Expected rule | Actual | Pass? | Notes |
|---|---|---|---|---|---|---|---|---|---|---|
| 0 | Main run | `northbridge-v1.1.json` | — | Confirmed | P1 | **High** | P1 × High = High; KEV +1 → High (capped) | | | |
| 1 | Applicability change | `variants/env_patched.json` | W15 at fixed build 9512 | Not applicable | P1 | **Low** | Gate: not applicable → Low | | | Impact unchanged (P1) |
| 2 | Impact change | `variants/env_low_priority.json` | W15 no PII, internal only | Confirmed | P3 | **Medium** | P3 × High = Low; KEV +1 → Medium | | | Applicability unchanged |
| 3a | Missing evidence | `variants/env_missing.json` | W15 build null | Unknown | P1 | **INSUFFICIENT_EVIDENCE** | Decisive fact unknown → review | | | Must not guess a build |
| 3b | Conflicting evidence | `variants/env_conflict.json` | S08 says Sept, asset says July | Conflict | P1 | **INSUFFICIENT_EVIDENCE** | Sources disagree → review | | | Output must name both sources |

## 3. Controlled failure (Student D designs the exact trigger)

| # | Failure | Expected behavior | Actual | Pass? |
|---|---|---|---|---|
| 4a | NVD API unreachable, cache present | One retry, then cached NVD record used, labeled `status: cached`; rating still **High**; confidence at most Medium | | |
| 4b | NVD API unreachable, no cache | Stop with **INSUFFICIENT_EVIDENCE**, naming the failed lookup (fixed build unknown) | | |
| 4c | Model requests a tool that doesn't exist | Call rejected with an error; model continues with valid tools; after 3 rejections the run stops without a rating | | |

## 4. Secondary scan of the base snapshot (optional demonstration)

If the agent assesses every asset, these are the expected results. Everything not listed is **Low (not applicable)**.

| Asset | Applicability | Priority | Expected decision | Rule |
|---|---|---|---|---|
| W15 FINLEG01–02 | Confirmed | P1 | **High** | P1 × High = High; KEV +1 (capped) |
| W02 CA-ROOT01 | Partial | P1 | **Medium** | P1 × High = High; KEV +1 (capped); Partial −1 → Medium |
| E02, 12 stale-sensor devices | Unknown | P3 | **INSUFFICIENT_EVIDENCE** | Build unknown |
