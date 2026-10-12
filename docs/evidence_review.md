# Evidence review of the final assessment (human step)

The assignment requires that **a group member verifies the assessment and its cited evidence**. This checklist is for the main run in `baseline/main_run/` (run `20261012T185021Z_check0`, the same run as check 0 in `docs/test_results.md`). Tool refs (R#) below refer to that run.

How to review: open `baseline/main_run/report.md` next to `baseline/main_run/tool_results.json`, then check each line against the **primary source** named in the "Check against" column, not against the agent's own text. Tick each box, or write what is wrong.

The "Pre-check" column was filled in by a scripted cross-check (Claude, while preparing the repo). It compares the saved assessment with the raw files. **It does not replace the human review below.**

## A. Main decision: W15 FINLEG01–FINLEG02

| # | Claim in the assessment | Check against | Pre-check | Reviewer ✔ / note |
|---|---|---|---|---|
| A1 | W15 runs Windows Server 2016, build 10.0.14393.9339 | `environment/northbridge-v1.1.json` assets[17] `os` and evidence S08 line "W15: ..." | Matches: assets[17] `os.build` 10.0.14393.9339, KB5099535; S08 line identical (cited R3, R12) | ☐ |
| A2 | First fixed build for Server 2016 is 10.0.14393.9512 | `inputs/CVE-2026-85880_nvd_raw.json` cpeMatch `windows_server_2016` `versionEndExcluding` (and the MSRC page, T3) | Matches: NVD raw cpeMatch `windows_server_2016` versionEndExcluding 10.0.14393.9512 (R1). MSRC page (T3) not saved yet: **to do** | ☐ |
| A3 | 9339 < 9512, so the build is vulnerable | Numeric comparison | Matches: 9339 < 9512 (same first three parts) | ☐ |
| A4 | A low-privilege local access path exists (payroll operators, `svc_finlegacy`) | assets[17] `low_priv_local_access`, `notes`; S03; assumption A15 in `environment/CHANGES.md` | Matches: `low_priv_local_access: true`; notes say payroll operators (non-admin) log on; A15 in CHANGES.md (R3, R8, R11). This is a group assumption, hence confidence Medium | ☐ |
| A5 | Restricted PII, protection undocumented, reachable from USERS → P1 | assets[17] `data_classification`, `data_protection`, `exposure`; A2, A6; flow F07 | Matches: restricted_pii / unprotected / intranet → `pii_unprotected x intranet` = P1 | ☐ |
| A6 | CVSS v3.1 7.8 (Microsoft CNA, Secondary) → High band | NVD raw `metrics.cvssMetricV31` | Matches: only `cvssMetricV31` entry is type Secondary, source secure@microsoft.com, 7.8 | ☐ |
| A7 | In CISA KEV, added 2026-09-08, due 2026-09-22 → KEV +1 (capped at High) | `inputs/CVE-2026-85880_kev_raw.json` | Matches: KEV raw dateAdded 2026-09-08, dueDate 2026-09-22 (R2, live) | ☐ |
| A8 | Rule `P1 x High = High; KEV +1 -> High` follows `docs/rating_policy.md` sections 3–6 | Policy document | Matches policy sections 3–6 | ☐ |
| A9 | Confidence Medium because the decisive facts rely on S07/S08 (section 7) | Policy section 7 | Matches: decisive sources T1, S08, T2, S07 | ☐ |
| A10 | Every citation has a source, a timestamp and the right mode (NVD/KEV `live`, snapshot `simulated`) | `report.md` evidence list | 7 citations: R3, R8, R9, R11, R12 simulated (snapshot locators); R1, R2 live with retrieved_at 2026-10-12T18:50Z | ☐ |
| A11 | The recommended action is sensible and doesn't contradict the rating | `report.md` (model-drafted text) | Steps 1 (patch to ≥ 9512) and 2 (restrict NTLM / `svc_finlegacy`) are sound, and it notes the KEV due date has passed. Step 3 misreads `patch_approval_recorded_days_before_snapshot: 60` as a requirement: **reviewer should edit or reject that step** | ☐ |

## B. Other non-Low assets

| # | Claim | Check against | Pre-check | Reviewer ✔ / note |
|---|---|---|---|---|
| B1 | W02 CA-ROOT01: build 10.0.20348.5256 < 5622, isolated, no low-privilege access → Partial → Medium | assets[2]; S08; NVD `windows_server_2022` | Matches: assets[2] build 10.0.20348.5256, exposure isolated, low_priv false; S08 "except offline root CA at 10.0.20348.5256" | ☐ |
| B2 | E02 stale-sensor devices: build null → INSUFFICIENT_EVIDENCE (not guessed) | assets of E02 (stale); S04; S08 "12 stale-sensor devices unknown" | Matches: stale-sensor record build null; S08 "12 stale-sensor devices unknown" | ☐ |
| B3 | All other Windows Server 2022 assets are at 5622 (= fixed) → Low | S08; NVD | Matches: all 19 other Server 2022 records at 10.0.20348.5622; E02 healthy at 10.0.19045.7725 (= fixed) | ☐ |
| B4 | Server 2012 and 2019 are not used | Snapshot `absences` list; searches in the trace | Searched in R4 (2012) and R6 (2019), both not_found; both on `absences` | ☐ |

## C. Process

| # | Check | Pre-check | Reviewer ✔ / note |
|---|---|---|---|
| C1 | The model chose the tools and queries itself (`messages.json` / `trace.jsonl`) | 15 tool calls chosen by the model (queries such as "Windows Server 2016", "Windows 10"); 1 invalid call (`limit: "invalid"`) rejected, then corrected | ☐ |
| C2 | The environment lookup and the external lookups (NVD, KEV) both ran and were used | Yes: R1 NVD, R2 KEV, R3–R15 environment | ☐ |
| C3 | The model did not see the snapshot's real name (blinding) | Yes: `messages.json` contains no `northbridge-v1.1.json` / snapshot ID | ☐ |
| C4 | The assessment output matches the group consensus in `docs/expected_results.md` section 1 | Output High = proposed consensus High; members still need to tick section 1 of expected_results.md | ☐ |

## Sign-off

| Reviewer | Date | Result (agree / disagree, with reason) |
|---|---|---|
| Puminun Prommark | | |
| Supawich Puengdang | | |

After signing, set `human_review` in `baseline/main_run/assessment.json` to `{"status": "reviewed", "reviewer": "...", "date": "..."}` and commit.
