# Student A deliverables

Copy these folders into the group repository as they are.

| Path | What it is |
|---|---|
| `inputs/SOURCES.md` | Risk question, why this CVE, source list, key facts |
| `inputs/CVE-2026-85880_nvd_summary.json` | NVD facts (transcribed; B replaces with the raw API response) |
| `inputs/CVE-2026-85880_kev_entry.json` | KEV facts (transcribed; B replaces with the raw feed entry) |
| `environment/northbridge-v1.1.json` | Adapted environment snapshot (base, never edited) |
| `environment/CHANGES.md` | Every change, assumption (A1–A15) and version added |
| `environment/make_variants.py` | Generates the four test variants from the base |
| `environment/variants/*.json` | Applicability, impact, missing and conflict variants |
| `docs/rating_policy.md` | Full applicability-and-impact policy with justifications |
| `docs/threat_prerequisites.md` | Decisive facts and fixed builds for CVE-2026-85880 |
| `docs/expected_results.md` | Consensus record and expected results, set before any run |
| `docs/handoff_to_B_C_D.md` | What B, C and D need from A |
| `docs/readme_sections_A.md` | Text to paste into the main README |
| `reference/policy_reference.py` | Runnable reference implementation of the policy |

## Check it works

```
python environment/make_variants.py
python reference/policy_reference.py environment/northbridge-v1.1.json
python reference/policy_reference.py environment/variants/env_patched.json W15
```

Python 3.9 or later, standard library only.

## Still to do by hand

1. Hold the consensus meeting and fill in section 1 of `docs/expected_results.md`.
2. Compare v1.1 with the course's official `windows_enterprise_environment.json` and note differences in `CHANGES.md`.
3. Save the MSRC page as a PDF, and have B save the raw NVD and KEV responses.
4. Verify the versions marked "verify" in the snapshot.
