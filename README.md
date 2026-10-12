# Security Triage Agent: Agentic CTI Risk Triage for Northbridge Services

An agentic cyber threat intelligence (CTI) risk-triage system that rates a CVE against a fictional Windows enterprise, Northbridge Services. The agent collects vulnerability evidence (NVD, CISA KEV, vendor advisories), checks it against an environment snapshot of the organization's assets, and applies a documented applicability-and-impact rating policy to produce a High / Medium / Low rating per asset, or INSUFFICIENT_EVIDENCE when a decisive fact is missing or conflicting. Results are compared against expected results set before any run and against a baseline.

## Group members

| Name | Role A/B/C/D | Contributions |
|---|---|---|
| _TBD_ | A | Case selection and sources; environment v1.1, change log and test variants; rating policy; threat prerequisites; expected results; reference policy implementation |
| _TBD_ | B | Agent tools and registry; NVD and KEV clients; cache and failure fallback; raw source data and comparison; tool tests; tool contracts |
| _TBD_ | C | _TBD_ |
| _TBD_ | D | _TBD_ |

## Repository layout

`outputs/` and `baseline/` are planned and are added as the work lands.

```
inputs/        Selected CVE, source list, transcribed and raw NVD / KEV data
environment/   Northbridge environment snapshot (v1.1), change log, test variants and generator
docs/          Rating policy, threat prerequisites, expected results, handoff notes, tool contracts
reference/     Runnable reference implementation of the rating policy
config/        settings.yaml: snapshot path, source URLs, timeouts (no secrets)
src/sources/   NVD and CISA KEV clients, file cache
src/tools/     Environment lookups and the tool registry the agent calls
tests/         Tests (pytest)
cache/         Cached NVD and KEV responses, used when a live lookup fails
outputs/       Agent run outputs (planned)
baseline/      Baseline results for comparison (planned)
```

## Setup

Python 3.10 or later.

```
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and fill in the values; `.env` is ignored by git and must never be committed. `NVD_API_KEY` is optional: the NVD lookup works without it at a lower rate limit.

## Running the tests

```
python -m pytest
```

The tests use no LLM and no network; NVD and KEV responses are replayed from the raw files in `inputs/`. To also call the real services, set the environment variable `RUN_LIVE=1`.

To check Student A's policy reference against the snapshot and variants:

```
python reference/policy_reference.py environment/northbridge-v1.1.json
python reference/policy_reference.py environment/variants/env_patched.json W15
```

## Student A sections

### Selected case

We assess **CVE-2026-85880**, a heap-based buffer overflow in Windows ALPC that lets a low-privileged local attacker become SYSTEM (CVSS v3.1 7.8, High). CISA added it to KEV on 2026-09-08. Microsoft fixed it in the September 2026 cumulative update.

**Risk question:** What is the risk that CVE-2026-85880 is exploited on Northbridge Services assets, given the environment snapshot as of 2026-10-01?

The main asset is **W15**, the legacy finance servers (Windows Server 2016, July 2026 patch level), which hold payroll and banking data for 1,000 employees. Sources are listed in `inputs/SOURCES.md`.

### Environment

We adapted the course-supplied Northbridge Services scenario (v1.0) into `environment/northbridge-v1.1.json`. The original is unchanged. We added data classification, data protection, exposure, priority overrides, a low-privilege access field, and OS builds and software versions using real vendor release numbers. All records are labeled `source_mode: simulated`. Every change and assumption (A1–A15) is listed in `environment/CHANGES.md`, and cited through evidence records S07 and S08.

### Rating policy (summary)

1. **Applicability gate:** not applicable → Low; unknown or conflicting decisive fact → INSUFFICIENT_EVIDENCE.
2. **Machine priority (impact):** PII without protection / with protection / none × internet / intranet / internal only → P1–P3, with P1 overrides for Tier-0 identity, control planes and 4-hour-RTO services.
3. **Severity:** CVSS v3.1 band.
4. **Final matrix:** priority × severity → High / Medium / Low.
5. **Modifiers:** KEV +1, then Partial −1.

CVSS describes technical severity; the rating describes local risk. The full policy with justifications is in `docs/rating_policy.md`.

### Limitations (environment and policy)

- The priority matrix measures confidentiality (PII) and exposure, not availability. Overrides cover the most important availability cases (identity, ERP).
- Logs are not treated as PII (assumption A8).
- Versions and assumptions are simulated additions to a fictional scenario; real environments would need verified asset data.
- The low-privilege access path on W15 (A15) is an assumption, which lowers confidence in the main result to Medium.
- Severity uses CVSS v3.1 only. CVSS v4.0 and EPSS were not used.
- The NVD and KEV inputs were first transcribed through a web-reading tool; the raw files must be saved before the baseline is frozen.

### Contributions: Student A

Case selection and source collection; environment adaptation (v1.1), assumptions and change log; test variants and generator script; rating policy design and justification; threat prerequisites; expected results; reference policy implementation for checking expected results.

### AI assistance

Claude (Anthropic) helped Student A select the CVE, look up current vendor version numbers, draft the policy and change log, and write the snapshot, variant generator and reference policy scripts. Student A reviewed and edited all output; the group verified the policy at the consensus meeting.

## Student B sections

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

The raw NVD response and KEV entry for CVE-2026-85880 are saved as `inputs/CVE-2026-85880_nvd_raw.json` and `inputs/CVE-2026-85880_kev_raw.json` (retrieved 2026-10-12 UTC; KEV catalog version 2026.10.08). Compared field by field with Student A's transcribed files, they show no difference in any fact the policy uses: CVSS 7.8, KEV dates and every fixed build match. The differences in wording and extra fields are listed in `inputs/SOURCES.md`.

### Limitations (tools)

- NVD's CPE data has no fixed build for Windows Server 2012 and 2012 R2. The tool reports it as unknown and gives the vendor's numbers separately (`cna_affected`). Northbridge has no Server 2012.
- The CVSS score is the Microsoft CNA score, because NVD has not published its own for this CVE. The tool records which score it used.
- The MSRC advisory (source T3) is not fetched by a tool; the page needs a browser.
- `search_assets` is plain text matching, so it can miss a product that is named differently in the snapshot.
- Every null is listed in `unknown_fields`, including `priority_override` and `business_service`, which are null by design on most assets.
- Tool results include the snapshot file name and ID. For the test variants these name the test, which the model can see.
- The cached KEV feed is a snapshot in time; a `cached` answer can be out of date.

### Contributions: Student B

NVD and KEV clients; file cache and retry-then-cache fallback; environment lookup functions; tool schemas and the validating registry; settings file; raw source data and the raw-versus-transcribed comparison; tool tests; tool contract documentation.

### AI assistance

Claude (Anthropic) helped Student B write the source clients, environment tools, registry, tests and tool contract documentation, fetch the raw NVD and KEV data, and compare it with the transcribed files. Student B reviewed the output; the tests were run before each commit.
