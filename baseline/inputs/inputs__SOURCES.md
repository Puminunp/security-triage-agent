# Selected case and sources

## Risk question

> What is the risk that **CVE-2026-85880** (Windows ALPC heap-based buffer overflow, local elevation of privilege to SYSTEM) is exploited on Northbridge Services assets, given the environment snapshot `northbridge-v1.1` (as of 2026-10-01)?

- **Input type:** one CVE/NVD record plus its CISA KEV entry
- **Primary asset assessed:** W15 Legacy finance application servers (Windows Server 2016, payroll and banking data)
- **Secondary scan:** every other Windows asset, to show where the CVE does and does not apply
- **Required output:** High, Medium or Low, or INSUFFICIENT_EVIDENCE, with rationale, evidence, unknowns and a recommended action (see `docs/rating_policy.md`)

## Why this case

- It is in **CISA KEV** (added 2026-09-08), so it has confirmed exploitation in the wild.
- It affects **Windows Server 2016**, the OS on W15, and was fixed in the **September 2026** cumulative update. W15's last installed update is July 2026, while the other servers have September's update. Applicability therefore differs between assets, which tests the agent's version comparison.
- W15 holds payroll and banking PII for 1,000 employees, so impact is clear and easy to justify.
- The scenario already hints at W15 as a development question (NTLM exception, patch lag).

## Sources

| ID | Source | URL | Retrieved | Saved as |
|---|---|---|---|---|
| T1 | NVD CVE record (API 2.0) | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-85880 | 2026-10-11 | `CVE-2026-85880_nvd_summary.json` |
| T2 | CISA KEV catalog entry | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | 2026-10-11 | `CVE-2026-85880_kev_entry.json` |
| T3 | Microsoft Security Update Guide | https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-85880 | to be saved (page needs JavaScript; save as PDF from a browser) | `CVE-2026-85880_msrc.pdf` |
| T4 | Patch Tuesday summary (secondary, for context only) | https://aicybr.com/blog/microsoft-september-2026-patch-tuesday-zero-days | 2026-10-11 | not needed |
| E1 | Northbridge Windows Enterprise Environment v1.0 (course-supplied) | Canvas | 2026-10-10 | original kept unchanged |

## Action needed before submission

The two JSON files in this folder were **transcribed** from the NVD record using a web-reading tool, because direct downloads were blocked in the environment where they were prepared. Before freezing the baseline:

1. Person B runs the NVD client and saves the **raw** API response as `CVE-2026-85880_nvd_raw.json`.
2. Person B saves the matching **raw** KEV feed entry as `CVE-2026-85880_kev_raw.json`.
3. Someone opens the MSRC page in a browser and saves it as a PDF.
4. Compare the raw files with the transcribed ones. If anything differs, the raw files win, and the difference is noted here.

## Key facts used by the policy

| Fact | Value | Source |
|---|---|---|
| CVSS v3.1 | 7.8 High, `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (Microsoft CNA score) | T1 |
| In KEV | Yes, added 2026-09-08, due 2026-09-22 | T1, T2 |
| Windows Server 2016 fixed build | 10.0.14393.**9512** (anything lower is vulnerable) | T1 |
| Windows Server 2022 fixed build | 10.0.20348.**5622** | T1 |
| Windows 10 22H2 fixed build | 10.0.19045.**7725** | T1 |
| Windows 11 | Not listed as affected | T1 |
| Attack prerequisite | Attacker already has low-privileged local code execution on the target | T1 (vector `AV:L/PR:L`) |

## Raw vs transcribed comparison

Added by Student B on 2026-10-11 (retrieved 2026-10-12T00:52Z). The raw files were saved by the tool clients in `src/sources/` and compared field by field with the transcribed files.

| Raw file | Source | Source timestamp |
|---|---|---|
| `CVE-2026-85880_nvd_raw.json` | T1, full NVD API 2.0 response | `timestamp` 2026-10-12T00:52:05, record `lastModified` 2026-09-24T23:19:20 |
| `CVE-2026-85880_kev_raw.json` | T2, the CVE's entry from the KEV JSON feed, unmodified | catalog version 2026.10.08, released 2026-10-08, 1,739 entries |

Copies are also in `cache/` (`nvd_CVE-2026-85880.json` and the whole feed as `kev_feed.json`) for the lookup-failure fallback.

**Result: no difference in any fact the policy uses.** CVSS score, vector and source, KEV dates, CWEs and every fixed build match. The raw files win where wording differs; none of the differences below changes `docs/rating_policy.md`, `docs/threat_prerequisites.md` or the expected results.

### Fields that match

NVD: CVE ID, source identifier, published, last modified, status (Analyzed), CVSS v3.1 source (`secure@microsoft.com`), type (Secondary), vector, base score 7.8, severity HIGH, exploitability 1.8, impact 5.9, CWE-122 and CWE-908, `cisaExploitAdd` 2026-09-08, `cisaActionDue` 2026-09-22, `cisaVulnerabilityName`, the MSRC reference and its tags, and `versionEndExcluding` for Windows 10 1607, 1809, 21H2, 22H2 and Windows Server 2016, 2019 and 2022. Windows 11 and Windows Server 2025 do not appear in the raw record, as transcribed.

KEV: `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded` 2026-09-08, `dueDate` 2026-09-22.

### Differences

| # | Field | Transcribed | Raw | Effect on the policy |
|---|---|---|---|---|
| 1 | NVD description | "...in Windows Advanced Local Procedure Call (ALPC) allows..." | "...in Windows ALPC allows..." | None. Wording only; the transcription expanded the abbreviation |
| 2 | NVD reference URL (CISA) | `...catalog?search_api_fulltext=CVE-2026-85880` | `...catalog?field_cve=CVE-2026-85880` | None. Same page, different query string |
| 3 | NVD SSVC source | `CISA-ADP` | `134c704f-9b21-4f2e-91b3-4a467353bcc0` (UUID; role "CISA Coordinator") | None. Label for the same source; exploitation, automatable and technical impact values match. SSVC is not used by the policy |
| 4 | NVD Windows Server 2012 / 2012 R2 fixed build | `fixed_build` 6.2.9200.26349 / 6.3.9600.23398 | Same numbers, but only in the vendor `affected` block (`lessThan`). The NVD CPE entries for 2012 and 2012 R2 have no `versionEndExcluding` | None for Northbridge (Windows Server 2012 is on the absences list). The NVD tool reports these two CPE rows with `versionEndExcluding: null` in `unknown_fields` and gives the vendor numbers separately under `cna_affected` |
| 5 | NVD `cisaRequiredAction` | not transcribed | present, full text | None. Now available from the tool |
| 6 | KEV `knownRansomwareCampaignUse` | `null` | `"Unknown"` | None. Not a policy input. The raw value is CISA's own "Unknown" |
| 7 | KEV `requiredAction` | paraphrased as `requiredAction_paraphrase` | full CISA text | None. Raw text should be quoted in outputs |
| 8 | KEV extra fields | absent | `shortDescription`, `notes`, `cwes` (CWE-122, CWE-908), `forensicTriage` ("No") | None. Extra context only |
| 9 | Bookkeeping fields | `_note`, `source`, `retrieved_at`, `status: transcribed` | absent (the raw files are unmodified source data) | None |

The transcribed files (`*_nvd_summary.json`, `*_kev_entry.json`) are kept for this record. Use the raw files, or the tools, as the source from now on.
