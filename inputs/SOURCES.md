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
