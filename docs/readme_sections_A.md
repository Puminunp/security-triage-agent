# README sections from Student A

Paste these into the main README.

## Selected case

We assess **CVE-2026-85880**, a heap-based buffer overflow in Windows ALPC that lets a low-privileged local attacker become SYSTEM (CVSS v3.1 7.8, High). CISA added it to KEV on 2026-09-08. Microsoft fixed it in the September 2026 cumulative update.

**Risk question:** What is the risk that CVE-2026-85880 is exploited on Northbridge Services assets, given the environment snapshot as of 2026-10-01?

The main asset is **W15**, the legacy finance servers (Windows Server 2016, July 2026 patch level), which hold payroll and banking data for 1,000 employees. Sources are listed in `inputs/SOURCES.md`.

## Environment

We adapted the course-supplied Northbridge Services scenario (v1.0) into `environment/northbridge-v1.1.json`. The original is unchanged. We added data classification, data protection, exposure, priority overrides, a low-privilege access field, and OS builds and software versions using real vendor release numbers. All records are labeled `source_mode: simulated`. Every change and assumption (A1–A15) is listed in `environment/CHANGES.md`, and cited through evidence records S07 and S08.

## Rating policy (summary)

1. **Applicability gate:** not applicable → Low; unknown or conflicting decisive fact → INSUFFICIENT_EVIDENCE.
2. **Machine priority (impact):** PII without protection / with protection / none × internet / intranet / internal only → P1–P3, with P1 overrides for Tier-0 identity, control planes and 4-hour-RTO services.
3. **Severity:** CVSS v3.1 band.
4. **Final matrix:** priority × severity → High / Medium / Low.
5. **Modifiers:** KEV +1, then Partial −1.

CVSS describes technical severity; the rating describes local risk. The full policy with justifications is in `docs/rating_policy.md`.

## Limitations (environment and policy)

- The priority matrix measures confidentiality (PII) and exposure, not availability. Overrides cover the most important availability cases (identity, ERP).
- Logs are not treated as PII (assumption A8).
- Versions and assumptions are simulated additions to a fictional scenario; real environments would need verified asset data.
- The low-privilege access path on W15 (A15) is an assumption, which lowers confidence in the main result to Medium.
- Severity uses CVSS v3.1 only. CVSS v4.0 and EPSS were not used.
- The NVD and KEV inputs were first transcribed through a web-reading tool. The raw files have since been saved and compared (`inputs/SOURCES.md`); no fact used by the policy differed.

## Contributions: Student A

Case selection and source collection; environment adaptation (v1.1), assumptions and change log; test variants and generator script; rating policy design and justification; threat prerequisites; expected results; reference policy implementation for checking expected results.

## AI assistance

Claude (Anthropic) helped Student A select the CVE, look up current vendor version numbers, draft the policy and change log, and write the snapshot, variant generator and reference policy scripts. Student A reviewed and edited all output; the group verified the policy at the consensus meeting.
