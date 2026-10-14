# README sections from Student A

Paste these into the main README.

## Selected case

We assess **CVE-2026-85880**, a heap-based buffer overflow in Windows ALPC that lets a low-privileged local attacker become SYSTEM (CVSS v3.1 7.8, High). CISA added it to KEV on 2026-09-08. Microsoft fixed it in the September 2026 cumulative update.

**Risk question:** What is the risk that CVE-2026-85880 is exploited on Northbridge Services assets, given the environment snapshot as of 2026-10-01?

The main asset is **W15**, the legacy finance servers (Windows Server 2016, July 2026 patch level), which hold payroll and banking data for 1,000 employees. Sources are listed in `inputs/SOURCES.md`.

## Environment

We adapted the course-supplied Northbridge Services scenario (v1.0) into `environment/northbridge-v1.1.json`. The original is unchanged. We added data classification, data protection, exposure, priority overrides, a low-privilege access field, and OS builds and software versions using real vendor release numbers. All records are labeled `source_mode: simulated`. Every change and assumption (A1–A15) is listed in `environment/CHANGES.md`, and cited through evidence records S07 and S08.

## Rating policy (summary)

The rating is computed by code in five steps. The model never chooses it.

1. **Applicability gate:** not applicable → Low; unknown or conflicting decisive fact → INSUFFICIENT_EVIDENCE.
2. **Machine priority (impact):** data sensitivity × exposure → P1–P3 (matrix 1), with P1 overrides.
3. **Severity:** CVSS v3.1 band (Critical 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9).
4. **Final matrix:** machine priority × vulnerability severity → High / Medium / Low (matrix 2).
5. **Modifiers:** KEV +1, then Partial −1. The result never goes above High or below Low.

**Step 1 in detail: the applicability gate**

Applicability asks whether the vulnerability can actually work on this machine. For CVE-2026-85880 there are three decisive facts: the machine runs an affected product, its build is below the fixed build, and an ordinary (non-admin) user can get onto it. The code checks them in this order, and the first answer that settles it is the result:

| Step | Question | Values used | If the answer settles it |
|---|---|---|---|
| 1 | Is the product on NVD's affected list? | OS name/version; NVD affected products | No → **Not applicable** (Low) |
| 2 | Do the sources agree on the build, and is it known? | `os.build`; evidence record S08 | Disagree → **Conflict**; blank → **Unknown** (both INSUFFICIENT_EVIDENCE) |
| 3 | Is the build below the first fixed build? | `os.build`; NVD `versionEndExcluding` | At or above → **Not applicable** (Low) |
| 4 | Can an ordinary user get onto the machine? | `low_priv_local_access`; `exposure` | Unknown → **Unknown**; isolated or admins only → **Partial**; yes → **Confirmed** |

Builds are compared number by number (10.0.14393.9339 < 10.0.14393.9512). A fact that is unknown is never guessed: it stops the gate and sends the asset to an analyst. **Confirmed** and **Partial** continue to steps 2–5; Partial takes −1 at the end.

| Asset | Step 1 | Step 2 | Step 3 | Step 4 | Applicability |
|---|---|---|---|---|---|
| W15 legacy finance servers | Server 2016, affected | 9339 in record and S08 | 9339 < 9512 | Payroll operators (non-admin) log on | **Confirmed** |
| W02 offline root CA | Server 2022, affected | 5256 in record and S08 | 5256 < 5622 | Isolated, admins only | **Partial** |
| Other Server 2022 servers | Server 2022, affected | 5622 in record and S08 | 5622 = fixed | not reached | **Not applicable** |
| E02 stale-sensor workstations | Windows 10 22H2, affected | Build blank | not reached | not reached | **Unknown** |
| Windows 11 laptops | Not on the list | not reached | not reached | not reached | **Not applicable** |

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
