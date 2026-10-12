# Rating policy: applicability and impact

**Owner:** Student A · **Version:** 1.0 · **Applies to:** snapshot `northbridge-v1.1` and its variants

This policy turns facts about one threat and one asset into **High**, **Medium**, **Low** or **INSUFFICIENT_EVIDENCE**. The language model gathers and extracts facts; **code applies this policy**. The model never chooses the rating.

`reference/policy_reference.py` implements this document exactly. Student C's `src/policy.py` must give the same results.

## 1. Overview

```
Threat facts (NVD, KEV) + asset facts (environment lookup)
        │
        ▼
Step 1  Applicability gate ──► Not applicable ─────────────► Low
        │                 ──► Unknown or conflicting ──────► INSUFFICIENT_EVIDENCE (analyst review)
        ▼ Confirmed / Partial
Step 2  Machine priority (impact): data × exposure, plus overrides ──► P1 / P2 / P3
Step 3  Severity band from CVSS ──► Critical / High / Medium / Low
Step 4  Final matrix: priority × severity
Step 5  Modifiers, in this order: KEV +1, then Partial −1 (result stays within Low–High)
```

**Applicability** answers "can this threat actually work on this asset?" **Impact** (machine priority) answers "how much would it hurt?" **Severity** (CVSS) describes the flaw's technical seriousness in general. CVSS is **not** local risk: a Critical CVE on a patched or unimportant asset can still be Low.

## 2. Step 1: Applicability gate

| Level | Definition | Effect |
|---|---|---|
| **Confirmed** | Affected product present, build below the fixed build, and every attack prerequisite is met | Continue to the matrix |
| **Partial** | Vulnerable build, but a prerequisite is blocked or a control strongly reduces it (e.g., the asset is isolated, or only administrators can log on) | Continue; apply −1 at Step 5 |
| **Not applicable** | Product not in the affected list, build at or above the fixed build, or the product is explicitly declared absent | **Low**. Stop |
| **Unknown** | A decisive fact is `null` or missing | **INSUFFICIENT_EVIDENCE**. Stop, route to an analyst |
| **Conflict** | Two sources disagree on a decisive fact | **INSUFFICIENT_EVIDENCE**. Stop, flag the conflict for review |

Rules:
- **A product-name match alone is not enough.** The agent must check the build and the prerequisites.
- **A "no match" lookup does not prove non-applicability.** Only the CVE's affected-products list, a version comparison, or an explicit absence statement (S06 or the snapshot's `absences` list) can.
- **Builds are compared numerically**, part by part (10.0.14393.9339 < 10.0.14393.9512). Fixed builds come from NVD or the Microsoft advisory, never from the model's memory.

For CVE-2026-85880, the **decisive facts** are listed in `docs/threat_prerequisites.md`.

## 3. Step 2: Machine priority (impact)

### Definitions

- **PII without protection:** personal data where encryption at rest, access limited to named groups, *or* access logging is missing or undocumented.
- **PII with protection:** all three controls are documented.
- **No PII:** no personal data stored. Logs are not counted as PII (assumption A8).
- **Internet-exposed:** reachable from the internet, directly or through a proxy or WAF.
- **Intranet:** reachable from the USERS or VPN zones.
- **Internal only:** reachable only from restricted zones (ADMIN, MGMT, named application servers). *Isolated* assets are treated as internal only.

**Unknown protection counts as "without protection."** This conservative default avoids under-rating an asset just because evidence is missing.

### Matrix

| Data \ Exposure | Internet | Intranet | Internal only |
|---|---|---|---|
| **PII without protection** | P1 | P1 | P2 |
| **PII with protection** | P1 | P2 | P3 |
| **No PII** | P2 | P3 | P3 |

### Justification for each cell

| Cell | Why |
|---|---|
| Unprotected PII × Internet = P1 | Anyone can attempt the attack, and success exposes readable personal data |
| Unprotected PII × Intranet = P1 | Any compromised staff laptop can reach it; 1,000 users means a large attack surface for readable PII |
| Unprotected PII × Internal = P2 | Readable PII, but the attacker first has to reach a restricted zone |
| Protected PII × Internet = P1 | Exposure to everyone outweighs the controls; controls slow an attacker but don't stop a successful exploit |
| Protected PII × Intranet = P2 | Reachable by many users, but encryption and logging limit and reveal misuse |
| Protected PII × Internal = P3 | Hard to reach, and the data is protected even if reached |
| No PII × Internet = P2 | No data loss on the asset itself, but internet exposure makes it a likely foothold |
| No PII × Intranet = P3 | Limited consequence and no outside exposure |
| No PII × Internal = P3 | Smallest attack surface and smallest consequence |

### Overrides (always P1)

The matrix measures confidentiality and exposure. It misses assets whose compromise leads to everything else, so these are always P1:

| Override | Assets | Why |
|---|---|---|
| **Tier-0 identity** | W01, W02, W03, E03, C01 | Control of these gives control of every account and therefore every PII system |
| **Control plane or remote-access gateway** | W07, W08, W09, H01, N02, N10, C04 | Can deploy code to, administer, back up or reach many machines |
| **Service with 4-hour RTO** | W11, W12 | Identity and ERP have the scenario's shortest recovery targets (S05); an outage over 4 hours delays orders and invoicing |

## 4. Step 3: Severity band

Use the **CVSS v3.1 base score**. Source order: NVD primary score; if absent, the CNA score shown in NVD (for Microsoft CVEs, Microsoft's); if absent, the vendor advisory.

| Band | CVSS |
|---|---|
| Critical | 9.0–10.0 |
| High | 7.0–8.9 |
| Medium | 4.0–6.9 |
| Low | 0.1–3.9 |

If no score exists from any source, severity is **unknown**. The result is INSUFFICIENT_EVIDENCE, because the matrix can't be applied. (For CVE-2026-85880, the score is 7.8 from Microsoft's CNA entry, so the band is **High**.)

## 5. Step 4: Final matrix

| Priority \ Severity | Critical | High | Medium | Low |
|---|---|---|---|---|
| **P1** | High | High | Medium | Medium |
| **P2** | High | Medium | Medium | Low |
| **P3** | Medium | Low | Low | Low |

Justification: a P1 asset is never rated Low when a confirmed flaw exists, because the consequence is too large to defer. A P3 asset reaches Medium only for Critical flaws, which are often remotely exploitable and wormable. The diagonal (P1 × High, P2 × Critical) is High because both a serious flaw and a serious consequence are present.

## 6. Step 5: Modifiers

Applied in this order, and the result never goes above High or below Low.

1. **KEV +1.** If the CVE is in CISA KEV, raise one level. Confirmed exploitation in the wild makes an attack more likely. Absence from KEV does not lower the rating.
2. **Partial −1.** If applicability is Partial, lower one level. A blocked prerequisite makes success less likely.

## 7. Confidence

| Confidence | When |
|---|---|
| **High** | Every decisive fact comes from a live or cached external source or an original scenario evidence record (S01–S06), with no conflicts |
| **Medium** | At least one decisive fact depends on a group assumption or simulated addition (S07, S08), or any source was a cached fallback |
| **Low** | A conflict was resolved by judgment, or a non-decisive unknown could plausibly change the result |

Confidence is reported alongside the rating; it never changes the rating.

## 8. Failure and stop rules

| Situation | What happens |
|---|---|
| External lookup fails (timeout, error) | Retry once. Then use the cached copy, labeled `status: cached`. Confidence drops to at most Medium |
| Lookup fails and no cache exists, for a decisive fact (e.g., fixed build) | **Stop.** INSUFFICIENT_EVIDENCE, with the failed lookup named in the output |
| Model requests a tool that doesn't exist, or passes invalid arguments | Code rejects it and returns an error to the model. After 3 rejected calls, **stop** with an error status; no rating is produced |
| Decisive fact is null | INSUFFICIENT_EVIDENCE (Step 1) |
| Two sources disagree on a decisive fact | INSUFFICIENT_EVIDENCE, conflict listed, analyst review |
| Non-decisive fact is null | Listed under `unknowns`; rating continues |

## 9. Worked example: CVE-2026-85880 on W15 (base snapshot)

| Step | Fact | Source | Result |
|---|---|---|---|
| 1 | W15 runs Windows Server 2016, build 10.0.14393.9339 | Environment (S08) | Affected product |
| 1 | Fixed build for Server 2016 is 10.0.14393.9512 | NVD (T1) | 9339 < 9512, so vulnerable |
| 1 | Payroll operators and service account `svc_finlegacy` have non-admin local access | Environment (S03, S07/A15) | Prerequisite met |
| 1 | — | — | **Confirmed** |
| 2 | Restricted PII (payroll, banking), protection undocumented, reachable from USERS | Environment (S05, S07/A2, A6) | Unprotected PII × Intranet = **P1** |
| 3 | CVSS v3.1 7.8 | NVD (T1, Microsoft CNA) | **High** band |
| 4 | P1 × High | Policy | **High** |
| 5 | In KEV since 2026-09-08 | KEV (T2) | +1, capped at **High** |
| — | Confidence | Decisive facts rely on S07/S08 | **Medium** |

**Decision: High.** Recommended action: install the September 2026 cumulative update (or later) on FINLEG01–02 immediately, since the KEV due date (2026-09-22) has passed; until then, limit interactive logon to named payroll operators and review recent logon activity on W15. **Evidence that would change the decision:** a patch report showing build 10.0.14393.9512 or later (→ Low), or proof that no non-admin account can log on (→ Partial, Medium).
