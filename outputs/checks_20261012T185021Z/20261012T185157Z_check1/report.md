# Triage report: CVE-2026-85880

- **Run:** `20261012T185157Z_check1` · status **completed** · model `gpt-oss:120b` · faults: none
- **Snapshot:** `environment/variants/env_patched.json` (northbridge-v1.1-applicability_change, simulated)
- **Risk question:** What is the risk that CVE-2026-85880 is exploited on Northbridge Services assets, given environment snapshot northbridge-v1.1-applicability_change (as of 2026-10-01)?

## Overall: Medium

Highest per-asset decision across 23 assessed asset records.

Counts: Medium 1, INSUFFICIENT_EVIDENCE 1, Low 21

## Threat

- Heap-based buffer overflow in Windows ALPC allows an authorized attacker to elevate privileges locally.
- CVSS v3.1 7.8 `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (cna_secondary, secure@microsoft.com)
- KEV: True (source: T2 lookup_kev; added 2026-09-08, due 2026-09-22)
- CVSS is the flaw's technical severity in general; the decision per asset is local risk from the applicability-and-impact policy.

## External lookups

| Ref | Tool | Status | Mode | Error |
|---|---|---|---|---|
| R1 | lookup_vulnerability | live | live |  |
| R2 | lookup_kev | live | live |  |

## Per-asset decisions

| Asset | Decision | Applicability | Priority | Rule | Confidence |
|---|---|---|---|---|---|
| W02 CA-ROOT01 | **Medium** | Partial | P1 | P1 x High = High; KEV +1 -> High; Partial -1 -> Medium | Medium |
| E02 Legacy workstations (stale sensors) | **INSUFFICIENT_EVIDENCE** | Unknown | P3 | gate: decisive fact unknown or conflicting -> INSUFFICIENT_EVIDENCE (analyst review) | n/a |
| E02 Legacy workstations (sensors healthy) | **Low** | Not applicable | P3 | gate: not applicable -> Low | Medium |
| W01 DC01-DC04 | **Low** | Not applicable | P1 | gate: not applicable -> Low | Medium |
| W02 CA-ISSUING01 | **Low** | Not applicable | P1 | gate: not applicable -> Low | Medium |
| W03 SYNC01-SYNC02 | **Low** | Not applicable | P1 | gate: not applicable -> Low | Medium |
| W04 DHCP01-DHCP02 | **Low** | Not applicable | P3 | gate: not applicable -> Low | Medium |
| W05 FILE01-FILE03 | **Low** | Not applicable | P3 | gate: not applicable -> Low | Medium |
| W05 FILE04 | **Low** | Not applicable | P1 | gate: not applicable -> Low | Medium |
| W06 PRINT01-PRINT02 | **Low** | Not applicable | P3 | gate: not applicable -> Low | Medium |
| W07 CM01, CMDP01 | **Low** | Not applicable | P1 | gate: not applicable -> Low | Medium |
| W08 JUMP01-JUMP02 | **Low** | Not applicable | P1 | gate: not applicable -> Low | Medium |
| W09 BKP01-BKP02 | **Low** | Not applicable | P1 | gate: not applicable -> Low | Medium |
| W10 RDS01-RDS04 | **Low** | Not applicable | P3 | gate: not applicable -> Low | Medium |
| W11 ERP01-ERP04 | **Low** | Not applicable | P1 | gate: not applicable -> Low | Medium |
| W12 SQL01-SQL04 | **Low** | Not applicable | P1 | gate: not applicable -> Low | Medium |
| W13 INTRA01-INTRA02 | **Low** | Not applicable | P3 | gate: not applicable -> Low | Medium |
| W13 PORTAL01-PORTAL02 | **Low** | Not applicable | P1 | gate: not applicable -> Low | Medium |
| W14 MSQL01-MSQL02 | **Low** | Not applicable | P3 | gate: not applicable -> Low | Medium |
| W15 FINLEG01-FINLEG02 | **Low** | Not applicable | P1 | gate: not applicable -> Low | Medium |
| W16 UTIL01-UTIL06 | **Low** | Not applicable | P3 | gate: not applicable -> Low | Medium |
| W17 DEPLOY01-DEPLOY02 | **Low** | Not applicable | P3 | gate: not applicable -> Low | Medium |
| W18 MON01-MON02 | **Low** | Not applicable | P3 | gate: not applicable -> Low | Medium |

### W02 CA-ROOT01: Medium

- **Role / zone:** Offline standalone root CA / IDENTITY
- **Applicability:** Partial. vulnerable build 10.0.20348.5256 < 10.0.20348.5622, but no low-privilege local access path (exposure=isolated, low_priv_local_access=False)
- **Impact:** P1 (override: Tier-0 identity)
- **Rule:** P1 x High = High; KEV +1 -> High; Partial -1 -> Medium
- **Confidence:** Medium (decisive facts rely on group-simulated evidence S07, S08)
- **Recommended action** (model (rating fixed by policy code)): 1) Verify that the CA server is running the fixed build 10.0.20348.5622; if not, apply the update immediately. 2) Because the KEV due date (2026-09-22) has passed, document compliance with CISA BOD 26‑04 and ensure the offline CA is isolated or decommissioned if it cannot be patched. 3) Review the CA’s configuration for any low‑privilege local access paths and confirm the isolation status remains unchanged.
- **Would change the decision:** Evidence that the server is already patched to the fixed build (or that a low‑privilege local access path exists) would shift the rating; confirmation of its current patch state would resolve the decision.
- **Decisive unknowns:** none
- **Assumptions:** none
- **Evidence:**
  - R13 `lookup_environment`  env_patched.json#assets[2] [simulated, ok, 2026-10-12T18:52:18Z]: asset record: OS Windows Server 2022 build 10.0.20348.5256, low_priv_local_access=False, data=none/n/a, exposure=isolated
  - R14 `lookup_environment` S01 env_patched.json#evidence[0] [simulated, ok, 2026-10-12T18:52:20Z]: Asset register (course scenario v1.0, 2026-10-01)
  - R10 `lookup_environment` S07 env_patched.json#evidence[6] [simulated, ok, 2026-10-12T18:52:07Z]: Group scenario adaptation: assumptions A1-A15 (added by group (simulated), 2026-10-11)
  - R11 `lookup_environment` S08 env_patched.json#evidence[7] [simulated, ok, 2026-10-12T18:52:07Z]: Group scenario adaptation: version and patch data (added by group (simulated), 2026-10-11)
  - R1 `lookup_vulnerability` T1 https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-85880 [live, live, 2026-10-12T18:51:58Z]: affected product windows_server_2022: listed; fixed build 10.0.20348.5622
  - R2 `lookup_kev` T2 https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json [live, live, 2026-10-12T18:51:59Z]: CVE listed in CISA KEV

### E02 Legacy workstations (stale sensors): INSUFFICIENT_EVIDENCE

- **Role / zone:** Legacy Windows 10 (ESU) / LEGACY
- **Applicability:** Unknown. OS build unknown (decisive)
- **Impact:** P3 (matrix: no_pii x intranet)
- **Rule:** gate: decisive fact unknown or conflicting -> INSUFFICIENT_EVIDENCE (analyst review)
- **Confidence:** None (no rating, so no confidence level; see the applicability reason)
- **Recommended action** (model (rating fixed by policy code)): 1) Obtain a current sensor heartbeat to confirm the workstation is online and can be queried. 2) Query the OS version and build number to determine if it is below the fixed build 10.0.19045.7725. 3) If the build is vulnerable, apply the vendor‑provided mitigation or patch as directed in the KEV guidance.
- **Would change the decision:** Evidence of the workstation’s actual OS build (and patch level) and confirmation that it is reachable would allow a definitive applicability determination.
- **Decisive unknowns:** os.build
- **Assumptions:** none
- **Evidence:**
  - R6 `lookup_environment`  env_patched.json#assets[27] [simulated, ok, 2026-10-12T18:52:03Z]: asset record: OS Windows 10 Enterprise build None, low_priv_local_access=True, data=none/n/a, exposure=intranet
  - R7 `lookup_environment` S03 env_patched.json#evidence[2] [simulated, ok, 2026-10-12T18:52:05Z]: Control and exception register (course scenario v1.0, 2026-10-01)
  - R12 `lookup_environment` S04 env_patched.json#evidence[3] [simulated, ok, 2026-10-12T18:52:11Z]: Telemetry coverage summary (course scenario v1.0, 2026-10-01)
  - R11 `lookup_environment` S08 env_patched.json#evidence[7] [simulated, ok, 2026-10-12T18:52:07Z]: Group scenario adaptation: version and patch data (added by group (simulated), 2026-10-11)
  - R1 `lookup_vulnerability` T1 https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-85880 [live, live, 2026-10-12T18:51:58Z]: affected product windows_10_22h2: listed; fixed build 10.0.19045.7725

## Human review

Pending. Use `docs/evidence_review.md`.
