# Triage report: CVE-2026-85880

- **Run:** `20261012T185451Z_check3b` · status **completed** · model `gpt-oss:120b` · faults: none
- **Snapshot:** `environment/variants/env_conflict.json` (northbridge-v1.1-conflicting_evidence, simulated)
- **Risk question:** What is the risk that CVE-2026-85880 is exploited on Northbridge Services assets, given environment snapshot northbridge-v1.1-conflicting_evidence (as of 2026-10-01)?

## Overall: Medium

Highest per-asset decision across 23 assessed asset records.

Counts: Medium 1, INSUFFICIENT_EVIDENCE 2, Low 20

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
| W15 FINLEG01-FINLEG02 | **INSUFFICIENT_EVIDENCE** | Conflict | P1 | gate: decisive fact unknown or conflicting -> INSUFFICIENT_EVIDENCE (analyst review) | n/a |
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
| W16 UTIL01-UTIL06 | **Low** | Not applicable | P3 | gate: not applicable -> Low | Medium |
| W17 DEPLOY01-DEPLOY02 | **Low** | Not applicable | P3 | gate: not applicable -> Low | Medium |
| W18 MON01-MON02 | **Low** | Not applicable | P3 | gate: not applicable -> Low | Medium |

### W02 CA-ROOT01: Medium

- **Role / zone:** Offline standalone root CA / IDENTITY
- **Applicability:** Partial. vulnerable build 10.0.20348.5256 < 10.0.20348.5622, but no low-privilege local access path (exposure=isolated, low_priv_local_access=False)
- **Impact:** P1 (override: Tier-0 identity)
- **Rule:** P1 x High = High; KEV +1 -> High; Partial -1 -> Medium
- **Confidence:** Medium (decisive facts rely on group-simulated evidence S07, S08)
- **Recommended action** (model (rating fixed by policy code)): 1) Verify that the most recent patch (build 10.0.20348.5622) is present on W02 CA-ROOT01 after its last power‑on (2026‑06) and document the result. 2) Because the KEV due date (2026‑09‑22) has already passed, record that the federal deadline was missed and report this to the compliance owner. 3) Review the system’s isolation status and confirm that no low‑privilege local accounts can access the server; if any such path is discovered, apply additional hardening or consider moving the CA to a higher‑security zone.
- **Would change the decision:** Evidence that the asset is exposed to low‑privilege local access (e.g., a newly created local account with limited rights) or that it is no longer isolated (e.g., network reachability) would upgrade the decision to High.
- **Decisive unknowns:** none
- **Assumptions:** none
- **Evidence:**
  - R6 `lookup_environment`  env_conflict.json#assets[2] [simulated, ok, 2026-10-12T18:54:56Z]: asset record: OS Windows Server 2022 build 10.0.20348.5256, low_priv_local_access=False, data=none/n/a, exposure=isolated
  - R8 `lookup_environment` S01 env_conflict.json#evidence[0] [simulated, ok, 2026-10-12T18:55:01Z]: Asset register (course scenario v1.0, 2026-10-01)
  - R14 `lookup_environment` S07 env_conflict.json#evidence[6] [simulated, ok, 2026-10-12T18:55:08Z]: Group scenario adaptation: assumptions A1-A15 (added by group (simulated), 2026-10-11)
  - R15 `lookup_environment` S08 env_conflict.json#evidence[7] [simulated, ok, 2026-10-12T18:55:08Z]: Group scenario adaptation: version and patch data (added by group (simulated), 2026-10-11)
  - R1 `lookup_vulnerability` T1 https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-85880 [live, live, 2026-10-12T18:54:52Z]: affected product windows_server_2022: listed; fixed build 10.0.20348.5622
  - R2 `lookup_kev` T2 https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json [live, live, 2026-10-12T18:54:53Z]: CVE listed in CISA KEV

### E02 Legacy workstations (stale sensors): INSUFFICIENT_EVIDENCE

- **Role / zone:** Legacy Windows 10 (ESU) / LEGACY
- **Applicability:** Unknown. OS build unknown (decisive)
- **Impact:** P3 (matrix: no_pii x intranet)
- **Rule:** gate: decisive fact unknown or conflicting -> INSUFFICIENT_EVIDENCE (analyst review)
- **Confidence:** None (no rating, so no confidence level; see the applicability reason)
- **Recommended action** (model (rating fixed by policy code)): 1) Query the legacy workstations directly (e.g., via SCCM, PowerShell, or remote inventory) to capture the exact Windows 10 Enterprise build number. 2) Compare the discovered build to the fixed build 10.0.19045.7725 and apply the update if the workstation is below that level. 3) Verify sensor heartbeat freshness and, if still stale, restart the sensor service or replace the endpoint to re‑establish monitoring.
- **Would change the decision:** Obtaining the actual OS build version (and confirming whether it meets or exceeds 10.0.19045.7725) would eliminate the insufficient evidence and allow a concrete risk rating to be assigned.
- **Decisive unknowns:** os.build
- **Assumptions:** none
- **Evidence:**
  - R7 `lookup_environment`  env_conflict.json#assets[27] [simulated, ok, 2026-10-12T18:54:57Z]: asset record: OS Windows 10 Enterprise build None, low_priv_local_access=True, data=none/n/a, exposure=intranet
  - R10 `lookup_environment` S03 env_conflict.json#evidence[2] [simulated, ok, 2026-10-12T18:55:02Z]: Control and exception register (course scenario v1.0, 2026-10-01)
  - R11 `lookup_environment` S04 env_conflict.json#evidence[3] [simulated, ok, 2026-10-12T18:55:03Z]: Telemetry coverage summary (course scenario v1.0, 2026-10-01)
  - R15 `lookup_environment` S08 env_conflict.json#evidence[7] [simulated, ok, 2026-10-12T18:55:08Z]: Group scenario adaptation: version and patch data (added by group (simulated), 2026-10-11)
  - R1 `lookup_vulnerability` T1 https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-85880 [live, live, 2026-10-12T18:54:52Z]: affected product windows_10_22h2: listed; fixed build 10.0.19045.7725

### W15 FINLEG01-FINLEG02: INSUFFICIENT_EVIDENCE

- **Role / zone:** Legacy finance application servers / LEGACY
- **Applicability:** Conflict. sources disagree on a decisive fact: S08 says 'W15: Windows Server 2016 build 10.0.14393.9512 (September 2026 update) per patch report dated 2026-09-30' but the asset record (env_conflict.json#assets[17]) says build 10.0.14393.9339
- **Impact:** P1 (matrix: pii_unprotected x intranet)
- **Rule:** gate: decisive fact unknown or conflicting -> INSUFFICIENT_EVIDENCE (analyst review)
- **Confidence:** None (no rating, so no confidence level; see the applicability reason)
- **Recommended action** (model (rating fixed by policy code)): 1) Obtain an authoritative source (e.g., the patch management system or Windows Update history) that confirms the exact OS build currently installed on W15 FINLEG01‑FINLEG02. 2) If the build is 10.0.14393.9512, document that the vulnerability is mitigated; if it remains at 10.0.14393.9339, schedule the required update to build 10.0.14393.9512. 3) Review the NTLM configuration and service‑account password age to ensure no additional exposure while the patch status is unresolved.
- **Would change the decision:** A definitive, verified OS build number (showing either the patched build 10.0.14393.9512 or confirming the unpatched build) would resolve the insufficient evidence and allow the decision to be set to Medium or High accordingly.
- **Decisive unknowns:** none
- **Assumptions:** A6 (S07): W15 is reachable from the USERS zone (flow F07), so its exposure is "intranet"; A15 (S07): Payroll operators (non-administrators) log on to W15 to run exports, and the NTLM service account `svc_finlegacy` runs there, so a low-privilege local access path exists
- **Evidence:**
  - R3 `lookup_environment`  env_conflict.json#assets[17] [simulated, ok, 2026-10-12T18:54:54Z]: asset record: OS Windows Server 2016 build 10.0.14393.9339, low_priv_local_access=True, data=restricted_pii/unprotected, exposure=intranet
  - R10 `lookup_environment` S03 env_conflict.json#evidence[2] [simulated, ok, 2026-10-12T18:55:02Z]: Control and exception register (course scenario v1.0, 2026-10-01)
  - R12 `lookup_environment` S05 env_conflict.json#evidence[4] [simulated, ok, 2026-10-12T18:55:04Z]: Business impact and recovery worksheet (course scenario v1.0, 2026-10-01)
  - R14 `lookup_environment` S07 env_conflict.json#evidence[6] [simulated, ok, 2026-10-12T18:55:08Z]: Group scenario adaptation: assumptions A1-A15 (added by group (simulated), 2026-10-11)
  - R15 `lookup_environment` S08 env_conflict.json#evidence[7] [simulated, ok, 2026-10-12T18:55:08Z]: Group scenario adaptation: version and patch data (added by group (simulated), 2026-10-11)
  - R1 `lookup_vulnerability` T1 https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-85880 [live, live, 2026-10-12T18:54:52Z]: affected product windows_server_2016: listed; fixed build 10.0.14393.9512

## Human review

Pending. Use `docs/evidence_review.md`.
