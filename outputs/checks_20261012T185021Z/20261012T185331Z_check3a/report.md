# Triage report: CVE-2026-85880

- **Run:** `20261012T185331Z_check3a` · status **completed** · model `gpt-oss:120b` · faults: none
- **Snapshot:** `environment/variants/env_missing.json` (northbridge-v1.1-missing_evidence, simulated)
- **Risk question:** What is the risk that CVE-2026-85880 is exploited on Northbridge Services assets, given environment snapshot northbridge-v1.1-missing_evidence (as of 2026-10-01)?

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
| W15 FINLEG01-FINLEG02 | **INSUFFICIENT_EVIDENCE** | Unknown | P1 | gate: decisive fact unknown or conflicting -> INSUFFICIENT_EVIDENCE (analyst review) | n/a |
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
- **Recommended action** (model (rating fixed by policy code)): 1) Confirm that the offline root CA remains isolated and has no network exposure. 2) Re‑verify that the system is running the fixed build 10.0.20348.5622 or later. 3) Apply any remaining vendor‑recommended mitigations and document compliance with the KEV BOD 26‑04 guidance (the federal due date has already passed).
- **Would change the decision:** Evidence that a low‑privilege local user can access the CA or that the CA is reachable on a network would increase the risk rating.
- **Decisive unknowns:** none
- **Assumptions:** none
- **Evidence:**
  - R13 `lookup_environment`  env_missing.json#assets[2] [simulated, ok, 2026-10-12T18:54:32Z]: asset record: OS Windows Server 2022 build 10.0.20348.5256, low_priv_local_access=False, data=none/n/a, exposure=isolated
  - R14 `lookup_environment` S01 env_missing.json#evidence[0] [simulated, ok, 2026-10-12T18:54:34Z]: Asset register (course scenario v1.0, 2026-10-01)
  - R11 `lookup_environment` S07 env_missing.json#evidence[6] [simulated, ok, 2026-10-12T18:54:25Z]: Group scenario adaptation: assumptions A1-A15 (added by group (simulated), 2026-10-11)
  - R12 `lookup_environment` S08 env_missing.json#evidence[7] [simulated, ok, 2026-10-12T18:54:25Z]: Group scenario adaptation: version and patch data (added by group (simulated), 2026-10-11)
  - R1 `lookup_vulnerability` T1 https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-85880 [live, live, 2026-10-12T18:53:32Z]: affected product windows_server_2022: listed; fixed build 10.0.20348.5622
  - R2 `lookup_kev` T2 https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json [live, live, 2026-10-12T18:53:33Z]: CVE listed in CISA KEV

### E02 Legacy workstations (stale sensors): INSUFFICIENT_EVIDENCE

- **Role / zone:** Legacy Windows 10 (ESU) / LEGACY
- **Applicability:** Unknown. OS build unknown (decisive)
- **Impact:** P3 (matrix: no_pii x intranet)
- **Rule:** gate: decisive fact unknown or conflicting -> INSUFFICIENT_EVIDENCE (analyst review)
- **Confidence:** None (no rating, so no confidence level; see the applicability reason)
- **Recommended action** (model (rating fixed by policy code)): 1) Determine the exact Windows 10 Enterprise build on the legacy workstations. 2) Check if the build is earlier than the fixed build 10.0.19045.7725. 3) If vulnerable, patch the machines or isolate them and follow the KEV mitigation instructions (the federal due date has already passed).
- **Would change the decision:** The specific OS build number (and corresponding patch level) would resolve the insufficient‑evidence determination.
- **Decisive unknowns:** os.build
- **Assumptions:** none
- **Evidence:**
  - R6 `lookup_environment`  env_missing.json#assets[27] [simulated, ok, 2026-10-12T18:53:37Z]: asset record: OS Windows 10 Enterprise build None, low_priv_local_access=True, data=none/n/a, exposure=intranet
  - R7 `lookup_environment` S03 env_missing.json#evidence[2] [simulated, ok, 2026-10-12T18:53:39Z]: Control and exception register (course scenario v1.0, 2026-10-01)
  - R8 `lookup_environment` S04 env_missing.json#evidence[3] [simulated, ok, 2026-10-12T18:53:40Z]: Telemetry coverage summary (course scenario v1.0, 2026-10-01)
  - R12 `lookup_environment` S08 env_missing.json#evidence[7] [simulated, ok, 2026-10-12T18:54:25Z]: Group scenario adaptation: version and patch data (added by group (simulated), 2026-10-11)
  - R1 `lookup_vulnerability` T1 https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-85880 [live, live, 2026-10-12T18:53:32Z]: affected product windows_10_22h2: listed; fixed build 10.0.19045.7725

### W15 FINLEG01-FINLEG02: INSUFFICIENT_EVIDENCE

- **Role / zone:** Legacy finance application servers / LEGACY
- **Applicability:** Unknown. OS build unknown (decisive)
- **Impact:** P1 (matrix: pii_unprotected x intranet)
- **Rule:** gate: decisive fact unknown or conflicting -> INSUFFICIENT_EVIDENCE (analyst review)
- **Confidence:** None (no rating, so no confidence level; see the applicability reason)
- **Recommended action** (model (rating fixed by policy code)): 1) Obtain the exact Windows Server 2016 build number for W15 FINLEG01‑FINLEG02. 2) Verify whether the system is running a build earlier than the fixed build 10.0.14393.9512. 3) If it is vulnerable, apply the vendor patch and implement the KEV mitigation steps (follow BOD 26‑04 guidance).
- **Would change the decision:** Discovery of the exact OS build (and thus whether it is below the fixed build) would resolve the insufficient‑evidence status.
- **Decisive unknowns:** os.build
- **Assumptions:** A6 (S07): W15 is reachable from the USERS zone (flow F07), so its exposure is "intranet"; A15 (S07): Payroll operators (non-administrators) log on to W15 to run exports, and the NTLM service account `svc_finlegacy` runs there, so a low-privilege local access path exists
- **Evidence:**
  - R3 `lookup_environment`  env_missing.json#assets[17] [simulated, ok, 2026-10-12T18:53:34Z]: asset record: OS Windows Server 2016 build None, low_priv_local_access=True, data=restricted_pii/unprotected, exposure=intranet
  - R7 `lookup_environment` S03 env_missing.json#evidence[2] [simulated, ok, 2026-10-12T18:53:39Z]: Control and exception register (course scenario v1.0, 2026-10-01)
  - R9 `lookup_environment` S05 env_missing.json#evidence[4] [simulated, ok, 2026-10-12T18:54:17Z]: Business impact and recovery worksheet (course scenario v1.0, 2026-10-01)
  - R11 `lookup_environment` S07 env_missing.json#evidence[6] [simulated, ok, 2026-10-12T18:54:25Z]: Group scenario adaptation: assumptions A1-A15 (added by group (simulated), 2026-10-11)
  - R12 `lookup_environment` S08 env_missing.json#evidence[7] [simulated, ok, 2026-10-12T18:54:25Z]: Group scenario adaptation: version and patch data (added by group (simulated), 2026-10-11)
  - R1 `lookup_vulnerability` T1 https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-85880 [live, live, 2026-10-12T18:53:32Z]: affected product windows_server_2016: listed; fixed build 10.0.14393.9512

## Human review

Pending. Use `docs/evidence_review.md`.
