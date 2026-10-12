# Triage report: CVE-2026-85880

- **Run:** `20261012T185643Z_check4c` · status **completed** · model `gpt-oss:120b` · faults: bad-tool
- **Snapshot:** `environment/northbridge-v1.1.json` (northbridge-v1.1, simulated)
- **Risk question:** What is the risk that CVE-2026-85880 is exploited on Northbridge Services assets, given environment snapshot northbridge-v1.1 (as of 2026-10-01)?

## Overall: High

Highest per-asset decision across 23 assessed asset records.

Counts: High 1, Medium 1, INSUFFICIENT_EVIDENCE 1, Low 20

## Threat

- Heap-based buffer overflow in Windows ALPC allows an authorized attacker to elevate privileges locally.
- CVSS v3.1 7.8 `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (cna_secondary, secure@microsoft.com)
- KEV: True (source: T2 lookup_kev; added 2026-09-08, due 2026-09-22)
- CVSS is the flaw's technical severity in general; the decision per asset is local risk from the applicability-and-impact policy.

## External lookups

| Ref | Tool | Status | Mode | Error |
|---|---|---|---|---|
| R2 | lookup_vulnerability | live | live |  |
| R3 | lookup_kev | live | live |  |

## Per-asset decisions

| Asset | Decision | Applicability | Priority | Rule | Confidence |
|---|---|---|---|---|---|
| W15 FINLEG01-FINLEG02 | **High** | Confirmed | P1 | P1 x High = High; KEV +1 -> High | Medium |
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
| W16 UTIL01-UTIL06 | **Low** | Not applicable | P3 | gate: not applicable -> Low | Medium |
| W17 DEPLOY01-DEPLOY02 | **Low** | Not applicable | P3 | gate: not applicable -> Low | Medium |
| W18 MON01-MON02 | **Low** | Not applicable | P3 | gate: not applicable -> Low | Medium |

### W15 FINLEG01-FINLEG02: High

- **Role / zone:** Legacy finance application servers / LEGACY
- **Applicability:** Confirmed. vulnerable build 10.0.14393.9339 < 10.0.14393.9512 and low-privilege local access exists
- **Impact:** P1 (matrix: pii_unprotected x intranet)
- **Rule:** P1 x High = High; KEV +1 -> High
- **Confidence:** Medium (decisive facts rely on group-simulated evidence S07, S08)
- **Recommended action** (model (rating fixed by policy code)): 1) Install the update to bring the OS to build 10.0.14393.9512 or later; 2) Apply the vendor‑specified mitigations for CVE‑2026‑85880 in line with CISA BOD 26‑04 (the federal due date of 2026‑09‑22 has already passed); 3) Disable NTLM for the svc_finlegacy account and rotate its password (currently 180 days old).
- **Would change the decision:** Evidence that the server is patched to the fixed build or that low‑privilege local access is no longer possible would lower the rating.
- **Decisive unknowns:** none
- **Assumptions:** A6 (S07): W15 is reachable from the USERS zone (flow F07), so its exposure is "intranet"; A15 (S07): Payroll operators (non-administrators) log on to W15 to run exports, and the NTLM service account `svc_finlegacy` runs there, so a low-privilege local access path exists
- **Evidence:**
  - R6 `lookup_environment`  northbridge-v1.1.json#assets[17] [simulated, ok, 2026-10-12T18:56:49Z]: asset record: OS Windows Server 2016 build 10.0.14393.9339, low_priv_local_access=True, data=restricted_pii/unprotected, exposure=intranet
  - R9 `lookup_environment` S03 northbridge-v1.1.json#evidence[2] [simulated, ok, 2026-10-12T18:56:52Z]: Control and exception register (course scenario v1.0, 2026-10-01)
  - R11 `lookup_environment` S05 northbridge-v1.1.json#evidence[4] [simulated, ok, 2026-10-12T18:56:53Z]: Business impact and recovery worksheet (course scenario v1.0, 2026-10-01)
  - R12 `lookup_environment` S07 northbridge-v1.1.json#evidence[6] [simulated, ok, 2026-10-12T18:56:53Z]: Group scenario adaptation: assumptions A1-A15 (added by group (simulated), 2026-10-11)
  - R13 `lookup_environment` S08 northbridge-v1.1.json#evidence[7] [simulated, ok, 2026-10-12T18:56:54Z]: Group scenario adaptation: version and patch data (added by group (simulated), 2026-10-11)
  - R2 `lookup_vulnerability` T1 https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-85880 [live, live, 2026-10-12T18:56:45Z]: affected product windows_server_2016: listed; fixed build 10.0.14393.9512
  - R3 `lookup_kev` T2 https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json [live, live, 2026-10-12T18:56:46Z]: CVE listed in CISA KEV

### W02 CA-ROOT01: Medium

- **Role / zone:** Offline standalone root CA / IDENTITY
- **Applicability:** Partial. vulnerable build 10.0.20348.5256 < 10.0.20348.5622, but no low-privilege local access path (exposure=isolated, low_priv_local_access=False)
- **Impact:** P1 (override: Tier-0 identity)
- **Rule:** P1 x High = High; KEV +1 -> High; Partial -1 -> Medium
- **Confidence:** Medium (decisive facts rely on group-simulated evidence S07, S08)
- **Recommended action** (model (rating fixed by policy code)): 1) Confirm the root CA has been updated to build 10.0.20348.5622; 2) If not, schedule a maintenance window to apply the patch while the CA is powered on; 3) Deploy any vendor‑recommended mitigations for CVE‑2026‑85880 and document compliance with BOD 26‑04 (the federal due date of 2026‑09‑22 has already passed).
- **Would change the decision:** Proof that the CA remains unpatched or that a low‑privilege local access path becomes available would raise the decision to High.
- **Decisive unknowns:** none
- **Assumptions:** none
- **Evidence:**
  - R8 `lookup_environment`  northbridge-v1.1.json#assets[2] [simulated, ok, 2026-10-12T18:56:50Z]: asset record: OS Windows Server 2022 build 10.0.20348.5256, low_priv_local_access=False, data=none/n/a, exposure=isolated
  - R14 `lookup_environment` S01 northbridge-v1.1.json#evidence[0] [simulated, ok, 2026-10-12T18:57:09Z]: Asset register (course scenario v1.0, 2026-10-01)
  - R12 `lookup_environment` S07 northbridge-v1.1.json#evidence[6] [simulated, ok, 2026-10-12T18:56:53Z]: Group scenario adaptation: assumptions A1-A15 (added by group (simulated), 2026-10-11)
  - R13 `lookup_environment` S08 northbridge-v1.1.json#evidence[7] [simulated, ok, 2026-10-12T18:56:54Z]: Group scenario adaptation: version and patch data (added by group (simulated), 2026-10-11)
  - R2 `lookup_vulnerability` T1 https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-85880 [live, live, 2026-10-12T18:56:45Z]: affected product windows_server_2022: listed; fixed build 10.0.20348.5622
  - R3 `lookup_kev` T2 https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json [live, live, 2026-10-12T18:56:46Z]: CVE listed in CISA KEV

### E02 Legacy workstations (stale sensors): INSUFFICIENT_EVIDENCE

- **Role / zone:** Legacy Windows 10 (ESU) / LEGACY
- **Applicability:** Unknown. OS build unknown (decisive)
- **Impact:** P3 (matrix: no_pii x intranet)
- **Rule:** gate: decisive fact unknown or conflicting -> INSUFFICIENT_EVIDENCE (analyst review)
- **Confidence:** None (no rating, so no confidence level; see the applicability reason)
- **Recommended action** (model (rating fixed by policy code)): 1) Retrieve the current Windows 10 build number from the workstation; 2) Verify whether the CVE‑2026‑85880 patch has been applied; 3) Confirm that the sensor heartbeat is recent (within 7 days) to establish asset visibility.
- **Would change the decision:** Obtaining the exact OS build (showing it is ≥10.0.19045.7725) and confirming patch status would allow a definitive risk rating.
- **Decisive unknowns:** os.build
- **Assumptions:** none
- **Evidence:**
  - R5 `lookup_environment`  northbridge-v1.1.json#assets[27] [simulated, ok, 2026-10-12T18:56:47Z]: asset record: OS Windows 10 Enterprise build None, low_priv_local_access=True, data=none/n/a, exposure=intranet
  - R9 `lookup_environment` S03 northbridge-v1.1.json#evidence[2] [simulated, ok, 2026-10-12T18:56:52Z]: Control and exception register (course scenario v1.0, 2026-10-01)
  - R10 `lookup_environment` S04 northbridge-v1.1.json#evidence[3] [simulated, ok, 2026-10-12T18:56:52Z]: Telemetry coverage summary (course scenario v1.0, 2026-10-01)
  - R13 `lookup_environment` S08 northbridge-v1.1.json#evidence[7] [simulated, ok, 2026-10-12T18:56:54Z]: Group scenario adaptation: version and patch data (added by group (simulated), 2026-10-11)
  - R2 `lookup_vulnerability` T1 https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-85880 [live, live, 2026-10-12T18:56:45Z]: affected product windows_10_22h2: listed; fixed build 10.0.19045.7725

## Human review

Pending. Use `docs/evidence_review.md`.
