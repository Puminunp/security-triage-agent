# Triage report: CVE-2026-85880

- **Run:** `20261012T185534Z_check4a` · status **completed** · model `gpt-oss:120b` · faults: nvd-down
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
| R1 | lookup_vulnerability | cached | cached | lookup failed after 2 attempts (ConnectionError: HTTPConnectionPool(host='127.0.0.1', port=9): Max retries exceeded with url: /unreachable?cveId=CVE-2026-85880 (Caused by NewConnectionError("HTTPConnection(host='127.0.0.1', port=9): Failed to establish a new connection: [Errno 61] Connection refused"))) |
| R2 | lookup_kev | live | live |  |

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
- **Confidence:** Medium (decisive facts rely on group-simulated evidence S07, S08; cached fallback used for lookup_vulnerability)
- **Recommended action** (model (rating fixed by policy code)): 1) Deploy the security update to bring the OS build to at least 10.0.14393.9512 on both W15 FINLEG01 and FINLEG02. 2) Verify and, if possible, disable NTLM authentication for non‑service accounts or restrict it to the svc_finlegacy account only. 3) Rotate the password for the svc_finlegacy service account (currently 180 days old) and document the change.
- **Would change the decision:** Confirmation that the OS build on the servers is now >= 10.0.14393.9512 (i.e., the patch has been applied).
- **Decisive unknowns:** none
- **Assumptions:** A6 (S07): W15 is reachable from the USERS zone (flow F07), so its exposure is "intranet"; A15 (S07): Payroll operators (non-administrators) log on to W15 to run exports, and the NTLM service account `svc_finlegacy` runs there, so a low-privilege local access path exists
- **Evidence:**
  - R3 `lookup_environment`  northbridge-v1.1.json#assets[17] [simulated, ok, 2026-10-12T18:55:38Z]: asset record: OS Windows Server 2016 build 10.0.14393.9339, low_priv_local_access=True, data=restricted_pii/unprotected, exposure=intranet
  - R8 `lookup_environment` S03 northbridge-v1.1.json#evidence[2] [simulated, ok, 2026-10-12T18:55:49Z]: Control and exception register (course scenario v1.0, 2026-10-01)
  - R9 `lookup_environment` S05 northbridge-v1.1.json#evidence[4] [simulated, ok, 2026-10-12T18:55:49Z]: Business impact and recovery worksheet (course scenario v1.0, 2026-10-01)
  - R10 `lookup_environment` S07 northbridge-v1.1.json#evidence[6] [simulated, ok, 2026-10-12T18:55:50Z]: Group scenario adaptation: assumptions A1-A15 (added by group (simulated), 2026-10-11)
  - R11 `lookup_environment` S08 northbridge-v1.1.json#evidence[7] [simulated, ok, 2026-10-12T18:55:50Z]: Group scenario adaptation: version and patch data (added by group (simulated), 2026-10-11)
  - R1 `lookup_vulnerability` T1 http://127.0.0.1:9/unreachable?cveId=CVE-2026-85880 [cached, cached, 2026-10-12T18:54:52Z]: affected product windows_server_2016: listed; fixed build 10.0.14393.9512
  - R2 `lookup_kev` T2 https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json [live, live, 2026-10-12T18:55:37Z]: CVE listed in CISA KEV

### W02 CA-ROOT01: Medium

- **Role / zone:** Offline standalone root CA / IDENTITY
- **Applicability:** Partial. vulnerable build 10.0.20348.5256 < 10.0.20348.5622, but no low-privilege local access path (exposure=isolated, low_priv_local_access=False)
- **Impact:** P1 (override: Tier-0 identity)
- **Rule:** P1 x High = High; KEV +1 -> High; Partial -1 -> Medium
- **Confidence:** Medium (decisive facts rely on group-simulated evidence S07, S08; cached fallback used for lookup_vulnerability)
- **Recommended action** (model (rating fixed by policy code)): 1) Apply the update that brings the CA to build 10.0.20348.5622 the next time it is powered on. 2) Verify that the root CA remains isolated with no low‑privilege local access paths. 3) Document that the KEV due date (2026-09-22) has already passed and ensure compliance with BOD 26‑04 remediation guidance.
- **Would change the decision:** Evidence that the CA has been patched to build 10.0.20348.5622 (or that a low‑privilege local access path exists, which would raise the rating).
- **Decisive unknowns:** none
- **Assumptions:** none
- **Evidence:**
  - R7 `lookup_environment`  northbridge-v1.1.json#assets[2] [simulated, ok, 2026-10-12T18:55:47Z]: asset record: OS Windows Server 2022 build 10.0.20348.5256, low_priv_local_access=False, data=none/n/a, exposure=isolated
  - R12 `lookup_environment` S01 northbridge-v1.1.json#evidence[0] [simulated, ok, 2026-10-12T18:55:52Z]: Asset register (course scenario v1.0, 2026-10-01)
  - R10 `lookup_environment` S07 northbridge-v1.1.json#evidence[6] [simulated, ok, 2026-10-12T18:55:50Z]: Group scenario adaptation: assumptions A1-A15 (added by group (simulated), 2026-10-11)
  - R11 `lookup_environment` S08 northbridge-v1.1.json#evidence[7] [simulated, ok, 2026-10-12T18:55:50Z]: Group scenario adaptation: version and patch data (added by group (simulated), 2026-10-11)
  - R1 `lookup_vulnerability` T1 http://127.0.0.1:9/unreachable?cveId=CVE-2026-85880 [cached, cached, 2026-10-12T18:54:52Z]: affected product windows_server_2022: listed; fixed build 10.0.20348.5622
  - R2 `lookup_kev` T2 https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json [live, live, 2026-10-12T18:55:37Z]: CVE listed in CISA KEV

### E02 Legacy workstations (stale sensors): INSUFFICIENT_EVIDENCE

- **Role / zone:** Legacy Windows 10 (ESU) / LEGACY
- **Applicability:** Unknown. OS build unknown (decisive)
- **Impact:** P3 (matrix: no_pii x intranet)
- **Rule:** gate: decisive fact unknown or conflicting -> INSUFFICIENT_EVIDENCE (analyst review)
- **Confidence:** None (no rating, so no confidence level; see the applicability reason)
- **Recommended action** (model (rating fixed by policy code)): 1) Retrieve the exact Windows 10 Enterprise build number from each legacy workstation. 2) Compare the build to the fixed build 10.0.19045.7725 to determine vulnerability status. 3) Verify network reachability and exposure of the workstations to confirm whether they are internet‑facing or internal only.
- **Would change the decision:** The OS build version of the workstations (the decisive fact currently unknown).
- **Decisive unknowns:** os.build
- **Assumptions:** none
- **Evidence:**
  - R17 `lookup_environment`  northbridge-v1.1.json#assets[27] [simulated, ok, 2026-10-12T18:56:13Z]: asset record: OS Windows 10 Enterprise build None, low_priv_local_access=True, data=none/n/a, exposure=intranet
  - R8 `lookup_environment` S03 northbridge-v1.1.json#evidence[2] [simulated, ok, 2026-10-12T18:55:49Z]: Control and exception register (course scenario v1.0, 2026-10-01)
  - R18 `lookup_environment` S04 northbridge-v1.1.json#evidence[3] [simulated, ok, 2026-10-12T18:56:16Z]: Telemetry coverage summary (course scenario v1.0, 2026-10-01)
  - R11 `lookup_environment` S08 northbridge-v1.1.json#evidence[7] [simulated, ok, 2026-10-12T18:55:50Z]: Group scenario adaptation: version and patch data (added by group (simulated), 2026-10-11)
  - R1 `lookup_vulnerability` T1 http://127.0.0.1:9/unreachable?cveId=CVE-2026-85880 [cached, cached, 2026-10-12T18:54:52Z]: affected product windows_10_22h2: listed; fixed build 10.0.19045.7725

## Human review

Pending. Use `docs/evidence_review.md`.
