# Changes from the supplied scenario (v1.0 → northbridge-v1.1)

The course-supplied **Northbridge Windows Enterprise Environment, scenario version 1.0**, is kept unchanged. Our adapted snapshot is `northbridge-v1.1.json`. Every addition below is **simulated** and is cited through evidence **S07** (assumptions) or **S08** (versions).

> **Reconcile with the official JSON.** v1.1 was built from the scenario document. Before freezing the baseline, compare it with the course's `windows_enterprise_environment.json` and copy over any asset IDs, flow IDs (the official file has 16 flows) and owner fields that differ. Note any differences here.

## 1. New fields added to every asset

| Field | Why we added it |
|---|---|
| `data_classification` | Drives the PII row of the machine priority matrix |
| `data_protection` | Splits PII into "with protection" and "without protection" |
| `exposure` | Drives the exposure column of the priority matrix |
| `priority_override` | Records why an asset is forced to P1 (Tier-0, control plane, 4-hour RTO) |
| `low_priv_local_access` | Prerequisite for local privilege-escalation CVEs such as CVE-2026-85880 |
| `os.build`, `os.last_cumulative_update`, `os.last_update_kb` | Lets the agent compare builds with the CVE's fixed builds |
| `source_mode: simulated` | Required labeling on every local record |

Priority itself is **not** stored in the snapshot. The policy code computes it from these fields, so facts and rating logic stay separate.

## 2. Cohorts split into instances

| Original | Split into | Reason |
|---|---|---|
| W02 Certificate authorities (2) | CA-ISSUING01, CA-ROOT01 | The offline root has different exposure (isolated) and patch level (June 2026) |
| W05 File servers (4) | FILE01–FILE03, FILE04 | FILE04 has different settings (S03) and holds the Finance/HR shares (A1) |
| W13 Intranet and portal (4) | PORTAL01–02, INTRA01–02 | Portal backends hold customer PII and are internet-facing through the proxy |
| E02 Legacy workstations (40) | 28 with healthy sensors, 12 with stale sensors | S04 says 12 sensors are stale, so their patch state can't be confirmed |

## 3. Assumptions (evidence S07)

| ID | Assumption | Affects |
|---|---|---|
| A1 | The Finance and HR shares are on FILE04; FILE01–03 hold general departmental shares only | W05 priority |
| A2 | Share access is limited by AD groups (stated), but encryption at rest and access logging are undocumented, so FILE04 is "unprotected" | W05 priority |
| A3 | Print servers do not keep print jobs after printing | W06 data |
| A4 | RDS hosts deliver applications but store no PII locally | W10 data |
| A5 | Portal backends count as internet-exposed indirectly, through the WAF and reverse proxy. The scenario notes that front-end exposure does not prove direct backend exposure; we chose the cautious reading | W13 exposure |
| A6 | W15 is reachable from the USERS zone (flow F07), so its exposure is "intranet" | W15 exposure |
| A7 | Integration and batch hosts pass data through without storing it | W16 data |
| A8 | Logs (usernames, IP addresses) are not treated as PII in this policy | W18, C03 |
| A9 | Partner order files on the SFTP servers contain customer names and addresses | L02 data |
| A10 | Git repositories contain no PII; secrets in code are out of scope | L03 data |
| A11 | User files sync to OneDrive (C02), so endpoints store no PII locally | E01–E05 data |
| A12 | Backup repositories are encrypted (the scenario states only "immutable" and "hardened") | N08 protection |
| A13 | Storage array encryption is undocumented, so storage is "unprotected" | N09 protection |
| A14 | Microsoft 365 data is encrypted at rest and protected by MFA, apart from the two emergency-account exceptions | C02 protection |
| A15 | Payroll operators (non-administrators) log on to W15 to run exports, and the NTLM service account `svc_finlegacy` runs there, so a low-privilege local access path exists | W15 applicability |

## 4. Version and patch data (evidence S08)

The scenario intentionally left builds and KBs unknown. We added real vendor version numbers that were current on the snapshot date (2026-10-01). Assigning them to Northbridge assets is simulated.

| Assets | Version added |
|---|---|
| W01–W14, W16–W18 (except CA-ROOT01) | Windows Server 2022, build 10.0.20348.5622 (KB5122882, Sept 2026) |
| CA-ROOT01 | Windows Server 2022, build 10.0.20348.5256 (KB5094128, June 2026); powered off since |
| **W15** | **Windows Server 2016, build 10.0.14393.9339 (KB5099535, July 2026)**. Consistent with the scenario's "patch approval recorded 60 days before snapshot" |
| E01, E03 | Windows 11 24H2, build 10.0.26100.9445 (KB5124008, Sept 2026) |
| E02 (28) | Windows 10 22H2 ESU, build 10.0.19045.7725 (KB5122878, Sept 2026) |
| E02 (12 stale) | **Unknown (null)**, kept from the original |
| Software | Entra Connect 2.6.92.0; ConfigMgr 2603; Veeam 12.3.2.4854; SQL Server 2022 CU27 (W12) and CU26 (W14); GitLab 19.4.1; ESXi 8.0 U3k; PAN-OS 11.1.13; FortiOS 7.4.12; BIG-IP 17.1.3.5; IOS XE 17.15.6; ISE 3.3 P11; PowerStoreOS 4.3.1.2 |
| Still unknown | macOS version, AP and printer firmware, Docker exact version |

Versions marked "verify" in the JSON (PAN-OS, FortiOS, Catalyst 9800, vCenter, Docker) must be checked on vendor sites before the baseline is frozen.

## 5. Other additions

- **Flows F01–F12** were written from the scenario's description of main paths. F07 (USERS → LEGACY for payroll operators) is our assumption A6/A15.
- **Absences list:** added "On-premises Exchange" (stated in the scenario) and "Windows Server 2025, 2019, 2012". The last three are **derived**: the W01–W18 table accounts for all 52 Windows server VMs, all on 2022 or 2016, and S06 says the register is complete.
- **Unknowns list** made explicit (see the JSON).

## 6. Errors or simplifications found in the original

| Item | Observation | Action |
|---|---|---|
| Patch state | The scenario intentionally omitted installed KBs, which makes any CVE assessment insufficient-evidence | Added S08 versions; kept unknowns for E02 (12), E04, N11, P01 |
| "SMB 3" on W05 | Server 2022 uses SMB 3.1.1 | Recorded as SMB 3.1.1 |
| W13 count | "Intranet and customer portal servers (4)" is two separate roles | Split into two records |

No other technical errors were found that affect this case. Add any further findings here.

## 7. Test variants

Generated by `environment/make_variants.py`. Each changes exactly one thing; the base file is never edited.

| File | Change | Policy check |
|---|---|---|
| `variants/env_patched.json` | W15 patched to the September 2026 build (asset record and S08 together) | Applicability change, impact held constant |
| `variants/env_low_priority.json` | W15 holds no PII and is reachable only from restricted zones | Impact change, applicability held constant |
| `variants/env_missing.json` | W15 build and patch date set to null, W15 line removed from S08 | Missing evidence |
| `variants/env_conflict.json` | S08 says W15 was patched in September; the asset record still says July | Conflicting evidence |
