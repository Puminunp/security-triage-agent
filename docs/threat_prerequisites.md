# Threat prerequisites: CVE-2026-85880

**Threat:** Heap-based buffer overflow in Windows Advanced Local Procedure Call (ALPC) that lets an authorized local attacker elevate privileges to SYSTEM.
**CVSS v3.1:** 7.8 High, `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` · **KEV:** yes, added 2026-09-08 · **Sources:** T1, T2 (see `inputs/SOURCES.md`)

## What an attacker needs

| # | Prerequisite | How it shows up in the vector | Environment field | Decisive? |
|---|---|---|---|---|
| 1 | The target runs an affected Windows version | Affected-products list | `os.name`, `os.version` | **Yes** |
| 2 | The target's build is below the fixed build | Fixed builds in NVD/MSRC | `os.build` (cross-check `last_cumulative_update`) | **Yes** |
| 3 | The attacker can already run code as a low-privileged local user | `AV:L`, `PR:L` | `low_priv_local_access` | **Yes** |
| 4 | No user interaction needed | `UI:N` | — | No (always true) |

If any decisive fact is `null` or conflicting, the result is INSUFFICIENT_EVIDENCE.

## Fixed builds (anything lower is vulnerable)

| Product | First fixed build |
|---|---|
| Windows Server 2016 / Windows 10 1607 | 10.0.14393.9512 |
| Windows Server 2019 / Windows 10 1809 | 10.0.17763.9245 |
| Windows Server 2022 | 10.0.20348.5622 |
| Windows 10 21H2 | 10.0.19044.7725 |
| Windows 10 22H2 | 10.0.19045.7725 |
| Windows Server 2012 / 2012 R2 | 6.2.9200.26349 / 6.3.9600.23398 |
| Windows 11, Windows Server 2025 | Not affected |

## Non-decisive facts (reported as context or unknowns)

- Defender for Endpoint coverage on servers (not stated for servers in the scenario)
- Log coverage: AD authentication logs are retained 90 days (S04), which helps detection but doesn't block the attack
- Service account `svc_finlegacy` password age of 180 days and the NTLM exception (S03). These make it easier to obtain the low-privilege foothold the attack needs, so mention them in the rationale and recommended action

## How the attack would chain at Northbridge

1. Attacker gains a low-privileged foothold: phishing a payroll operator, or reusing the stale `svc_finlegacy` credential over NTLM.
2. Attacker logs on to W15 (FINLEG01–02) from the USERS zone (flow F07).
3. Attacker exploits CVE-2026-85880 to become SYSTEM on W15.
4. Attacker reads or changes payroll and banking data for 1,000 employees, or uses SYSTEM access to move further.

## Expected applicability across the environment (base snapshot)

| Asset | Build | Applicability | Reason |
|---|---|---|---|
| **W15** | 14393.9339 | **Confirmed** | Below 9512; non-admin logon exists (A15) |
| W02 CA-ROOT01 | 20348.5256 | **Partial** | Below 5622, but the server is isolated and powered off, with no low-privilege access path |
| Other Server 2022 servers | 20348.5622 | Not applicable | At the fixed build |
| E02, 28 devices | 19045.7725 | Not applicable | At the fixed build |
| E02, 12 stale-sensor devices | unknown | **Unknown** | Decisive fact missing |
| E01, E03 (Windows 11) | — | Not applicable | Product not affected |
| Linux, macOS, appliances, cloud | — | Not applicable | Not Windows |
