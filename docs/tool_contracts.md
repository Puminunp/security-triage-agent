# Tool contracts

The agent has three tools. The model sees their schemas in `registry.TOOL_SCHEMAS`; code runs them through `registry.execute()`. Tools return evidence only. They never rate anything: the rating comes from the policy code (`docs/rating_policy.md`).

| Tool | Reads | Code |
|---|---|---|
| `lookup_vulnerability` | NVD CVE API 2.0 (live) | `src/sources/nvd.py` |
| `lookup_kev` | CISA KEV JSON feed (live) | `src/sources/kev.py` |
| `lookup_environment` | Northbridge snapshot (simulated) | `src/tools/environment.py` |

## Calling a tool

```python
from src.tools import registry

registry.TOOL_SCHEMAS            # list of {"name", "description", "parameters"} for the model
result = registry.execute("lookup_environment", {"action": "get_asset", "query": "W15"})

# Tests: point the environment tool at a variant. The model cannot set this.
result = registry.execute("lookup_environment", {"action": "get_asset", "query": "W15"},
                          snapshot_path="environment/variants/env_missing.json")
```

`execute()` never raises. Every call, valid or not, returns the same wrapper:

| Field | Meaning |
|---|---|
| `tool`, `args` | The call as received |
| `status` | `live` (fresh external data), `cached` (live call failed, cached copy returned), `ok` (environment match), `not_found` (no match), `error` (no data) |
| `source` | URL for external lookups; snapshot locator such as `northbridge-v1.1.json#assets[17]` for the environment |
| `retrieved_at` | UTC time the data was fetched. For `cached`, the time the cached copy was saved |
| `source_mode` | `live`, `cached` or `simulated`. `null` when the call was rejected before running |
| `data` | The result, or `null` on `error` |
| `unknown_fields` | Paths of values that are null or missing in `data`. These are unknown, not false and not zero |
| `error` | Reason for an `error`. For `cached`, the reason the live call failed. Otherwise `null` |

### Validation

Calls are checked before anything runs. A rejected call returns `status: "error"` and never reaches the network or the snapshot.

| Problem | Example | `error` |
|---|---|---|
| Unknown tool | `execute("nope", {})` | `unknown tool: 'nope'. Available tools: ...` |
| Missing argument | `{"action": "get_asset"}` | `invalid arguments: missing required argument(s): query` |
| Extra argument | `{"cve_id": "...", "x": 1}` | `invalid arguments: unknown argument(s): x` |
| Wrong type or empty string | `{"action": "get_asset", "query": 15}` | `invalid arguments: argument 'query' must be of type string` |
| Bad CVE ID | `{"cve_id": "CVE-123"}` | `invalid arguments: argument 'cve_id' must match ^CVE-\d{4}-\d{4,}$` |
| Unknown action | `{"action": "delete_asset", ...}` | `invalid arguments: argument 'action' must be one of: ...` |

The registry does not count rejected calls. The "stop after 3 rejected calls" rule (rating policy section 8) belongs to the agent loop: count results with `status == "error"` and `source_mode is None`.

### Failure behavior (external lookups)

Follows rating policy section 8.

1. The live call is tried, then retried once after `retry_wait_seconds` (timeout 15 s each; `config/settings.yaml`).
2. If both fail and a cached copy exists, it is returned with `status: "cached"`, `source_mode: "cached"` and the failure reason in `error`. The policy caps confidence at Medium.
3. If both fail and there is no cache, the result is `status: "error"` with `data: null`. For a decisive fact the policy stops with INSUFFICIENT_EVIDENCE.

A response is cached only if it is valid JSON of the expected shape, so an error page never overwrites good data. Timeouts, connection errors, HTTP 4xx/5xx and malformed bodies all count as failures. No field is ever filled in from anywhere but the source.

## lookup_vulnerability

| | |
|---|---|
| **Purpose** | Get the facts about one CVE from NVD: what it is, how severe, which products and builds are affected |
| **Inputs** | `cve_id` (string, required, must match `^CVE-\d{4}-\d{4,}$`) |
| **Outputs** (`data`) | `cve_id`, `description`, `published`, `last_modified`, `vuln_status`; `cvss_v31` {`base_score`, `base_severity`, `vector`, `source`, `type`, `score_used`}; `cwe` []; `kev` {`in_kev`, `cisaExploitAdd`, `cisaActionDue`, `cisaRequiredAction`}; `affected_products` [] of {`product`, `cpe`, `vulnerable`, `versionStartIncluding`, `versionEndExcluding`}; `cna_affected` [] of {`source`, `product`, `status`, `version_start`, `lessThan`}; `references` [] of {`url`, `tags`} |
| **Source attribution** | `source` is the request URL (source T1 in `inputs/SOURCES.md`). `cvss_v31.score_used` says which score was taken: `nvd_primary` (NVD's own, `type: Primary`) if present, else `cna_secondary` (the vendor's). For CVE-2026-85880 it is the Microsoft CNA score |
| **Role in the risk decision** | Supplies severity (CVSS band, policy step 3) and the fixed build that the asset's `os.build` is compared with (applicability gate, step 1). `versionEndExcluding` is the first fixed build; anything lower is vulnerable. The `kev` block is NVD's copy of the KEV fields; `lookup_kev` is the primary source for the KEV modifier |
| **Unknowns** | A CPE row with no `versionEndExcluding` keeps `null` and is listed, e.g. `affected_products[10].versionEndExcluding` (Windows Server 2012). The vendor's number, if NVD carries it, is in `cna_affected[].lessThan`, kept separate so its origin stays clear |
| **Failure behavior** | Retry once, then cache, then error (see above). A CVE ID that NVD has no record for returns `status: "not_found"`; that is an answer from NVD, so the cache is not used |

`affected_products` has one row per CPE as NVD lists them (x64, x86 and arm64 rows are separate). `product` is the CPE vendor and product, e.g. `microsoft windows_server_2016`.

## lookup_kev

| | |
|---|---|
| **Purpose** | Check whether a CVE is in the CISA Known Exploited Vulnerabilities catalog |
| **Inputs** | `cve_id` (string, required, must match `^CVE-\d{4}-\d{4,}$`) |
| **Outputs** (`data`) | `cve_id`, `in_kev` (true/false), `catalog_version`, `catalog_date_released`, `entry` (the feed entry unchanged: `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`, `shortDescription`, `requiredAction`, `dueDate`, `knownRansomwareCampaignUse`, `notes`, `cwes`, ...) or `null`; `note` when not listed |
| **Source attribution** | `source` is the feed URL (source T2). `catalog_version` and `catalog_date_released` identify the catalog edition that was read |
| **Role in the risk decision** | Decides the KEV modifier (policy step 5: KEV +1). `dateAdded` and `dueDate` support the recommended action |
| **Not listed** | `status` stays `live` (or `cached`), `in_kev: false`, `entry: null`, `note: "absence from KEV does not establish safety"` |
| **Failure behavior** | Retry once, then cache, then error. The whole feed is cached as `cache/kev_feed.json`, so the fallback works for any CVE, including "not listed" answers as of the cached catalog version |

## lookup_environment

| | |
|---|---|
| **Purpose** | Read facts about Northbridge assets, evidence, network flows, documented absences and business services from the environment snapshot |
| **Inputs** | `action` (required, one of the six below), `query` (string, required), `limit` (integer 1 to 50, `search_assets` only, default 10) |
| **Outputs** (`data`) | Always `snapshot_id`, `locator`, `query`; then the fields for the action (below); `note` when there is one |
| **Source attribution** | `source_mode` is always `simulated`. `source` and `data.locator` point into the snapshot file, e.g. `northbridge-v1.1.json#assets[17]`. Asset records carry `evidence_ids` (S01 to S08) to cite |
| **Role in the risk decision** | Supplies the three decisive facts for the applicability gate (`os.name`/`os.version`, `os.build`, `low_priv_local_access`) and the inputs for machine priority (`data_classification`, `data_protection`, `exposure`, `priority_override`). `get_evidence` lets the agent cross-check an asset fact against the evidence it cites; a disagreement on a decisive fact means INSUFFICIENT_EVIDENCE |
| **Unknowns** | Values are returned exactly as stored. `null` stays `null` and its path is listed in `unknown_fields`, nested paths included (`os.build`, `config.encryption_at_rest`) |
| **Failure behavior** | Empty or non-string input, a bad `limit`, or an unreadable snapshot file returns `status: "error"`. No match returns `status: "not_found"` with the note `no match does not prove absence; only check_absence can` |

| Action | `query` is | Returns in `data` |
|---|---|---|
| `get_asset` | Asset ID (`W15`), instance (`FINLEG01-FINLEG02`) or one hostname (`FINLEG01`); case-insensitive | `matches` [] of {`locator`, `unknown_fields`, `asset`}. One asset ID can have several records (W02, W05, W13, E02) |
| `search_assets` | Text, matched case-insensitively against every field of every asset | `total_matches`, `matches` [] (same shape, at most `limit`) |
| `get_evidence` | Evidence ID `S01` to `S08` | `evidence` {`evidence_id`, `title`, `date`, `origin`, `facts`, `limitations`} |
| `get_flows` | Zone ID, e.g. `LEGACY` | `zone`, `inbound` [], `outbound` [], `default_policy` |
| `check_absence` | Exact product name, case-insensitive | `absent` (true or null), `matched_entry`, and `similar_entries` when there is no exact match |
| `get_business_service` | Service name from an asset's `business_service` | `business_service` {`service`, `consequence`, `rto`, `rpo`} |

Notes for callers:

- **Where unknowns appear.** Each match has its own `unknown_fields` relative to the asset (`os.build`). The wrapper's `unknown_fields` holds the same paths qualified by record (`assets[17].os.build`), so they stay distinct when several records match.
- **Nulls that are not gaps.** Every null is listed, as the handoff requires. Two fields are null by design on most assets: `priority_override` (no override) and `business_service` (none assigned). See `field_definitions` in the snapshot. Neither is a decisive fact.
- **`check_absence` is strict.** Only an exact name on the `absences` list gives `absent: true`. `"Windows"` does not match `"Windows Server 2019"`; it returns `not_found`, `absent: null` and the near matches in `similar_entries`. `absent` is never `false`: not being on the list says nothing either way.
- **Variants.** The tool returns the snapshot's own `snapshot_id` and file name. For the test variants these name the test (`northbridge-v1.1-missing_evidence`, `env_missing.json`), which a model could read as a hint. The `variant_of` and `variant_change` fields are never returned.

## Examples

Real calls and responses from a run on 2026-10-12 (UTC) against the base snapshot. Long lists are cut where marked; nothing else is edited.

### lookup_vulnerability

`affected_products` has 15 rows and `cna_affected` 13; the rows not shown follow the same pattern.

Request:

```python
registry.execute("lookup_vulnerability", {"cve_id": "CVE-2026-85880"})
```

Response:

```json
{
  "tool": "lookup_vulnerability",
  "args": {
    "cve_id": "CVE-2026-85880"
  },
  "status": "live",
  "source": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-85880",
  "retrieved_at": "2026-10-12T00:52:04Z",
  "source_mode": "live",
  "data": {
    "cve_id": "CVE-2026-85880",
    "description": "Heap-based buffer overflow in Windows ALPC allows an authorized attacker to elevate privileges locally.",
    "published": "2026-09-08T18:21:14.087",
    "last_modified": "2026-09-24T23:19:20.773",
    "vuln_status": "Analyzed",
    "cvss_v31": {
      "base_score": 7.8,
      "base_severity": "HIGH",
      "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
      "source": "secure@microsoft.com",
      "type": "Secondary",
      "score_used": "cna_secondary"
    },
    "cwe": [
      "CWE-122",
      "CWE-908"
    ],
    "kev": {
      "in_kev": true,
      "cisaExploitAdd": "2026-09-08",
      "cisaActionDue": "2026-09-22",
      "cisaRequiredAction": "Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines."
    },
    "affected_products": [
      {
        "product": "microsoft windows_10_1607",
        "cpe": "cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:x64:*",
        "vulnerable": true,
        "versionStartIncluding": null,
        "versionEndExcluding": "10.0.14393.9512"
      },
      "... rows 1-9 omitted ...",
      {
        "product": "microsoft windows_server_2012",
        "cpe": "cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*",
        "vulnerable": true,
        "versionStartIncluding": null,
        "versionEndExcluding": null
      },
      {
        "product": "microsoft windows_server_2012 r2",
        "cpe": "cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*",
        "vulnerable": true,
        "versionStartIncluding": null,
        "versionEndExcluding": null
      },
      {
        "product": "microsoft windows_server_2016",
        "cpe": "cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:*:*",
        "vulnerable": true,
        "versionStartIncluding": null,
        "versionEndExcluding": "10.0.14393.9512"
      },
      {
        "product": "microsoft windows_server_2019",
        "cpe": "cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*",
        "vulnerable": true,
        "versionStartIncluding": null,
        "versionEndExcluding": "10.0.17763.9245"
      },
      {
        "product": "microsoft windows_server_2022",
        "cpe": "cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*",
        "vulnerable": true,
        "versionStartIncluding": null,
        "versionEndExcluding": "10.0.20348.5622"
      }
    ],
    "cna_affected": [
      {
        "source": "secure@microsoft.com",
        "product": "Windows 10 Version 1607",
        "status": "affected",
        "version_start": "10.0.14393.0",
        "lessThan": "10.0.14393.9512"
      },
      "... 12 more rows omitted ..."
    ],
    "references": [
      {
        "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-85880",
        "tags": [
          "Patch",
          "Vendor Advisory"
        ]
      },
      {
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-85880",
        "tags": [
          "US Government Resource"
        ]
      }
    ]
  },
  "unknown_fields": [
    "affected_products[10].versionEndExcluding",
    "affected_products[11].versionEndExcluding"
  ],
  "error": null
}
```

### lookup_vulnerability: live call fails, cached copy returned

Same call with `nvd_base_url` pointed at an unreachable host. `retrieved_at` is when the cached copy was saved.

Request:

```python
registry.execute("lookup_vulnerability", {"cve_id": "CVE-2026-85880"})
```

Response:

```json
{
  "tool": "lookup_vulnerability",
  "args": {
    "cve_id": "CVE-2026-85880"
  },
  "status": "cached",
  "source": "http://127.0.0.1:9/unreachable?cveId=CVE-2026-85880",
  "retrieved_at": "2026-10-12T00:52:04Z",
  "source_mode": "cached",
  "data": "... same fields as the live response above ...",
  "unknown_fields": [
    "affected_products[10].versionEndExcluding",
    "affected_products[11].versionEndExcluding"
  ],
  "error": "lookup failed after 2 attempts (ConnectionError: HTTPConnectionPool(host='127.0.0.1', port=9): Max retries exceeded with url: /unreachable?cveId=CVE-2026-85880 (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0x000001FBA5EEDE50>: Failed to establish a new connection: [WinError 10061] No connection could be made because the target machine actively refused it')))"
}
```

### lookup_vulnerability: live call fails, no cache

Request:

```python
registry.execute("lookup_vulnerability", {"cve_id": "CVE-2026-85880"})
```

Response:

```json
{
  "tool": "lookup_vulnerability",
  "args": {
    "cve_id": "CVE-2026-85880"
  },
  "status": "error",
  "source": "http://127.0.0.1:9/unreachable?cveId=CVE-2026-85880",
  "retrieved_at": "2026-10-12T00:55:01Z",
  "source_mode": "live",
  "data": null,
  "unknown_fields": [],
  "error": "lookup failed after 2 attempts (ConnectionError: HTTPConnectionPool(host='127.0.0.1', port=9): Max retries exceeded with url: /unreachable?cveId=CVE-2026-85880 (Caused by NewConnectionError('<urllib3.connection.HTTPConnection object at 0x000001FBA5E93360>: Failed to establish a new connection: [WinError 10061] No connection could be made because the target machine actively refused it'))); no cached copy"
}
```

### lookup_kev

Request:

```python
registry.execute("lookup_kev", {"cve_id": "CVE-2026-85880"})
```

Response:

```json
{
  "tool": "lookup_kev",
  "args": {
    "cve_id": "CVE-2026-85880"
  },
  "status": "live",
  "source": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
  "retrieved_at": "2026-10-12T00:52:04Z",
  "source_mode": "live",
  "data": {
    "cve_id": "CVE-2026-85880",
    "in_kev": true,
    "catalog_version": "2026.10.08",
    "catalog_date_released": "2026-10-08T20:09:18.9833Z",
    "entry": {
      "cveID": "CVE-2026-85880",
      "vendorProject": "Microsoft",
      "product": "Windows",
      "vulnerabilityName": "Microsoft Windows Heap-Based Buffer Overflow Vulnerability",
      "dateAdded": "2026-09-08",
      "shortDescription": "Microsoft Windows Advanced Local Procedure Call contains a heap-based buffer overflow vulnerability that allows an attacker to elevate privileges locally.",
      "requiredAction": "Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Security Updates Based on Risk (see URL in Notes) guidance and CISA’s “Forensics Triage Requirements” (see URL in Notes). Follow applicable BOD 26-04 guidance for cloud services or discontinue use of the product if mitigations are unavailable. Stakeholders are responsible for evaluating each asset's internet exposure and ensuring adherence to BOD 26-04 patching guidelines.",
      "dueDate": "2026-09-22",
      "knownRansomwareCampaignUse": "Unknown",
      "forensicTriage": "No",
      "notes": "https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2026-85880 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk ; Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk ; https://nvd.nist.gov/vuln/detail/CVE-2026-85880",
      "cwes": [
        "CWE-122",
        "CWE-908"
      ]
    }
  },
  "unknown_fields": [],
  "error": null
}
```

### lookup_environment: get_asset

Request:

```python
registry.execute("lookup_environment", {"action": "get_asset", "query": "W15"})
```

Response:

```json
{
  "tool": "lookup_environment",
  "args": {
    "action": "get_asset",
    "query": "W15"
  },
  "status": "ok",
  "source": "northbridge-v1.1.json#assets[17]",
  "retrieved_at": "2026-10-12T00:52:04Z",
  "source_mode": "simulated",
  "data": {
    "snapshot_id": "northbridge-v1.1",
    "locator": "northbridge-v1.1.json#assets[17]",
    "query": "W15",
    "matches": [
      {
        "locator": "northbridge-v1.1.json#assets[17]",
        "unknown_fields": [
          "priority_override",
          "config.encryption_at_rest"
        ],
        "asset": {
          "asset_id": "W15",
          "instance": "FINLEG01-FINLEG02",
          "count": 2,
          "role": "Legacy finance application servers",
          "zone": "LEGACY",
          "os": {
            "name": "Windows Server 2016",
            "version": "1607",
            "build": "10.0.14393.9339",
            "last_cumulative_update": "2026-07",
            "last_update_kb": "KB5099535"
          },
          "software": [
            {
              "name": "Northbridge Finance Legacy",
              "version": "2.8 (fictional)"
            },
            ".NET Framework 4.8"
          ],
          "data_classification": "restricted_pii",
          "data_protection": "unprotected",
          "exposure": "intranet",
          "priority_override": null,
          "low_priv_local_access": true,
          "business_service": "payroll_legacy_finance",
          "controls": [],
          "config": {
            "ntlm_allowed": true,
            "ntlm_exception_account": "svc_finlegacy",
            "service_account_password_age_days": 180,
            "patch_approval_recorded_days_before_snapshot": 60,
            "encryption_at_rest": null
          },
          "evidence_ids": [
            "S03",
            "S05",
            "S07",
            "S08"
          ],
          "notes": "Payroll export and reconciliation for 1,000 employees. Payroll operators (non-admin) log on to run exports.",
          "source_mode": "simulated"
        }
      }
    ]
  },
  "unknown_fields": [
    "assets[17].priority_override",
    "assets[17].config.encryption_at_rest"
  ],
  "error": null
}
```

### lookup_environment: get_evidence

Request:

```python
registry.execute("lookup_environment", {"action": "get_evidence", "query": "S08"})
```

Response:

```json
{
  "tool": "lookup_environment",
  "args": {
    "action": "get_evidence",
    "query": "S08"
  },
  "status": "ok",
  "source": "northbridge-v1.1.json#evidence[7]",
  "retrieved_at": "2026-10-12T00:52:04Z",
  "source_mode": "simulated",
  "data": {
    "snapshot_id": "northbridge-v1.1",
    "locator": "northbridge-v1.1.json#evidence[7]",
    "query": "S08",
    "evidence": {
      "evidence_id": "S08",
      "title": "Group scenario adaptation: version and patch data",
      "date": "2026-10-11",
      "origin": "added by group (simulated)",
      "facts": [
        "OS builds, last cumulative update months and software versions per asset, using real vendor release numbers current as of 2026-10-01",
        "W15: Windows Server 2016 build 10.0.14393.9339 (July 2026 update, KB5099535)",
        "Other Windows Server 2022 servers: build 10.0.20348.5622 (September 2026, KB5122882), except offline root CA at 10.0.20348.5256 (June 2026)",
        "E02: 28 devices at 10.0.19045.7725 (September 2026); 12 stale-sensor devices unknown"
      ],
      "limitations": "Version assignment to Northbridge assets is simulated; version numbers are real releases."
    }
  },
  "unknown_fields": [],
  "error": null
}
```

### lookup_environment: get_flows

Request:

```python
registry.execute("lookup_environment", {"action": "get_flows", "query": "LEGACY"})
```

Response:

```json
{
  "tool": "lookup_environment",
  "args": {
    "action": "get_flows",
    "query": "LEGACY"
  },
  "status": "ok",
  "source": "northbridge-v1.1.json#flows[6]",
  "retrieved_at": "2026-10-12T00:52:04Z",
  "source_mode": "simulated",
  "data": {
    "snapshot_id": "northbridge-v1.1",
    "locator": "northbridge-v1.1.json#flows[6]",
    "query": "LEGACY",
    "zone": {
      "zone_id": "LEGACY",
      "hq_subnet": "10.20.70.0/24",
      "purpose": "Legacy workstations and finance VMs"
    },
    "inbound": [
      {
        "flow_id": "F07",
        "from": "USERS",
        "to": "LEGACY",
        "ports": [
          "443/tcp",
          "3389/tcp"
        ],
        "purpose": "Payroll operators to legacy finance application (assumption A15)"
      }
    ],
    "outbound": [],
    "default_policy": "Deny unlisted inter-zone traffic and unsolicited Internet ingress (S02)"
  },
  "unknown_fields": [],
  "error": null
}
```

### lookup_environment: check_absence

Request:

```python
registry.execute("lookup_environment", {"action": "check_absence", "query": "Kubernetes"})
```

Response:

```json
{
  "tool": "lookup_environment",
  "args": {
    "action": "check_absence",
    "query": "Kubernetes"
  },
  "status": "ok",
  "source": "northbridge-v1.1.json#absences[0]",
  "retrieved_at": "2026-10-12T00:52:04Z",
  "source_mode": "simulated",
  "data": {
    "snapshot_id": "northbridge-v1.1",
    "locator": "northbridge-v1.1.json#absences[0]",
    "query": "Kubernetes",
    "absent": true,
    "matched_entry": "Kubernetes"
  },
  "unknown_fields": [],
  "error": null
}
```

### lookup_environment: get_business_service

Request:

```python
registry.execute("lookup_environment", {"action": "get_business_service", "query": "payroll_legacy_finance"})
```

Response:

```json
{
  "tool": "lookup_environment",
  "args": {
    "action": "get_business_service",
    "query": "payroll_legacy_finance"
  },
  "status": "ok",
  "source": "northbridge-v1.1.json#business_services[2]",
  "retrieved_at": "2026-10-12T00:52:04Z",
  "source_mode": "simulated",
  "data": {
    "snapshot_id": "northbridge-v1.1",
    "locator": "northbridge-v1.1.json#business_services[2]",
    "query": "payroll_legacy_finance",
    "business_service": {
      "service": "payroll_legacy_finance",
      "consequence": "Payroll disruption or disclosure/change of banking and HR data",
      "rto": "8h",
      "rpo": "4h"
    }
  },
  "unknown_fields": [],
  "error": null
}
```

### lookup_environment: search_assets with no match

Request:

```python
registry.execute("lookup_environment", {"action": "search_assets", "query": "nonexistent"})
```

Response:

```json
{
  "tool": "lookup_environment",
  "args": {
    "action": "search_assets",
    "query": "nonexistent"
  },
  "status": "not_found",
  "source": "northbridge-v1.1.json#assets",
  "retrieved_at": "2026-10-12T00:52:04Z",
  "source_mode": "simulated",
  "data": {
    "snapshot_id": "northbridge-v1.1",
    "locator": "northbridge-v1.1.json#assets",
    "query": "nonexistent",
    "total_matches": 0,
    "matches": [],
    "note": "no match does not prove absence; only check_absence can"
  },
  "unknown_fields": [],
  "error": null
}
```

### Rejected call: invalid CVE ID

Request:

```python
registry.execute("lookup_vulnerability", {"cve_id": "CVE-123"})
```

Response:

```json
{
  "tool": "lookup_vulnerability",
  "args": {
    "cve_id": "CVE-123"
  },
  "status": "error",
  "source": null,
  "retrieved_at": "2026-10-12T00:52:04Z",
  "source_mode": null,
  "data": null,
  "unknown_fields": [],
  "error": "invalid arguments: argument 'cve_id' must match ^CVE-\\d{4}-\\d{4,}$"
}
```
