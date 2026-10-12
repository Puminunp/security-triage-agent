# Handoff from Student A

## To Student B (tools)

**Environment lookup** must read `environment/northbridge-v1.1.json` (path from config, so tests can point to a variant) and return these fields for each asset:

`asset_id`, `instance`, `count`, `role`, `zone`, `os.name`, `os.version`, `os.build`, `os.last_cumulative_update`, `os.last_update_kb`, `software`, `data_classification`, `data_protection`, `exposure`, `priority_override`, `low_priv_local_access`, `business_service`, `controls`, `config`, `evidence_ids`, `notes`, `source_mode`

Also expose:
- `get_evidence(evidence_id)` for S01–S08. Note that S08 holds a W15 build line that can disagree with the asset record (that's the conflict test).
- `get_flows(zone)` for reachability.
- `check_absence(product)` reading the `absences` list.
- `get_business_service(name)` reading `business_services`.

Rules: `null` stays `null` and is listed in `unknown_fields`; a no-match result says "does not prove absence"; every result carries `source_mode: simulated`, `snapshot_id` and a locator such as `northbridge-v1.1.json#assets[17]`.

**External lookups** for this case:
- NVD: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-85880`. Return the CVSS v3.1 score and vector (Microsoft CNA, `type: Secondary`), the KEV fields, and the CPE `versionEndExcluding` values.
- KEV: the CISA JSON feed, filtered to the CVE.
- Save raw responses into `cache/` and replace the transcribed files in `inputs/` (see `inputs/SOURCES.md`).

## To Student C (agent and policy code)

- Implement `docs/rating_policy.md` in `src/policy.py`. It must produce the same results as `reference/policy_reference.py` on the base snapshot and all four variants. Run both and compare.
- Priority is **computed**, not read from the snapshot.
- The **decisive facts** the model must extract for CVE-2026-85880: affected product (yes/no/unknown), build below fixed build (yes/no/unknown), low-privilege local access (yes/no/unknown). See `docs/threat_prerequisites.md`.
- The model may draft the recommended action and the "evidence that would change the decision" text; it must not choose the rating.
- Output fields must include asset IDs, the S0x evidence IDs and T1/T2 source IDs used, `source_mode`, and the policy rule that fired (e.g., `"P1 x High = High; KEV +1 -> High"`).

## To Student D (testing and review)

- Expected results are in `docs/expected_results.md`; they were fixed before any run.
- Regenerate variants any time with `python environment/make_variants.py`.
- Hold the consensus meeting (section 1 of that file) before C's first full run.
