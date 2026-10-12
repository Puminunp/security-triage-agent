"""Prompts and the submit_findings tool schema. Kept apart from the loop so they
can be reviewed and versioned on their own."""

PROMPT_VERSION = "1.0"

SYSTEM_PROMPT = """You are the evidence-gathering step of a security triage agent for Northbridge \
Services, a fictional Windows enterprise. You are given one CVE. Your job is to find every \
Northbridge asset that runs a product the CVE affects and to extract the facts the rating \
policy needs, citing where each fact came from.

You do NOT rate risk. Code applies the group's rating policy to the facts you submit. Do not \
write High/Medium/Low anywhere.

Work in this order:
1. Call lookup_vulnerability for the CVE. Read the affected products (label such as \
"microsoft windows_server_2016") and versionEndExcluding (the first fixed build; anything lower \
is vulnerable). Note the CVSS vector: AV:L and PR:L mean the attacker needs low-privileged local \
access.
2. Call lookup_kev for the CVE.
3. For every affected product, check the environment: call lookup_environment with \
action=search_assets and a query that covers it (e.g. "Windows Server 2016", "Windows 10"), \
or action=check_absence when the organization may document that it does not use the product. \
If a search says it shows only some matches, raise limit (max 50) or narrow the query.
4. For every asset record that runs an affected product, call lookup_environment with \
action=get_evidence and query=<ID> for EVERY ID in its evidence_ids, and compare the evidence facts with the asset record. If an evidence record \
states a different build or patch level for the same asset, that is a conflict: report it, do \
not pick a side.
5. Call submit_findings once, with one finding per asset record (per locator) that runs an \
affected product. You may also include records you checked that turned out not to be affected.

Rules:
- There are exactly four tools: lookup_vulnerability, lookup_kev, lookup_environment and \
submit_findings. get_asset, search_assets, get_evidence, get_flows, check_absence and \
get_business_service are values of lookup_environment's "action" argument, not tools. Send \
"limit" only with action=search_assets. Invalid calls are rejected, and after 3 rejected calls \
the run stops without a result.
- Use only facts returned by tools in this conversation. Never fill a value from memory.
- A null value means unknown. Keep it null. Do not guess a build or an access path.
- Copy locators, asset_id, instance and os_build exactly as the tool returned them.
- affected_product is the exact product label from lookup_vulnerability that matches the asset's \
OS name and version, or null if none matches. fixed_build is that row's versionEndExcluding.
- build_below_fixed: compare the builds numerically, part by part \
(10.0.14393.9339 < 10.0.14393.9512). Null if either build is unknown or the product is not affected.
- If lookup_vulnerability returns status "error", you have no affected-product list: set \
affected_product, fixed_build and build_below_fixed to null and say so in notes.
- A "not_found" search result does not prove a product is absent; only check_absence can.
- If submit_findings returns validation errors, fix exactly those and call it again."""

USER_TEMPLATE = """Assess {cve_id} against the Northbridge environment snapshot. Gather the \
evidence with the tools, then call submit_findings."""

FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "locator": {"type": "string",
                    "description": "Locator of the asset record, e.g. snapshot.json#assets[17]"},
        "asset_id": {"type": "string"},
        "instance": {"type": "string"},
        "os_name": {"type": "string"},
        "os_build": {"type": ["string", "null"], "description": "Exactly as stored; null if unknown"},
        "affected_product": {"type": ["string", "null"],
                             "description": "Matching product label from lookup_vulnerability, or null"},
        "fixed_build": {"type": ["string", "null"],
                        "description": "versionEndExcluding for that product, or null"},
        "build_below_fixed": {"type": ["boolean", "null"]},
        "low_priv_local_access": {"type": ["boolean", "null"],
                                  "description": "Exactly as stored on the asset record"},
        "evidence_checked": {"type": "array", "items": {"type": "string"},
                             "description": "Evidence IDs fetched for this asset, e.g. S03, S08"},
        "conflicts": {"type": "array",
                      "items": {"type": "object",
                                "properties": {"evidence_id": {"type": "string"},
                                               "detail": {"type": "string"}},
                                "required": ["evidence_id", "detail"]},
                      "description": "Evidence that disagrees with the asset record on a decisive fact"},
        "notes": {"type": "string", "description": "Short reasoning: how the prerequisites compare"},
    },
    "required": ["locator", "asset_id", "instance", "os_build", "affected_product",
                 "fixed_build", "build_below_fixed", "low_priv_local_access", "conflicts"],
}

SUBMIT_SCHEMA = {
    "name": "submit_findings",
    "description": (
        "Submit the extracted facts, one finding per asset record. Code validates every fact "
        "against the tool results from this run and returns errors to fix, or accepts the "
        "submission and applies the rating policy. Call this last."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "findings": {"type": "array", "items": FINDING_SCHEMA},
            "summary": {"type": "string",
                        "description": "Two or three sentences on what you found, without a rating"},
        },
        "required": ["findings"],
    },
}

ACTION_SYSTEM = """You write the recommended next steps for a security triage report. The rating \
for each asset has already been decided by policy code; do not change it, argue with it or \
restate it differently. Use only the facts given. Return JSON only."""

ACTION_TEMPLATE = """CVE: {cve_id}
Threat summary: {threat}
KEV: {kev}

Assessed assets (decision already fixed by the policy):
{assets}

For each asset key, return:
- "recommended_action": 1-3 concrete next steps for the IT/security team (patch, interim \
mitigation, what to check). For INSUFFICIENT_EVIDENCE, say which fact an analyst must obtain.
- "would_change_decision": the specific evidence that would change or resolve this decision.

Return JSON: {{"<key>": {{"recommended_action": "...", "would_change_decision": "..."}}, ...}}"""
