"""Tool schemas for the model and the single entry point that runs a tool call.

    from src.tools import registry
    result = registry.execute("lookup_environment", {"action": "get_asset", "query": "W15"})

execute() validates the call, never raises, and always returns the wrapper:
    {"tool", "args", "status": "live|cached|error|ok|not_found", "source",
     "retrieved_at", "source_mode": "live|cached|simulated", "data",
     "unknown_fields", "error"}
"""
import re

from src.sources import kev, nvd
from src.sources.cache import now_iso
from src.tools import environment

CVE_PATTERN = r"^CVE-\d{4}-\d{4,}$"

ENVIRONMENT_ACTIONS = {
    "get_asset": environment.get_asset,
    "search_assets": environment.search_assets,
    "get_evidence": environment.get_evidence,
    "get_flows": environment.get_flows,
    "check_absence": environment.check_absence,
    "get_business_service": environment.get_business_service,
}

_CVE_PARAMETERS = {
    "type": "object",
    "properties": {
        "cve_id": {
            "type": "string",
            "pattern": CVE_PATTERN,
            "description": "CVE identifier, e.g. CVE-2026-85880.",
        },
    },
    "required": ["cve_id"],
    "additionalProperties": False,
}

TOOL_SCHEMAS = [
    {
        "name": "lookup_vulnerability",
        "description": (
            "Look up one CVE in the NIST National Vulnerability Database (NVD). Use this first, "
            "to learn what the vulnerability is and which products and builds it affects. "
            "Returns the description, CVSS v3.1 score and vector (and whether the score is "
            "NVD's own or the vendor's), CWE list, affected products with versionEndExcluding "
            "(the first fixed build; anything lower is vulnerable), the KEV fields NVD carries, "
            "and reference URLs. A null versionEndExcluding is listed in unknown_fields; do not "
            "guess a fixed build. If status is 'cached' the live lookup failed and the data may "
            "be stale. If status is 'error' there is no data: do not fill it in from memory."
        ),
        "parameters": _CVE_PARAMETERS,
    },
    {
        "name": "lookup_kev",
        "description": (
            "Check whether a CVE is in the CISA Known Exploited Vulnerabilities (KEV) catalog, "
            "the authoritative list of vulnerabilities exploited in the wild. Use this to "
            "confirm exploitation status from the primary source and to get dateAdded, dueDate, "
            "requiredAction and ransomware-campaign use. data.in_kev false means only that the "
            "CVE is not listed; absence from KEV does not establish safety."
        ),
        "parameters": _CVE_PARAMETERS,
    },
    {
        "name": "lookup_environment",
        "description": (
            "Query the Northbridge Services environment snapshot (simulated organization data). "
            "Use this to find out whether the organization runs an affected product, at which "
            "build, and what the asset holds and who can reach it. Choose one action:\n"
            "- get_asset: full record(s) for an asset ID (W15), instance (FINLEG01-FINLEG02) or "
            "hostname (FINLEG01): OS name/version/build, software, data classification, "
            "exposure, low_priv_local_access, evidence_ids. Use when you know which asset you "
            "want.\n"
            "- search_assets: text search across all asset records, e.g. 'Windows Server 2016'. "
            "Use to find which assets run a product. Optional limit (default 10).\n"
            "- get_evidence: one evidence record by ID (S01-S08). Use to cross-check a fact on "
            "an asset record against the evidence it cites in evidence_ids.\n"
            "- get_flows: network flows into and out of a zone (e.g. LEGACY), for reachability.\n"
            "- check_absence: whether the organization documents that it does NOT use a "
            "product (exact product name, e.g. 'Kubernetes'). This is the only action that can "
            "establish absence.\n"
            "- get_business_service: consequence, RTO and RPO for a business service named in "
            "an asset's business_service field.\n"
            "Values are returned exactly as stored. A null value means unknown and its path is "
            "listed in unknown_fields; never replace it with a guess. A 'not_found' result "
            "does not prove absence."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": list(ENVIRONMENT_ACTIONS),
                    "description": "Which environment lookup to run.",
                },
                "query": {
                    "type": "string",
                    "description": (
                        "The lookup value: asset ID, instance or hostname (get_asset); search "
                        "text (search_assets); evidence ID (get_evidence); zone ID (get_flows); "
                        "product name (check_absence); service name (get_business_service)."
                    ),
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 50,
                    "description": "search_assets only: maximum records to return (default 10).",
                },
            },
            "required": ["action", "query"],
            "additionalProperties": False,
        },
    },
]

_SCHEMAS_BY_NAME = {s["name"]: s for s in TOOL_SCHEMAS}
_TYPES = {"string": str, "integer": int}


def _wrap(tool, args, status, source=None, retrieved_at=None, source_mode=None,
          data=None, unknown_fields=None, error=None):
    return {
        "tool": tool,
        "args": args,
        "status": status,
        "source": source,
        "retrieved_at": retrieved_at or now_iso(),
        "source_mode": source_mode,
        "data": data,
        "unknown_fields": unknown_fields or [],
        "error": error,
    }


def _validate(schema, args):
    """Return an error message, or None if args fit the tool's parameter schema."""
    if not isinstance(args, dict):
        return "args must be an object"
    props = schema["parameters"]["properties"]
    missing = [k for k in schema["parameters"]["required"] if k not in args]
    if missing:
        return f"missing required argument(s): {', '.join(missing)}"
    extra = [k for k in args if k not in props]
    if extra:
        return f"unknown argument(s): {', '.join(extra)}"
    for key, value in args.items():
        spec = props[key]
        if isinstance(value, bool) or not isinstance(value, _TYPES[spec["type"]]):
            return f"argument '{key}' must be of type {spec['type']}"
        if spec["type"] == "string" and not value.strip():
            return f"argument '{key}' must not be empty"
        if "enum" in spec and value not in spec["enum"]:
            return f"argument '{key}' must be one of: {', '.join(spec['enum'])}"
        if "pattern" in spec and not re.fullmatch(spec["pattern"], value):
            return f"argument '{key}' must match {spec['pattern']}"
        if "minimum" in spec and not spec["minimum"] <= value <= spec["maximum"]:
            return f"argument '{key}' must be from {spec['minimum']} to {spec['maximum']}"
    if "limit" in args and args.get("action") != "search_assets":
        return "argument 'limit' is only valid with action 'search_assets'"
    return None


def _run_source(tool, args, fetch):
    r = fetch(args["cve_id"])
    mode = "cached" if r["status"] == "cached" else "live"
    return _wrap(tool, args, r["status"], source=r["source"], retrieved_at=r["retrieved_at"],
                 source_mode=mode, data=r["data"], unknown_fields=r["unknown_fields"],
                 error=r["error"])


def _run_environment(tool, args, snapshot_path):
    kwargs = {"snapshot_path": snapshot_path}
    if "limit" in args:
        kwargs["limit"] = args["limit"]
    r = ENVIRONMENT_ACTIONS[args["action"]](args["query"], **kwargs)
    data = None
    if r["data"] is not None:
        data = {"snapshot_id": r["snapshot_id"], "locator": r["locator"], **r["data"]}
        if r["note"]:
            data["note"] = r["note"]
    return _wrap(tool, args, r["status"], source=r["locator"],
                 source_mode=environment.SOURCE_MODE, data=data,
                 unknown_fields=r["unknown_fields"], error=r["error"])


def execute(tool_name, args, snapshot_path=None):
    """Validate and run one tool call. Returns the wrapper described in the module docstring.

    snapshot_path overrides the configured environment snapshot (for the test
    variants); it is set by the caller, never by the model.
    """
    schema = _SCHEMAS_BY_NAME.get(tool_name) if isinstance(tool_name, str) else None
    if schema is None:
        return _wrap(tool_name, args, "error",
                     error=f"unknown tool: {tool_name!r}. Available tools: "
                           f"{', '.join(_SCHEMAS_BY_NAME)}")
    problem = _validate(schema, args)
    if problem:
        return _wrap(tool_name, args, "error", error=f"invalid arguments: {problem}")
    try:
        if tool_name == "lookup_vulnerability":
            return _run_source(tool_name, args, nvd.fetch_cve)
        if tool_name == "lookup_kev":
            return _run_source(tool_name, args, kev.fetch_kev_entry)
        return _run_environment(tool_name, args, snapshot_path)
    except Exception as exc:  # a tool failure must reach the model as data, not a crash
        return _wrap(tool_name, args, "error", error=f"{type(exc).__name__}: {exc}")
