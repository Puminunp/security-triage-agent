"""Evidence ledger: every tool result the agent received in one run.

Each result gets a reference (R1, R2, ...) that the assessment cites. The
validator and the policy read facts from here, never from the model's text.

The model sees a "blinded" copy of each result: the snapshot file name and
snapshot ID are replaced by neutral labels, so a test variant
(e.g. env_conflict.json / "...-conflicting_evidence") cannot tell the model
which answer the test expects. The ledger keeps the real values.
"""
import json
import re

BLIND_FILE = "snapshot.json"
BLIND_ID = "northbridge-snapshot"

# Source IDs from inputs/SOURCES.md
SOURCE_IDS = {"lookup_vulnerability": "T1", "lookup_kev": "T2"}


class Ledger:
    def __init__(self, snapshot_filename, snapshot_id):
        self.snapshot_filename = snapshot_filename
        self.snapshot_id = snapshot_id
        self.entries = []          # {"ref", "tool", "args", "result", "blinded"}
        self.assets = {}           # blinded locator -> {"record", "ref"}
        self.evidence = {}         # "S08" -> {"record", "ref"}
        self.searches = []         # {"query", "complete", "ref"} for search_assets
        self.absences = []         # {"query", "absent", "ref"} for check_absence
        self.nvd = None            # latest entry with data
        self.nvd_attempts = []     # every lookup_vulnerability entry
        self.kev = None
        self.kev_attempts = []
        self.rejected = 0          # calls rejected before running (unknown tool / bad args)

    # --- blinding -------------------------------------------------------
    def blind(self, obj):
        text = json.dumps(obj, ensure_ascii=False, default=str)
        if self.snapshot_filename:
            text = text.replace(self.snapshot_filename, BLIND_FILE)
        if self.snapshot_id:
            text = re.sub(re.escape(self.snapshot_id) + r"(?![\w.-])", BLIND_ID, text)
        return json.loads(text)

    # --- recording ------------------------------------------------------
    def add(self, tool, args, result):
        ref = f"R{len(self.entries) + 1}"
        blinded = self.blind(result)
        entry = {"ref": ref, "tool": tool, "args": args, "result": result, "blinded": blinded,
                 "rejected": False}
        self.entries.append(entry)

        if result.get("status") == "error" and str(result.get("error", "")).startswith(
                ("unknown tool", "invalid arguments")):
            self.rejected += 1
            entry["rejected"] = True
            return entry

        data = blinded.get("data") or {}
        if tool == "lookup_vulnerability":
            self.nvd_attempts.append(entry)
            if result.get("data") and result.get("status") in ("live", "cached"):
                self.nvd = entry
        elif tool == "lookup_kev":
            self.kev_attempts.append(entry)
            if result.get("data") and result.get("status") in ("live", "cached"):
                self.kev = entry
        elif tool == "lookup_environment":
            action = args.get("action")
            for m in data.get("matches", []) or []:
                self.assets[m["locator"]] = {"record": m["asset"], "ref": ref}
            if action == "get_evidence" and data.get("evidence"):
                ev = data["evidence"]
                self.evidence[str(ev.get("evidence_id")).upper()] = {"record": ev, "ref": ref}
            if action == "search_assets":
                total = data.get("total_matches", 0)
                complete = result.get("status") in ("ok", "not_found") and \
                    total <= len(data.get("matches", []) or [])
                self.searches.append({"query": args.get("query", ""), "complete": complete,
                                      "ref": ref})
            if action == "check_absence":
                self.absences.append({"query": args.get("query", ""),
                                      "absent": data.get("absent"), "ref": ref})
        return entry

    def ref_of(self, ref):
        return next((e for e in self.entries if e["ref"] == ref), None)

    def citation(self, ref, locator=None, fact=None):
        """One evidence citation for the assessment."""
        e = self.ref_of(ref)
        r = e["result"]
        return {
            "ref": ref,
            "source_id": SOURCE_IDS.get(e["tool"]),
            "tool": e["tool"],
            "args": e["args"],
            "source": locator or r.get("source"),
            "retrieved_at": r.get("retrieved_at"),
            "status": r.get("status"),
            "source_mode": r.get("source_mode"),
            "fact": fact,
        }

    def cached_sources(self):
        out = set()
        for e in (self.nvd, self.kev):
            if e and e["result"].get("status") == "cached":
                out.add(e["tool"])
        return out

    def real_locator(self, blinded_locator):
        return blinded_locator.replace(BLIND_FILE, self.snapshot_filename, 1)


def preview(tool, args, result):
    """One-line summary of a tool result, for the trace and the demo viewer."""
    status = result.get("status")
    if status == "error":
        return f"error: {result.get('error')}"
    data = result.get("data") or {}
    if tool == "lookup_vulnerability":
        cvss = data.get("cvss_v31") or {}
        rows = data.get("affected_products") or []
        return (f"{status}: CVSS {cvss.get('base_score')} ({cvss.get('score_used')}), "
                f"{len({r.get('product') for r in rows})} affected products, "
                f"KEV fields in_kev={(data.get('kev') or {}).get('in_kev')}")
    if tool == "lookup_kev":
        e = data.get("entry") or {}
        return (f"{status}: in_kev={data.get('in_kev')}"
                + (f", added {e.get('dateAdded')}, due {e.get('dueDate')}" if e else ""))
    action = (args or {}).get("action")
    if data.get("matches") is not None:
        ms = data["matches"]
        names = ", ".join(f"{m['asset'].get('asset_id')} {m['asset'].get('instance')} "
                          f"(build {(m['asset'].get('os') or {}).get('build')})" for m in ms[:4])
        more = f" +{len(ms) - 4} more" if len(ms) > 4 else ""
        return f"{status}: {data.get('total_matches', len(ms))} match(es): {names}{more}" if ms else \
            f"{status}: no match (does not prove absence)"
    if action == "get_evidence" and data.get("evidence"):
        ev = data["evidence"]
        return f"{status}: {ev.get('evidence_id')} {ev.get('title')}"
    if action == "check_absence":
        return f"{status}: absent={data.get('absent')}"
    return f"{status}"
