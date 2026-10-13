"""Local demo app: one page that explains the project and drives the real code.

    python -m demo            # then open http://127.0.0.1:8765

Standard library only. Every number the page shows comes from the repository:
the threat from inputs/, the environment from environment/, ratings from
src/policy.py, tool calls through src/tools/registry.py, and live runs through
src/agent.py. The server listens on 127.0.0.1 only.
"""
import glob
import json
import mimetypes
import re
import subprocess
import sys
import threading
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from src import policy
from src.agent import Trace, run as run_agent
from src.config import REPO_ROOT
from src.evidence import preview
from src.faults import FAULTS
from src.report import _assumptions_by_asset
from src.sources import nvd
from src.tools import registry
from src.validation import cpe_label_for_os, nvd_index

STATIC = Path(__file__).resolve().parent / "static"
CVE = "CVE-2026-85880"
SNAPSHOTS = [
    {"path": "environment/northbridge-v1.1.json", "label": "Base snapshot (northbridge-v1.1)", "check": "0"},
    {"path": "environment/variants/env_patched.json", "label": "Check 1: applicability change (W15 patched)", "check": "1"},
    {"path": "environment/variants/env_low_priority.json", "label": "Check 2: impact change (W15 no PII, internal only)", "check": "2"},
    {"path": "environment/variants/env_missing.json", "label": "Check 3a: missing evidence (W15 build unknown)", "check": "3a"},
    {"path": "environment/variants/env_conflict.json", "label": "Check 3b: conflicting evidence (S08 vs record)", "check": "3b"},
]
DOCS = {
    "rating_policy": "docs/rating_policy.md", "architecture": "docs/architecture.md",
    "test_results": "docs/test_results.md", "evidence_review": "docs/evidence_review.md",
    "tool_contracts": "docs/tool_contracts.md", "changes": "environment/CHANGES.md",
    "readme": "README.md", "worksheet": "docs/design_studio/revised_worksheet_assignment3.md",
    "baseline": "baseline/README.md",
}
LIVE = {}            # run id -> {"trace", "events", "done", "assessment", "run_dir", "error"}
LIVE_LOCK = threading.Lock()


def read_json(rel):
    with open(REPO_ROOT / rel, encoding="utf-8") as f:
        return json.load(f)


def rel(path):
    return str(Path(path).resolve().relative_to(REPO_ROOT))


# --- data endpoints ------------------------------------------------------------

def threat():
    raw = read_json(f"inputs/{CVE}_nvd_raw.json")
    data, _ = nvd.parse(raw, CVE)
    kev = read_json(f"inputs/{CVE}_kev_raw.json")
    products = {}
    for row in data["affected_products"]:
        label = row["product"].replace("microsoft ", "")
        products.setdefault(label, row["versionEndExcluding"])
    return {"nvd": {k: v for k, v in data.items() if k != "references"},
            "references": data["references"][:6], "kev": kev,
            "products": [{"product": k, "fixed_build": v} for k, v in products.items()]}


def baseline_decisions():
    try:
        a = read_json("baseline/main_run/assessment.json")
    except OSError:
        return {}
    out = {}
    for x in a["assessments"]:
        loc = x["asset"]["locator"].split("#")[-1]
        out[loc] = {"decision": x["decision"], "rule": x["rationale"]["policy_rule"],
                    "applicability": x["rationale"]["applicability"]["level"]}
    return out


def environment(path):
    if path not in [s["path"] for s in SNAPSHOTS]:
        raise ValueError("unknown snapshot")
    snap = read_json(path)
    index = nvd_index(nvd.parse(read_json(f"inputs/{CVE}_nvd_raw.json"), CVE)[0])
    assumptions = _assumptions_by_asset()
    decisions = baseline_decisions() if path == SNAPSHOTS[0]["path"] else {}
    evidence = {e["evidence_id"]: e for e in snap.get("evidence", [])}
    threat_facts = {"cvss_score": 7.8, "in_kev": True}
    assets = []
    for i, a in enumerate(snap["assets"]):
        prio, why = policy.priority(a)
        label = cpe_label_for_os(a.get("os"))
        affected = label in index
        fixed = next(iter(index[label]["fixed_builds"]), None) if affected else None
        conflicts = [f for e in evidence.values() for f in e.get("facts", [])
                     if f.startswith(f"{a['asset_id']}:") and (a.get("os") or {}).get("build")
                     and a["os"]["build"] not in f]
        rated = policy.rate({**a, "os_build": (a.get("os") or {}).get("build"), "affected": affected,
                             "fixed_build": fixed, "conflicts": conflicts}, threat_facts)
        assets.append({"index": i, "locator": f"assets[{i}]", "record": a, "priority": prio,
                       "priority_reason": why, "cpe_label": label, "affected": affected,
                       "fixed_build": fixed, "policy": rated,
                       "agent": decisions.get(f"assets[{i}]"),
                       "assumptions": assumptions.get(a["asset_id"], [])})
    return {"snapshot_id": snap.get("snapshot_id"), "snapshot_date": snap.get("snapshot_date"),
            "variant_change": snap.get("variant_change"), "zones": snap.get("zones", []),
            "flows": snap.get("flows", []), "flows_note": snap.get("flows_note"),
            "default_policy": snap.get("default_policy"), "evidence": snap.get("evidence", []),
            "absences": snap.get("absences", []), "business_services": snap.get("business_services", []),
            "organization": snap.get("organization"), "assets": assets}


def rate(body):
    asset, threat_facts = body.get("asset", {}), body.get("threat", {})
    result = policy.rate(asset, threat_facts)
    srcs = ["T1"] if result["applicability"] == "Not applicable" and asset.get("affected") is False \
        else ["T1", "S08"] + (["T2", "S07"] if result["applicability"] in ("Confirmed", "Partial") else [])
    level, why = policy.confidence(result, srcs, set(), threat_facts.get("in_kev") is None
                                   and result["applicability"] in ("Confirmed", "Partial"))
    return {**result, "confidence": level, "confidence_reason": why,
            "matrices": {"priority": {f"{k[0]}|{k[1]}": v for k, v in policy.PRIORITY_MATRIX.items()},
                         "final": {f"{k[0]}|{k[1]}": v for k, v in policy.FINAL_MATRIX.items()}}}


def try_tool(body):
    snapshot = body.get("snapshot") or SNAPSHOTS[0]["path"]
    if snapshot not in [s["path"] for s in SNAPSHOTS]:
        raise ValueError("unknown snapshot")
    result = registry.execute(body.get("name"), body.get("args"), snapshot_path=snapshot)
    return {"result": result, "preview": preview(body.get("name"), body.get("args") or {}, result)}


def saved_runs():
    rows = []
    paths = ["baseline/main_run"] + sorted(
        {str(Path(p).parent.relative_to(REPO_ROOT)) for p in glob.glob(str(REPO_ROOT / "outputs/**/assessment.json"), recursive=True)},
        reverse=True)
    for p in paths:
        try:
            a = read_json(f"{p}/assessment.json")
        except OSError:
            continue
        w15 = next((x for x in a["assessments"] if x["asset"]["asset_id"] == "W15"), None)
        rows.append({"path": p, "run_id": a["run"]["run_id"], "label": a["run"].get("label"),
                     "status": a["run"]["status"], "faults": a["run"].get("faults", []),
                     "snapshot": a["intake"]["snapshot_path"], "overall": a["overall"]["decision"],
                     "w15": w15["decision"] if w15 else None})
    return rows


def saved_run(path):
    path = path.strip("/")
    if not re.fullmatch(r"(baseline/main_run|outputs/[\w./-]+)", path) or ".." in path:
        raise ValueError("bad run path")
    a = read_json(f"{path}/assessment.json")
    tools = {t["ref"]: t for t in read_json(f"{path}/tool_results.json")}
    events = []
    with open(REPO_ROOT / path / "trace.jsonl", encoding="utf-8") as f:
        for line in f:
            e = json.loads(line)
            if e["event"] == "tool_call" and "preview" not in e and e.get("ref") in tools:
                t = tools[e["ref"]]
                e["preview"] = preview(t["tool"], t["args"], t["result"])
            events.append(e)
    return {"assessment": a, "events": events, "path": path,
            "report": (REPO_ROOT / path / "report.md").read_text(encoding="utf-8")}


def saved_tool(path, ref):
    path = path.strip("/")
    if not re.fullmatch(r"(baseline/main_run|outputs/[\w./-]+)", path) or ".." in path:
        raise ValueError("bad run path")
    for t in read_json(f"{path}/tool_results.json"):
        if t["ref"] == ref:
            return t
    raise KeyError(ref)


def checks():
    candidates = sorted(glob.glob(str(REPO_ROOT / "outputs/checks_*/summary.json")))
    src = candidates[-1] if candidates else str(REPO_ROOT / "baseline/checks/summary.json")
    rows = json.loads(Path(src).read_text(encoding="utf-8"))
    return {"source": rel(src), "rows": rows}


# --- live runs ---------------------------------------------------------------

def start_live(body):
    snapshot = body.get("snapshot") or SNAPSHOTS[0]["path"]
    if snapshot not in [s["path"] for s in SNAPSHOTS]:
        raise ValueError("unknown snapshot")
    faults = [f for f in body.get("faults", []) if f in FAULTS]
    rid = uuid.uuid4().hex[:8]
    state = {"events": [], "done": False, "assessment": None, "run_dir": None, "error": None}

    def on_event(e):
        with LIVE_LOCK:
            state["events"].append(json.loads(json.dumps(e, default=str)))

    trace = Trace(on_event=on_event)
    state["trace"] = trace

    def work():
        try:
            a, run_dir = run_agent(CVE, snapshot_path=snapshot, faults=faults, label="demo",
                                   out_root="outputs/demo_runs", trace=trace)
            state["assessment"], state["run_dir"] = a, rel(run_dir)
        except Exception as exc:  # shown in the page, not swallowed
            state["error"] = f"{type(exc).__name__}: {exc}"
            traceback.print_exc()
        finally:
            state["done"] = True

    with LIVE_LOCK:
        LIVE[rid] = state
    threading.Thread(target=work, daemon=True).start()
    return {"id": rid}


def poll_live(rid, since):
    state = LIVE.get(rid)
    if state is None:
        raise KeyError(rid)
    with LIVE_LOCK:
        events = state["events"][since:]
    out = {"events": events, "done": state["done"], "error": state["error"]}
    if state["done"] and state["run_dir"]:
        out["run"] = saved_run(state["run_dir"])
    return out


def live_tool(rid, ref):
    ledger = LIVE[rid]["trace"].ledger
    e = ledger.ref_of(ref) if ledger else None
    if e is None:
        raise KeyError(ref)
    return {"ref": ref, "tool": e["tool"], "args": e["args"], "result": e["result"],
            "model_saw": e["blinded"]}


def run_pytest():
    p = subprocess.run([sys.executable, "-m", "pytest", "-q", "--no-header", "--color=no", "-p", "no:cacheprovider"],
                       cwd=REPO_ROOT, capture_output=True, text=True, timeout=300)
    return {"returncode": p.returncode, "output": p.stdout[-6000:] + p.stderr[-2000:]}


# --- HTTP ----------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # quiet
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _json_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def _route(self, method):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        p = u.path
        try:
            if method == "GET":
                if p in ("/", "/index.html"):
                    return self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
                if p.startswith("/static/"):
                    f = (STATIC / p[len("/static/"):]).resolve()
                    if STATIC not in f.parents or not f.is_file():
                        return self._send(404, {"error": "not found"})
                    ctype = mimetypes.guess_type(f.name)[0] or "application/octet-stream"
                    return self._send(200, f.read_bytes(), ctype)
                if p == "/workflow.png":
                    return self._send(200, (REPO_ROOT / "docs/workflow.png").read_bytes(), "image/png")
                if p == "/api/meta":
                    return self._send(200, {"cve": CVE, "snapshots": SNAPSHOTS, "faults": list(FAULTS),
                                            "tools": registry.TOOL_SCHEMAS})
                if p == "/api/threat":
                    return self._send(200, threat())
                if p == "/api/environment":
                    return self._send(200, environment(q.get("snapshot", SNAPSHOTS[0]["path"])))
                if p == "/api/runs":
                    return self._send(200, saved_runs())
                if p == "/api/run":
                    return self._send(200, saved_run(q["path"]))
                if p == "/api/run/tool":
                    return self._send(200, saved_tool(q["path"], q["ref"]))
                if p == "/api/live":
                    return self._send(200, poll_live(q["id"], int(q.get("since", 0))))
                if p == "/api/live/tool":
                    return self._send(200, live_tool(q["id"], q["ref"]))
                if p == "/api/checks":
                    return self._send(200, checks())
                if p == "/api/doc":
                    name = q.get("name")
                    if name not in DOCS:
                        return self._send(404, {"error": "unknown doc"})
                    return self._send(200, {"name": name, "path": DOCS[name],
                                            "text": (REPO_ROOT / DOCS[name]).read_text(encoding="utf-8")})
            if method == "POST":
                body = self._json_body()
                if p == "/api/rate":
                    return self._send(200, rate(body))
                if p == "/api/tool":
                    return self._send(200, try_tool(body))
                if p == "/api/live":
                    return self._send(200, start_live(body))
                if p == "/api/pytest":
                    return self._send(200, run_pytest())
            return self._send(404, {"error": "not found"})
        except (KeyError, ValueError, OSError) as exc:
            return self._send(400, {"error": f"{type(exc).__name__}: {exc}"})

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")


def main(port=8765):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Security triage demo: http://127.0.0.1:{port}   (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
