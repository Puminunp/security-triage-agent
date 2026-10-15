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
                if p == "/api/review":
                    return self._send(200, review_state())
                if p == "/api/review/source":
                    return self._send(200, review_sources(q["id"]))
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
                if p == "/api/review/mark":
                    return self._send(200, review_mark(body))
                if p == "/api/review/signoff":
                    return self._send(200, review_signoff(body))
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


# --- evidence review (scene 11) ------------------------------------------------

REVIEW_DOC = REPO_ROOT / "docs" / "evidence_review.md"
REVIEW_LOCK = threading.Lock()  # the page can save several fields at once; one writer at a time
ROW = re.compile(r"^\| ([ABC]\d+) \|(.*)\|\s*$")


def _cells(line):
    return [c.strip() for c in line.strip().strip("|").split("|")]


def review_state():
    items, signoff, section = [], [], None
    for line in REVIEW_DOC.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            section = line[3:].strip()
        m = ROW.match(line)
        if m:
            c = _cells(line)
            if len(c) == 5:
                items.append({"id": c[0], "section": section, "claim": c[1], "check": c[2], "precheck": c[3], "review": c[4]})
            else:
                items.append({"id": c[0], "section": section, "claim": c[1], "check": "", "precheck": c[2], "review": c[3]})
        elif section == "Sign-off" and line.startswith("| ") and not line.startswith(("| Reviewer", "|---")):
            c = _cells(line)
            signoff.append({"name": c[0], "date": c[1], "result": c[2]})
    return {"path": "docs/evidence_review.md", "items": items, "signoff": signoff}


def _clean(text):
    return " ".join(str(text).replace("|", "/").split())


def review_mark(body):
    with REVIEW_LOCK:
        return _review_mark(body)


def _review_mark(body):
    rid, verdict, note = body.get("id"), body.get("verdict"), _clean(body.get("note", ""))
    mark = {"ok": "✅", "issue": "⚠️", "": "☐"}.get(verdict)
    if mark is None or not re.fullmatch(r"[ABC]\d+", str(rid)):
        raise ValueError("bad review update")
    cell = f"{mark} {note}".strip()
    lines = REVIEW_DOC.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines):
        if line.startswith(f"| {rid} |"):
            c = _cells(line)
            c[-1] = cell
            lines[i] = "| " + " | ".join(c) + " |"
            REVIEW_DOC.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return review_state()
    raise KeyError(rid)


def review_signoff(body):
    with REVIEW_LOCK:
        return _review_signoff(body)


def _review_signoff(body):
    name = _clean(body.get("name", ""))
    date, result = _clean(body.get("date", "")), _clean(body.get("result", ""))
    lines = REVIEW_DOC.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines):
        if line.startswith(f"| {name} |"):
            lines[i] = f"| {name} | {date} | {result} |"
            REVIEW_DOC.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return review_state()
    raise KeyError(name)


def review_sources(rid):
    snap = read_json(SNAPSHOTS[0]["path"])
    assets = snap["assets"]
    loc = {f"{a['asset_id']} {a['instance']}": (i, a) for i, a in enumerate(assets)}
    ev = {e["evidence_id"]: (i, e) for i, e in enumerate(snap["evidence"])}
    f = "northbridge-v1.1.json"
    base = read_json("baseline/main_run/assessment.json")
    by = {f"{x['asset']['asset_id']} {x['asset']['instance']}": x for x in base["assessments"]}
    w15i, w15 = loc["W15 FINLEG01-FINLEG02"]
    bw = by["W15 FINLEG01-FINLEG02"]
    cve = read_json(f"inputs/{CVE}_nvd_raw.json")["vulnerabilities"][0]["cve"]
    cpe = [m for c in cve["configurations"] for n in c["nodes"] for m in n["cpeMatch"]]
    kev = read_json(f"inputs/{CVE}_kev_raw.json")
    msrc = (REPO_ROOT / f"inputs/{CVE}_msrc_builds.txt").read_text(encoding="utf-8").splitlines()
    changes = (REPO_ROOT / "environment/CHANGES.md").read_text(encoding="utf-8").splitlines()
    tools = read_json("baseline/main_run/tool_results.json")
    messages_text = (REPO_ROOT / "baseline/main_run/messages.json").read_text(encoding="utf-8")
    s08 = ev["S08"][1]["facts"]
    assumption = lambda *ids: [l for l in changes if any(l.startswith(f"| {a} |") for a in ids)]
    agent = lambda key: {"decision": by[key]["decision"], "rule": by[key]["rationale"]["policy_rule"],
                         "applicability": by[key]["rationale"]["applicability"]["reason"]}
    srv22 = {k: a["os"]["build"] for k, (i, a) in loc.items() if a["os"].get("name") == "Windows Server 2022"}
    S = lambda label, source, value: {"label": label, "source": source, "value": value}
    table = {
        "A1": [S("Asset record: W15 operating system", f"{f}#assets[{w15i}].os", w15["os"]),
               S("Evidence S08, the W15 line", f"{f}#evidence[{ev['S08'][0]}]", [x for x in s08 if x.startswith("W15")]),
               S("What the agent reported", "baseline/main_run/assessment.json", bw["rationale"]["applicability"]["facts"]["os_build"])],
        "A2": [S("NVD: rows for windows_server_2016", f"inputs/{CVE}_nvd_raw.json → configurations",
                 [{"criteria": m["criteria"], "versionEndExcluding": m.get("versionEndExcluding")} for m in cpe if "windows_server_2016" in m["criteria"]]),
               S("Microsoft (MSRC) page", f"inputs/{CVE}_msrc_builds.txt (full page: inputs/{CVE}_msrc.pdf)", [l for l in msrc if "Server 2016" in l]),
               S("What the agent reported", "baseline/main_run/assessment.json", bw["rationale"]["applicability"]["facts"]["fixed_build"])],
        "A3": [S("Compare part by part", "code (src/policy.py build_tuple)",
                 f"{w15['os']['build']} vs {bw['rationale']['applicability']['facts']['fixed_build']}: the first three parts are equal (10.0.14393), and 9339 < 9512, so the build is below the fix → vulnerable")],
        "A4": [S("Asset record: access", f"{f}#assets[{w15i}]", {"low_priv_local_access": w15["low_priv_local_access"], "notes": w15["notes"]}),
               S("Evidence S03 (course scenario)", f"{f}#evidence[{ev['S03'][0]}]", [x for x in ev["S03"][1]["facts"] if "W15" in x]),
               S("Group assumption A15", "environment/CHANGES.md", assumption("A15"))],
        "A5": [S("Asset record: data and exposure", f"{f}#assets[{w15i}]", {k: w15[k] for k in ("data_classification", "data_protection", "exposure")}),
               S("Network flow F07", f"{f}#flows", [x for x in snap["flows"] if x["flow_id"] == "F07"]),
               S("Group assumptions A2 and A6", "environment/CHANGES.md", assumption("A2", "A6")),
               S("Policy priority matrix", "docs/rating_policy.md section 3", "PII without protection × Intranet = P1")],
        "A6": [S("NVD CVSS v3.1 entries", f"inputs/{CVE}_nvd_raw.json → metrics.cvssMetricV31",
                 [{"type": m["type"], "source": m["source"], "baseScore": m["cvssData"]["baseScore"], "vector": m["cvssData"]["vectorString"]} for m in cve["metrics"]["cvssMetricV31"]]),
               S("Microsoft (MSRC) page", f"inputs/{CVE}_msrc.pdf, page 1", "CVSS:3.1 7.8 / 7.2 (base 7.8), CVSS source: Microsoft"),
               S("Policy severity bands", "docs/rating_policy.md section 4", "7.0–8.9 = High")],
        "A7": [S("CISA KEV entry", f"inputs/{CVE}_kev_raw.json", {k: kev.get(k) for k in ("cveID", "dateAdded", "dueDate", "knownRansomwareCampaignUse", "requiredAction")})],
        "A8": [S("Rule the agent applied", "baseline/main_run/assessment.json", bw["rationale"]["policy_rule"]),
               S("Policy final matrix", "docs/rating_policy.md section 5", "P1 × High = High"),
               S("Policy modifiers", "docs/rating_policy.md section 6", "KEV +1 level, never above High")],
        "A9": [S("Confidence the agent reported", "baseline/main_run/assessment.json", bw["confidence"]),
               S("Policy confidence rule", "docs/rating_policy.md section 7", "Medium when a decisive fact depends on a group assumption or simulated addition (S07, S08)")],
        "A10": [S("Citations in the assessment", "baseline/main_run/assessment.json",
                  [{"ref": e["ref"], "tool": e["tool"], "source": e["source"], "mode": e["source_mode"], "retrieved_at": e["retrieved_at"]} for e in bw["evidence"]])],
        "A11": [S("Recommended action (written by the AI)", "baseline/main_run/assessment.json", bw["action"]),
                S("The field step 3 is based on", f"{f}#assets[{w15i}].config", {"patch_approval_recorded_days_before_snapshot": w15["config"]["patch_approval_recorded_days_before_snapshot"]}),
                S("What that field really means (S03)", f"{f}#evidence[{ev['S03'][0]}]", [x for x in ev["S03"][1]["facts"] if "patch approval" in x])],
        "B1": [S("Asset record: CA-ROOT01", f"{f}#assets[{loc['W02 CA-ROOT01'][0]}]",
                 {k: loc["W02 CA-ROOT01"][1][k] for k in ("os", "exposure", "low_priv_local_access", "priority_override")}),
               S("Evidence S08", f"{f}#evidence[{ev['S08'][0]}]", [x for x in s08 if "root CA" in x]),
               S("What the agent decided", "baseline/main_run/assessment.json", agent("W02 CA-ROOT01"))],
        "B2": [S("Asset record: E02 stale sensors", f"{f}#assets[{loc['E02 Legacy workstations (stale sensors)'][0]}]",
                 loc["E02 Legacy workstations (stale sensors)"][1]["os"]),
               S("Evidence S08", f"{f}#evidence[{ev['S08'][0]}]", [x for x in s08 if x.startswith("E02")]),
               S("What the agent decided", "baseline/main_run/assessment.json", agent("E02 Legacy workstations (stale sensors)"))],
        "B3": [S("Windows Server 2022 builds in the snapshot", f"{f}#assets", srv22),
               S("Fixed build for Server 2022 (NVD)", f"inputs/{CVE}_nvd_raw.json", [m.get("versionEndExcluding") for m in cpe if "windows_server_2022" in m["criteria"]]),
               S("What the agent decided", "baseline/main_run/assessment.json", {k: by[k]["decision"] for k in srv22 if k in by})],
        "B4": [S("Products the company documents it does NOT use", f"{f}#absences", snap["absences"]),
               S("The agent's searches", "baseline/main_run/tool_results.json",
                 [{"ref": t["ref"], "args": t["args"], "status": t["result"]["status"]} for t in tools if t["args"].get("action") == "search_assets"])],
        "C1": [S("Every tool call the model chose", "baseline/main_run/tool_results.json",
                 [f"{t['ref']} {t['tool']} {json.dumps(t['args'])}" + (" → REJECTED" if str(t['result'].get('error') or '').startswith(('unknown tool', 'invalid arguments')) else "") for t in tools])],
        "C2": [S("External and environment lookups", "baseline/main_run/tool_results.json",
                 [f"{t['ref']} {t['tool']} → {t['result']['status']} ({t['result'].get('source_mode')})" for t in tools])],
        "C3": [S("Times the real snapshot name appears in what the model saw", "baseline/main_run/messages.json",
                 {"northbridge-v1.1.json": messages_text.count("northbridge-v1.1.json"), "snapshot.json (blinded name)": messages_text.count("snapshot.json")})],
        "C4": [S("Group consensus", "docs/expected_results.md section 1",
                 [l for l in (REPO_ROOT / "docs/expected_results.md").read_text(encoding="utf-8").splitlines() if l.startswith(("| Proposed rating", "| Group consensus"))]),
               S("What the agent decided for W15", "baseline/main_run/assessment.json", bw["decision"])],
    }
    if rid not in table:
        raise KeyError(rid)
    return {"id": rid, "sources": table[rid]}
