"""Run inside the ATG container after a scan: prints the latest scan's endpoints and findings as JSON,
in the shape bench/run_opensource.py scores (python bench/run_opensource.py --score-only --tag real)."""
import glob
import json
import os

runs = sorted(glob.glob("/work/runs/*/analysis.json"), key=os.path.getmtime)
a = json.load(open(runs[-1]))
e = json.load(open(runs[-1].replace("analysis.json", "eujf.json")))
t = json.load(open(runs[-1].replace("analysis.json", "timings.json")))
sj = runs[-1].replace("analysis.json", "scan.json")
scan = json.load(open(sj)) if os.path.exists(sj) else {}
print(json.dumps({
    "company": os.environ.get("ATG_SYSTEM", ""), "users": "real images, own load generator and opensource/real/<id>/load.txt",
    "scan_s": round(sum(v for k, v in t.items() if k.endswith("_ms")) / 1000, 1), "timings": t,
    "flows": scan.get("flows"), "span_batches": scan.get("span_batches"),
    "run_id": a["run_id"], "summary": a["summary"], "eujf_summary": e["summary"], "gateway": e.get("gateway"),
    "endpoints": [{"id": x["id"], "service": x["service"], "method": x["method"], "path": x["path"],
                   "inventory": x["inventory_status"], "seen_in": x["seen_in"], "public_paths": x["public_paths"]}
                  for x in e["endpoints"]],
    "findings": [{"rule": f["rule_id"], "target": f["target"], "detail": f["detail"], "severity": f["severity"],
                  "score": f["score"]} for f in a["findings"]],
    "routes": [{k: r.get(k) for k in ("match_prefix", "upstream_service", "auth", "gateway", "strip_prefix", "replace_with")}
               for r in e["gateway_routes"]],
    "services": [{"name": s["name"], "role": s["role"], "exposure": s["exposure"]["level"]} for s in e["services"]],
    "trace_services": sorted({s["service"] for s in e.get("trace_services", [])}),
}, indent=1))
