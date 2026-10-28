"""
Metrics M1-M4 for one experiment run, for every combination of discovery sources.

Ground truth comes from two places that the tool never reads:
  topology.yaml   endpoints, auth, documentation and call sites mined from source
  gt/*.jsonl      the testbed's own access logs: what actually ran in this run

Matching: an inventory entry matches a ground-truth endpoint when the HTTP method
is equal and the path shape is equal ({...} parameters ignored), either at the
backend path or at its public path through the gateway.

  M1 coverage     recall over all true endpoints, over observable ones (documented or
                  exercised in this run) and over exercised ones; strict precision
                  (duplicates count as false positives) and lenient precision; F1
                  uses strict precision and recall over all
  M2 duplicates   raw observations -> inventory entries; duplicates collapsed across
                  sources; unresolved fragments (concrete values left in a path)
  M3 observation  service attribution, auth inference, inventory label (documented /
                  shadow / zombie / dormant), shadow-API detection P/R
  M4 dependencies service->service edges: precision, recall (all / exercised)
"""
from __future__ import annotations

import itertools
import json
import re
import shutil
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

from atg.normalizer import normalize
from bench.common import IGNORED, load_topology, public_path, shape

SOURCES = {"O": "openapi", "T": "runtime_traffic", "K": "infrastructure", "C": "callchain"}
LABELS = {"O": "OpenAPI", "T": "Traffic", "K": "K8s/gateway", "C": "Traces"}


def subsets():
    keys = list(SOURCES)
    for r in range(1, len(keys) + 1):
        for combo in itertools.combinations(keys, r):
            yield "".join(combo)


# ---------------------------------------------------------------- ground truth
def ground_truth(testbed: str) -> dict:
    topo = load_topology(testbed)
    gw = topo["gateway"]["service"]
    eps = []
    for s in topo["services"]:
        svc_doc = s.get("documented")
        for e in s["endpoints"]:
            if e["path"] in IGNORED:
                continue
            doc = e.get("documented", svc_doc is True)
            pp = e["path"] if s["name"] == gw else public_path(topo, e["path"], s["name"])
            aliases = {shape(e["path"])} | ({shape(pp)} if pp else set())
            rx = "^" + re.sub(r"\\\{[^}]*\\\}", "[^/]+", re.escape(e["path"].rstrip("/") or "/")) + "/?$"
            eps.append({"service": s["name"], "method": e["method"], "path": e["path"], "auth": e.get("auth", "none"),
                        "documented": bool(doc), "deprecated": bool(e.get("deprecated")), "public": bool(pp),
                        "aliases": aliases, "regex": re.compile(rx),
                        "key": (s["name"], e["method"], shape(e["path"]))})
    edges = {(s["name"], c["service"]) for s in topo["services"] for e in s["endpoints"] for c in e.get("calls", [])
             if c["service"] != s["name"]}
    routed = {r["service"] for r in topo["gateway"]["routes"]}
    edges |= {(gw, svc) for svc in routed if any(x["service"] == svc and x["public"] for x in eps)}
    return {"topology": topo, "gateway": gw, "endpoints": eps, "edges": edges}


def exercised(gt: dict, gt_dir: Path) -> tuple[set, set]:
    """(endpoint keys that served at least one non-404 request, edges that carried a call)."""
    keys, callers = set(), set()
    for f in gt_dir.glob("*.jsonl"):
        for line in f.read_text(encoding="utf-8").splitlines():
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if r.get("ua", "").startswith("atg-") or r["route"] in ("(no route)", "/v2/api-docs") or r["status"] == 404:
                continue
            keys.add((r["service"], r["method"], shape(r["route"])))
            if r.get("caller"):
                callers.add((r["caller"], r["service"]))
    ex_eps = {e["key"] for e in gt["endpoints"] if e["key"] in keys}
    if not callers:  # testbed logs carry no caller (ShopLite): an edge ran if its callee endpoint ran
        topo = gt["topology"]
        for s in topo["services"]:
            for e in s["endpoints"]:
                if (s["name"], e["method"], shape(e["path"])) in ex_eps:
                    for c in e.get("calls", []):
                        callers.add((s["name"], c["service"]))
        for (a, b) in gt["edges"]:
            if a == gt["gateway"] and any(k[0] == b for k in ex_eps):
                callers.add((a, b))
    return ex_eps, callers & gt["edges"]


# ---------------------------------------------------------------- inventory per subset
def eujf_for(raw: Path, combo: str, reconcile: bool = True) -> dict:
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        for k in combo:
            src = raw / f"{SOURCES[k]}.json"
            if src.exists():
                shutil.copy(src, td / src.name)
        if (raw / "manifest.json").exists():
            shutil.copy(raw / "manifest.json", td / "manifest.json")
        return normalize(td, reconcile=reconcile)


def _entries(eujf: dict) -> list[dict]:
    out = []
    for e in eujf["endpoints"]:
        if e["path"] in IGNORED or "**" in e["path"] or e["path"] == "/v2/api-docs":
            continue
        out.append(e)
    return out


def match(eujf: dict, gt: dict):
    by_method = defaultdict(list)
    for g in gt["endpoints"]:
        by_method[g["method"]].append(g)
    pairs, unmatched, fragments = [], [], []
    for e in _entries(eujf):
        shapes = {shape(e["path"])} | {shape(p) for p in e.get("public_paths", [])}
        hits = [g for g in by_method[e["method"]] if g["aliases"] & shapes]
        if hits:
            # same service first, then backend-path match
            hits.sort(key=lambda g: (g["service"] != e["service"], shape(g["path"]) not in shapes))
            pairs.append((e, hits[0]))
        else:
            unmatched.append(e)
            concrete = re.sub(r"\{[^}]*\}", "x", e["path"])
            if any(g["regex"].match(concrete) for g in by_method[e["method"]]):
                fragments.append(e)
    return pairs, unmatched, fragments


def gt_label(g, ex):
    if g["deprecated"] and g["key"] in ex:
        return "zombie"
    if g["documented"]:
        return "documented" if g["key"] in ex else "dormant"
    return "shadow" if g["key"] in ex else "unobservable"


def metrics(eujf: dict, gt: dict, ex: set, ex_edges: set) -> dict:
    pairs, unmatched, fragments = match(eujf, gt)
    found = {g["key"] for _, g in pairs}
    n_gt, n_ex = len(gt["endpoints"]), len(ex)
    n_entries = len(pairs) + len(unmatched)
    # strict precision: each true endpoint can be claimed by one entry; extra entries
    # for the same endpoint (duplicates) count as false positives
    prec = len(found) / n_entries if n_entries else 0.0
    prec_len = len(pairs) / n_entries if n_entries else 0.0
    observable = {g["key"] for g in gt["endpoints"] if g["documented"] or g["key"] in ex}
    rec_obs = len(found & observable) / len(observable) if observable else 0.0
    rec_all = len(found) / n_gt if n_gt else 0.0
    rec_ex = len(found & ex) / n_ex if n_ex else 0.0
    f1 = 2 * prec * rec_all / (prec + rec_all) if prec + rec_all else 0.0

    per_gt = Counter(g["key"] for _, g in pairs)
    # M3 on the best entry per ground-truth endpoint
    best = {}
    for e, g in pairs:
        if g["key"] not in best or (e["service"] == g["service"] and best[g["key"]][0]["service"] != g["service"]):
            best[g["key"]] = (e, g)
    svc_ok = sum(1 for e, g in best.values() if e["service"] == g["service"])
    decided = [(e, g) for e, g in best.values() if e["auth_required"] in ("enforced", "not_enforced")]
    auth_ok = sum(1 for e, g in decided if (e["auth_required"] == "enforced") == (g["auth"] == "required"))
    lab = [(e["inventory_status"], gt_label(g, ex)) for e, g in best.values()]
    lab_ok = sum(1 for p, t in lab if p == t)
    pred_sh = {g["key"] for e, g in best.values() if e["inventory_status"] == "shadow"}
    true_sh = {g["key"] for g in gt["endpoints"] if gt_label(g, ex) == "shadow"}

    edges = {(d["from"], d["to"]) for d in eujf["dependencies"]}
    tp_e = edges & gt["edges"]

    def r(x):
        return round(x, 4)
    return {
        "M1": {"gt_endpoints": n_gt, "exercised": n_ex, "entries": n_entries, "found": len(found),
               "observable": len(observable), "precision": r(prec), "precision_lenient": r(prec_len),
               "recall_all": r(rec_all), "recall_observable": r(rec_obs), "recall_exercised": r(rec_ex), "f1": r(f1)},
        "M2": {"entries": n_entries, "unmatched": len(unmatched), "fragments": len(fragments),
               "split_endpoints": sum(1 for v in per_gt.values() if v > 1),
               "reconciled": eujf["summary"].get("reconciled_traffic_paths", 0)},
        "M3": {"matched": len(best),
               "service_attribution": r(svc_ok / len(best)) if best else None,
               "auth_decided": r(len(decided) / len(best)) if best else None,
               "auth_accuracy": r(auth_ok / len(decided)) if decided else None,
               "label_accuracy": r(lab_ok / len(lab)) if lab else None,
               "label_confusion": {f"{t}->{p}": n for (p, t), n in Counter(lab).items()},
               "shadow_precision": r(len(pred_sh & true_sh) / len(pred_sh)) if pred_sh else None,
               "shadow_recall": r(len(pred_sh & true_sh) / len(true_sh)) if true_sh else None,
               "true_shadow": len(true_sh)},
        "M4": {"gt_edges": len(gt["edges"]), "exercised_edges": len(ex_edges), "found_edges": len(edges),
               "precision": r(len(tp_e) / len(edges)) if edges else None,
               "recall_all": r(len(tp_e) / len(gt["edges"])) if gt["edges"] else None,
               "recall_exercised": r(len(tp_e & ex_edges) / len(ex_edges)) if ex_edges else None},
    }


def evaluate_run(testbed: str, run_dir: Path) -> dict:
    gt = ground_truth(testbed)
    ex, ex_edges = exercised(gt, run_dir / "gt")
    raw = run_dir / "raw"
    out = {"testbed": testbed, "subsets": {}, "reconcile_off": {}}
    for combo in subsets():
        out["subsets"][combo] = metrics(eujf_for(raw, combo), gt, ex, ex_edges)
    for combo in ("TK", "OTKC"):
        out["reconcile_off"][combo] = metrics(eujf_for(raw, combo, reconcile=False), gt, ex, ex_edges)
    flows = [json.loads(l) for l in (run_dir / "capture/flows.jsonl").read_text().splitlines() if l.strip()] \
        if (run_dir / "capture/flows.jsonl").exists() else []
    flows = [f for f in flows if not f.get("user_agent", "").startswith("atg-")]
    single = sum(out["subsets"][k]["M1"]["entries"] for k in SOURCES)
    merged = out["subsets"]["OTKC"]["M1"]["entries"]
    out["raw"] = {"flows": len(flows), "distinct_concrete_paths": len({(f["method"], f["path"]) for f in flows}),
                  "entries_single_sources_total": single, "entries_merged": merged,
                  "duplicates_collapsed": single - merged}
    return out
