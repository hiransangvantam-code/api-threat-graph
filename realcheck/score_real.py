"""
Score a capture of the REAL crAPI against the ground truth mined from crAPI's
source (bench/testbeds/crapi/topology.yaml), and put it next to the replica
results from the main experiment.

    python realcheck/score_real.py        -> realcheck/out/real_vs_gt.md and .json

There is no access log inside the real containers, so "exercised" cannot be
known exactly. Here an endpoint counts as seen when the inventory entry that
matches it carries traffic evidence. Every inventory entry that matches nothing
in the ground truth is listed: it is either noise, or an endpoint the miner
missed, and each one is worth checking against crAPI's source by hand.
"""
from __future__ import annotations

import json
import statistics as st
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bench.evaluate import eujf_for, ground_truth, match  # noqa: E402

RAW = ROOT / "realcheck/out/raw"
OUT = ROOT / "realcheck/out"
TRAFFIC = {"traffic", "public_traffic"}


def score(combo: str, gt: dict) -> dict:
    e = eujf_for(RAW, combo)
    pairs, unmatched, fragments = match(e, gt)
    best = {}
    for ent, g in pairs:
        if g["key"] not in best or (ent["service"] == g["service"] and best[g["key"]][0]["service"] != g["service"]):
            best[g["key"]] = (ent, g)
    seen = {k: v for k, v in best.items() if TRAFFIC & set(v[0]["seen_in"])}
    documented = [g for g in gt["endpoints"] if g["documented"]]
    decided = [(ent, g) for ent, g in seen.values() if ent["auth_required"] in ("enforced", "not_enforced")]
    auth_ok = [(ent, g) for ent, g in decided if (ent["auth_required"] == "enforced") == (g["auth"] == "required")]
    true_shadow = {k for k, (ent, g) in seen.items() if not g["documented"]}
    pred_shadow = {k for k, (ent, g) in best.items() if ent["inventory_status"] == "shadow"}
    n = len(pairs) + len(unmatched)
    return {
        "entries": n, "matched_endpoints": len(best),
        "precision": round(len(best) / n, 4) if n else None,
        "documented_recall": round(sum(1 for g in documented if g["key"] in best) / len(documented), 4),
        "seen_in_traffic": len(seen),
        "seen_documented": len(seen) - len(true_shadow),
        "seen_undocumented": len(true_shadow),
        "shadow_precision": round(len(pred_shadow & true_shadow) / len(pred_shadow), 4) if pred_shadow else None,
        "shadow_recall": round(len(pred_shadow & true_shadow) / len(true_shadow), 4) if true_shadow else None,
        "auth_decided": len(decided), "auth_correct": len(auth_ok),
        "auth_wrong": [f'{g["method"]} {g["path"]} (truth: {g["auth"]}, inferred: {ent["auth_required"]})'
                       for ent, g in decided if (ent, g) not in auth_ok],
        "fragments": len(fragments),
        "unmatched": [f'{x["service"]}  {x["method"]} {x["path"]}  [{", ".join(x["seen_in"])}]' for x in unmatched],
        "seen_list": sorted(f'{g["method"]} {g["path"]}  ({ent["inventory_status"]}, auth {ent["auth_required"]})'
                            for ent, g in seen.values()),
    }


def replica_baseline() -> dict | None:
    runs = [json.loads(f.read_text()) for f in sorted((ROOT / "results/grid").glob("crapi-C2-*/run.json"))]
    if not runs:
        return None
    s = [r["metrics"]["subsets"]["OTK"] for r in runs]
    return {"runs": len(runs),
            "precision": round(st.fmean(x["M1"]["precision"] for x in s), 4),
            "recall_observable": round(st.fmean(x["M1"]["recall_observable"] for x in s), 4),
            "label_accuracy": round(st.fmean(x["M3"]["label_accuracy"] for x in s), 4),
            "auth_accuracy": round(st.fmean(x["M3"]["auth_accuracy"] for x in s if x["M3"]["auth_accuracy"] is not None), 4)}


def main():
    import argparse
    global RAW, OUT
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", default=str(RAW), help="extractor output folder")
    ap.add_argument("--out", default=str(OUT))
    a = ap.parse_args()
    RAW, OUT = Path(a.raw), Path(a.out)
    OUT.mkdir(parents=True, exist_ok=True)
    if not (RAW / "runtime_traffic.json").exists():
        sys.exit("no extractor output yet. Run: python -m extractor --config realcheck/extractor-crapi-real.yaml")
    gt = ground_truth("crapi")
    res = {c: score(c, gt) for c in ("O", "T", "OT", "TK", "OTK")}
    base = replica_baseline()
    manifest = json.loads((RAW / "manifest.json").read_text())
    flows = manifest["sources"]["runtime_traffic"].get("stats", {})
    out = {"ground_truth": {"endpoints": len(gt["endpoints"]),
                            "documented": sum(g["documented"] for g in gt["endpoints"])},
           "capture": flows, "subsets": res, "replica_baseline_C2_OTK": base}
    (OUT / "real_vs_gt.json").write_text(json.dumps(out, indent=1))

    a = res["OTK"]
    md = ["# Real crAPI vs mined ground truth", "",
          f"Ground truth: {out['ground_truth']['endpoints']} endpoints mined from crAPI source, "
          f"{out['ground_truth']['documented']} of them in crAPI's published spec.", "",
          f"Capture: {flows.get('flows', '?')} API flows kept, {flows.get('flows_ignored', '?')} dropped (web assets, probes).", "",
          "## By source subset", "",
          "| Sources | Entries | Matched | Precision | Documented recall | Seen in traffic | Seen, undocumented | Fragments |",
          "|---|---|---|---|---|---|---|---|"]
    for c, r in res.items():
        md.append(f"| {c} | {r['entries']} | {r['matched_endpoints']} | {r['precision']} | {r['documented_recall']} | "
                  f"{r['seen_in_traffic']} | {r['seen_undocumented']} | {r['fragments']} |")
    md += ["", "## All three sources (O+T+K)", "",
           f"- Shadow detection: precision {a['shadow_precision']}, recall {a['shadow_recall']}",
           f"- Auth inference: {a['auth_correct']} of {a['auth_decided']} decided endpoints correct", ""]
    if base:
        md += [f"Replica, same sources, condition C2 (mean of {base['runs']} runs): precision {base['precision']}, "
               f"observable recall {base['recall_observable']}, label accuracy {base['label_accuracy']}, "
               f"auth accuracy {base['auth_accuracy']}.", ""]
    md += ["## Entries with no match in the ground truth", "",
           "Check each against crAPI's source: noise, or an endpoint the miner missed?", ""]
    md += [f"- `{u}`" for u in a["unmatched"]] or ["(none)"]
    md += ["", "## Wrong auth inferences", ""] + ([f"- {w}" for w in a["auth_wrong"]] or ["(none)"])
    md += ["", "## Endpoints seen in traffic", ""] + [f"- {s}" for s in a["seen_list"]]
    (OUT / "real_vs_gt.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(md[:16]))
    print(f"\nfull report: {OUT / 'real_vs_gt.md'}")


if __name__ == "__main__":
    main()
