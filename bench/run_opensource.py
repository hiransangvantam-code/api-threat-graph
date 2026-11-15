"""
ATG on the ten open-source systems (opensource/), run like START does it, and scored against
each system's ground truth (opensource/<id>/ground-truth.json, see bench/oss_scoring.py).

    python opensource/fetch.py && python opensource/build.py      once
    python bench/run_opensource.py --tag v1.4                       all ten
    python bench/run_opensource.py bookinfo --tag v1.4              one
    python bench/run_opensource.py --score-only --tag v1.4          score saved runs again

For each system: start its stand-in Docker, start ATG on its network (ATG reads the system's
real manifests, gateway configuration and API documents from upstream/), run its users, scan,
copy the scan's endpoints and findings out, and stop both Dockers.

Writes results/opensource/atg-<tag>/<id>.json, scores.json and tables.md.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "bench"))
sys.path.insert(0, str(ROOT / "opensource"))
import oss_scoring as sc  # noqa: E402
from fetch import SYSTEMS  # noqa: E402
from run_companies import run_company  # noqa: E402

OUT = ROOT / "results" / "opensource"


def atg_pairs(res: dict, al: dict) -> set[tuple[str, str]]:
    pairs = set()
    for f in res["findings"]:
        cat = sc.ATG_CATS.get(f["rule"])
        if cat:
            pairs.add((cat, sc.norm(f["target"], al)))
    return pairs


def score_run(sid: str, res: dict) -> dict:
    al = sc.aliases(sid)
    s = sc.score(sid, atg_pairs(res, al))
    s["endpoints"] = sc.endpoint_score(sid, {e["id"] for e in res["endpoints"]}, al)
    s["scan_s"] = res.get("scan_s")
    s["system"] = sid
    return s


def pct(a, b):
    return f"{100 * a / b:.0f}%" if b else "-"


def tables(scores: list[dict], tag: str) -> str:
    import yaml
    rows, tot = [], {}
    for s in scores:
        y = yaml.safe_load((ROOT / "opensource" / s["system"] / "system.yaml").read_text(encoding="utf-8"))
        e, g = s["endpoints"], s["by_group"]
        cells = [f"{e['correct']}/{e['real']}", pct(e["correct"], e["listed"])]
        for grp in sc.GROUPS:
            cells.append(f"{g[grp]['found']}/{g[grp]['labels']}")
        cells.append(f"{s['confirmed']}/{s['reported']} ({pct(s['confirmed'], s['reported'])})")
        rows.append(f"| {y['name']} | {y['field']} | {', '.join(y['languages'])} | " + " | ".join(cells) + f" | {s['scan_s']:.1f} |")
        for k, v in (("er", e["real"]), ("ec", e["correct"]), ("el", e["listed"]), ("rep", s["reported"]), ("con", s["confirmed"])):
            tot[k] = tot.get(k, 0) + v
        for grp in sc.GROUPS:
            tot[grp + "l"] = tot.get(grp + "l", 0) + g[grp]["labels"]
            tot[grp + "f"] = tot.get(grp + "f", 0) + g[grp]["found"]
        tot["t"] = tot.get("t", 0) + (s["scan_s"] or 0)
    rows.append(f"| **All ten** | | | {tot['ec']}/{tot['er']} ({pct(tot['ec'], tot['er'])}) | {pct(tot['ec'], tot['el'])} | "
                + " | ".join(f"{tot[g + 'f']}/{tot[g + 'l']} ({pct(tot[g + 'f'], tot[g + 'l'])})" for g in sc.GROUPS)
                + f" | {tot['con']}/{tot['rep']} ({pct(tot['con'], tot['rep'])}) | {tot['t'] / len(scores):.1f} avg |")
    cats = {}
    for s in scores:
        for c, v in s["by_cat"].items():
            cats.setdefault(c, [0, 0])
            cats[c][0] += v["labels"]
            cats[c][1] += v["found"]
    cat_rows = "\n".join(f"| {c} | {sc.CAT_NAMES[c]} | {v[0]} | {v[1]} ({pct(v[1], v[0])}) |"
                         for c, v in sorted(cats.items(), key=lambda kv: (kv[0][0], int(kv[0][1:]))))
    return f"""# ATG on ten open-source systems ({tag})

Produced by `bench/run_opensource.py`. ATG read each system's real deployment files and API
documents; the running services were stand-ins answering the same operations (see
`opensource/README.md`). Ground truth: `opensource/<id>/ground-truth.json`.

| System | Field | Languages | Operations found | Operation precision | {' | '.join(f'{g} labels found' for g in sc.GROUPS)} | Findings that match a label | Scan (s) |
|---|---|---|---:|---:|{'---:|' * len(sc.GROUPS)}---:|---:|
{chr(10).join(rows)}

## By category

| Category | Meaning | Labels | Found by ATG |
|---|---|---:|---:|
{cat_rows}
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("systems", nargs="*", default=SYSTEMS)
    ap.add_argument("--tag", default="v1.4")
    ap.add_argument("--score-only", action="store_true")
    a = ap.parse_args()
    out = OUT / f"atg-{a.tag}"
    out.mkdir(parents=True, exist_ok=True)
    for sid in a.systems:
        if a.score_only:
            continue
        print(f"== {sid}", flush=True)
        t = time.time()
        res = run_company(sid, "opensource")
        (out / f"{sid}.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
        s = score_run(sid, res)
        print(f"   {res['users']}\n   operations {s['endpoints']['correct']}/{s['endpoints']['real']} "
              f"(+{len(s['endpoints']['extra'])}), labels {s['found']}/{s['labels']}, "
              f"findings matching a label {s['confirmed']}/{s['reported']}, {time.time() - t:.0f} s", flush=True)
    scores = [score_run(sid, json.loads((out / f"{sid}.json").read_text(encoding="utf-8")))
              for sid in SYSTEMS if (out / f"{sid}.json").exists()]
    (out / "scores.json").write_text(json.dumps(scores, indent=1), encoding="utf-8")
    (out / "tables.md").write_text(tables(scores, a.tag), encoding="utf-8")
    print(f"wrote {(out / 'tables.md').relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
