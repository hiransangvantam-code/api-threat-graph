"""
ATG next to the free tools on the ten open-source systems: one set of tables from the saved runs.

    python bench/compare_tools.py                 ATG v1.5 against the tools, v1.4 for before/after
    python bench/compare_tools.py --atg v1.5 --before v1.4

Reads results/opensource/atg-<tag>/<id>.json and results/opensource/tools/<tool>/<id>.json, scores
everything again with the current ground truth (bench/oss_scoring.py), and writes
results/opensource/comparison.md and comparison.json.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "bench"))
sys.path.insert(0, str(ROOT / "opensource"))
import oss_scoring as sc  # noqa: E402
from fetch import SYSTEMS  # noqa: E402
from run_opensource import atg_pairs  # noqa: E402
from run_tools import LANG_TOOL, SCOPE, SOURCES  # noqa: E402

OUT = ROOT / "results" / "opensource"
TOOLS = ["checkov", "kubescape", "kube-linter", "polaris", "spectral", "bandit", "gosec", "njsscan"]
NAMES = {"atg": "ATG", "checkov": "Checkov", "kubescape": "Kubescape", "kube-linter": "kube-linter", "polaris": "Polaris",
         "spectral": "Spectral (OWASP)", "bandit": "Bandit", "gosec": "gosec", "njsscan": "njsscan"}
ATG_SCOPE = {c for c in sc.ATG_CATS.values() if c}


def labels(sid: str) -> set[tuple[str, str]]:
    gt = json.loads((ROOT / "opensource" / sid / "ground-truth.json").read_text(encoding="utf-8"))
    return {(l["cat"], l["target"]) for l in gt["labels"]}


def found_set(sid: str, pairs: set) -> set:
    s = sc.score(sid, pairs)
    return labels(sid) - {tuple(m) for m in s["missed"]}


def load(tag: str) -> dict:
    """{tool: {sid: {"applicable", "why", "pairs", "seconds", "findings", "covered", "services"}}}"""
    runs = {"atg": {}}
    d = OUT / f"atg-{tag}"
    for sid in SYSTEMS:
        f = d / f"{sid}.json"
        if f.exists():
            r = json.loads(f.read_text(encoding="utf-8"))
            runs["atg"][sid] = {"applicable": True, "pairs": atg_pairs(r, sc.aliases(sid)), "seconds": r.get("scan_s"),
                                "findings": len(r["findings"]), "endpoints": {e["id"] for e in r["endpoints"]}}
    for t in TOOLS:
        runs[t] = {}
        for sid in SYSTEMS:
            f = OUT / "tools" / t / f"{sid}.json"
            if f.exists():
                r = json.loads(f.read_text(encoding="utf-8"))
                r["pairs"] = {tuple(p) for p in r.get("pairs", [])}
                runs[t][sid] = r
    return runs


def pct(a, b):
    return f"{100 * a / b:.0f}%" if b else "–"


def tally(tool: str, runs: dict) -> dict:
    scope = ATG_SCOPE if tool == "atg" else SCOPE.get(tool, set())
    t = {"ran": 0, "labels": 0, "found": 0, "reported": 0, "confirmed": 0, "in_reach": 0, "in_reach_found": 0,
         "groups": {g: [0, 0] for g in sc.GROUPS}, "cats": {}, "secs": [], "na": {}}
    for sid in SYSTEMS:
        lab = labels(sid)
        t["labels"] += len(lab)
        for g, cats in sc.GROUPS.items():
            t["groups"][g][0] += sum(1 for l in lab if l[0] in cats)
        for l in lab:
            t["cats"].setdefault(l[0], [0, 0])[0] += 1
        r = runs[tool].get(sid)
        if not r or not r.get("applicable"):
            t["na"][sid] = (r or {}).get("why", "not run")
            continue
        t["ran"] += 1
        s = sc.score(sid, r["pairs"], scope)
        f = lab - {tuple(m) for m in s["missed"]}
        t["found"] += len(f)
        t["reported"] += s["reported"]
        t["confirmed"] += s["confirmed"]
        t["in_reach"] += s["in_reach"]["labels"]
        t["in_reach_found"] += s["in_reach"]["found"]
        for g, cats in sc.GROUPS.items():
            t["groups"][g][1] += sum(1 for l in f if l[0] in cats)
        for l in f:
            t["cats"][l[0]][1] += 1
        if r.get("seconds") is not None:
            t["secs"].append(r["seconds"])
    return t


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--atg", default="v1.5")
    ap.add_argument("--before", default="v1.4")
    a = ap.parse_args()
    runs = load(a.atg)
    before = load(a.before)["atg"] if (OUT / f"atg-{a.before}").exists() else {}
    order = ["atg"] + TOOLS
    T = {t: tally(t, runs) for t in order}
    md = [f"# ATG and eight free tools on ten open-source systems (ATG {a.atg})", "",
          "Produced by `bench/compare_tools.py` from the saved runs in `results/opensource/`. Every tool is scored "
          "against the same ground truth (`opensource/<id>/ground-truth.json`): a label counts as found when the "
          "tool reports the same weakness category on the same service or endpoint. Method and limits: "
          "`docs/BENCHMARK_OSS.md`.", ""]

    # ---- Table A: overall
    md += ["## Table A. Overall", "",
           "*Labels found* counts every label in all ten systems, so a tool that cannot run on a system scores 0 "
           "there. *In reach* counts only the labels in categories the tool can report at all, on the systems it ran "
           "on. *Precision* is the share of the tool's (category, place) reports that match a label.", "",
           "| Tool | Runs on | Labels found (all) | " + " | ".join(sc.GROUPS) + " | In reach | Precision | Time per system (median) |",
           "|---|---:|---:|" + "---:|" * len(sc.GROUPS) + "---:|---:|---:|"]
    for t in order:
        x = T[t]
        groups = " | ".join(f"{v[1]}/{v[0]} ({pct(v[1], v[0])})" for v in x["groups"].values())
        m = statistics.median(x["secs"]) if x["secs"] else None
        med = "–" if m is None else f"{m:.2f} s" if m < 0.1 else f"{m:.1f} s"
        md.append(f"| {'**ATG**' if t == 'atg' else NAMES[t]} | {x['ran']}/10 | {x['found']}/{x['labels']} ({pct(x['found'], x['labels'])}) | "
                  f"{groups} | {x['in_reach_found']}/{x['in_reach']} ({pct(x['in_reach_found'], x['in_reach'])}) | "
                  f"{x['confirmed']}/{x['reported']} ({pct(x['confirmed'], x['reported'])}) | {med} |")
    md += ["", "ATG's time is the whole scan as START runs it (about 7 s of it is waiting for the sidecar and the "
           "Collector to go quiet); the analysis itself (Phases 1-4) takes well under a second. The other tools' "
           "time is one run of the tool on the system's files.", ""]

    # ---- Table B: by category
    cats = sorted(T["atg"]["cats"], key=lambda c: (c[0], int(c[1:])))
    md += ["## Table B. Found, by weakness category", "",
           "| Category | Meaning | Labels | " + " | ".join(NAMES[t] for t in order) + " |",
           "|---|---|---:|" + "---:|" * len(order)]
    for c in cats:
        n = T["atg"]["cats"][c][0]
        cells = []
        for t in order:
            scope = ATG_SCOPE if t == "atg" else SCOPE.get(t, set())
            cells.append(str(T[t]["cats"].get(c, [0, 0])[1]) if c in scope else "·")
        md.append(f"| {c} | {sc.CAT_NAMES[c]} | {n} | " + " | ".join(cells) + " |")
    md += ["", "· = the tool has no check for this category. ATG reports missing resource limits (C3) only for "
           "services reachable from the internet, where they matter for API4 (resource consumption); the scanners "
           "report every container, which is why they find more C3 labels.", ""]

    # ---- Table C: per system, configuration labels
    md += ["## Table C. Per system", "",
           "Labels found (all groups) / labels. n/a = the tool cannot run on that system.", "",
           "| System | Labels | " + " | ".join(NAMES[t] for t in order) + " |", "|---|---:|" + "---:|" * len(order)]
    for sid in SYSTEMS:
        lab = labels(sid)
        cells = []
        for t in order:
            r = runs[t].get(sid)
            if not r or not r.get("applicable"):
                cells.append("n/a")
            else:
                cells.append(str(len(found_set(sid, r["pairs"]))))
        md.append(f"| {sid} | {len(lab)} | " + " | ".join(cells) + " |")
    md.append("")

    # ---- Table D: where tools stop
    md += ["## Table D. Where each tool stops", "",
           "| Tool | Needs | Systems it could not run on |", "|---|---|---|"]
    needs = {"atg": "a running test deployment (any language), plus whatever files exist",
             "checkov": "Kubernetes manifests", "kubescape": "Kubernetes manifests (current API versions)",
             "kube-linter": "Kubernetes manifests", "polaris": "Kubernetes manifests",
             "spectral": "an OpenAPI document", "bandit": "Python source", "gosec": "Go source", "njsscan": "Node.js source"}
    for t in order:
        na = T[t]["na"]
        why = sorted(set(na.values()))
        md.append(f"| {NAMES[t]} | {needs[t]} | {len(na)}: {', '.join(na) or 'none'}" + (f" ({'; '.join(why)})" if why else "") + " |")
    md += ["", "Kubescape also ran on FTGO but found 6 of 82 labels: FTGO declares its Deployments and StatefulSets "
           "with API versions Kubernetes has removed (`extensions/v1beta1`, `apps/v1beta1`), and Kubescape skipped "
           "them, scanning only the Services, the Secret and the Job. The other scanners read them.", "",
           "Single-language code scanners: services each one could read, per system.", "",
           "| System | Services | Bandit (Python) | gosec (Go) | njsscan (Node.js) |", "|---|---:|---:|---:|---:|"]
    tot = [0, 0, 0, 0]
    for sid in SYSTEMS:
        n = len(SOURCES[sid])
        cov = [runs[t].get(sid, {}).get("covered", 0) for t in ("bandit", "gosec", "njsscan")]
        tot = [tot[0] + n] + [tot[i + 1] + cov[i] for i in range(3)]
        md.append(f"| {sid} | {n} | " + " | ".join(str(c) for c in cov) + " |")
    md.append(f"| **All** | {tot[0]} | " + " | ".join(f"{c} ({pct(c, tot[0])})" for c in tot[1:]) + " |")
    md += ["", f"Together the three code scanners read {sum(tot[1:])} of {tot[0]} services "
           f"({pct(sum(tot[1:]), tot[0])}); the Java, C#, Ruby and PHP services have no free scanner here. "
           "ATG does not read source code, so it works the same for every language.", ""]

    # ---- Table E: ATG plus a Kubernetes scanner
    md += ["## Table E. ATG together with a Kubernetes scanner", "",
           "Labels found by each tool, by both, and by either. The scanners add the container-hardening checks "
           "ATG does not have (C9, C10); ATG adds the API, inventory and Compose findings they cannot make.", "",
           "| Pair | ATG | Other tool | Both | Either |", "|---|---:|---:|---:|---:|"]
    for t in ("polaris", "kubescape", "checkov"):
        A = B = U = I = 0
        for sid in SYSTEMS:
            fa = found_set(sid, runs["atg"][sid]["pairs"]) if sid in runs["atg"] else set()
            r = runs[t].get(sid)
            fb = found_set(sid, r["pairs"]) if r and r.get("applicable") else set()
            A, B, U, I = A + len(fa), B + len(fb), U + len(fa | fb), I + len(fa & fb)
        tl = sum(len(labels(sid)) for sid in SYSTEMS)
        md.append(f"| ATG + {NAMES[t]} | {A} | {B} | {I} | {U}/{tl} ({pct(U, tl)}) |")
    md.append("")

    # ---- Table F: ATG before and after the version 1.5 fixes
    if before:
        md += [f"## Table F. ATG {a.before} and {a.atg} on the same systems", "",
               "Version 1.5 was made after reading the misses of version 1.4 on these systems (see "
               "`docs/BENCHMARK_OSS.md`), so this table shows the fixes worked, not how ATG does on unseen systems.", "",
               "| System | Labels | Found " + a.before + " | Found " + a.atg + " | Precision " + a.before + " | Precision " + a.atg + " |",
               "|---|---:|---:|---:|---:|---:|"]
        tb = tally_runs = {"before": [0, 0, 0], "after": [0, 0, 0]}
        for sid in SYSTEMS:
            if sid not in before or sid not in runs["atg"]:
                continue
            lab = labels(sid)
            sb = sc.score(sid, before[sid]["pairs"])
            sa = sc.score(sid, runs["atg"][sid]["pairs"])
            md.append(f"| {sid} | {len(lab)} | {sb['found']} | {sa['found']} | {pct(sb['confirmed'], sb['reported'])} | "
                      f"{pct(sa['confirmed'], sa['reported'])} |")
            for k, s in (("before", sb), ("after", sa)):
                tb[k][0] += s["found"]
                tb[k][1] += s["confirmed"]
                tb[k][2] += s["reported"]
        tl = sum(len(labels(s)) for s in SYSTEMS if s in before and s in runs["atg"])
        md.append(f"| **All** | {tl} | {tb['before'][0]} ({pct(tb['before'][0], tl)}) | {tb['after'][0]} ({pct(tb['after'][0], tl)}) | "
                  f"{pct(tb['before'][1], tb['before'][2])} | {pct(tb['after'][1], tb['after'][2])} |")
        md.append("")

    (OUT / "comparison.md").write_text("\n".join(md), encoding="utf-8")
    js = {t: {k: v for k, v in T[t].items() if k != "secs"} | {"median_s": statistics.median(T[t]["secs"]) if T[t]["secs"] else None}
          for t in order}
    (OUT / "comparison.json").write_text(json.dumps(js, indent=1), encoding="utf-8")
    print(f"wrote {(OUT / 'comparison.md').relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
