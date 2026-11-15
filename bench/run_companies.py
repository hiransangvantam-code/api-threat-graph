"""
Flexibility test: ATG on ten companies of different kinds (companies/).

    python bench/run_companies.py                 run all ten in Docker, then score and write the tables
    python bench/run_companies.py paynow fleetgo  only these
    python bench/run_companies.py --score-only    score the saved results again (no Docker)
    python bench/run_companies.py --tag v1.3      file name suffix, e.g. to keep a run from an earlier version

For each company, exactly as START does it: start the company's Docker, start the ATG Docker
on the company's network, run the company's users, run one scan. Then the endpoints and
findings of that scan are copied out of the ATG container (in memory there) and both
Dockers are stopped with their data deleted.

Scoring against companies/<id>/ground-truth.json (written by companies/build.py from the
company definition, before any scan):
  endpoints   recall = real endpoints ATG lists / real endpoints;
              precision = real endpoints ATG lists / endpoints ATG lists
  planted     a planted weakness is found when a finding has its rule and its target
              (and, for gateway findings, names its route)
  controls    negative controls: a finding there is a false alarm by construction
  findings    precision = findings that match a planted weakness / all findings; the
              others are listed for review in results/companies/review-<tag>.md

Writes results/companies/<id>-<tag>.json and results/companies/tables-<tag>.md.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "companies"))
from build import COMPANIES  # noqa: E402

OUT = ROOT / "results" / "companies"

DUMP = r"""
import json, glob, os
runs = sorted(glob.glob('/work/runs/*/analysis.json'), key=os.path.getmtime)
a = json.load(open(runs[-1])); e = json.load(open(runs[-1].replace('analysis.json', 'eujf.json')))
print(json.dumps({
  'run_id': a['run_id'], 'summary': a['summary'], 'eujf_summary': e['summary'], 'gateway': e.get('gateway'),
  'endpoints': [{'id': x['id'], 'service': x['service'], 'method': x['method'], 'path': x['path'],
                 'inventory': x['inventory_status'], 'seen_in': x['seen_in'], 'public_paths': x['public_paths']}
                for x in e['endpoints']],
  'findings': [{'rule': f['rule_id'], 'target': f['target'], 'detail': f['detail'], 'severity': f['severity'],
                'score': f['score']} for f in a['findings']],
  'routes': [{k: r.get(k) for k in ('match_prefix', 'upstream_service', 'auth', 'gateway', 'strip_prefix', 'replace_with')}
             for r in e['gateway_routes']],
  'services': [{'name': s['name'], 'role': s['role'], 'exposure': s['exposure']['level']} for s in e['services']],
}))
"""


def sh(cmd: list[str], env: dict | None = None, check: bool = True, capture: bool = False, timeout: int = 900):
    r = subprocess.run(cmd, cwd=ROOT, env={**os.environ, **(env or {})}, text=True, timeout=timeout,
                       stdout=subprocess.PIPE if capture else None, stderr=subprocess.STDOUT if capture else None)
    if check and r.returncode:
        raise RuntimeError(f"failed ({r.returncode}): {' '.join(cmd)}\n{r.stdout or ''}")
    return r


def read_env(cid: str, folder: str = "companies") -> dict:
    env = {}
    for line in (ROOT / folder / cid / "atg.env").read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k] = v.strip().strip('"')
    return env


def run_company(cid: str, folder: str = "companies") -> dict:
    env = read_env(cid, folder)
    comp = ["docker", "compose", "-f", f"{folder}/{cid}/docker-compose.yml"]
    sh(["docker", "compose", "down", "-v", "--remove-orphans"], env, check=False, capture=True)
    t0 = time.time()
    sh(comp + ["up", "-d", "--build", "--wait"], env, capture=True)
    sh(["docker", "compose", "up", "-d", "--build", "--wait"], env, capture=True)
    t_up = time.time() - t0
    users = sh(comp + ["run", "--rm", "users"], env, capture=True).stdout.strip().splitlines()[-1]
    t1 = time.time()
    scan = sh(["docker", "compose", "exec", "-T", "atg", "python", "docker/scan.py", "--label", cid, "--manifests", "k8s"],
              env, capture=True).stdout
    t_scan = time.time() - t1
    dump = json.loads(sh(["docker", "compose", "exec", "-T", "atg", "python", "-c", DUMP], env, capture=True).stdout)
    sh(["docker", "compose", "down", "-v", "--remove-orphans"], env, check=False, capture=True)
    sh(comp + ["--profile", "users", "down", "-v", "--remove-orphans"], env, check=False, capture=True)
    phases = [ln.strip() for ln in scan.splitlines() if ln.strip().startswith(("[ok]", "[fail]", "!", "[scan]"))]
    return {"company": cid, "users": users, "startup_s": round(t_up, 1), "scan_s": round(t_scan, 1),
            "scan_log": phases, **dump}


def score(cid: str, res: dict) -> dict:
    gt = json.loads((ROOT / "companies" / cid / "ground-truth.json").read_text(encoding="utf-8"))
    real = {e["id"] for e in gt["endpoints"]}
    listed = {e["id"] for e in res["endpoints"]}

    def hit(item, f):
        return f["rule"] == item["rule"] and f["target"] == item["target"] and item.get("match", "") in f["detail"]

    planted = []
    for p in gt["planted"]:
        found = [f for f in res["findings"] if hit(p, f)]
        planted.append({**p, "found": bool(found)})
    controls = []
    for p in gt["not_flaws"]:
        found = [f for f in res["findings"] if hit(p, f)]
        controls.append({**p, "false_alarm": bool(found)})
    matched = [f for f in res["findings"] if any(hit(p, f) for p in gt["planted"])]
    other = [f for f in res["findings"] if f not in matched]
    visible = [p for p in planted if not p.get("expect_miss")]
    return {
        "company": cid, "name": gt["name"],
        "endpoints": {"real": len(real), "listed": len(listed), "correct": len(real & listed),
                      "missed": sorted(real - listed), "extra": sorted(listed - real)},
        "planted": {"total": len(planted), "found": sum(p["found"] for p in planted),
                    "visible": len(visible), "visible_found": sum(p["found"] for p in visible),
                    "items": planted},
        "controls": {"total": len(controls), "false_alarms": sum(c["false_alarm"] for c in controls), "items": controls},
        "findings": {"total": len(res["findings"]), "matching_planted": len(matched),
                     "other": [{k: f[k] for k in ("rule", "target", "detail")} for f in other],
                     "other_by_rule": dict(Counter(f["rule"] for f in other).most_common())},
    }


def pct(a: int, b: int) -> str:
    return f"{100 * a / b:.0f}%" if b else "-"


def tables(scores: list[dict], runs: dict, tag: str) -> str:
    rows = []
    tot = Counter()
    for s in scores:
        c = json.loads((ROOT / "companies" / s["company"] / "ground-truth.json").read_text())
        y = __import__("yaml").safe_load((ROOT / "companies" / s["company"] / "company.yaml").read_text())
        r = runs[s["company"]]
        ep, pl, fi, co = s["endpoints"], s["planted"], s["findings"], s["controls"]
        rows.append(f"| {c['name']} | {y['industry']} | {y['language']} | {y['gateway']['type']} | "
                    f"{ep['correct']}/{ep['real']} ({pct(ep['correct'], ep['real'])}) | {pct(ep['correct'], ep['listed'])} | "
                    f"{pl['found']}/{pl['total']} | {pl['visible_found']}/{pl['visible']} | "
                    f"{fi['matching_planted']}/{fi['total']} ({pct(fi['matching_planted'], fi['total'])}) | "
                    f"{co['false_alarms']}/{co['total']} | {r['scan_s']:.1f} |")
        for k, v in (("ep_real", ep["real"]), ("ep_listed", ep["listed"]), ("ep_ok", ep["correct"]),
                     ("pl", pl["total"]), ("pl_found", pl["found"]), ("vis", pl["visible"]), ("vis_found", pl["visible_found"]),
                     ("fi", fi["total"]), ("fi_ok", fi["matching_planted"]), ("co", co["total"]), ("co_fa", co["false_alarms"])):
            tot[k] += v
        tot["scan"] += r["scan_s"]
    rows.append(f"| **All ten** | | | | {tot['ep_ok']}/{tot['ep_real']} ({pct(tot['ep_ok'], tot['ep_real'])}) | "
                f"{pct(tot['ep_ok'], tot['ep_listed'])} | {tot['pl_found']}/{tot['pl']} ({pct(tot['pl_found'], tot['pl'])}) | "
                f"{tot['vis_found']}/{tot['vis']} ({pct(tot['vis_found'], tot['vis'])}) | "
                f"{tot['fi_ok']}/{tot['fi']} ({pct(tot['fi_ok'], tot['fi'])}) | {tot['co_fa']}/{tot['co']} | "
                f"{tot['scan'] / max(1, len(scores)):.1f} avg |")
    head = ("| Company | Industry | Services in | Gateway | Endpoints found (recall) | Endpoint precision | "
            "Planted found | Planted found, passive-visible | Findings that are planted | Negative controls flagged | Scan (s) |\n"
            "|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|")
    by_rule = Counter()
    for s in scores:
        for p in s["planted"]["items"]:
            by_rule[(p["rule"], p["found"])] += 1
    rules = sorted({r for r, _ in by_rule})
    rule_rows = "\n".join(f"| {r} | {by_rule[(r, True)] + by_rule[(r, False)]} | {by_rule[(r, True)]} |" for r in rules)
    missed = "\n".join(f"| {s['name']} | {p['rule']} | `{p['at']}` | {p.get('expect_miss') or ''} |"
                       for s in scores for p in s["planted"]["items"] if not p["found"]) or "| - | - | - | - |"
    fa = "\n".join(f"| {s['name']} | {c['rule']} | `{c['at']}` | {c['why']} |"
                   for s in scores for c in s["controls"]["items"] if c["false_alarm"]) or "| - | - | - | - |"
    return f"""# Flexibility test: ten companies ({tag})

Produced by `bench/run_companies.py`. Each company was started in its own Docker, ATG joined its
network, the company's users sent their requests (seeded), and one scan ran. Ground truth is
`companies/<id>/ground-truth.json`, written from the company definition before any scan.

## Table 25. Results per company

{head}
{chr(10).join(rows)}

"Passive-visible" leaves out the planted weaknesses marked in advance as outside what a passive
review can see (`expect_miss` in the company definition). A negative control is something that
looks like a weakness but is not one; a finding there is a false alarm by construction.

## Table 26. Planted weaknesses by rule

| Rule | Planted | Found |
|---|---:|---:|
{rule_rows}

## Planted weaknesses not found

| Company | Rule | Where | Known in advance to be out of reach |
|---|---|---|---|
{missed}

## Negative controls that were flagged (false alarms)

| Company | Rule | Where | Why it is not a weakness |
|---|---|---|---|
{fa}
"""


def review(scores: list[dict], tag: str) -> str:
    parts = [f"# Findings that match no planted weakness ({tag})\n",
             "Each one needs a reading: a true weakness that was not planted (the baseline was not as clean as meant), "
             "a consequence of a planted one, or a false alarm.\n"]
    for s in scores:
        parts.append(f"\n## {s['name']} ({len(s['findings']['other'])})\n")
        if s["endpoints"]["missed"] or s["endpoints"]["extra"]:
            parts.append(f"Endpoints missed: {', '.join(s['endpoints']['missed']) or 'none'}  \n"
                         f"Endpoints listed that do not exist: {', '.join(s['endpoints']['extra']) or 'none'}\n")
        for f in s["findings"]["other"]:
            parts.append(f"- **{f['rule']}** `{f['target']}`: {f['detail']}")
    return "\n".join(parts) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("companies", nargs="*", default=COMPANIES)
    ap.add_argument("--score-only", action="store_true")
    ap.add_argument("--tag", default="v1.4")
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    for cid in a.companies:
        if a.score_only:
            continue
        print(f"== {cid}", flush=True)
        t = time.time()
        res = run_company(cid)
        (OUT / f"{cid}-{a.tag}.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
        s = score(cid, res)
        print(f"   {res['users']}\n   endpoints {s['endpoints']['correct']}/{s['endpoints']['real']} "
              f"(+{len(s['endpoints']['extra'])} extra), planted {s['planted']['found']}/{s['planted']['total']}, "
              f"findings {s['findings']['matching_planted']}/{s['findings']['total']} planted, "
              f"controls flagged {s['controls']['false_alarms']}/{s['controls']['total']}, {time.time() - t:.0f} s", flush=True)
    runs, scores = {}, []
    for cid in COMPANIES:
        p = OUT / f"{cid}-{a.tag}.json"
        if p.exists():
            runs[cid] = json.loads(p.read_text(encoding="utf-8"))
            scores.append(score(cid, runs[cid]))
    (OUT / f"scores-{a.tag}.json").write_text(json.dumps(scores, indent=1), encoding="utf-8")
    (OUT / f"tables-{a.tag}.md").write_text(tables(scores, runs, a.tag), encoding="utf-8")
    (OUT / f"review-{a.tag}.md").write_text(review(scores, a.tag), encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}/tables-{a.tag}.md and review-{a.tag}.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
