"""
Section V tables and figures from the evaluation runs on the ten open-source systems
(bench/oss_eval.py, bench/oss_fixes.py, bench/oss_stress.py). Nothing here runs a system: it
reads the saved Phase 1 output, EUJF and analysis of each scan and scores them against
opensource/<id>/ground-truth.json and system.yaml.

    python bench/oss_report.py          -> results/opensource/eval/tables.md, eval/summary.json, eval/figures/

What it measures
  discovery      operations found by each Phase 1 source alone and by all four (Phase 2 run on
                 each subset of the scan's Phase 1 files), against the operations in the code
  reconciliation flows, spans and records in, entries out; extra entries with and without
                 reconciliation against API documents
  window         operations found as the observed part of the user session grows (traffic
                 records cut at their first-seen time)
  dependencies   service-to-service calls ATG lists vs the calls the code makes (system.yaml)
  overhead       the sidecar's added latency (oss_eval.py)
  zap            OWASP ZAP against the same systems: requests, time, operations reached, alerts,
                 labels its alerts match
  controls       negative controls from the systems' own code: operations that check the caller's
                 identity, operations that check ownership, services that verify tokens themselves
  fixes          measured vs predicted risk after ATG's configuration fixes (oss_fixes.py)
"""
from __future__ import annotations

import glob
import json
import re
import shutil
import statistics
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "bench"))
sys.path.insert(0, str(ROOT / "opensource"))
import oss_scoring as sc  # noqa: E402
from atg.normalizer import normalize  # noqa: E402
from fetch import SYSTEMS  # noqa: E402

EVAL = ROOT / "results" / "opensource" / "eval"
SRC = {"O": "openapi", "T": "runtime_traffic", "K": "infrastructure", "C": "callchain"}
SRC_NAME = {"O": "API documents", "T": "Traffic", "K": "Deployment / gateway", "C": "Traces"}
SHORT = {"online-boutique": "Online Boutique", "bank-of-anthos": "Bank of Anthos", "robot-shop": "Robot Shop",
         "acme-air": "Acme Air", "petclinic": "PetClinic", "piggymetrics": "PiggyMetrics",
         "lakeside-mutual": "Lakeside Mutual", "ftgo": "FTGO", "hotel-reservation": "Hotel Reservation",
         "bookinfo": "Bookinfo"}


def raw_dir(sid: str, tag: str = "base") -> Path:
    return Path(glob.glob(str(EVAL / tag / sid / "live" / "scans" / "*" / "raw"))[-1])


def run_files(sid: str, tag: str = "base") -> tuple[dict, dict]:
    """The scan's analysis and EUJF; the version 1.6 recomputation (bench/oss_rescore.py) when there is one."""
    v16 = EVAL / tag / sid / "v16" / "analysis.json"
    a = str(v16) if v16.exists() else sorted(glob.glob(str(EVAL / tag / sid / "runs" / "*" / "analysis.json")))[-1]
    return json.loads(Path(a).read_text()), json.loads(Path(a.replace("analysis.json", "eujf.json")).read_text())


def system(sid: str) -> dict:
    return yaml.safe_load((ROOT / "opensource" / sid / "system.yaml").read_text(encoding="utf-8"))


def eujf_subset(raw: Path, combo: str, reconcile: bool = True, traffic_until: float | None = None) -> dict:
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        for k in combo:
            src = raw / f"{SRC[k]}.json"
            if not src.exists():
                continue
            if k == "T" and traffic_until is not None:
                doc = json.loads(src.read_text())
                doc["records"] = [r for r in doc["records"] if r.get("kind") != "endpoint" or r.get("first_seen", 0) <= traffic_until]
                (td / src.name).write_text(json.dumps(doc))
            else:
                shutil.copy(src, td / src.name)
        if (raw / "manifest.json").exists():
            shutil.copy(raw / "manifest.json", td / "manifest.json")
        return normalize(td, reconcile=reconcile)


def ops_score(sid: str, eujf: dict, al: dict) -> dict:
    return sc.endpoint_score(sid, {e["id"] for e in eujf["endpoints"]}, al)


# ---------------------------------------------------------------- V-A
def discovery() -> dict:
    out = {}
    for sid in SYSTEMS:
        raw, al = raw_dir(sid), sc.aliases(sid)
        row = {}
        for combo in ("O", "T", "K", "C", "TKC", "OKC", "OTC", "OTK", "OTKC"):
            s = ops_score(sid, eujf_subset(raw, combo), al)
            row[combo] = {"real": s["real"], "listed": s["listed"], "correct": s["correct"]}
        nr = ops_score(sid, eujf_subset(raw, "OTKC", reconcile=False), al)
        tr = ops_score(sid, eujf_subset(raw, "T"), al)
        a, e = run_files(sid)
        stats = {k: json.loads((raw / f"{v}.json").read_text())["stats"] for k, v in SRC.items() if (raw / f"{v}.json").exists()}
        singles = sum(row[k]["listed"] for k in "OTC")
        out[sid] = {"by_source": row, "no_reconcile": {"listed": nr["listed"], "correct": nr["correct"]},
                    "traffic_only_extra": tr["listed"] - tr["correct"],
                    "flows": stats["T"]["flows"], "spans": stats["C"]["spans"], "traffic_records": stats["T"]["endpoints"],
                    "probes": stats["O"].get("probes", 0), "spec_operations": stats["O"].get("operations", 0),
                    "single_source_entries": singles, "merged": len(e["endpoints"]),
                    "scan_endpoints_match": len(e["endpoints"]) == row["OTKC"]["listed"]}
        print(f"  discovery {sid}: " + ", ".join(f"{k} {v['correct']}/{v['real']}" for k, v in row.items()), flush=True)
    return out


def window(points=(0.05, 0.1, 0.2, 0.3, 0.5, 0.75, 1.0)) -> dict:
    """Operations found as the observed share of the user session grows."""
    curves = {}
    for sid in SYSTEMS:
        raw, al = raw_dir(sid), sc.aliases(sid)
        recs = [r for r in json.loads((raw / "runtime_traffic.json").read_text())["records"] if r.get("kind") == "endpoint"]
        t0, t1 = min(r["first_seen"] for r in recs), max(r["first_seen"] for r in recs)
        c = {"T": [], "OTK": []}
        for f in points:
            until = t0 + f * (t1 - t0) + 1e-6
            for combo in c:
                s = ops_score(sid, eujf_subset(raw, combo, traffic_until=until), al)
                c[combo].append(s["correct"] / s["real"])
        curves[sid] = c
    return {"points": list(points), "curves": curves}


def dependencies() -> dict:
    out = {}
    for sid in SYSTEMS:
        y = system(sid)
        gt = set()
        for svc, sv in (y.get("services") or {}).items():
            for _, op in ((sv or {}).get("routes") or {}).items():
                for call in (op or {}).get("calls", []) or []:
                    parts = (call.get("to", "") if isinstance(call, dict) else call).split()
                    if len(parts) >= 2:
                        gt.add((svc, parts[1]))
        for job in y.get("jobs", []) or []:
            for call in job.get("calls", []) or []:
                parts = (call.get("to", "") if isinstance(call, dict) else call).split()
                if len(parts) >= 2:
                    gt.add((job.get("name", "job"), parts[1]))
        _, e = run_files(sid)
        al = sc.aliases(sid)
        found = {(al.get(d["from"], d["from"]), al.get(d["to"], d["to"])) for d in e.get("dependencies", [])}
        gtn = {(al.get(a, a), al.get(b, b)) for a, b in gt}
        out[sid] = {"real": len(gtn), "listed": len(found), "correct": len(found & gtn),
                    "missed": sorted(map(list, gtn - found)), "extra": sorted(map(list, found - gtn))}
    return out


# ---------------------------------------------------------------- V-B: ZAP
CWE_CATS = [({284, 285, 287, 306, 862, 863}, ["A1", "A3", "A5"]), ({639}, ["A2"]),
            ({200, 201, 209, 213, 215, 359, 489, 497, 532, 538, 548, 615}, ["A4", "A9"]),
            ({307}, ["A6"]), ({598}, ["A7"]), ({918}, ["A8"]), ({319, 311}, ["C8"]), ({400, 770, 789}, ["C3"])]


def gt_ops(sid: str):
    gt = json.loads((ROOT / "opensource" / sid / "ground-truth.json").read_text())
    ops = []
    for e in gt["endpoints"]:
        rx = re.compile("^" + re.sub(r"\\\{[^}]*\\\}", "[^/]+", re.escape(e["path"])) + "/?$")
        ops.append((e["service"], e["method"], rx, e["id"]))
    return ops


def zap(tag: str = "base") -> dict:
    out = {}
    for sid in SYSTEMS:
        f = EVAL / tag / f"{sid}.json"
        if not f.exists():
            continue
        r = json.loads(f.read_text())
        z = r.get("zap") if tag == "base" else r
        if not z:
            continue
        al = sc.aliases(sid)
        ops = gt_ops(sid)
        tcfg = yaml.safe_load((ROOT / "opensource" / sid / "atg-target.yaml").read_text())
        gw_svc = re.match(r"https?://([^:/]+)", tcfg["sources"]["openapi"]["live_targets"][0]["base_url"]).group(1)

        def locate(url: str):
            m = re.match(r"https?://([^:/]+)(?::\d+)?(/[^?#]*)?", url)
            if not m:
                return None, None
            svc, path = z["by_ip"].get(m.group(1)), m.group(2) or "/"
            hits = [o for o in ops if o[0] == svc and o[2].match(path)]
            if not hits:   # through the entry service: any operation whose public path matches
                hits = [o for o in ops if o[2].match(path)]
            return svc, hits
        reached = set()
        for u in z["urls"]:
            _, hits = locate(u)
            reached |= {sc.norm(h[3], al) for h in hits or []}
        pairs = set()
        for a in z["alerts"]:
            try:
                cwe = int(a.get("cweid") or -1)
            except ValueError:
                cwe = -1
            cats = next((cs for cwes, cs in CWE_CATS if cwe in cwes), [])
            svc, hits = locate(a.get("url") or "")
            for c in cats:
                for h in hits or []:
                    pairs.add((c, sc.norm(h[3], al)))
                if svc:
                    pairs.add((c, sc.norm("svc:" + svc, al)))
        s = sc.score(sid, pairs)
        atg = json.loads((ROOT / "results" / "opensource" / "atg-v1.5" / "scores.json").read_text())
        atg_s = next(x for x in atg if x["system"] == sid)
        raw = raw_dir(sid)
        probes = json.loads((raw / "openapi.json").read_text())["stats"].get("probes", 0)
        real_ops = len({sc.norm(o[3], al) for o in ops})
        out[sid] = {"requests": z["messages"], "seconds": z["total_s"], "alerts": len(z["alerts"]),
                    "alert_types": Counter(f"{a['alert']} (CWE-{a['cweid']}, {a['risk']})" for a in z["alerts"]),
                    "ops_reached": len(reached), "ops_real": real_ops, "labels_found": s["found"], "labels": s["labels"],
                    "atg_labels_found": atg_s["found"], "atg_probes": probes,
                    "atg_ops": atg_s["endpoints"]["correct"], "gateway": gw_svc}
    return out


# ---------------------------------------------------------------- V-E: negative controls from the code
def controls() -> dict:
    rows = defaultdict(lambda: [0, 0])          # kind -> [controls, flagged]
    detail = []
    for sid in SYSTEMS:
        y = system(sid)
        a, _ = run_files(sid)
        al = sc.aliases(sid)
        by_target = defaultdict(set)
        for f in a["findings"]:
            by_target[sc.norm(f["target"], al)].add(f["rule_id"])
        for svc, sv in (y.get("services") or {}).items():
            sv = sv or {}
            svc_rules = by_target.get(sc.norm(f"svc:{svc}", al), set())
            ep_rules = set()
            for key, op in (sv.get("routes") or {}).items():
                op = op or {}
                method, path = key.split(" ", 1)
                tgt = sc.norm(f"ep:{svc}:{method}:{re.sub(r'{[^}]+}', '{}', path)}", al)
                rules = by_target.get(tgt, set()) | {r for t, rs in by_target.items()
                                                    if t.split(":")[:3] == tgt.split(":")[:3] and
                                                    re.sub(r"\{[^}]*\}", "{}", t.split(":", 3)[-1]) == tgt.split(":", 3)[-1]
                                                    for r in rs}
                ep_rules |= rules
                if op.get("auth") and op.get("client") != "none":
                    rows["auth"][0] += 1
                    bad = rules & {"TS-01", "TS-03"}
                    rows["auth"][1] += bool(bad)
                    if bad:
                        detail.append((sid, "auth", key, sorted(bad)))
                if op.get("owner"):
                    rows["owner"][0] += 1
                    bad = rules & {"API1"}
                    rows["owner"][1] += bool(bad)
                    if bad:
                        detail.append((sid, "owner", key, sorted(bad)))
            if sv.get("verify") == "self":
                rows["verify"][0] += 1
                bad = (svc_rules | ep_rules) & {"TS-08"}
                rows["verify"][1] += bool(bad)
                if bad:
                    detail.append((sid, "verify", svc, sorted(bad)))
    return {"rows": {k: {"controls": v[0], "flagged": v[1]} for k, v in rows.items()}, "detail": detail}


def unmatched() -> dict:
    """ATG reports that match no label, by rule (precision analysis)."""
    s = json.loads((ROOT / "results" / "opensource" / "atg-v1.5" / "scores.json").read_text())
    c = Counter()
    for x in s:
        for cat, tgt in x["unconfirmed"]:
            c[cat] += 1
    return dict(c.most_common())


# ---------------------------------------------------------------- figures
def figures(summary: dict) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    BLUE, ORANGE, GRAYS, INK, INK2, GRID = "#2a78d6", "#eb6834", ["#c9c8c2", "#a3a29b", "#7a7973"], "#0b0b0b", "#52514e", "#dcdcd8"
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8, "axes.edgecolor": GRID, "axes.labelcolor": INK2,
                         "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False,
                         "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.5, "axes.axisbelow": True,
                         "legend.frameon": False, "savefig.dpi": 220, "savefig.bbox": "tight"})
    fig_dir = EVAL / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)

    # observation window, pooled over the ten systems
    w = summary["window"]
    real = {sid: len(json.loads((ROOT / "opensource" / sid / "ground-truth.json").read_text())["endpoints"]) for sid in w["curves"]}
    xs = [100 * p for p in w["points"]]
    fig, ax = plt.subplots(figsize=(3.4, 2.3))
    for key, col, lab in (("T", ORANGE, "Traffic only"), ("OTK", BLUE, "Traffic + API documents + deployment files")):
        ys = [100 * sum(w["curves"][s][key][i] * real[s] for s in real) / sum(real.values()) for i in range(len(xs))]
        ax.plot(xs, ys, color=col, lw=2, marker="o", ms=3.5, label=lab, zorder=3)
        ax.text(xs[-1] + 1.5, ys[-1] - (3 if key == "T" else -3), f"{ys[-1]:.0f}%", fontsize=7, color=INK, va="center")
        ax.text(xs[0] + 1.5, ys[0] + (3 if key == "OTK" else -4), f"{ys[0]:.0f}%", fontsize=7, color=INK)
    ax.set_xlim(0, 108)
    ax.set_ylim(0, 105)
    ax.set_xlabel("Share of the user session observed (%)")
    ax.set_ylabel("Operations found (%)")
    ax.legend(loc="upper left", fontsize=6.8)
    fig.savefig(fig_dir / "fig_window.png")
    plt.close(fig)

    # measured vs predicted risk after the configuration fixes
    fx = summary.get("fixes")
    if fx:
        fig, ax = plt.subplots(figsize=(6.6, 2.4))
        n = len(fx)
        wd = 0.27
        for j, (key, col, lab) in enumerate((("R_before", GRAYS[1], "Before"), ("R_predicted", ORANGE, "Predicted by the plan"),
                                              ("R_measured", BLUE, "Measured after rescanning"))):
            vals = [r[key] for r in fx]
            ax.bar([i + (j - 1) * (wd + 0.02) for i in range(n)], vals, wd, color=col, label=lab, zorder=2)
        for i, r in enumerate(fx):
            red = 100 * (1 - r["R_measured"] / r["R_before"]) if r["R_before"] else 0
            ax.text(i + wd + 0.02, max(r["R_measured"], 8) + 18, f"-{red:.0f}%", ha="center", fontsize=6.5, color=INK)
        ax.set_xticks(range(n), [SHORT[r["system"]] for r in fx], rotation=25, ha="right")
        ax.set_ylabel("Attack-path risk R")
        ax.grid(axis="x", visible=False)
        ax.set_ylim(0, max(r["R_before"] for r in fx) * 1.12)
        ax.legend(ncol=3, fontsize=7, loc="lower center", bbox_to_anchor=(0.5, 1.0))
        fig.savefig(fig_dir / "fig_fixes.png")
        plt.close(fig)

    # the planner's predicted curve on each system (version 1.6 analyses)
    import oss_figures
    ps = {}
    for sid in SYSTEMS:
        f = EVAL / "base" / sid / "v16" / "analysis.json"
        if f.exists():
            ps[sid] = json.loads(f.read_text())["mitigation_plan"]
    if ps:
        oss_figures.FIG = fig_dir
        oss_figures.fig_plans(ps)

    # stress test from Online Boutique
    st = summary.get("stress")
    if st:
        fig, axs = plt.subplots(1, 2, figsize=(6.6, 2.3))
        ok = [r for r in st["size"] if "phase3_ms" in r]
        a = axs[0]
        a.plot([r["services"] for r in ok], [r["phase3_ms"] / 1000 for r in ok], color=BLUE, marker="o", ms=3.5, lw=2, zorder=3)
        for r in ok[-1:]:
            a.annotate(f"{r['phase3_ms'] / 1000:.1f} s\n{r['attack_paths']:,} paths", (r["services"], r["phase3_ms"] / 1000),
                       (-62, 0), textcoords="offset points", fontsize=7, color=INK)
        a.set_xlabel("Workloads (k copies of Online Boutique)")
        a.set_ylabel("Phase 3 time (s)")
        a.set_title("System size", loc="left", fontsize=8.5, fontweight="bold")
        b = axs[1]
        okd = [r for r in st["density"] if "phase3_ms" in r]
        b.plot([r["d"] for r in okd], [r["phase3_ms"] / 1000 for r in okd], color=ORANGE, marker="o", ms=3.5, lw=2, zorder=3)
        bad = [r for r in st["density"] if "phase3_ms" not in r and "skipped" not in r]
        for r in bad:
            b.scatter([r["d"]], [max(x["phase3_ms"] for x in okd) / 1000], marker="x", color=INK, zorder=4)
            b.annotate("limit", (r["d"], max(x["phase3_ms"] for x in okd) / 1000), (4, 4), textcoords="offset points", fontsize=7)
        if okd:
            r = okd[-1]
            b.annotate(f"{r['phase3_ms'] / 1000:.1f} s\n{r['attack_paths']:,} paths", (r["d"], r["phase3_ms"] / 1000),
                       (-58, -6), textcoords="offset points", fontsize=7, color=INK)
        b.set_xlabel(f"Random calls per operation ({st['density'][0]['k']} copies)")
        b.set_ylabel("Phase 3 time (s)")
        b.set_title("Call-chain density", loc="left", fontsize=8.5, fontweight="bold")
        fig.tight_layout(w_pad=2)
        fig.savefig(fig_dir / "fig_stress_oss.png")
        plt.close(fig)


def main() -> int:
    summary = {"discovery": discovery(), "dependencies": dependencies(), "window": window(), "zap": zap(),
               "controls": controls(), "unmatched_by_category": unmatched()}
    summary["overhead"] = {sid: json.loads((EVAL / "base" / f"{sid}.json").read_text()).get("overhead") for sid in SYSTEMS}
    fx = ROOT / "results" / "opensource" / "fixes" / "summary.json"
    if fx.exists():
        summary["fixes"] = json.loads(fx.read_text())
    st = EVAL / "stress.json"
    if st.exists():
        summary["stress"] = json.loads(st.read_text())
    zi = {}
    for sid in SYSTEMS:
        f = EVAL / "zapinv" / f"{sid}.json"
        if f.exists():
            zi[sid] = f
    if zi:
        summary["zap_inventory"] = zap(tag="zapinv")
    (EVAL / "summary.json").write_text(json.dumps(summary, indent=1, default=lambda o: dict(o)), encoding="utf-8")
    figures(json.loads((EVAL / "summary.json").read_text()))
    print("wrote", (EVAL / "summary.json").relative_to(ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
