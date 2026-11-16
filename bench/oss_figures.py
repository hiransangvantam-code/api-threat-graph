"""
Figures and one HTML page for the open-source benchmark, drawn only from the saved runs:

    python bench/oss_figures.py --atg laptop      (BENCH-Windows.bat / bench.sh run this)
    python bench/oss_figures.py --atg v1.5

Reads results/opensource/comparison.json and comparison.md (bench/compare_tools.py), the tool runs in
results/opensource/tools/, ATG's runs in results/opensource/atg-<tag>/, and the fix plans in
demo/<id>/exports/*/threat-graph.json when demo-all has run. Writes results/opensource/figures/*.png and
results/opensource/comparison.html (open it in a browser; every chart and table is on that one page).
"""
from __future__ import annotations

import argparse
import base64
import glob
import json
import statistics
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "bench"))
sys.path.insert(0, str(ROOT / "opensource"))
from compare_tools import NAMES, TOOLS, found_set, labels, load  # noqa: E402
from fetch import SYSTEMS  # noqa: E402
from run_tools import SOURCES, system  # noqa: E402

OUT = ROOT / "results" / "opensource"
FIG = OUT / "figures"
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"
INK, INK2, GRID = "#0b0b0b", "#52514e", "#dcdcd8"
GRAYS = ["#c9c8c2", "#a3a29b", "#7a7973"]
plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 8, "axes.edgecolor": GRID, "axes.labelcolor": INK2,
    "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.5, "axes.axisbelow": True,
    "legend.frameon": False, "savefig.dpi": 200, "savefig.bbox": "tight",
})
SHORT = {"online-boutique": "Online Boutique", "bank-of-anthos": "Bank of Anthos", "robot-shop": "Robot Shop",
         "acme-air": "Acme Air", "petclinic": "PetClinic", "piggymetrics": "PiggyMetrics",
         "lakeside-mutual": "Lakeside Mutual", "ftgo": "FTGO", "hotel-reservation": "Hotel Reservation",
         "bookinfo": "Bookinfo"}


def save(fig, name):
    FIG.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIG / f"{name}.png")
    plt.close(fig)
    return FIG / f"{name}.png"


def fig_groups(cmp: dict, atg_name: str):
    """Labelled weaknesses found, per category group, per tool."""
    order = ["atg"] + TOOLS
    groups = list(cmp["atg"]["groups"])
    cols = [BLUE, ORANGE, AQUA]
    fig, ax = plt.subplots(figsize=(6.4, 4.6))
    h = 0.27
    for gi, g in enumerate(groups):
        ys = [i * 1.15 + (gi - 1) * (h + 0.03) for i in range(len(order))]
        vals = [100 * cmp[t]["groups"][g][1] / cmp[t]["groups"][g][0] for t in order]
        ax.barh(ys, vals, h, color=cols[gi], label=g, zorder=2)
        for y, v in zip(ys, vals):
            if v > 0:
                ax.text(v + 1, y, f"{v:.0f}%", va="center", fontsize=7, color=INK)
    ax.set_yticks([i * 1.15 for i in range(len(order))], [f"{atg_name if t == 'atg' else NAMES[t]}  (runs on {cmp[t]['ran']}/10)"
                                      for t in order])
    ax.invert_yaxis()
    ax.set_xlim(0, 112)
    ax.set_xlabel("Labelled weaknesses found (% of the labels in the group, all ten systems)")
    ax.grid(axis="y", visible=False)
    ax.legend(loc="lower center", bbox_to_anchor=(0.45, 1.0), ncol=3, fontsize=7.5)
    ax.set_title("Weaknesses found, by category group", loc="left", fontsize=9, fontweight="bold", pad=24)
    return save(fig, "fig1_groups")


def fig_systems(runs: dict, atg_name: str):
    """Labels found per system: ATG against the two best Kubernetes scanners."""
    tools = [("atg", BLUE, atg_name), ("polaris", ORANGE, "Polaris"), ("checkov", AQUA, "Checkov")]
    fig, ax = plt.subplots(figsize=(6.4, 3.0))
    w = 0.26
    for ti, (t, c, name) in enumerate(tools):
        xs, vals = [], []
        for i, sid in enumerate(SYSTEMS):
            r = runs[t].get(sid)
            x = i + (ti - 1) * (w + 0.02)
            if r and r.get("applicable"):
                v = 100 * len(found_set(sid, r["pairs"])) / len(labels(sid))
                xs.append(x)
                vals.append(v)
            else:
                ax.text(x, 2, "n/a", rotation=90, ha="center", va="bottom", fontsize=6, color=INK2)
        ax.bar(xs, vals, w, color=c, label=name, zorder=2)
    ax.set_xticks(range(len(SYSTEMS)), [SHORT[s] for s in SYSTEMS], rotation=35, ha="right")
    ax.set_ylim(0, 100)
    ax.set_ylabel("Labels found (%)")
    ax.grid(axis="x", visible=False)
    ax.legend(ncol=3, loc="upper right", fontsize=7.5)
    ax.set_title("Per system (n/a: the tool cannot read this system's files)", loc="left", fontsize=9, fontweight="bold")
    return save(fig, "fig2_systems")


def fig_reach(runs: dict):
    """Where each tool stops: systems it can run on, and services a one-language scanner can read."""
    fig, axs = plt.subplots(1, 2, figsize=(6.4, 2.5), gridspec_kw={"width_ratios": [1.25, 1]})
    order = ["atg"] + TOOLS
    vals = [sum(1 for s in SYSTEMS if (runs[t].get(s) or {}).get("applicable")) for t in order]
    a = axs[0]
    a.barh(range(len(order)), vals, 0.6, color=[BLUE] + [GRAYS[2]] * len(TOOLS), zorder=2)
    for i, v in enumerate(vals):
        a.text(v + 0.15, i, f"{v}/10", va="center", fontsize=7, color=INK)
    a.set_yticks(range(len(order)), ["ATG" if t == "atg" else NAMES[t] for t in order])
    a.invert_yaxis()
    a.set_xlim(0, 11.5)
    a.set_xlabel("Systems the tool can run on")
    a.grid(axis="y", visible=False)
    a.set_title("Systems covered", loc="left", fontsize=9, fontweight="bold")
    b = axs[1]
    total = sum(len(SOURCES[s]) for s in SYSTEMS)
    cov = {t: sum((runs[t].get(s) or {}).get("covered", 0) for s in SYSTEMS) for t in ("bandit", "gosec", "njsscan")}
    names = ["ATG (any language)", "Bandit (Python)", "gosec (Go)", "njsscan (Node.js)", "All three together"]
    vs = [total, cov["bandit"], cov["gosec"], cov["njsscan"], sum(cov.values())]
    b.barh(range(len(vs)), vs, 0.6, color=[BLUE, GRAYS[2], GRAYS[2], GRAYS[2], GRAYS[1]], zorder=2)
    for i, v in enumerate(vs):
        b.text(v + 0.8, i, f"{v}/{total}", va="center", fontsize=7, color=INK)
    b.set_yticks(range(len(vs)), names)
    b.invert_yaxis()
    b.set_xlim(0, total * 1.3)
    b.set_xlabel("Services whose code it can read")
    b.grid(axis="y", visible=False)
    b.set_title("Language limits", loc="left", fontsize=9, fontweight="bold")
    fig.tight_layout(w_pad=1.5)
    return save(fig, "fig3_reach")


def fig_speed(runs: dict, atg_label: str):
    order = ["atg"] + TOOLS
    med = []
    for t in order:
        secs = [r["seconds"] for r in runs[t].values() if r.get("applicable") and r.get("seconds") is not None]
        med.append(statistics.median(secs) if secs else 0)
    fig, ax = plt.subplots(figsize=(6.4, 2.4))
    ax.barh(range(len(order)), med, 0.6, color=[BLUE] + [GRAYS[2]] * len(TOOLS), zorder=2)
    for i, v in enumerate(med):
        ax.text(v * 1.15 if v else 0.01, i, f"{v:.2f} s" if v < 1 else f"{v:.1f} s", va="center", fontsize=7, color=INK)
    ax.set_xscale("log")
    ax.set_yticks(range(len(order)), [atg_label if t == "atg" else NAMES[t] for t in order])
    ax.invert_yaxis()
    ax.set_xlabel("Median time per system (s, log scale)")
    ax.grid(axis="y", visible=False)
    ax.set_title("Speed", loc="left", fontsize=9, fontweight="bold")
    return save(fig, "fig4_speed")


def plans() -> dict:
    out = {}
    for sid in SYSTEMS:
        fs = sorted(glob.glob(str(ROOT / "demo" / sid / "exports" / "*" / "threat-graph.json")))
        if fs:
            p = json.loads(Path(fs[-1]).read_text(encoding="utf-8")).get("mitigation_plan") or {}
            if p.get("steps") and p.get("total_path_risk"):
                out[sid] = p
    return out


def fig_plans(ps: dict):
    if not ps:
        return None
    fig, ax = plt.subplots(figsize=(6.4, 3.0))
    seen, long_curves = set(), []
    for sid, p in ps.items():
        compose = "compose" in (system(sid).get("artifacts") or {})
        rem = [100.0] + [100 * s["remaining"] / p["total_path_risk"] for s in p["steps"]]
        lab = "Docker Compose systems (3)" if compose else "Kubernetes systems (7)"
        ax.plot(range(len(rem)), rem, color=ORANGE if compose else BLUE, lw=1.4, zorder=3 if compose else 2,
                label=None if lab in seen else lab)
        seen.add(lab)
        if compose:
            long_curves.append((len(rem), rem, SHORT[sid]))
    long_curves.sort()   # name the long curves; curves of almost the same length share one name
    groups = []
    for n, rem, name in long_curves:
        if groups and n - groups[-1][0] < 6:
            groups[-1][2].append(name)
        else:
            groups.append([n, rem, [name]])
    for n, rem, names in groups:
        x = int(n * 0.55)
        ax.annotate(", ".join(names), (x, rem[x]), (x + 6, rem[x] + 14), fontsize=7, color=INK2,
                    arrowprops={"arrowstyle": "-", "color": INK2, "lw": 0.6})
    for y, lab in ((30, "70% removed"), (10, "90% removed")):
        ax.axhline(y, color=GRAYS[2], lw=0.8, ls="--", zorder=1)
        ax.text(101, y, lab, fontsize=7, color=INK2, va="center", ha="right", backgroundcolor="white")
    ax.set_ylim(0, 102)
    ax.set_xlim(0, 101)
    ax.legend(loc="upper right", fontsize=7.5)
    ax.set_xlabel("Fixes applied, in the order of the fix plan")
    ax.set_ylabel("Attack-path risk left (% of R)")
    ax.set_title("Risk left after each fix (ATG's fix plan, each system)", loc="left", fontsize=9, fontweight="bold")
    return save(fig, "fig5_fixplans")


def plan_table(ps: dict) -> str:
    if not ps:
        return ""
    rows = ["| System | Path risk R | Fixes for 70% | Fixes for 90% | First fix |", "|---|---:|---:|---:|---|"]
    for sid, p in ps.items():
        first = p["steps"][0].get("title", "")
        rows.append(f"| {SHORT[sid]} | {p['total_path_risk']:g} | {p.get('fixes_for_70pct') or '–'} | "
                    f"{p.get('fixes_for_90pct') or '–'} | {first} |")
    return "\n".join(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--atg", default="laptop")
    a = ap.parse_args()
    runs = load(a.atg)
    if not runs["atg"]:
        raise SystemExit(f"no ATG runs in results/opensource/atg-{a.atg}/: run DEMO-ALL first")
    cmp = json.loads((OUT / "comparison.json").read_text(encoding="utf-8"))
    atg_name = "ATG"
    pngs = [fig_groups(cmp, atg_name), fig_systems(runs, atg_name), fig_reach(runs),
            fig_speed(runs, "ATG (Phases 1-4)" if a.atg == "laptop" else "ATG (whole scan)")]
    ps = plans()
    pngs.append(fig_plans(ps))
    import markdown
    md = (OUT / "comparison.md").read_text(encoding="utf-8")
    pt = plan_table(ps)
    if pt:
        md += "\n\n## Table G. ATG's fix plan per system\n\nFrom the saved reviews in `demo/<system>/` (the \"What to fix\" pages).\n\n" + pt
    body = markdown.markdown(md, extensions=["tables"])
    imgs = "".join(f'<figure><img src="data:image/png;base64,{base64.b64encode(p.read_bytes()).decode()}"></figure>'
                   for p in pngs if p)
    page = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>ATG vs other tools: ten open-source systems</title>
<style>body{{font:14px/1.5 system-ui,Segoe UI,sans-serif;max-width:1100px;margin:24px auto;padding:0 20px;color:#1c2430}}
table{{border-collapse:collapse;font-size:12.5px;margin:8px 0 20px}}td,th{{border:1px solid #d5d9df;padding:4px 8px}}
th{{background:#f2f4f7}}figure{{margin:16px 0}}img{{max-width:100%;border:1px solid #e5e7eb}}h1{{font-size:24px}}
code{{background:#f2f4f7;padding:0 3px}}</style></head><body>
<h1>ATG and eight free tools on ten open-source systems</h1>
<p>Generated by <code>bench/oss_figures.py</code> from the runs on this computer: ATG in <code>results/opensource/atg-{a.atg}/</code>,
the tools in <code>results/opensource/tools/</code>. Every chart below is drawn from those files.</p>
{imgs}{body}</body></html>"""
    (OUT / "comparison.html").write_text(page, encoding="utf-8")
    print(f"wrote {len([p for p in pngs if p])} figures in results/opensource/figures/ and results/opensource/comparison.html")
    return 0


if __name__ == "__main__":
    sys.exit(main())
