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
from compare_tools import NAMES, TOOLS, found_set, labels, load, zap_runs  # noqa: E402
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
    groups = [g for g in cmp["atg"]["groups"] if not g.startswith("Inventory")]   # inventory: its own table
    cols = [BLUE, ORANGE]
    fig, ax = plt.subplots(figsize=(6.4, 4.0))
    h = 0.36
    for gi, g in enumerate(groups):
        ys = [i * 1.15 + (gi - 0.5) * (h + 0.03) for i in range(len(order))]
        vals = [100 * cmp[t]["groups"][g][1] / cmp[t]["groups"][g][0] for t in order]
        ax.barh(ys, vals, h, color=cols[gi], label=g, zorder=2)
        inventory = g.startswith("Inventory")
        for y, v, t in zip(ys, vals, order):
            if v <= 0:          # the tool found none of this group
                ax.text(1, y, "Not detected", va="center", fontsize=6.3, color=INK2)
            elif inventory:     # a capability only one tool has: say so rather than give a score
                found, total = cmp[t]["groups"][g][1], cmp[t]["groups"][g][0]
                ax.text(v + 1, y, f"Detected ({found}/{total})", va="center", fontsize=7, color=INK)
            else:
                ax.text(v + 1, y, f"{v:.0f}%" if v >= 0.5 else "<1%", va="center", fontsize=7, color=INK)
    ax.set_yticks([i * 1.15 for i in range(len(order))], [f"{atg_name if t == 'atg' else NAMES[t]}  (runs on {cmp[t]['ran']}/10)"
                                      for t in order])
    ax.invert_yaxis()
    ax.set_xlim(0, 112)
    ax.set_xlabel("Known weaknesses found (% of the labels in the group, all ten systems)")
    ax.grid(axis="y", visible=False)
    ax.legend(loc="lower center", bbox_to_anchor=(0.45, 1.0), ncol=2, fontsize=7.5)
    ax.set_title("Known weaknesses found: configuration and API behaviour", loc="left", fontsize=9, fontweight="bold", pad=24)
    out = save(fig, "fig1_groups")
    _groups_column(cmp, atg_name, order, groups, cols)
    return out


def _groups_column(cmp, atg_name, order, groups, cols):
    """The same chart one column wide (the report): shorter labels, the systems count on its own line."""
    fig, ax = plt.subplots(figsize=(3.5, 4.1))
    h = 0.38
    for gi, g in enumerate(groups):
        ys = [i * 1.15 + (gi - 0.5) * (h + 0.03) for i in range(len(order))]
        vals = [100 * cmp[t]["groups"][g][1] / cmp[t]["groups"][g][0] for t in order]
        ax.barh(ys, vals, h, color=cols[gi], label=g, zorder=2)
        for y, v in zip(ys, vals):
            if v <= 0:
                ax.text(1, y, "Not detected", va="center", fontsize=5.6, color=INK2)
            else:
                ax.text(v + 1, y, f"{v:.0f}%" if v >= 0.5 else "<1%", va="center", fontsize=6.2, color=INK)
    ax.set_yticks([i * 1.15 for i in range(len(order))],
                  [f"{atg_name if t == 'atg' else NAMES[t].replace(' (OWASP)', '')}\n(runs on {cmp[t]['ran']}/10)" for t in order],
                  fontsize=6.5)
    ax.invert_yaxis()
    ax.set_xlim(0, 115)
    ax.tick_params(axis="x", labelsize=6.5)
    ax.set_xlabel("Known weaknesses found (% of the group, all ten systems)", fontsize=6.5)
    ax.grid(axis="y", visible=False)
    ax.legend(loc="lower left", bbox_to_anchor=(-0.02, 1.0), ncol=2, fontsize=6.5, handlelength=1.2)
    save(fig, "fig1_groups_column")


def fig_systems(runs: dict, atg_name: str):
    """Known weaknesses found on each system by every tool: one chart per system, most found first."""
    outs = []
    for sid in sorted(SYSTEMS, key=lambda x: -len(labels(x))):     # the systems with the most known weaknesses first
        n_lab = len(labels(sid))
        rows = []
        for t in ["atg"] + TOOLS:
            r = runs[t].get(sid)
            f = len(found_set(sid, r["pairs"])) if r and r.get("applicable") else None
            rows.append((t, f))
        rows.sort(key=lambda x: (x[1] is None, -(x[1] or 0)))          # largest first, n/a at the bottom
        fig, ax = plt.subplots(figsize=(4.2, 2.7))
        for i, (t, f) in enumerate(rows):
            if f is not None:
                v = 100 * f / n_lab
                ax.barh(i, v, 0.62, color=BLUE if t == "atg" else GRAYS[2], zorder=2)
                ax.text(v + 1.5, i, f"{f}/{n_lab} ({v:.0f}%)", va="center", fontsize=6.5, color=INK)
            else:
                ax.text(1.5, i, "n/a (cannot read this system's files)", va="center", fontsize=6.5, color=INK2)
        ax.set_yticks(range(len(rows)), [atg_name if t == "atg" else NAMES[t] for t, _ in rows], fontsize=7)
        for lab, (t, _) in zip(ax.get_yticklabels(), rows):
            if t == "atg":
                lab.set_fontweight("bold")
        ax.set_ylim(len(rows) - 0.3, -0.7)       # top to bottom, with room above the axis
        ax.set_xlim(0, 118)
        ax.set_xticks([0, 20, 40, 60, 80, 100])
        ax.set_xlabel("Known weaknesses found (%)", fontsize=7)
        ax.grid(axis="y", visible=False)
        ax.set_title(f"{SHORT[sid]}: {n_lab} known weaknesses", loc="left", fontsize=8.5, fontweight="bold")
        outs.append(save(fig, f"fig2_system_{sid}"))
    _systems_grid(runs, atg_name)
    return outs


def _systems_grid(runs: dict, atg_name: str):
    """All ten per-system charts as one small-multiples figure, two rows of five (the report)."""
    sids = sorted(SYSTEMS, key=lambda x: -len(labels(x)))
    fig, axs = plt.subplots(2, 5, figsize=(7.2, 3.5))
    for ax, sid in zip(axs.flat, sids):
        n_lab = len(labels(sid))
        rows = []
        for t in ["atg"] + TOOLS:
            r = runs[t].get(sid)
            rows.append((t, len(found_set(sid, r["pairs"])) if r and r.get("applicable") else None))
        rows.sort(key=lambda x: (x[1] is None, -(x[1] or 0)))
        for i, (t, f) in enumerate(rows):
            if f is not None:
                v = 100 * f / n_lab
                ax.barh(i, v, 0.66, color=BLUE if t == "atg" else GRAYS[2], zorder=2)
                ax.text(v + 2, i, f"{f} ({v:.0f}%)", va="center", fontsize=4.6, color=INK)
            else:
                ax.text(2, i, "n/a", va="center", fontsize=4.6, color=INK2)
        ax.set_yticks(range(len(rows)), [atg_name if t == "atg" else NAMES[t].replace(" (OWASP)", "") for t, _ in rows],
                      fontsize=5.2)
        for lab, (t, _) in zip(ax.get_yticklabels(), rows):
            if t == "atg":
                lab.set_fontweight("bold")
        ax.tick_params(axis="y", length=0, pad=1.5)
        ax.set_ylim(len(rows) - 0.4, -0.6)
        ax.set_xlim(0, 135)
        ax.set_xticks([0, 50, 100])
        ax.tick_params(axis="x", labelsize=4.8, length=2, pad=1)
        ax.grid(axis="y", visible=False)
        ax.set_title(f"{SHORT[sid]} ({n_lab})", loc="left", fontsize=6.2, fontweight="bold", pad=3)
    fig.supxlabel("Known weaknesses found (% of the system's known weaknesses)", fontsize=5.6, y=0.035)
    fig.tight_layout(w_pad=0.6, h_pad=0.9, rect=(0, 0.04, 1, 1))
    save(fig, "fig2_systems_grid")


def fig_languages(runs: dict):
    """Language limits for every tool: services it can review, and how many languages they are in."""
    import compare_tools as ct
    reach = ct.tool_reach(runs)
    order = ["atg"] + TOOLS
    total = sum(len(SOURCES[s]) for s in SYSTEMS)
    n_lang = len({l for rows in ct.service_languages().values() for _, l in rows})
    names = ["ATG (many languages)" if t == "atg" else f"{NAMES[t]} ({ct.TOOL_READS[t]})" for t in order]
    cols = [BLUE] + [GRAYS[2]] * len(TOOLS)
    panels = (([len(reach[t]) for t in order], total, "Services each tool can review", f"Services (of {total})"),
              ([len({l for *_, l in reach[t]}) for t in order], n_lang, "Languages each tool can read",
               f"Languages of those services (of {n_lang})"))

    def panel(ax, vals, top, title, xl):
        ax.barh(range(len(order)), vals, 0.6, color=cols, zorder=2)
        for i, v in enumerate(vals):
            ax.text(v + top * 0.02, i, f"{v}/{top}", va="center", fontsize=7, color=INK)
        ax.set_xlim(0, top * 1.25)
        ax.set_xlabel(xl)
        ax.grid(axis="y", visible=False)
        ax.set_title(title, loc="left", fontsize=9, fontweight="bold")

    # each panel on its own, one column wide (the report)
    for pnl, name in zip(panels, ("fig3b_services", "fig3c_languages")):
        f1, a1 = plt.subplots(figsize=(3.5, 2.5))
        panel(a1, *pnl)
        a1.set_yticks(range(len(order)), names, fontsize=7)
        a1.invert_yaxis()
        save(f1, name)
    fig, axs = plt.subplots(1, 2, figsize=(7.4, 3.0), sharey=True)
    for ax, pnl in zip(axs, panels):
        panel(ax, *pnl)
    axs[0].set_yticks(range(len(order)), names)
    axs[0].invert_yaxis()
    fig.tight_layout(w_pad=1.2)
    return save(fig, "fig3b_languages")


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
    names = ["ATG (many languages)", "Bandit (Python)", "gosec (Go)", "njsscan (Node.js)", "All three together"]
    vs = [total, cov["bandit"], cov["gosec"], cov["njsscan"], sum(cov.values())]
    b.barh(range(len(vs)), vs, 0.6, color=[BLUE, GRAYS[2], GRAYS[2], GRAYS[2], GRAYS[1]], zorder=2)
    for i, v in enumerate(vs):
        b.text(v + 0.8, i, f"{v}/{total}", va="center", fontsize=7, color=INK)
    b.set_yticks(range(len(vs)), names)
    b.invert_yaxis()
    b.set_xlim(0, total * 1.3)
    b.set_xlabel("Services it can review")
    b.grid(axis="y", visible=False)
    b.set_title("Language limits", loc="left", fontsize=9, fontweight="bold")
    fig.tight_layout(w_pad=1.5)
    out = save(fig, "fig3_reach")
    # the two panels on their own, for sections 4 and 5 of the page
    for i, name in ((0, "fig3a_systems"),):
        f2, ax2 = plt.subplots(figsize=(6.4, 2.4))
        src = [a, b][i]
        for bar in src.patches:
            ax2.barh(bar.get_y() + bar.get_height() / 2, bar.get_width(), bar.get_height(), color=bar.get_facecolor(), zorder=2)
        for txt in src.texts:
            ax2.text(*txt.get_position(), txt.get_text(), va="center", fontsize=7, color=INK)
        ax2.set_yticks(src.get_yticks(), [t.get_text() for t in src.get_yticklabels()])
        ax2.set_ylim(src.get_ylim())
        ax2.set_xlim(src.get_xlim())
        ax2.set_xlabel(src.get_xlabel())
        ax2.grid(axis="y", visible=False)
        ax2.set_title(src.get_title(loc="left"), loc="left", fontsize=9, fontweight="bold")
        save(f2, name)
    return out


def fig_speed(runs: dict, atg_label: str, zap: dict | None = None):
    order = ["atg"] + TOOLS
    med = []
    for t in order:
        secs = [r["seconds"] for r in runs[t].values() if r.get("applicable") and r.get("seconds") is not None]
        med.append(statistics.median(secs) if secs else 0)
    cols = [BLUE] + [GRAYS[2]] * len(TOOLS)
    if zap:
        order.append("zap")
        med.append(statistics.median([z["seconds"] for z in zap.values()]))
        cols.append(GRAYS[1])
    rows = sorted(zip(order, med, cols), key=lambda r: -r[1])        # largest first
    order, med, cols = [r[0] for r in rows], [r[1] for r in rows], [r[2] for r in rows]
    fig, ax = plt.subplots(figsize=(6.4, 0.24 * len(order) + 0.6))
    ax.barh(range(len(order)), med, 0.6, color=cols, zorder=2)
    for i, v in enumerate(med):
        ax.text(v * 1.15 if v else 0.01, i, f"{v:.2f} s" if v < 1 else f"{v:.1f} s", va="center", fontsize=7, color=INK)
    ax.set_xscale("log")
    ax.set_yticks(range(len(order)), [atg_label if t == "atg" else "OWASP ZAP" if t == "zap" else NAMES[t] for t in order])
    ax.invert_yaxis()
    ax.set_xlabel("Median time per system (s, log scale)")
    ax.grid(axis="y", visible=False)
    ax.set_title("Speed: time to review one system", loc="left", fontsize=9, fontweight="bold")
    return save(fig, "fig4_speed")


def fig_resources(runs: dict, zap: dict):
    """CPU time and peak memory per system (median), ATG's scan against each tool: two panels, one scale each."""
    order = ["atg"] + TOOLS
    names = ["ATG scan" if t == "atg" else NAMES[t] for t in order]
    cpu = [statistics.median([r["cpu_s"] for r in runs[t].values() if r.get("applicable") and r.get("cpu_s") is not None] or [0])
           for t in order]
    mem = [statistics.median([r["peak_mb"] for r in runs[t].values() if r.get("applicable") and r.get("peak_mb") is not None] or [0])
           for t in order]
    cols = [BLUE] + [GRAYS[2]] * len(TOOLS)
    if zap:
        names.append("OWASP ZAP")
        cpu.append(statistics.median([z["cpu_s"] for z in zap.values()]))
        mem.append(statistics.median([z["peak_mb"] for z in zap.values()]))
        cols.append(GRAYS[1])
    if not any(cpu):
        return None
    panels = ((cpu, "CPU time per system", "seconds (median, log scale)",
               lambda v: f"{v:.2f} s" if v < 1 else f"{v:.1f} s" if v < 100 else f"{v:.0f} s"),
              (mem, "Memory at its peak, per system", "MB (median, log scale)", lambda v: f"{v:,.0f} MB"))

    def panel(ax, vals0, title, label, fmt):
        rows = sorted(zip(names, vals0, cols), key=lambda r: -r[1])      # largest first, in each panel
        nm, vals, cl = [r[0] for r in rows], [r[1] for r in rows], [r[2] for r in rows]
        ax.set_title(title, loc="left", fontsize=9, fontweight="bold")
        ax.barh(range(len(nm)), [max(v, 1e-3) for v in vals], 0.6, color=cl, zorder=2)
        ax.set_yticks(range(len(nm)), nm)
        ax.invert_yaxis()
        for i, v in enumerate(vals):
            if v:
                ax.text(v * 1.15, i, fmt(v), va="center", fontsize=6.5, color=INK)
        ax.set_xscale("log")
        ax.set_xlim(min(v for v in vals if v) / 2, max(vals) * 8)
        ax.set_xlabel(label)
        ax.grid(axis="y", visible=False)

    # each panel on its own, one column wide (the report)
    for (vals0, title, label, fmt), name in zip(panels, ("fig6a_cpu", "fig6b_memory")):
        f1, a1 = plt.subplots(figsize=(3.5, 0.22 * len(names) + 0.8))
        panel(a1, vals0, title, label, fmt)
        save(f1, name)
    fig, axs = plt.subplots(1, 2, figsize=(7.0, 0.25 * len(names) + 0.9))
    for ax, pnl in zip(axs, panels):
        panel(ax, *pnl)
    fig.tight_layout(w_pad=1.5)
    return save(fig, "fig6_resources")


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
    ap.add_argument("--with-zap", action="store_true", help="also chart OWASP ZAP (bench/oss_eval.py --zap-usage)")
    a = ap.parse_args()
    runs = load(a.atg)
    if not runs["atg"]:
        raise SystemExit(f"no ATG runs in results/opensource/atg-{a.atg}/: run DEMO-ALL first")
    cmp = json.loads((OUT / "comparison.json").read_text(encoding="utf-8"))
    atg_name = "ATG"
    zap = zap_runs() if a.with_zap else {}
    figs = {"1.": [fig_speed(runs, "ATG (Phases 1-4)" if a.atg == "laptop" else "ATG (whole scan)", zap)],
            "2.": [fig_resources(runs, zap)],
            "3.": [fig_groups(cmp, atg_name)]}
    per_system = fig_systems(runs, atg_name)
    fig_reach(runs)
    figs["4."] = [FIG / "fig3a_systems.png"]
    figs["5."] = [fig_languages(runs)]
    import markdown
    md = (OUT / "comparison.md").read_text(encoding="utf-8")

    def img(p):
        return (f'<figure><img src="data:image/png;base64,{base64.b64encode(p.read_bytes()).decode()}"></figure>'
                if p and Path(p).exists() else "")
    parts = md.split("\n## ")
    head = markdown.markdown(parts[0].split("\n", 1)[1] if "\n" in parts[0] else "", extensions=["tables"])
    body = ""
    for sec in parts[1:]:
        title, _, rest = sec.partition("\n")
        key = title.split(" ", 1)[0]
        lead, sep, tables = rest.partition("\n### ")   # the section's own explanation first, then its charts
        body += f"<section><h2>{title}</h2>" + markdown.markdown(lead, extensions=["tables"]) + \
                "".join(img(p) for p in figs.get(key, [])) + \
                markdown.markdown(sep.lstrip("\n") + tables, extensions=["tables"]) + "</section>"
    grid = '<div class="grid">' + "".join(img(p) for p in per_system) + "</div>"
    body = body.replace("<!--FIG:systems-->", grid)
    n = sum(1 for v in figs.values() for p in v if p) + len(per_system)
    TOT = cmp["atg"]["labels"]
    GS = {g: v[0] for g, v in cmp["atg"]["groups"].items()}
    intro = f"""<div class="how"><h2>How this test works</h2>
<p>It works like an exam with an answer key. Ten real open-source microservice systems (65 services, 201 API
operations) were reviewed by hand and by fixed rules, and every known weakness was written down: {TOT} of them, each
one a <b>label</b> made of <i>what</i> and <i>where</i>, for example "no rate limit on login at POST /login of the
frontend". The answer keys are in <code>opensource/&lt;system&gt;/ground-truth.json</code>.</p>
<ol><li><b>ATG</b> reviews each running system (DEMO-ALL): the system's users send their requests through ATG's
sidecar and ATG scans.</li>
<li><b>Eight free tools</b> run on the same systems' files (BENCH): four Kubernetes scanners (Checkov, Kubescape,
kube-linter, Polaris), one API-document checker (Spectral) and three one-language code scanners (Bandit, gosec,
njsscan).</li>
<li><b>One marking script</b> scores every tool the same way: a label counts as found when the tool reports the same
kind of weakness at the same service or operation.</li></ol>
<p>The labels fall into three groups. <b>Configuration</b> ({GS['Configuration']}): mistakes in the deployment files, such as running
as root, no network policy, no memory limits, secrets in plain files, no HTTPS. <b>API behaviour</b> ({GS['API behaviour']}): how the
running API behaves, such as no login check, services calling each other without credentials, admin pages open, no
rate limit on login. <b>Inventory and visibility</b> ({GS['Inventory and visibility']}): APIs nobody documented, and services that send no
traces.</p>
<p><b>Runs on 7/10</b> means the tool could read only 7 of the 10 systems; it scores 0 on the others.
<b>n/a</b>: the tool cannot read that system's files. <b>Precision</b>: of everything the tool reported, the share
that matches a label (higher means fewer false alarms).</p></div>"""
    page = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>ATG vs other tools: ten open-source systems</title>
<style>body{{font:14px/1.5 system-ui,Segoe UI,sans-serif;max-width:1100px;margin:24px auto;padding:0 20px;color:#1c2430}}
table{{border-collapse:collapse;font-size:12.5px;margin:8px 0 20px}}td,th{{border:1px solid #d5d9df;padding:4px 8px}}
th{{background:#f2f4f7}}figure{{margin:16px 0}}img{{max-width:100%;border:1px solid #e5e7eb}}h1{{font-size:24px}}
h2{{font-size:20px;margin-top:36px;border-bottom:2px solid #2a78d6;padding-bottom:4px}}h3{{font-size:15px}}
.how{{background:#f6f8fb;border:1px solid #dfe5ee;padding:4px 18px 8px;border-radius:6px}}.how h2{{margin-top:12px}}
code{{background:#f2f4f7;padding:0 3px}}.grid{{display:grid;grid-template-columns:1fr 1fr;gap:4px 14px}}
.grid figure{{margin:4px 0}}</style></head><body>
<h1>ATG and eight free tools on ten open-source systems</h1>
<p>Generated by <code>bench/oss_figures.py</code> from the runs on this computer: ATG in <code>results/opensource/atg-{a.atg}/</code>,
the tools in <code>results/opensource/tools/</code>. Every chart and table below is drawn from those files.</p>
{intro}{head}{body}</body></html>"""
    (OUT / "comparison.html").write_text(page, encoding="utf-8")
    print(f"wrote {n} figures in results/opensource/figures/ and results/opensource/comparison.html")
    return 0


if __name__ == "__main__":
    sys.exit(main())
