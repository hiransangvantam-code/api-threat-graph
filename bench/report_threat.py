"""
Phase 2-4 tables and figures (called from bench/report.py).
Reads results/grid/*/threat.json (current tool), threat-v1.json (before the
evaluation-driven fixes), results/hardened/hardened.json and results/stores.json.
"""
from __future__ import annotations

import json
import statistics as st
from collections import Counter, defaultdict

from bench.evaluate_threat import ABLATION, CRAPI_CHALLENGES, OUT_OF_SCOPE
from bench.report import FIGS, RES, TB_NAMES, TB_ORDER, _plt, ms, name

SUBSET_NAME = {"OTKC": "All four"}


def _f1(x: dict) -> float | None:
    d = 2 * x["tp"] + x["fp"] + x["fn"]
    return 2 * x["tp"] / d if d else None


def _ratio_v1(rv1: dict, current: list[dict]) -> float | None:
    """v1 tool R over the current oracle R of the same run (the oracle got one fix after
    the v1 runs; it changed only exposure, so only R needs re-dividing)."""
    cur = next((r for r in current if r["run"] == rv1["run"]), None)
    o = (cur or rv1)["oracle_graph"]["total_path_risk"]
    return rv1["vs_oracle"]["risk"]["tool_R"] / o if o else None


def load(tag: str = ""):
    fname = f"threat-{tag}.json" if tag else "threat.json"
    runs = defaultdict(list)
    for f in sorted((RES / "grid").glob(f"*/{fname}")):
        tb, cond, _ = f.parent.name.split("-")
        runs[(tb, cond)].append(json.loads(f.read_text()))
    return runs


def _pooled(rs, part):
    tp = sum(r["vs_oracle"][part]["tp"] for r in rs)
    fp = sum(r["vs_oracle"][part]["fp"] for r in rs)
    fn = sum(r["vs_oracle"][part]["fn"] for r in rs)
    p = tp / (tp + fp) if tp + fp else None
    rc = tp / (tp + fn) if tp + fn else None
    return p, rc


def threat_tables(out):
    runs, before = load(), load("v1")
    if not runs:
        return
    out.md += ["---", "", "# Phases 2-4: threat analysis", "",
               "Tool = Phases 2-3 on the extractor output (all four sources). Oracle = the same Phase 3 code on an EUJF built "
               "from ground truth (bench/oracle.py). Differences come from discovery and normalization only.", ""]

    # ---------------------------------------------------------------- T11 threat model produced
    rows = []
    for tb in TB_ORDER:
        for cond in ("C1", "C2"):
            rs = runs.get((tb, cond), [])
            if not rs:
                continue
            G = [r["graph"] for r in rs]
            sev = lambda k: ms([x["by_severity"][k] for x in G], 1)  # noqa: E731
            rows.append([TB_NAMES[tb], cond, ms([x["findings"] for x in G], 1), sev("critical"), sev("high"),
                         ms([x["rules_fired"] for x in G], 1), ms([x["nodes"] for x in G], 0), ms([x["edges"] for x in G], 0),
                         ms([x["attack_paths"] for x in G], 0), ms([x["critical_or_high_paths"] for x in G], 0),
                         ms([x["hops_mean"] for x in G], 2), ms([x["apcr_max"] for x in G], 1),
                         ms([x["total_path_risk"] for x in G], 0), ms([r["oracle_graph"]["total_path_risk"] for r in rs], 0),
                         ms([x["fixes_for_70pct"] for x in G], 1), ms([x["max_blast_radius"] for x in G], 1)])
    out.table("t11_threat_model", "Table 11. Threat model produced per run (Phase 3)",
              ["Testbed", "Cond.", "Findings", "Critical", "High", "Rules fired (of 27)", "Graph nodes", "Graph edges",
               "Attack paths", "Paths APCR ≥ 12", "Mean path length", "Max APCR", "Path risk R", "Oracle R",
               "Fixes for 70% of R", "Largest blast radius"], rows,
              "R is the sum over findings of the highest APCR among the paths that reach it. Blast radius: services "
              "upstream of a service, i.e. affected if it is compromised or down.")

    # ---------------------------------------------------------------- T12 tool vs oracle
    rows = []
    for tb in TB_ORDER:
        for cond in ("C1", "C2"):
            rs = runs.get((tb, cond), [])
            if not rs:
                continue
            V = [r["vs_oracle"] for r in rs]
            rows.append([TB_NAMES[tb], cond,
                         ms([v["findings"]["precision"] for v in V]), ms([v["findings"]["recall"] for v in V]),
                         ms([v["findings"]["f1"] for v in V]), ms([v["findings"]["recall_critical_high"] for v in V]),
                         ms([v["findings"]["severity_agreement"] for v in V]),
                         ms([v["paths"]["precision"] for v in V]), ms([v["paths"]["recall"] for v in V]),
                         ms([v["risk"]["ratio"] for v in V], 2), ms([v["risk"]["top10_overlap"] for v in V], 2),
                         ms([v["risk"]["service_risk_spearman"] for v in V], 2)])
    out.table("t12_vs_oracle", "Table 12. Threat model fidelity: tool vs oracle",
              ["Testbed", "Cond.", "Finding precision", "Finding recall", "Finding F1", "Recall, critical+high",
               "Same severity", "Path precision", "Path recall", "R tool / R oracle", "Top-10 overlap",
               "Service risk rank corr."], rows,
              "A finding matches when rule and target agree (target = the true endpoint, or the service). A path matches "
              "on (entry actor, finding). Top-10 overlap compares the ten findings ranked highest by APCR. Rank "
              "correlation is Spearman over the propagated risk of every service.")

    # ---------------------------------------------------------------- T13 per rule
    per = {c: defaultdict(Counter) for c in ("C1", "C2")}
    for (tb, cond), rs in runs.items():
        for r in rs:
            for rule, x in r["vs_oracle"]["per_rule"].items():
                per[cond][rule].update({"tp": x["tp"], "fp": x["fp"], "fn": x["fn"]})
    rows = []
    for rule in sorted(set(per["C1"]) | set(per["C2"])):
        row = [rule]
        for cond in ("C1", "C2"):
            c = per[cond][rule]
            p = c["tp"] / (c["tp"] + c["fp"]) if c["tp"] + c["fp"] else None
            rc = c["tp"] / (c["tp"] + c["fn"]) if c["tp"] + c["fn"] else None
            row += [c["tp"] + c["fn"], "n/a" if p is None else f"{p:.2f}", "n/a" if rc is None else f"{rc:.2f}"]
        rows.append(row)
    out.table("t13_per_rule", "Table 13. Per-rule agreement with the oracle (pooled over testbeds and seeds)",
              ["Rule", "C1 oracle findings", "C1 precision", "C1 recall", "C2 oracle findings", "C2 precision", "C2 recall"],
              rows, "n/a: the rule never fired on that side.")

    # ---------------------------------------------------------------- T14 ablation
    rows = []
    for combo in ABLATION:
        row = [name(combo)]
        for tb in TB_ORDER:
            for cond in ("C1", "C2"):
                rs = runs.get((tb, cond), [])
                row.append(ms([_f1(r["ablation"][combo]) for r in rs], 2) if rs else "n/a")
        rows.append(row)
    out.table("t14_threat_ablation", "Table 14. Finding F1 against the oracle, by source subset (rules only)",
              ["Sources"] + [f"{TB_NAMES[t]} {c}" for t in TB_ORDER for c in ("C1", "C2")], rows,
              "Same oracle as Table 12; the tool side runs Phases 2-3 on a subset of the Phase 1 files.")
    _fig_threat_ablation(runs)

    # ---------------------------------------------------------------- T15 crAPI challenges
    cr = runs.get(("crapi", "C1"), []), runs.get(("crapi", "C2"), [])
    if cr[0] and cr[0][0].get("known"):
        rows = []
        for i, (cid, title, owasp, key, rules, needs) in enumerate(CRAPI_CHALLENGES):
            def frac(rs, side):
                vals = [r["known"]["challenges"][i][side] for r in rs]
                top = Counter(vals).most_common(1)[0]
                return top[0] if top[1] == len(vals) else ", ".join(f"{v} {n}/{len(vals)}" for v, n in Counter(vals).items())
            fired = sorted({x for r in cr[1] for x in r["known"]["challenges"][i]["tool_rules"]})
            rows.append([cid, title, owasp, f"{key[1]} {key[2]}",
                         ", ".join(rules) or ("out of scope" if cid in OUT_OF_SCOPE else "no rule"), needs,
                         frac(cr[0], "oracle"), frac(cr[0], "tool"), frac(cr[1], "tool"), ", ".join(fired) or "none"])
        out.table("t15_crapi_challenges", "Table 15. OWASP crAPI's own vulnerability list (external ground truth)",
                  ["#", "Challenge", "OWASP", "Endpoint", "Rule family", "What a passive tool would need to see",
                   "Oracle (perfect discovery)", "Tool C1", "Tool C2", "Rules that fired on it (C2, any seed)"], rows,
                  "'flagged by another auth rule': a different authorization rule (usually API1, possible BOLA) fired on "
                  "that endpoint, so the endpoint is pointed at but under another category. Replicas return "
                  "generic bodies, so rules that read response content cannot fire on crAPI here; testing those needs a "
                  "Phases 1-3 run on the real crAPI (the realcheck/ kit currently scores Phase 1 only and has not been run).")

    # ---------------------------------------------------------------- T16 ShopLite planted + hardened
    rows = []
    for cond in ("C1", "C2"):
        rs = runs.get(("shoplite", cond), [])
        for side in ("tool", "oracle"):
            K = [r["known"][side] for r in rs]
            rows.append([cond, side, ms([k["planted_found"] for k in K], 1), K[0]["planted"] if K else "",
                         ms([k["precision"] for k in K]), ms([k["recall"] for k in K])])
    out.table("t16_shoplite_planted", "Table 16. ShopLite: weaknesses built into the demo",
              ["Cond.", "Side", "Planted found", "Planted (incl. 3 no rule covers)", "Precision", "Recall"], rows,
              "Recall counts the three weaknesses no rule covers (BOLA through a query parameter, user_id trusted from the "
              "body, weak signing secret) as misses. The list was written by the same team as the rules.")
    hp = RES / "hardened" / "hardened.json"
    if hp.exists():
        H = json.loads(hp.read_text())
        rows = []
        for cond in ("C1", "C2"):
            hs = [h for h in H if f"-{cond}-" in h["run"]]
            if not hs:
                continue
            rows.append([cond, len(hs), ms([h["findings"] for h in hs], 1),
                         f"{sum(not h['missing'] and not h['unexpected_not_tracing_gaps'] for h in hs)}/{len(hs)}",
                         ms([h["paths_vulnerable"] for h in hs], 0), ms([h["paths_hardened"] for h in hs], 0),
                         ms([h["R_vulnerable"] for h in hs], 0), ms([h["R_hardened"] for h in hs], 1),
                         ms([h["reduction_pct"] for h in hs], 1), ms([h["plan_fixes_for_70pct"] for h in hs], 1)])
        out.table("t17_hardening", "Table 17. Applying the fixes: ShopLite vulnerable vs hardened build",
                  ["Cond.", "Seeds", "Findings after", "Runs with only the 2 kept on purpose (+ tracing gaps)", "Attack paths before",
                   "Attack paths after", "R before", "R after", "Measured reduction %", "Plan: fixes for 70%"], rows,
                  "The hardened build implements the dashboard's recommendations; it keeps one deprecated endpoint in use "
                  "and one untraced cron job on purpose. Under C2 the experiment itself leaves about 30% of services "
                  "untraced, so LT-02 / LT-03 findings there are true and are not counted against the build. In two C2 "
                  "seeds the untraced user-service hides the cron job, so LT-01 is missed.")
        _fig_hardening(H)

    # ---------------------------------------------------------------- T18 timing
    rows = []
    for tb in TB_ORDER:
        for cond in ("C1", "C2"):
            rs = runs.get((tb, cond), [])
            if not rs:
                continue
            T = [r["timing"] for r in rs]
            rows.append([TB_NAMES[tb], cond, ms([t["phase2_normalize_ms"] for t in T], 1), ms([t["rule_engine_ms"] for t in T], 1),
                         ms([t["threat_graph_ms"] for t in T], 1), ms([t["attack_path_query_ms"] for t in T], 0),
                         ms([t.get("mitigation_plan_ms") for t in T], 0),
                         ms([t["phase3_total_ms"] for t in T], 0), ms([t["phase4_dashboard_ms"] for t in T], 1),
                         ms([t["dashboard_kb"] for t in T], 0)])
    out.table("t18_phase234_time", "Table 18. Phases 2-4 processing time per run",
              ["Testbed", "Cond.", "Phase 2 normalize (ms)", "Rule engine (ms)", "Graph build + store (ms)",
               "Attack path query (ms)", "Mitigation plan (ms)", "Phase 3 total (ms)", "Phase 4 dashboard (ms)",
               "Dashboard size (KB)"], rows,
              "Measured in-process (Table 7 runs each phase as a fresh process, so its times include start-up). "
              "In-memory SQLite graph store. The attack path query enumerates every simple path up to 9 hops inside the "
              "database (recursive CTE); the greedy mitigation planner re-scores every remaining action after each step. "
              "Together they take nearly all of Phase 3 on the larger graphs.")
    sp = RES / "stores.json"
    if sp.exists():
        S = json.loads(sp.read_text())
        rows = []
        for s in S:
            def cell(x):
                return ms(x["attack_path_query_ms"], 0) if isinstance(x, dict) else x
            rows.append([s["run"], s["sqlite"]["paths"] if isinstance(s.get("sqlite"), dict) else "",
                         cell(s.get("sqlite")), cell(s.get("postgresql")), "yes" if s["identical"] else "no"])
        out.table("t19_stores", "Table 19. Graph store: SQLite vs PostgreSQL (same recursive SQL)",
                  ["Run", "Attack paths", "SQLite query (ms)", "PostgreSQL query (ms)", "Identical paths"], rows)

    # ---------------------------------------------------------------- T20 before / after fixes
    if before:
        rows = []
        for tb in TB_ORDER:
            for cond in ("C1", "C2"):
                b, a = before.get((tb, cond), []), runs.get((tb, cond), [])
                if not (a and b):
                    continue
                rows.append([TB_NAMES[tb], cond,
                             ms([r["vs_oracle"]["findings"]["precision"] for r in b], 2), ms([r["vs_oracle"]["findings"]["precision"] for r in a], 2),
                             ms([r["vs_oracle"]["findings"]["recall"] for r in b], 2), ms([r["vs_oracle"]["findings"]["recall"] for r in a], 2),
                             ms([r["vs_oracle"]["findings"]["f1"] for r in b], 2), ms([r["vs_oracle"]["findings"]["f1"] for r in a], 2),
                             ms([_ratio_v1(r, a) for r in b], 2), ms([r["vs_oracle"]["risk"]["ratio"] for r in a], 2)])
        out.table("t20_fixes", "Table 20. Evaluation-driven fixes: finding fidelity before (v1) and after (v1.1)",
                  ["Testbed", "Cond.", "Precision v1", "Precision v1.1", "Recall v1", "Recall v1.1", "F1 v1", "F1 v1.1",
                   "R ratio v1", "R ratio v1.1"], rows,
                  "v1.1 fixes five evidence-handling bugs the oracle comparison exposed (docs/EXPERIMENT.md). The rules "
                  "themselves were not changed. Both versions are scored against the same oracle.")
    _fig_fidelity(runs, before)


# ---------------------------------------------------------------- figures
def _fig_fidelity(runs, before):
    plt = _plt()
    fig, axes = plt.subplots(1, 2, figsize=(9.5, 3.2), sharey=True)
    labels = [f"{TB_NAMES[t]}\n{c}" for t in TB_ORDER for c in ("C1", "C2")]
    x = range(len(labels))
    for ax, part, title in ((axes[0], "findings", "Findings vs oracle (F1)"), (axes[1], "paths", "Attack paths vs oracle (F1)")):
        for i, (src, lbl, col) in enumerate(((before, "v1", "#C9C9C9"), (runs, "v1.1", "#4C72B0"))):
            vals = [st.fmean(r["vs_oracle"][part]["f1"] or 0 for r in src.get((t, c), [])) if src.get((t, c)) else 0
                    for t in TB_ORDER for c in ("C1", "C2")]
            ax.bar([j + (i - 0.5) * 0.38 for j in x], vals, 0.38, label=lbl, color=col)
        ax.set_xticks(list(x), labels, fontsize=7)
        ax.set_title(title)
        ax.set_ylim(0, 1.05)
    axes[0].legend(frameon=False, fontsize=7, loc="lower left")
    fig.tight_layout()
    fig.savefig(FIGS / "fig_threat_fidelity.png")
    plt.close(fig)


def _fig_threat_ablation(runs):
    plt = _plt()
    cols = [(t, "C2") for t in TB_ORDER]
    data = [[st.fmean(_f1(r["ablation"][c]) or 0 for r in runs[k]) if runs.get(k) else 0 for k in cols] for c in ABLATION]
    fig, ax = plt.subplots(figsize=(4.4, 4.0))
    im = ax.imshow(data, cmap="viridis", vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(cols)), [TB_NAMES[t] for t, _ in cols])
    ax.set_yticks(range(len(ABLATION)), ["+".join(c) for c in ABLATION])
    for i, row in enumerate(data):
        for j, v in enumerate(row):
            ax.text(j, i, f"{v:.2f}", ha="center", va="center", color="white" if v < 0.6 else "black", fontsize=7)
    ax.set_title("Finding F1 vs oracle by source subset (C2)\nO=OpenAPI T=Traffic K=K8s/gateway C=Traces", fontsize=8)
    fig.colorbar(im, ax=ax, fraction=0.04)
    fig.tight_layout()
    fig.savefig(FIGS / "fig_threat_ablation.png")
    plt.close(fig)


def _fig_hardening(H):
    plt = _plt()
    h = next((x for x in H if x["run"] == "shoplite-C1-s1"), H[0])
    from bench.evaluate_threat import run_analysis
    from atg.normalizer import normalize
    a, _ = run_analysis(normalize(RES / "grid" / h["run"] / "raw"))
    steps = a["mitigation_plan"]["steps"]
    fig, ax = plt.subplots(figsize=(4.8, 3.0))
    ax.plot(range(0, len(steps) + 1), [0] + [s["cumulative_reduction_pct"] for s in steps], marker="o", ms=3,
            label="Plan (predicted, greedy order)")
    ax.axhline(h["reduction_pct"], color="#DD8452", ls="--", label=f"Hardened build (measured): {h['reduction_pct']}%")
    ax.axhline(70, color="#999", lw=0.8, ls=":")
    ax.set_xlabel("Fixes applied")
    ax.set_ylabel("Attack-path risk removed (%)")
    ax.set_ylim(0, 105)
    ax.legend(frameon=False, fontsize=7, loc="lower right")
    ax.set_title("ShopLite: mitigation plan vs measured")
    fig.tight_layout()
    fig.savefig(FIGS / "fig_hardening_shoplite.png")
    plt.close(fig)
