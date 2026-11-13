"""
The fix planner as it was up to version 1.2, kept as the reference for two things:

  tests/test_plan.py   the current planner (atg.analysis.mitigation_plan) must give the same plan
  bench/stress.py      --planner v1 measures how this version scaled

It scores every remaining action against every remaining path at every step
(actions x actions x paths), which made it the slowest part of Phase 3 on large systems.
"""
from __future__ import annotations

from atg.analysis import EDGE_CUT, assign_actions


def mitigation_plan_v1(findings: list[dict], paths: list[dict]) -> dict:
    """Greedy: repeatedly apply the remediation action that removes the most remaining
    attack-path risk. Total risk R = sum over findings of the highest APCR among the
    paths that still reach it."""
    actions = assign_actions(findings)

    def kills(a, p):
        if p["finding_id"] in a["finding_ids"]:
            return True
        actor = EDGE_CUT.get(a["kind"])
        return bool(actor) and p["nodes"][0] == actor and len(p["nodes"]) > 1 and p["nodes"][1] == a["target"]

    def total(alive):
        best = {}
        for p in alive:
            best[p["finding_id"]] = max(best.get(p["finding_id"], 0), p["apcr"])
        return sum(best.values())

    alive = list(paths)
    start = total(alive)
    steps, done = [], set()
    while alive:
        cand = None
        for a in actions:
            if a["id"] in done:
                continue
            remaining = [p for p in alive if not kills(a, p)]
            gain = total(alive) - total(remaining)
            if gain > 1e-9 and (cand is None or gain > cand[1]):
                cand = (a, gain, remaining)
        if not cand:
            break
        a, gain, alive = cand
        done.add(a["id"])
        left = total(alive)
        steps.append({**a, "risk_removed": round(gain, 2), "remaining": round(left, 2),
                      "cumulative_reduction_pct": round(100 * (1 - left / start), 1) if start else 0})

    def fixes_for(pct):
        return next((i + 1 for i, s in enumerate(steps) if s["cumulative_reduction_pct"] >= pct), None)

    return {"total_path_risk": round(start, 2), "actions": len(actions), "steps": steps,
            "fixes_for_70pct": fixes_for(70), "fixes_for_90pct": fixes_for(90),
            "unscheduled": [a for a in actions if a["id"] not in done]}
