"""
Phase 2-4 evaluation: is the threat model built from extracted data the threat model
the system really has?

For every experiment run:
  tool      Phase 2 + 3 on the extractor output (all four sources)
  oracle    Phase 3 on the oracle EUJF (bench/oracle.py): same rules, same graph code,
            but fed with ground truth

and then
  T1 findings      precision / recall / F1 of tool findings against oracle findings,
                   overall and per rule; severity agreement on the matched ones
  T2 attack paths  precision / recall of (entry actor, finding) pairs
  T3 risk          total attack-path risk R (tool / oracle), top-10 overlap of the
                   ranking by APCR, rank correlation of per-service propagated risk,
                   number of fixes the plan needs for 70% / 90% risk reduction
  T4 graph         node / edge counts by type, path length, APCR distribution
  T5 ablation      finding F1 against the oracle for source subsets (rules only)
  T6 known vulns   crAPI: OWASP's own list of 18 challenges (external ground truth);
                   ShopLite: the weaknesses built into the demo, before and after hardening
  T7 timing        Phase 2, rule engine, graph, attack-path query, Phase 4 dashboard
"""
from __future__ import annotations

import json
import re
import statistics as st
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path

from atg.analysis import analyze, run_rules
from atg.dashboard import build_dashboard
from atg.graphstore import GraphStore
from atg.normalizer import normalize
from bench.common import shape
from bench.evaluate import eujf_for, ground_truth
from bench.oracle import build as build_oracle
from bench.oracle import tool_id_to_gt

ABLATION = ["O", "T", "C", "OT", "TK", "OTK", "OTC", "OKC", "TKC", "OTKC"]

# --------------------------------------------------------------------------- external ground truth
# OWASP crAPI's own challenge list (docs/challenges.md at the pinned commit), with the
# endpoint each challenge is about (from docs/challengeSolutions.md and the source) and
# the rule family that would report it. `needs` says what the evidence would have to
# contain for a passive, design-level tool to see it.
CRAPI_CHALLENGES = [
    (1, "BOLA: another user's vehicle location", "API1:2023", ("crapi-identity", "GET", "/identity/api/v2/vehicle/{}/location"), ["API1"], "response content (owner / location fields)"),
    (2, "BOLA: other users' mechanic reports", "API1:2023", ("crapi-workshop", "GET", "/workshop/api/mechanic/mechanic_report"), ["API1"], "object ID in the query string (API1 reads path IDs only)"),
    (3, "Broken auth: reset another user's password (OTP brute force on v2)", "API2:2023", ("crapi-identity", "POST", "/identity/api/auth/v2/check-otp"), ["TS-07"], "failed attempts in traffic (crAPI answers 500, the rule counts 401/403)"),
    (4, "Excessive data exposure: other users' data in community posts", "API3:2023", ("crapi-community", "GET", "/community/api/v2/community/posts/recent"), ["API3"], "response content"),
    (5, "Excessive data exposure: internal video property", "API3:2023", ("crapi-identity", "GET", "/identity/api/v2/user/videos/{}"), ["API3"], "response content"),
    (6, "Rate limiting: layer-7 DoS through contact mechanic", "API4:2023", ("crapi-workshop", "POST", "/workshop/api/merchant/contact_mechanic"), ["API4"], "request semantics (repeat count field)"),
    (7, "BFLA: delete another user's video through the admin API", "API5:2023", ("crapi-identity", "DELETE", "/identity/api/v2/admin/videos/{}"), ["API5"], "calls by an authenticated non-admin user succeeding"),
    (8, "Mass assignment: get an item for free", "API3:2023", ("crapi-workshop", "PUT", "/workshop/api/shop/orders/{}"), [], "request semantics (writable status field); no mass-assignment rule"),
    (9, "Mass assignment: increase balance", "API3:2023", ("crapi-workshop", "PUT", "/workshop/api/shop/orders/{}"), [], "request semantics (writable quantity field); no mass-assignment rule"),
    (10, "Mass assignment: update internal video properties", "API3:2023", ("crapi-identity", "PUT", "/identity/api/v2/user/videos/{}"), [], "request semantics (writable internal field); no mass-assignment rule"),
    (11, "SSRF through contact mechanic", "API7:2023", ("crapi-workshop", "POST", "/workshop/api/merchant/contact_mechanic"), ["API7"], "URL-typed request field (named mechanic_api)"),
    (12, "NoSQL injection: free coupons", "API8:2023", ("crapi-community", "POST", "/community/api/v2/coupon/validate-coupon"), [], "payload testing"),
    (13, "SQL injection: redeem a used coupon", "API8:2023", ("crapi-workshop", "POST", "/workshop/api/shop/apply_coupon"), [], "payload testing"),
    (14, "Unauthenticated access to order details", "API2:2023", ("crapi-workshop", "GET", "/workshop/api/shop/orders/{}"), ["TS-01", "TS-03"], "an anonymous request in the traffic (TS-03: spec says auth, it succeeds); TS-01 also needs response content"),
    (15, "Forge valid JWT tokens", "API2:2023", ("crapi-identity", "GET", "/identity/api/auth/jwks.json"), [], "token / crypto testing"),
    (16, "Chatbot prompt injection", "LLM", ("crapi-chatbot", "POST", "/chatbot/genai/ask"), [], "LLM testing"),
    (17, "Chatbot leaks another user's credentials", "LLM", ("crapi-chatbot", "POST", "/chatbot/genai/ask"), [], "LLM testing"),
    (18, "Chatbot acts on behalf of another user", "LLM", ("crapi-chatbot", "POST", "/chatbot/genai/ask"), [], "LLM testing"),
]
AUTHZ_RULES = {"API1", "API5", "TS-01", "TS-03", "TS-08"}
# challenges a passive design review cannot see at all (need payloads, crypto or LLM testing)
OUT_OF_SCOPE = {12, 13, 15, 16, 17, 18}

# ShopLite: weaknesses built into the vulnerable build (tests/test_pipeline.py), as
# (rule, target) with target = (service, METHOD, shape) or the service name
_P = lambda s, m, p: (s, m, shape(p))  # noqa: E731
SHOPLITE_PLANTED = {
    ("API5", _P("payment-service", "GET", "/admin/transactions")), ("API3", _P("payment-service", "GET", "/admin/transactions")),
    ("TS-01", _P("payment-service", "GET", "/admin/transactions")), ("API9-SHADOW", _P("payment-service", "GET", "/admin/transactions")),
    ("TS-01", _P("payment-service", "POST", "/charge")), ("TS-03", _P("payment-service", "POST", "/charge")),
    ("TS-08", _P("payment-service", "POST", "/charge")),
    ("TS-01", _P("payment-service", "POST", "/refund")), ("API9-SHADOW", _P("payment-service", "POST", "/refund")),
    ("TS-01", _P("user-service", "GET", "/internal/users/export")), ("API5", _P("user-service", "GET", "/internal/users/export")),
    ("API3", _P("user-service", "GET", "/internal/users/export")), ("API9-SHADOW", _P("user-service", "GET", "/internal/users/export")),
    ("LT-01", _P("user-service", "GET", "/internal/users/export")),
    ("API1", _P("user-service", "GET", "/users/{}")), ("API1", _P("user-service", "GET", "/users/{}/addresses")),
    ("API1", _P("order-service", "GET", "/orders/{}")), ("API1", _P("order-service", "DELETE", "/orders/{}")),
    ("API9-ZOMBIE", _P("order-service", "DELETE", "/orders/{}")),
    ("TS-02", "api-gateway"), ("TS-05", "api-gateway"), ("API8-NETPOL", "api-gateway"),
    ("API8-DEBUG", _P("api-gateway", "GET", "/_debug/config")), ("API9-SHADOW", _P("api-gateway", "GET", "/_debug/config")),
    ("TS-07", _P("user-service", "POST", "/auth/login")),
    ("TS-04", "order-service"), ("API4", "order-service"), ("API8-ROOT", "order-service"), ("API8-NETPOL", "order-service"),
    ("TS-04", "payment-service"), ("API4", "payment-service"), ("API8-ROOT", "payment-service"),
    ("API8-PRIV", "payment-service"), ("API8-TAG", "payment-service"), ("API8-NODEPORT", "payment-service"),
    ("API8-NETPOL", "payment-service"), ("API9-NOSPEC", "payment-service"),
}
# weaknesses in ShopLite that no rule covers (docs/THREAT_MODEL.md, known limitations)
SHOPLITE_UNCOVERED = [
    ("BOLA through a query parameter", _P("order-service", "GET", "/orders")),
    ("Order created for another user (user_id trusted from the body)", _P("order-service", "POST", "/orders")),
    ("Weak token signing secret", "user-service"),
]
SHOPLITE_HARDENED_EXPECTED = {("API9-ZOMBIE", _P("order-service", "DELETE", "/orders/{}")),
                              ("LT-01", _P("user-service", "GET", "/internal/users/export"))}


# --------------------------------------------------------------------------- keys
def _disc(f: dict) -> str:
    d = f["detail"]
    if f["rule_id"] == "TS-02":
        m = re.search(r"route (\S+?)/\*\* ", d)
        return m.group(1) if m else d
    if f["rule_id"] == "TS-04":
        return d.split()[0]
    if f["rule_id"] in ("TS-05", "API10", "LT-01"):
        return d
    return ""


def fkey(f: dict, id2key: dict) -> tuple:
    if f["target"].startswith("ep:"):
        return (f["rule_id"], id2key.get(f["target"], ("unmatched", f["target"])))
    return (f["rule_id"], ("svc", f["service"], _disc(f)))


def simple_target(k: tuple):
    """(rule, target) without discriminators, for comparing with hand-written lists."""
    rule, t = k
    return (rule, t[1]) if t and t[0] == "svc" else (rule, t)


def keyed(findings: list[dict], id2key: dict) -> dict:
    out = {}
    for f in findings:
        k = fkey(f, id2key)
        if k not in out or (f.get("best_apcr", 0), f["score"]) > (out[k].get("best_apcr", 0), out[k]["score"]):
            out[k] = f
    return out


def prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if tp + fp + fn else None
    return {"tp": tp, "fp": fp, "fn": fn, "precision": _r(p), "recall": _r(r), "f1": _r(f1)}


def _r(x):
    return None if x is None else round(x, 4)


def spearman(a: list[float], b: list[float]) -> float | None:
    if len(a) < 3:
        return None

    def ranks(v):
        order = sorted(range(len(v)), key=lambda i: v[i])
        r = [0.0] * len(v)
        i = 0
        while i < len(v):
            j = i
            while j + 1 < len(v) and v[order[j + 1]] == v[order[i]]:
                j += 1
            for k in range(i, j + 1):
                r[order[k]] = (i + j) / 2 + 1
            i = j + 1
        return r
    ra, rb = ranks(a), ranks(b)
    ma, mb = st.fmean(ra), st.fmean(rb)
    cov = sum((x - ma) * (y - mb) for x, y in zip(ra, rb))
    va = sum((x - ma) ** 2 for x in ra) ** 0.5
    vb = sum((y - mb) ** 2 for y in rb) ** 0.5
    return round(cov / (va * vb), 4) if va and vb else None


# --------------------------------------------------------------------------- analysis helpers
def run_analysis(eujf: dict) -> tuple[dict, dict]:
    t = time.perf_counter()
    a = analyze(eujf, GraphStore("sqlite:///:memory:"))
    timing = dict(a["timing"])
    timing["phase3_total_ms"] = round((time.perf_counter() - t) * 1000, 1)
    with tempfile.TemporaryDirectory() as td:
        t = time.perf_counter()
        out = build_dashboard(a, eujf, [], Path(td) / "dashboard.html", {}, phase1_report=None)
        timing["phase4_dashboard_ms"] = round((time.perf_counter() - t) * 1000, 1)
        timing["dashboard_kb"] = round(Path(out).stat().st_size / 1024, 1)
    return a, timing


def graph_stats(a: dict) -> dict:
    nodes, edges, paths = a["graph"]["nodes"], a["graph"]["edges"], a["attack_paths"]
    apcr = sorted(p["apcr"] for p in paths)
    hops = [p["hops"] for p in paths]
    q = lambda v, x: v[min(len(v) - 1, int(x * (len(v) - 1)))] if v else None  # noqa: E731
    return {"nodes": len(nodes), "edges": len(edges),
            "nodes_by_type": dict(Counter(n["type"] for n in nodes)),
            "edges_by_rel": dict(Counter(e["rel"] for e in edges)),
            "attack_paths": len(paths), "critical_or_high_paths": sum(1 for p in paths if p["apcr"] >= 12),
            "internet_paths": sum(1 for p in paths if p["entry"] == "actor:internet"),
            "hops_mean": _r(st.fmean(hops)) if hops else None, "hops_max": max(hops, default=None),
            "apcr_median": q(apcr, 0.5), "apcr_p90": q(apcr, 0.9), "apcr_max": apcr[-1] if apcr else None,
            "total_path_risk": a["summary"]["total_path_risk"],
            "findings": a["summary"]["findings"], "by_severity": a["summary"]["by_severity"],
            "rules_fired": a["summary"]["rules_fired"],
            "fixes_for_70pct": a["mitigation_plan"]["fixes_for_70pct"],
            "fixes_for_90pct": a["mitigation_plan"]["fixes_for_90pct"],
            "remediation_actions": a["mitigation_plan"]["actions"],
            "longest_chain": a["dependency"]["longest_chain"],
            "max_blast_radius": max((len(s["blast_radius"]) for s in a["dependency"]["services"]), default=0)}


def compare(tool: dict, tool_ids: dict, oracle: dict, oracle_ids: dict) -> dict:
    tk, ok = keyed(tool["findings"], tool_ids), keyed(oracle["findings"], oracle_ids)
    T, O = set(tk), set(ok)
    rules = sorted({k[0] for k in T | O})
    per_rule = {r: prf(len({k for k in T & O if k[0] == r}), len({k for k in T - O if k[0] == r}),
                       len({k for k in O - T if k[0] == r})) for r in rules}
    matched = T & O
    same_sev = sum(1 for k in matched if tk[k]["severity"] == ok[k]["severity"])
    crit_o = {k for k in O if ok[k]["severity"] in ("critical", "high")}

    def pkeys(a, keys_by_id):
        return {(p["entry"], keys_by_id[p["finding_id"]]) for p in a["attack_paths"] if p["finding_id"] in keys_by_id}
    tid = {f["id"]: fkey(f, tool_ids) for f in tool["findings"]}
    oid = {f["id"]: fkey(f, oracle_ids) for f in oracle["findings"]}
    TP_, OP_ = pkeys(tool, tid), pkeys(oracle, oid)

    def top(keymap, n=10):
        return [k for k, _ in sorted(keymap.items(), key=lambda kv: (-kv[1]["best_apcr"], -kv[1]["score"], str(kv[0])))][:n]
    t10, o10 = top(tk), top(ok)

    def svc_risk(a):
        return {n["label"]: n.get("propagated_risk", 0) for n in a["graph"]["nodes"] if n["type"] == "API"}
    rt, ro = svc_risk(tool), svc_risk(oracle)
    common = sorted(set(rt) & set(ro))
    return {
        "findings": {**prf(len(matched), len(T - O), len(O - T)), "tool": len(T), "oracle": len(O),
                     "duplicate_tool_findings": len(tool["findings"]) - len(T),
                     "recall_critical_high": _r(len(crit_o & T) / len(crit_o)) if crit_o else None,
                     "severity_agreement": _r(same_sev / len(matched)) if matched else None,
                     "score_mae": _r(st.fmean(abs(tk[k]["score"] - ok[k]["score"]) for k in matched)) if matched else None},
        "per_rule": per_rule,
        "paths": {**prf(len(TP_ & OP_), len(TP_ - OP_), len(OP_ - TP_)), "tool": len(TP_), "oracle": len(OP_)},
        "risk": {"tool_R": tool["summary"]["total_path_risk"], "oracle_R": oracle["summary"]["total_path_risk"],
                 "ratio": _r(tool["summary"]["total_path_risk"] / oracle["summary"]["total_path_risk"])
                 if oracle["summary"]["total_path_risk"] else None,
                 "top10_overlap": _r(len(set(t10) & set(o10)) / max(1, min(10, len(o10)))),
                 "service_risk_spearman": spearman([rt[s] for s in common], [ro[s] for s in common]),
                 "fixes_70_tool": tool["mitigation_plan"]["fixes_for_70pct"],
                 "fixes_70_oracle": oracle["mitigation_plan"]["fixes_for_70pct"]},
        "missed": sorted(map(str, O - T))[:40], "extra": sorted(map(str, T - O))[:40],
    }


def known_vulns(testbed: str, analyses: dict[str, tuple[dict, dict]]) -> dict | None:
    """analyses: label -> (analysis, id->gt key)."""
    if testbed == "crapi":
        rows = []
        for cid, title, owasp, key, rules, needs in CRAPI_CHALLENGES:
            row = {"id": cid, "title": title, "owasp": owasp, "endpoint": f"{key[1]} {key[2]}", "rules": rules, "needs": needs}
            for label, (a, ids) in analyses.items():
                on_ep = {f["rule_id"] for f in a["findings"] if ids.get(f["target"]) == key}
                row[label] = ("out of scope" if cid in OUT_OF_SCOPE else "detected" if set(rules) & on_ep else
                              "flagged by another auth rule" if on_ep & AUTHZ_RULES else "not detected")
                row[label + "_rules"] = sorted(on_ep)
            rows.append(row)
        return {"challenges": rows}
    if testbed == "shoplite":
        out = {}
        for label, (a, ids) in analyses.items():
            got = {simple_target(fkey(f, ids)) for f in a["findings"]}
            planted = SHOPLITE_PLANTED
            out[label] = {**prf(len(got & planted), len(got - planted), len(planted - got) + len(SHOPLITE_UNCOVERED)),
                          "planted_found": len(got & planted), "planted": len(planted) + len(SHOPLITE_UNCOVERED),
                          "uncovered_by_rules": len(SHOPLITE_UNCOVERED),
                          "missed": sorted(map(str, planted - got)), "extra": sorted(map(str, got - planted))}
        return out
    return None


# --------------------------------------------------------------------------- one run
def evaluate_threat_run(testbed: str, run_dir: Path, c1_dir: Path | None = None, ablation: bool = True) -> dict:
    gt = ground_truth(testbed)
    t = time.perf_counter()
    tool_e = normalize(run_dir / "raw")
    t_norm = round((time.perf_counter() - t) * 1000, 1)
    content = normalize((c1_dir or run_dir) / "raw") if c1_dir and c1_dir != run_dir else tool_e
    tool_ids = tool_id_to_gt(tool_e, gt)
    tool_a, timing = run_analysis(tool_e)
    timing["phase2_normalize_ms"] = t_norm
    oracle_e, oracle_ids = build_oracle(testbed, run_dir, tool_e, content)
    oracle_a, otiming = run_analysis(oracle_e)
    out = {"testbed": testbed, "run": run_dir.name, "timing": timing, "oracle_timing": otiming,
           "graph": graph_stats(tool_a), "oracle_graph": graph_stats(oracle_a),
           "vs_oracle": compare(tool_a, tool_ids, oracle_a, oracle_ids),
           "known": known_vulns(testbed, {"tool": (tool_a, tool_ids), "oracle": (oracle_a, oracle_ids)}),
           "inventory": {"tool": tool_e["summary"]["inventory"], "oracle": oracle_e["summary"]["inventory"]}}
    if ablation:
        ok = set(keyed(oracle_a["findings"], oracle_ids))
        out["ablation"] = {}
        for combo in ABLATION:
            e = eujf_for(run_dir / "raw", combo) if combo != "OTKC" else tool_e
            fs, _ = run_rules(e)
            tk = set(keyed(fs, tool_id_to_gt(e, gt)))
            out["ablation"][combo] = prf(len(tk & ok), len(tk - ok), len(ok - tk))
    return out


def evaluate_hardened(run_dir: Path, vulnerable_dir: Path) -> dict:
    """ShopLite after the fixes: findings vs the two left on purpose, and the risk
    reduction actually achieved against the vulnerable build (same seed, same condition)."""
    gt = ground_truth("shoplite")
    e = normalize(run_dir / "raw")
    a, timing = run_analysis(e)
    ids = tool_id_to_gt(e, gt)
    got = {simple_target(fkey(f, ids)) for f in a["findings"]}
    ve = normalize(vulnerable_dir / "raw")
    va, _ = run_analysis(ve)
    # what the vulnerable run's own plan predicted for the fixes that hardening applied
    plan = va["mitigation_plan"]
    return {"run": run_dir.name, "findings": len(a["findings"]), "expected_left": len(SHOPLITE_HARDENED_EXPECTED),
            "match_expected": got == SHOPLITE_HARDENED_EXPECTED, "unexpected": sorted(map(str, got - SHOPLITE_HARDENED_EXPECTED)),
            "missing": sorted(map(str, SHOPLITE_HARDENED_EXPECTED - got)),
            # C2 leaves ~30% of services untraced on purpose: LT-02 / LT-03 there are true tracing gaps
            "unexpected_not_tracing_gaps": sorted(str(k) for k in got - SHOPLITE_HARDENED_EXPECTED
                                                  if k[0] not in ("LT-02", "LT-03")),
            "R_vulnerable": va["summary"]["total_path_risk"], "R_hardened": a["summary"]["total_path_risk"],
            "reduction_pct": round(100 * (1 - a["summary"]["total_path_risk"] / va["summary"]["total_path_risk"]), 1),
            "plan_steps": len(plan["steps"]), "plan_final_reduction_pct": plan["steps"][-1]["cumulative_reduction_pct"] if plan["steps"] else 0,
            "plan_fixes_for_70pct": plan["fixes_for_70pct"], "paths_vulnerable": len(va["attack_paths"]),
            "paths_hardened": len(a["attack_paths"]), "graph": graph_stats(a)}
