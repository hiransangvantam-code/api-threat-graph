"""
Phase 3 - ANALYSIS & RISK ASSESSMENT

    EUJF ──► Rule engine ──► Vulnerability analyzer ──► Findings (severity, risk score, affected API)
      │                                   │
      └──► Dependency analyzer ──► Threat graph generation ──► graph store (PostgreSQL / SQLite)
                                                                   │
                                                     Attack path analysis (recursive SQL)
                                                                   │
                                          APCR per path, propagated risk per node, mitigation plan

Threat graph node types (the professor asked for these to be defined):

  Actor          Where an attack starts.
                   actor:internet   external attacker; can create an ordinary customer
                                    account (standard OWASP assumption), nothing more
                   actor:in-cluster code running in some pod (a compromised container
                                    or an unidentified internal job)
  API            One microservice that serves an API (id svc:<name>).
  Endpoint       One operation: service + method + path (id ep:...).
  Dependency     Something of value an API relies on or hands out:
                   data assets (customer PII, payment records), credentials
                   (Secrets, plaintext env secrets).
  Vulnerability  One finding from the rule engine (id vuln:F-001).
  Risk           A business consequence (data breach, fraud, account takeover...).

Edge types:
  reaches   Actor -> API / Endpoint   network reachability (Ingress, NodePort, no NetworkPolicy,
                                      or an observed call from an untraced caller)
  exposes   API -> Endpoint           the service serves this endpoint
  routes    API(gateway) -> Endpoint  a gateway route forwards a public path to it
  calls     Endpoint -> Endpoint      seen in a distributed trace call chain
  depends_on API -> API               service dependency (traces / config / routes)
  runs_on   Endpoint -> API           used only to reach service-level vulnerabilities
  handles   Endpoint -> Dependency    the endpoint returns this data asset
  uses      API -> Dependency         the service holds this credential
  has_vuln  Endpoint/API -> Vulnerability
  leads_to  Vulnerability -> Risk

Attack Path Contextual Risk (APCR), per path, 0-25 like L x I:
    APCR = L(finding) x I(finding) x entry_factor x 0.95^(chained calls)
    entry_factor = 1.0 for the internet actor, 0.5 for in-cluster (needs a foothold first)

Propagated risk, per node:
    propagated(n) = max(own(n), 0.85 x max(propagated(child)))   along reaches/exposes/routes/calls
  so a gateway inherits the risk of the worst thing it exposes, decayed per hop.
"""
from __future__ import annotations

import time
from collections import defaultdict

from .graphstore import GraphStore
from .rules import RISKS, RULES, Context

SEVERITY_BANDS = [(20, "critical"), (12, "high"), (6, "medium"), (0, "low")]
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
ENTRY_FACTOR = {"actor:internet": 1.0, "actor:in-cluster": 0.5}
DECAY = 0.85


def severity(score: float) -> str:
    return next(name for floor, name in SEVERITY_BANDS if score >= floor)


def _clamp(x: int) -> int:
    return max(1, min(5, x))


# ---------------------------------------------------------------------------
# Vulnerability analyzer: run rules, score, de-duplicate, number
# ---------------------------------------------------------------------------
def _target_exposure(ctx: Context, target: str) -> tuple[int, str] | None:
    if target.startswith("ep:"):
        e = next((x for x in ctx.endpoints if x["id"] == target), None)
        if not e:
            return None
        svc = ctx.services.get(e["service"], {})
        if e["public_paths"] or svc.get("node_port"):
            return +1, "reachable from the internet"
        return -1, "reachable only inside the cluster"
    svc = next((s for s in ctx.services.values() if s["id"] == target), None)
    if not svc:
        return None
    lvl = svc["exposure"]["level"]
    return {"internet": (+1, "service reachable from the internet"), "node": (0, "service reachable on cluster nodes"),
            "internal": (-1, "service reachable only inside the cluster")}.get(lvl)


def run_rules(eujf: dict) -> tuple[list[dict], dict]:
    ctx = Context(eujf)
    labels = {e["id"]: (f"{e['method']} {e['path']}", e["service"]) for e in eujf["endpoints"]}
    labels |= {s["id"]: (s["name"], s["name"]) for s in eujf["services"]}
    findings, timing = [], {}
    for r in RULES:
        t0 = time.perf_counter()
        for h in r.check(ctx) or []:
            L, I = r.likelihood, r.impact
            factors = [f"likelihood base {r.likelihood}", f"impact base {r.impact}"]
            adj = list(h.likelihood_adj)
            if r.exposure_sensitive:
                ex = _target_exposure(ctx, h.target)
                if ex and ex[0]:
                    adj.append(ex)
            for d, why in adj:
                L += d
                factors.append(f"likelihood {'+' if d >= 0 else ''}{d}: {why}")
            for d, why in h.impact_adj:
                I += d
                factors.append(f"impact {'+' if d >= 0 else ''}{d}: {why}")
            L, I = _clamp(L), _clamp(I)
            label, service = labels.get(h.target, (h.target, h.target.split(":")[1] if ":" in h.target else h.target))
            findings.append({
                "rule_id": r.id, "group": r.group, "title": r.title, "description": r.description,
                "detail": h.detail, "target": h.target, "target_kind": "endpoint" if h.target.startswith("ep:") else "service",
                "affected_api": label, "service": service,
                "likelihood": L, "impact": I, "score": L * I, "severity": severity(L * I), "factors": factors,
                "confidence": h.confidence, "evidence": h.evidence, "sources": h.sources,
                "risk": h.risk or r.risk, "owasp": r.owasp, "cwe": r.cwe, "attack": r.attack, "nist": r.nist,
                "recommendation": h.recommendation, "mitigation": r.mitigation, "snippet": r.snippet,
            })
        timing[r.id] = round((time.perf_counter() - t0) * 1000, 3)
    findings.sort(key=lambda f: (-f["score"], SEV_ORDER[f["severity"]], f["rule_id"], f["affected_api"]))
    for i, f in enumerate(findings, 1):
        f["id"] = f"F-{i:03d}"
    return findings, timing


# ---------------------------------------------------------------------------
# Dependency analyzer
# ---------------------------------------------------------------------------
def dependency_analysis(eujf: dict) -> dict:
    deps = eujf["dependencies"]
    out_edges, in_edges = defaultdict(set), defaultdict(set)
    for d in deps:
        out_edges[d["from"]].add(d["to"])
        in_edges[d["to"]].add(d["from"])

    def upstream(n, seen=None):
        seen = seen if seen is not None else set()
        for p in in_edges[n]:
            if p not in seen:
                seen.add(p)
                upstream(p, seen)
        return seen

    def downstream(n, seen=None):
        seen = seen if seen is not None else set()
        for c in out_edges[n]:
            if c not in seen:
                seen.add(c)
                downstream(c, seen)
        return seen

    services = sorted({s["name"] for s in eujf["services"]} | set(in_edges) | set(out_edges))
    rows = []
    for s in services:
        rows.append({"service": s, "calls": sorted(out_edges[s]), "called_by": sorted(in_edges[s]),
                     "fan_in": len(in_edges[s]), "fan_out": len(out_edges[s]),
                     # if s is compromised or down, these upstream services are affected
                     "blast_radius": sorted(upstream(s)), "reaches": sorted(downstream(s))})
    longest = max((len(c["hops"]) for c in eujf["call_chains"]), default=0)
    return {"services": rows, "edges": deps, "longest_chain": longest,
            "most_depended_on": max(rows, key=lambda r: r["fan_in"])["service"] if rows else None}


# ---------------------------------------------------------------------------
# Threat graph generation
# ---------------------------------------------------------------------------
DATA_ASSET_LABEL = {"pii": "Customer PII", "financial": "Payment / order records", "payment_card": "Card data",
                    "credential": "Credentials", "government_id": "Government IDs"}


def build_graph(eujf: dict, findings: list[dict]) -> tuple[list[dict], list[dict]]:
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    gateway = eujf.get("gateway")

    def node(nid, typ, label, **props):
        if nid not in nodes:
            nodes[nid] = {"id": nid, "type": typ, "label": label, "props": props}
        return nid

    def edge(src, dst, rel, **props):
        edges.append({"src": src, "dst": dst, "rel": rel, "props": props})

    node("actor:internet", "Actor", "Internet attacker", note="can register a normal customer account")
    node("actor:in-cluster", "Actor", "In-cluster caller", note="code running in some pod (foothold needed)")

    services = {s["name"]: s for s in eujf["services"]}
    for s in eujf["services"]:
        node(s["id"], "API", s["name"], role=s["role"], exposure=s["exposure"]["level"],
             network_policy=s["network_policy"]["present"])
        if s["role"] == "gateway" and s["exposure"]["level"] == "internet":
            edge("actor:internet", s["id"], "reaches", via="Ingress")
        if s["node_port"]:
            edge("actor:internet", s["id"], "reaches", via="NodePort")
        if s["in_manifests"] and not s["network_policy"]["present"]:
            edge("actor:in-cluster", s["id"], "reaches", via="no NetworkPolicy")
        for sec in s["secret_refs"]:
            node(f"dep:secret:{sec}", "Dependency", f"Secret {sec}", kind="credential")
            edge(s["id"], f"dep:secret:{sec}", "uses")
        for env in s["plaintext_sensitive_env"]:
            nid = node(f"dep:env:{s['name']}:{env}", "Dependency", f"{env} (plaintext)", kind="credential")
            edge(s["id"], nid, "uses")

    for e in eujf["endpoints"]:
        node(e["id"], "Endpoint", f"{e['method']} {e['path']}", service=e["service"],
             inventory=e["inventory_status"], public=e["public_paths"], auth=e["auth_required"],
             data=list(e["data_classes"]))
        svc = services.get(e["service"])
        if svc:
            edge(svc["id"], e["id"], "exposes")
            edge(e["id"], svc["id"], "runs_on")
        if e["gateway_route"] and gateway and e["service"] != gateway:
            edge(services[gateway]["id"], e["id"], "routes", prefix=e["gateway_route"]["prefix"],
                 auth=e["gateway_route"]["auth"])
        for cls in e["data_classes"]:
            nid = node(f"dep:data:{e['service']}:{cls}", "Dependency",
                       f"{DATA_ASSET_LABEL.get(cls, cls)} ({e['service']})", kind="data", data_class=cls)
            edge(e["id"], nid, "handles")

    for ent in eujf["entrypoints"]:
        if ent["from_outside_gateway"]:
            method, _, path = ent["operation"].partition(" ")
            ep = next((x for x in eujf["endpoints"] if x["service"] == ent["service"] and x["method"] == method
                       and x["path"] == path), None)
            if ep:
                edge("actor:in-cluster", ep["id"], "reaches", via="observed untraced caller", traces=ent["traces"])

    for d in eujf["dependencies"]:
        if d["from"] in services and d["to"] in services:
            edge(services[d["from"]]["id"], services[d["to"]]["id"], "depends_on", evidence=d["evidence"], calls=d["calls"])

    # endpoint -> endpoint calls from distinct trace chains (skip the gateway hop, it is a router)
    by_op = {(e["service"], f"{e['method']} {e['path']}"): e["id"] for e in eujf["endpoints"]}
    seen = set()
    for ch in eujf["call_chains"]:
        stack: dict[int, str] = {}
        for hop in ch["hops"]:
            eid = by_op.get((hop["service"], hop["operation"]))
            stack[hop["depth"]] = eid
            parent = stack.get(hop["depth"] - 1)
            if eid and parent and (parent, eid) not in seen:
                seen.add((parent, eid))
                edge(parent, eid, "calls", traces=ch["traces"])

    for key, (title, desc) in RISKS.items():
        node(f"risk:{key}", "Risk", title, description=desc)
    for f in findings:
        vid = node(f"vuln:{f['id']}", "Vulnerability", f"{f['id']} {f['title']}", finding=f["id"], rule=f["rule_id"],
                   severity=f["severity"], score=f["score"])
        nodes[vid]["own_risk"] = f["score"]
        edge(f["target"], vid, "has_vuln")
        edge(vid, f"risk:{f['risk']}", "leads_to")

    used = {e["src"] for e in edges} | {e["dst"] for e in edges}
    return [n for n in nodes.values() if n["id"] in used or n["type"] != "Risk"], edges


# ---------------------------------------------------------------------------
# Attack paths + risk propagation + mitigation plan
# ---------------------------------------------------------------------------
def score_paths(raw_paths, findings: list[dict], nodes: dict) -> list[dict]:
    by_vuln = {f"vuln:{f['id']}": f for f in findings}
    best: dict[tuple, dict] = {}
    for ids, rels in raw_paths:
        vuln = next((i for i in ids if i.startswith("vuln:")), None)
        f = by_vuln.get(vuln)
        if not f:
            continue
        chained = rels.count("calls")
        apcr = round(f["likelihood"] * f["impact"] * ENTRY_FACTOR.get(ids[0], 0.5) * (0.95 ** chained), 2)
        # one path per (entry actor, first hop, finding): the other variants only differ
        # in which sibling endpoint was used to reach a service-level weakness
        key = (ids[0], ids[1], f["id"])
        # highest APCR, then fewest hops, then the lexicographically first node list, so the
        # chosen variant does not depend on the order the database returns rows in
        cur = best.get(key)
        if cur is None or (-apcr, len(ids) - 1, ids) < (-cur["apcr"], cur["hops"], cur["nodes"]):
            best[key] = {"nodes": ids, "rels": rels, "finding_id": f["id"], "apcr": apcr, "severity": severity(apcr),
                         "entry": ids[0], "risk": ids[-1], "hops": len(ids) - 1,
                         "labels": [nodes[i]["label"] if i in nodes else i for i in ids]}
    paths = sorted(best.values(), key=lambda p: (-p["apcr"], p["hops"], p["finding_id"], p["nodes"]))  # deterministic on any DB
    for i, p in enumerate(paths, 1):
        p["id"] = f"P-{i:03d}"
    return paths


def propagate(nodes: dict, edges: list[dict], findings: list[dict]) -> dict[str, tuple[float, float]]:
    own = defaultdict(float)
    for e in edges:
        if e["rel"] == "has_vuln":
            own[e["src"]] = max(own[e["src"]], nodes[e["dst"]].get("own_risk", 0))
    children = defaultdict(list)
    for e in edges:
        if e["rel"] in ("reaches", "exposes", "routes", "calls"):
            children[e["src"]].append(e["dst"])
    prop = {n: own[n] for n in nodes}
    for _ in range(len(nodes)):
        changed = False
        for n in nodes:
            best = max((prop[c] for c in children[n]), default=0) * DECAY
            v = round(max(own[n], best), 2)
            if v > prop[n] + 1e-9:
                prop[n] = v
                changed = True
        if not changed:
            break
    return {n: (round(own[n], 2), prop[n]) for n in nodes}


# One fix often resolves several findings: adding authentication + an admin check
# to /admin/transactions closes TS-01, API5 and API3 on that endpoint at once.
# The plan therefore works on remediation ACTIONS, not single findings.
ACTION_OF_RULE = {
    "TS-01": "authz", "TS-03": "authz", "TS-08": "authz", "API5": "authz", "API3": "authz",
    "API1": "ownership",
    "API8-PRIV": "harden", "API8-ROOT": "harden", "API8-TAG": "harden", "API4": "harden",
    "TS-04": "secrets", "API8-NODEPORT": "clusterip", "API8-NETPOL": "netpol",
    "API9-SHADOW": "inventory", "API9-ZOMBIE": "inventory", "API9-NOSPEC": "inventory",
}
ACTION_TITLE = {
    "authz": "Enforce authentication and role checks on {t}",
    "ownership": "Add an object ownership check to {t}",
    "harden": "Harden the {t} container (non-root, unprivileged, limits, pinned image)",
    "secrets": "Move plaintext secrets of {t} into a Secret and rotate them",
    "clusterip": "Stop exposing {t} on node ports (ClusterIP only)",
    "netpol": "Add a NetworkPolicy for {t}",
    "inventory": "Document or remove {t}",
}
# fixes that also cut network edges, so they close paths to OTHER findings too
EDGE_CUT = {"clusterip": "actor:internet", "netpol": "actor:in-cluster"}


def assign_actions(findings: list[dict]) -> list[dict]:
    actions: dict[str, dict] = {}
    for f in findings:
        kind = ACTION_OF_RULE.get(f["rule_id"], f["rule_id"].lower())
        key = f"{kind}:{f['target']}"
        if kind not in ACTION_TITLE:
            title = f["recommendation"]
        else:
            title = ACTION_TITLE[kind].format(t=f["affected_api"] if f["target_kind"] == "service"
                                              else f"{f['affected_api']} ({f['service']})")
        a = actions.setdefault(key, {"id": key, "kind": kind, "target": f["target"], "title": title,
                                     "finding_ids": [], "rules": [], "mitigation": []})
        a["finding_ids"].append(f["id"])
        a["rules"].append(f["rule_id"])
        a["mitigation"] += [m for m in f["mitigation"] if m not in a["mitigation"]]
        f["action"] = key
    return list(actions.values())


def mitigation_plan(findings: list[dict], paths: list[dict]) -> dict:
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


def analyze(eujf: dict, store: GraphStore) -> dict:
    timing = {}
    t = time.perf_counter()
    findings, rule_timing = run_rules(eujf)
    timing["rule_engine_ms"] = round((time.perf_counter() - t) * 1000, 2)

    t = time.perf_counter()
    deps = dependency_analysis(eujf)
    timing["dependency_analyzer_ms"] = round((time.perf_counter() - t) * 1000, 2)

    t = time.perf_counter()
    nodes_list, edges = build_graph(eujf, findings)
    nodes = {n["id"]: n for n in nodes_list}
    store.save_graph(eujf["run_id"], eujf["target"], eujf["generated_at"], nodes_list, edges)
    timing["threat_graph_ms"] = round((time.perf_counter() - t) * 1000, 2)

    t = time.perf_counter()
    raw = store.attack_paths(eujf["run_id"])
    paths = score_paths(raw, findings, nodes)
    timing["attack_path_query_ms"] = round((time.perf_counter() - t) * 1000, 2)

    t = time.perf_counter()
    risks = propagate(nodes, edges, findings)
    for nid, (o, p) in risks.items():
        nodes[nid]["own_risk"], nodes[nid]["propagated_risk"] = o, p
    store.update_risk(eujf["run_id"], risks)
    timing["risk_propagation_ms"] = round((time.perf_counter() - t) * 1000, 2)
    t = time.perf_counter()
    plan = mitigation_plan(findings, paths)
    timing["mitigation_plan_ms"] = round((time.perf_counter() - t) * 1000, 2)

    for f in findings:
        mine = [p for p in paths if p["finding_id"] == f["id"]]
        f["attack_paths"] = len(mine)
        f["best_apcr"] = max((p["apcr"] for p in mine), default=0)

    sev = defaultdict(int)
    for f in findings:
        sev[f["severity"]] += 1
    summary = {
        "findings": len(findings),
        "by_severity": {k: sev.get(k, 0) for k in ("critical", "high", "medium", "low")},
        "attack_paths": len(paths),
        "critical_paths": sum(1 for p in paths if p["severity"] in ("critical", "high")),
        "total_path_risk": plan["total_path_risk"],
        "endpoints": eujf["summary"]["endpoints"],
        "shadow_endpoints": eujf["summary"]["inventory"].get("shadow", 0),
        "services": eujf["summary"]["services"],
        "rules_evaluated": len(RULES),
        "rules_fired": len({f["rule_id"] for f in findings}),
    }
    store.save_results(eujf["run_id"], findings, paths, summary)
    return {
        "schema": "atg.analysis/v1", "run_id": eujf["run_id"], "target": eujf["target"],
        "store": store.label, "summary": summary, "findings": findings, "attack_paths": paths,
        "mitigation_plan": plan, "dependency": deps,
        "graph": {"nodes": list(nodes.values()), "edges": edges},
        "timing": timing, "rule_timing_ms": rule_timing,
    }
