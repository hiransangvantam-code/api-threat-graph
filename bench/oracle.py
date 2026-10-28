"""
Oracle threat model: the EUJF a perfect Phase 1 + Phase 2 would have produced for
one experiment run, built from ground truth instead of from the extractors.

Phase 3 (rules, threat graph, attack paths, APCR, mitigation plan) is then run on
this oracle EUJF with exactly the same code as on the tool's EUJF. Any difference
between the two analyses therefore comes from discovery and normalization (what
the tool saw and inferred), not from the rules themselves.

What the oracle takes from where:

  endpoints          topology.yaml (every documented endpoint, plus every endpoint
                     that served a request in this run according to its access log)
  traffic, auth      the services' own access logs (gt/*.jsonl): every request once,
                     with the real caller, the real status and whether a credential
                     was sent
  traces             which services were instrumented in this run (run.json) and who
                     really called whom (caller field of the access logs)
  dependencies       call edges that carried traffic in this run, gateway routes
  deployment config  services, routes, ingress, secrets: from the manifests, i.e. the
                     tool's own parse of them (identical in every condition)
  response content   data classes, owner fields, collections, query parameters and
                     request fields: from the C1 capture of the same seed, because the
                     topology files do not describe response bodies. For the replicas
                     these are empty by construction (generic responses).
"""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from bench.common import load_topology, public_path, shape
from bench.evaluate import ground_truth, match

AUTH_STATUSES = ("401", "403")


def _id(service: str, method: str, path: str) -> str:
    return f"ep:{service}:{method.upper()}:{re.sub(r'{[^}]*}', '{}', path)}"


def _rx(path: str) -> re.Pattern:
    return re.compile("^" + re.sub(r"\\\{[^}]*\\\}", "[^/]+", re.escape(path.rstrip("/") or "/")) + "/?$")


def tool_entry_map(eujf: dict, gt: dict) -> dict:
    """GT key -> best matching tool endpoint entry (same service preferred)."""
    pairs, _, _ = match(eujf, gt)
    best = {}
    for e, g in pairs:
        cur = best.get(g["key"])
        if cur is None or (e["service"] == g["service"] and cur["service"] != g["service"]):
            best[g["key"]] = e
    return best


def tool_id_to_gt(eujf: dict, gt: dict) -> dict:
    """tool endpoint id -> GT key (for mapping findings)."""
    pairs, _, _ = match(eujf, gt)
    out = {}
    for e, g in pairs:
        if e["id"] not in out or g["service"] == e["service"]:
            out[e["id"]] = g["key"]
    return out


def _access_log(gt: dict, run_dir: Path) -> dict:
    """GT key -> list of request records (each request counted once, where it was served)."""
    topo = gt["topology"]
    gw = gt["gateway"]
    by_key = {e["key"]: e for e in gt["endpoints"]}
    public_rx = [(e["method"], _rx(public_path(topo, e["path"], e["service"]) or e["path"]), e["key"])
                 for e in gt["endpoints"] if e["public"] and e["service"] != gw]
    recs = defaultdict(list)
    for f in sorted((run_dir / "gt").glob("*.jsonl")):
        for line in f.read_text(encoding="utf-8").splitlines():
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if r.get("ua", "").startswith("atg-") or r["route"] in ("(no route)", "/v2/api-docs"):
                continue
            key = (r["service"], r["method"], shape(r["route"]))
            if key in by_key:
                if r["status"] != 404:
                    recs[key].append(r)
            elif r["service"] == gw and r.get("denied_here"):
                # rejected by the gateway itself: the backend never saw it
                k = next((k for m, rx, k in public_rx if m == r["method"] and rx.match(r["path"])), None)
                if k:
                    recs[k].append({**r, "caller": gw, "at_gateway": True})
    return recs


def build(testbed: str, run_dir: Path, tool_eujf: dict, content_eujf: dict | None = None) -> tuple[dict, dict]:
    """Return (oracle EUJF, oracle endpoint id -> GT key)."""
    gt = ground_truth(testbed)
    topo = gt["topology"]
    gw = gt["gateway"]
    run = json.loads((run_dir / "run.json").read_text()) if (run_dir / "run.json").exists() else {}
    untraced = set(run.get("untraced") or [])
    if topo["gateway"].get("uninstrumented"):
        untraced.add(gw)
    traced = lambda s: s not in untraced  # noqa: E731
    recs = _access_log(gt, run_dir)
    content = tool_entry_map(content_eujf or tool_eujf, gt)
    spec_src = tool_entry_map(tool_eujf, gt)
    routes = tool_eujf.get("gateway_routes", [])
    live_doc = topo.get("documentation") == "live-swagger"

    endpoints, id2key = [], {}
    for g in gt["endpoints"]:
        rs = recs.get(g["key"], [])
        exercised = bool(rs)
        if not (g["documented"] or exercised):
            continue  # undocumented and never called: invisible to any passive method
        eid = _id(g["service"], g["method"], g["path"])
        id2key[eid] = g["key"]
        c = content.get(g["key"]) or {}
        sources = {}
        if g["documented"]:
            s = (spec_src.get(g["key"]) or c).get("sources", {}).get("spec")
            sources["spec"] = dict(s) if s else {"documents": [{"origin": "live" if live_doc else "file",
                                                                 "location": "spec", "api_version": "?"}],
                                                  "auth_declared": "none", "deprecated": False,
                                                  "request_fields": {}, "parameters": []}
            sources["spec"]["deprecated"] = g["deprecated"]
        codes = Counter(str(r["status"]) for r in rs)
        anon = [r for r in rs if not r["auth"]]
        anon_codes = Counter(str(r["status"]) for r in anon)
        ct = (c.get("sources", {}).get("traffic") or {})
        if exercised:
            sources["traffic"] = {
                "hits": len(rs), "status_codes": dict(codes), "auth_seen": len(rs) - len(anon),
                "auth_missing": len(anon), "status_without_auth": dict(anon_codes),
                "schemes": ["Bearer"] if len(rs) > len(anon) else [], "capture_points": ["oracle"],
                "request_shape": ct.get("request_shape"), "response_shape": ct.get("response_shape"),
                "latency_p50_ms": None}
        pub = [r for r in rs if r.get("caller") == gw and g["service"] != gw]
        if pub:
            pa = [r for r in pub if not r["auth"]]
            sources["public_traffic"] = {"hits": len(pub), "status_codes": dict(Counter(str(r["status"]) for r in pub)),
                                         "auth_missing": len(pa),
                                         "status_without_auth": dict(Counter(str(r["status"]) for r in pa)),
                                         "gateway_paths": []}
        served = [r for r in rs if not r.get("at_gateway")]
        if served and traced(g["service"]):
            callers = sorted({r["caller"] for r in served if r.get("caller") and r["caller"] != gw})
            sources["trace"] = {"spans": len(served), "errors": 0, "callers": callers}
        anon_ok = sum(1 for r in anon if 200 <= r["status"] < 300)
        anon_ok_pub = sum(1 for r in anon if 200 <= r["status"] < 300 and r.get("caller") == gw)
        anon_denied = sum(1 for r in anon if str(r["status"]) in AUTH_STATUSES)
        ao = {"anonymous_success": anon_ok, "anonymous_success_public": anon_ok_pub,
              "anonymous_success_internal": anon_ok - anon_ok_pub, "anonymous_denied": anon_denied,
              "authenticated_calls": len(rs) - len(anon), "forbidden_seen": codes.get("403", 0),
              "throttled_seen": codes.get("429", 0)}
        spec = sources.get("spec")
        auth_required = ("enforced" if anon_denied and not anon_ok else "not_enforced" if anon_ok
                         else "declared" if spec and spec.get("auth_declared") == "required" else "unknown")
        if g["deprecated"] and exercised:
            status = "zombie"
        elif g["documented"]:
            status = "documented" if exercised else "dormant"
        else:
            status = "shadow"
        pp = (g["path"] if g["service"] == gw else public_path(topo, g["path"], g["service"])) if g["public"] else None
        groute = None
        if pp and g["service"] != gw:
            r = next((r for r in sorted(routes, key=lambda r: -len(r["match_prefix"] or ""))
                      if r["upstream_service"] == g["service"] and pp.startswith(r["match_prefix"] or "")), None)
            if r:
                groute = {"prefix": r["match_prefix"], "auth": r["auth"], "defined_in": r["defined_in"]}
        endpoints.append({
            "id": eid, "service": g["service"], "method": g["method"], "path": g["path"],
            "path_params": re.findall(r"{([^}]*)}", g["path"]), "object_id_in_path": "{" in g["path"],
            "query_params": c.get("query_params", []), "sources": sources,
            "inventory_status": status, "public_paths": [pp] if pp else [], "gateway_route": groute,
            "auth_observed": ao, "auth_required": auth_required,
            "data_classes": c.get("data_classes", {}), "request_data_classes": c.get("request_data_classes", {}),
            "returns_collection": c.get("returns_collection", False), "owner_fields": c.get("owner_fields", []),
            "seen_in": sorted(sources)})

    # dependencies that carried traffic, plus gateway routes
    called = Counter()
    for key, rs in recs.items():
        for r in rs:
            if r.get("caller") and r["caller"] != key[0] and not r.get("at_gateway"):
                called[(r["caller"], key[0])] += 1
    deps = [{"from": a, "to": b, "calls": n, "operations": [],
             "evidence": "trace" if traced(a) and traced(b) else "observed"} for (a, b), n in sorted(called.items())]
    known = set(called)
    for r in topo["gateway"]["routes"]:
        if (gw, r["service"]) not in known:
            deps.append({"from": gw, "to": r["service"], "calls": 0, "operations": [], "evidence": f"gateway route {r['path']}"})
            known.add((gw, r["service"]))

    # unidentified callers: calls that did not come through the gateway and whose
    # caller emits no traces (in-cluster jobs, uninstrumented services)
    entry = Counter()
    for key, rs in recs.items():
        for r in rs:
            c_ = r.get("caller")
            if key[0] == gw:  # the gateway's own handlers are called from outside
                continue
            if not r.get("at_gateway") and c_ != gw and (c_ is None or not traced(c_)):
                entry[key] += 1
    by_key = {e["key"]: e for e in gt["endpoints"]}
    entrypoints = [{"service": k[0], "operation": f"{by_key[k]['method']} {by_key[k]['path']}", "traces": n,
                    "from_outside_gateway": True} for k, n in sorted(entry.items()) if any(id2key[i] == k for i in id2key)]

    # endpoint -> endpoint calls (mined call sites whose both ends served traffic)
    chains = []
    ex = {k for k, rs in recs.items() if rs}
    for s in topo["services"]:
        for e in s["endpoints"]:
            k = (s["name"], e["method"], shape(e["path"]))
            if k not in ex:
                continue
            for c in e.get("calls", []):
                ck = (c["service"], c["method"], shape(c["path"]))
                if ck in ex and (s["name"], c["service"]) in called:
                    chains.append({"traces": 1, "hops": [
                        {"depth": 0, "service": s["name"], "operation": f"{e['method']} {e['path']}"},
                        {"depth": 1, "service": c["service"], "operation": f"{by_key[ck]['method']} {by_key[ck]['path']}"}]})

    names = {s["name"] for s in topo["services"]} | {gw}
    services = []
    for s in tool_eujf["services"]:
        # every workload the manifests deploy is real, API or not (e.g. a web UI)
        if s["name"] not in names and not s.get("in_manifests"):
            continue
        s = json.loads(json.dumps(s))
        doc = next((x for x in topo["services"] if x["name"] == s["name"]), {})
        if live_doc:
            s["spec"]["live"] = doc.get("documented") is True
        s["role"] = "gateway" if s["name"] == gw else "service"
        s["endpoint_ids"] = sorted(e["id"] for e in endpoints if e["service"] == s["name"])
        services.append(s)

    inv = Counter(e["inventory_status"] for e in endpoints)
    trace_services = sorted({e["service"] for e in endpoints if "trace" in e["sources"]} |
                            {d["from"] for d in deps if d["evidence"] == "trace"})
    oracle = {
        "schema": "atg.eujf/v1", "run_id": f"oracle-{run_dir.name}", "target": f"{topo['name']} (oracle)",
        "generated_at": "oracle", "raw_inputs": {}, "gateway": gw, "services": services, "endpoints": endpoints,
        "gateway_routes": routes, "dependencies": deps, "ingress": tool_eujf.get("ingress", []),
        "secrets": tool_eujf.get("secrets", []),
        "trace_services": [{"service": s, "spans": 1} for s in trace_services],
        "entrypoints": entrypoints, "call_chains": chains,
        "summary": {"services": len(services), "endpoints": len(endpoints), "inventory": dict(inv),
                    "public_endpoints": sum(1 for e in endpoints if e["public_paths"]),
                    "endpoints_with_sensitive_data": sum(1 for e in endpoints if e["data_classes"]),
                    "dependencies": len(deps), "reconciled_traffic_paths": 0},
    }
    return oracle, id2key
