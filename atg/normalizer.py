"""
Phase 2 - API NORMALIZER  ->  Extended Universal JSON Format (EUJF)

Input : output/raw/{runtime_traffic,openapi,infrastructure,callchain}.json
Output: output/eujf.json  (schema "atg.eujf/v1")

What it does
  1. Builds one service list from all sources (manifests, traces, traffic, specs).
  2. Finds the edge gateway (the workload an Ingress points at) and folds its
     traffic into the backend endpoints using the gateway route table, so
     "GET /api/users/{int}" at the gateway and "GET /users/{user_id}" at
     user-service become ONE endpoint with a public path and a backend path.
  3. Joins every endpoint across spec / traffic / trace on
     (service, method, path shape), keeping provenance per source.
  4. Classifies each endpoint for the inventory:
        documented  in a spec and seen running
        shadow      seen running, in no spec
        zombie      deprecated in the spec but still called
        dormant     in a spec, never seen running
  5. Attaches infrastructure facts to each service (exposure, network policy,
     container flags, secrets) and the service-to-service dependencies.

Every merged fact keeps `sources`, because Phase 3 rules need to know *who*
says something (a spec saying "auth required" is not the same as traffic
proving it).
"""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from extractor.common import match_key, now_iso

SCHEMA = "atg.eujf/v1"
SENSITIVE_FORMATS = {"email": "pii", "phone": "pii", "card_number": "payment_card", "jwt": "credential"}
SENSITIVE_FIELD_NAMES = {
    r"pass(word)?|secret|api_?key|private_?key": "credential",
    r"card|pan|cvv|iban|account_?number": "payment_card",
    r"ssn|national_?id|passport|citizen": "government_id",
    r"amount|payment_?id|transaction|balance": "financial",
    r"email|phone|address|line1|zip|dob|birth": "pii",
}
OWNER_FIELDS = re.compile(r"^(user_?id|owner(_?id)?|account_?id|customer_?id|tenant_?id)$", re.I)


def _load(raw_dir: Path, name: str) -> dict | None:
    p = raw_dir / f"{name}.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def _recs(doc, kind):
    return [r for r in (doc or {}).get("records", []) if r.get("kind") == kind]


def _walk_shape(shape, prefix=""):
    """Yield (field_path, type_string) for every leaf of a body shape."""
    if isinstance(shape, dict):
        for k, v in shape.items():
            yield from _walk_shape(v, f"{prefix}{k}.")
    elif isinstance(shape, list):
        if shape:
            yield from _walk_shape(shape[0], prefix.rstrip(".") + "[].")
    elif shape is not None:
        yield prefix.rstrip("."), str(shape)


def classify_data(shape) -> dict:
    """Which kinds of sensitive data a body shape carries, with the fields."""
    out: dict[str, set] = defaultdict(set)
    for field, typ in _walk_shape(shape):
        leaf = field.split(".")[-1].replace("[]", "")
        for part in typ.split("|"):
            fmt = part.split(":", 1)[1] if ":" in part else ""
            if fmt in SENSITIVE_FORMATS:
                out[SENSITIVE_FORMATS[fmt]].add(field)
        for rx, cls in SENSITIVE_FIELD_NAMES.items():
            if re.search(rx, leaf, re.I):
                out[cls].add(field)
    return {k: sorted(v) for k, v in sorted(out.items())}


def _is_collection(shape) -> bool:
    if isinstance(shape, list):
        return True
    if isinstance(shape, dict):
        return any(isinstance(v, list) and v and isinstance(v[0], dict) for v in shape.values())
    return False


def _owner_fields(shape) -> list[str]:
    return sorted({f for f, _ in _walk_shape(shape) if OWNER_FIELDS.match(f.split(".")[-1].replace("[]", ""))})


def _merge_counts(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, v in b.items():
        out[k] = out.get(k, 0) + v
    return dict(sorted(out.items()))


def _segments_match(template: str, observed: str) -> int | None:
    """Score how well an observed (traffic) path fits a known template.
    None = no fit. Literal segments must be equal; a template {param} accepts
    anything. Higher score = more literal segments agree (more specific)."""
    t, o = template.strip("/").split("/"), observed.strip("/").split("/")
    if len(t) != len(o):
        return None
    score = 0
    for a, b in zip(t, o):
        if a.startswith("{"):
            continue
        if a != b:
            return None
        score += 1
    return score


def _to_backend(r: dict, public: str) -> str:
    """Path the upstream receives for a public path matched by route r."""
    rw = r.get("replace_with")
    if rw is not None:
        rest = public[len(r["match_prefix"]):]
        return rw.rstrip("/") + "/" + rest.lstrip("/") if rest else rw
    return public[len(r.get("strip_prefix") or ""):] or "/"


def _to_public(r: dict, backend: str) -> str | None:
    """Public path for a backend path through route r, or None if r cannot produce it."""
    rw = r.get("replace_with")
    if rw is not None:
        if backend == rw.rstrip("/") or backend == rw:
            return r["match_prefix"]
        base = rw.rstrip("/") + "/"
        if backend.startswith(base):
            return r["match_prefix"].rstrip("/") + "/" + backend[len(base):]
        return None
    public = (r.get("strip_prefix") or "") + backend
    return public if public.startswith(r["match_prefix"]) else None


def normalize(raw_dir: str | Path, reconcile: bool = True) -> dict:
    """reconcile=True enables contract reconciliation: traffic paths whose dynamic
    segments the regex templating could not recognise (dates, train numbers,
    names...) are matched against templates declared by OpenAPI specs or reported
    by trace spans (http.route) for the same service and method."""
    raw_dir = Path(raw_dir)
    rt, oa = _load(raw_dir, "runtime_traffic"), _load(raw_dir, "openapi")
    inf, cc = _load(raw_dir, "infrastructure"), _load(raw_dir, "callchain")
    manifest = json.loads((raw_dir / "manifest.json").read_text()) if (raw_dir / "manifest.json").exists() else {}

    workloads = {w["name"]: w for w in _recs(inf, "workload")}
    k8s_services = _recs(inf, "service")
    exposure = defaultdict(list)
    for e in _recs(inf, "exposure"):
        exposure[e["workload"]].append(e)
    routes = sorted(_recs(inf, "gateway_route"), key=lambda r: len(r["match_prefix"] or ""), reverse=True)
    ingresses = _recs(inf, "ingress")

    # ---- 1. the edge gateway ------------------------------------------------
    # A gateway named by its own route config (SCG, nginx) is the strongest signal.
    # Otherwise take the Ingress-exposed workload; if several are exposed, prefer
    # the one with the most ingress rules pointing at it.
    named = [r.get("gateway_service") for r in routes if r.get("gateway_service")]
    if named:
        gateway = max(sorted(set(named)), key=named.count)
    else:
        ing = Counter(e["workload"] for e in _recs(inf, "exposure")
                      if e["level"] == "internet" and e["via"] and e["via"][0].startswith("Ingress"))
        gateway = max(sorted(ing), key=ing.get) if ing else None

    # ---- 2. service list ----------------------------------------------------
    names = set(workloads) | {s["service"] for s in _recs(cc, "service")}
    names |= {e["service"] for e in _recs(rt, "endpoint") if ":" not in e["service"]}
    names |= {s["service"] for s in _recs(oa, "spec")}

    # ---- 3. endpoints -------------------------------------------------------
    endpoints: dict[tuple, dict] = {}

    def ep(service: str, method: str, path: str) -> dict:
        key = (service, match_key(method, path))
        e = endpoints.get(key)
        if e is None:
            e = endpoints[key] = {
                "id": f"ep:{service}:{method.upper()}:{re.sub(r'{[^}]*}', '{}', path)}",
                "service": service, "method": method.upper(), "path": path,
                "path_params": re.findall(r"{([^}]*)}", path), "query_params": set(),
                "sources": {},
            }
        # prefer real parameter names ({user_id}) over traffic guesses ({int})
        if re.search(r"{(?!int}|uuid}|hex}|id})[^}]+}", path):
            e["path"] = path
            e["path_params"] = re.findall(r"{([^}]*)}", path)
        return e

    for s in _recs(oa, "spec"):
        for o in s["operations"]:
            e = ep(s["service"], o["method"], o["path"])
            src = e["sources"].setdefault("spec", {"documents": [], "auth_declared": o["auth_declared"],
                                                   "deprecated": False, "request_fields": {}, "parameters": []})
            src["documents"].append({"origin": s["origin"], "location": s["location"], "api_version": s["api_version"]})
            # a live spec beats a stale file for the declared contract
            if s["origin"] == "live" or src["auth_declared"] == "none":
                src["auth_declared"] = o["auth_declared"]
            src["deprecated"] |= o["deprecated"]
            src["request_fields"].update((o.get("request_body") or {}).get("fields") or {})
            src["parameters"] = o["parameters"] or src["parameters"]
            e["query_params"] |= {p["name"] for p in o["parameters"] if p.get("in") == "query"}

    def route_for(path: str):
        return next((r for r in routes if path.startswith(r["match_prefix"])), None)

    # templates other sources vouch for, per (service, method)
    known_tpl: dict[tuple, set] = defaultdict(set)
    for s_ in _recs(oa, "spec"):
        for o in s_["operations"]:
            known_tpl[(s_["service"], o["method"].upper())].add(o["path"])
    for s_ in _recs(cc, "service"):
        for op in s_["served_operations"]:
            m_, _, p_ = op["operation"].partition(" ")
            if p_.startswith("/") and "**" not in p_ and "(no route)" not in p_:
                known_tpl[(s_["service"], m_.upper())].add(p_)
    stats_norm = {"reconciled": 0, "traffic_templates_in": 0}

    def fit(service: str, method: str, path: str) -> str:
        stats_norm["traffic_templates_in"] += 1
        if not reconcile:
            return path
        cands = known_tpl.get((service, method.upper()), set())
        if path in cands:
            return path
        best = None
        for c in cands:
            sc = _segments_match(c, path)
            if sc is not None and (best is None or sc > best[0]):
                best = (sc, c)
        if best and match_key(method, best[1]) != match_key(method, path):
            stats_norm["reconciled"] += 1
            return best[1]
        return path

    public_traffic: list[dict] = []
    gateway_own: list[dict] = []
    def served(t) -> bool:
        # only 404/405 answers = no handler exists (probing, removed routes)
        return not set(t["status_codes"]) <= {"404", "405", "None"}

    for t in _recs(rt, "endpoint"):
        if not served(t):
            continue
        if gateway and t["service"] == gateway:
            r = route_for(t["path_template"])
            (public_traffic if r else gateway_own).append(t)
            continue
        e = ep(t["service"], t["method"], fit(t["service"], t["method"], t["path_template"]))
        e["query_params"] |= set(t["query_params"])
        prev = e["sources"].get("traffic")
        cur = {
            "hits": t["hits"], "status_codes": t["status_codes"],
            "auth_seen": t["auth"]["authorization_header_seen"],
            "auth_missing": t["auth"]["authorization_header_missing"],
            "status_without_auth": t["auth"].get("status_codes_without_auth", {}),
            "schemes": t["auth"]["schemes"], "capture_points": t["capture_points"],
            "request_shape": t["request"]["body_shape"], "response_shape": t["response"]["body_shape"],
            "latency_p50_ms": t["latency_ms"]["p50"],
        }
        if prev:  # same endpoint captured under two templates ({int} and {id})
            for k in ("hits", "auth_seen", "auth_missing"):
                cur[k] += prev[k]
            cur["status_codes"] = _merge_counts(prev["status_codes"], cur["status_codes"])
            cur["status_without_auth"] = _merge_counts(prev["status_without_auth"], cur["status_without_auth"])
        e["sources"]["traffic"] = cur

    # gateway endpoints = the gateway's own handlers (not routes) are real endpoints too
    for t in gateway_own:
        e = ep(gateway, t["method"], fit(gateway, t["method"], t["path_template"]))
        e["sources"]["traffic"] = {
            "hits": t["hits"], "status_codes": t["status_codes"],
            "auth_seen": t["auth"]["authorization_header_seen"], "auth_missing": t["auth"]["authorization_header_missing"],
            "status_without_auth": t["auth"].get("status_codes_without_auth", {}),
            "schemes": t["auth"]["schemes"], "capture_points": t["capture_points"],
            "request_shape": t["request"]["body_shape"], "response_shape": t["response"]["body_shape"],
            "latency_p50_ms": t["latency_ms"]["p50"],
        }

    for s in _recs(cc, "service"):
        for op in s["served_operations"]:
            method, _, path = op["operation"].partition(" ")
            if not path.startswith("/"):
                continue
            # at the gateway, routed traffic ("/api/users/**") belongs to the backend
            # endpoint; only the gateway's own handlers count as gateway endpoints
            if "**" in path or "(no route)" in path or (s["service"] == gateway and path.startswith("/{")):
                continue
            e = ep(s["service"], method, path)
            tr = e["sources"].setdefault("trace", {"spans": 0, "errors": 0, "callers": []})
            tr["spans"] += op["count"]
            tr["errors"] += op["errors"]
    for edge in _recs(cc, "edge"):
        for op in edge["operations"]:
            method, _, path = op["operation"].partition(" ")
            key = (edge["to"], match_key(method, path))
            if key in endpoints and "trace" in endpoints[key]["sources"]:
                callers = endpoints[key]["sources"]["trace"]["callers"]
                if edge["from"] not in callers:
                    callers.append(edge["from"])
    for ent in _recs(cc, "entrypoint"):
        method, _, path = ent["operation"].partition(" ")
        key = (ent["service"], match_key(method, path))
        if key in endpoints and "trace" in endpoints[key]["sources"]:
            endpoints[key]["sources"]["trace"]["untraced_caller_traces"] = ent["traces"]

    # ---- 4. public exposure through gateway routes ---------------------------
    for e in endpoints.values():
        e["gateway_route"] = None
        e["public_paths"] = []
        if e["service"] == gateway:
            e["public_paths"] = [e["path"]]
            continue
        for r in routes:
            if r["upstream_service"] != e["service"]:
                continue
            public = _to_public(r, e["path"])
            if public:
                e["gateway_route"] = {"prefix": r["match_prefix"], "auth": r["auth"], "defined_in": r["defined_in"]}
                e["public_paths"].append(public)
                break

    # public traffic (north-south at the gateway) -> backend endpoint
    for t in public_traffic:
        r = route_for(t["path_template"])
        backend_path = fit(r["upstream_service"], t["method"], _to_backend(r, t["path_template"]))
        key = (r["upstream_service"], match_key(t["method"], backend_path))
        e = endpoints.get(key) or ep(r["upstream_service"], t["method"], backend_path)
        # seen only at the gateway (no east-west capture, no trace): new entry here
        e.setdefault("gateway_route", None)
        e.setdefault("public_paths", [])
        pub = e["sources"].setdefault("public_traffic", {"hits": 0, "status_codes": {}, "auth_missing": 0, "auth_seen": 0,
                                                         "status_without_auth": {}, "gateway_paths": [],
                                                         "request_shape": None, "response_shape": None})
        pub["hits"] += t["hits"]
        pub["auth_seen"] += t["auth"]["authorization_header_seen"]
        pub["request_shape"] = pub["request_shape"] or t["request"]["body_shape"]
        pub["response_shape"] = pub["response_shape"] or t["response"]["body_shape"]
        pub["auth_missing"] += t["auth"]["authorization_header_missing"]
        pub["status_codes"] = _merge_counts(pub["status_codes"], t["status_codes"])
        pub["status_without_auth"] = _merge_counts(pub["status_without_auth"], t["auth"].get("status_codes_without_auth", {}))
        pub["gateway_paths"].append(f'{t["method"]} {t["path_template"]}')
        if not e["gateway_route"]:
            e["gateway_route"] = {"prefix": r["match_prefix"], "auth": r["auth"], "defined_in": r["defined_in"]}
            e["public_paths"].append(t["path_template"])

    # ---- 5. classification + derived facts ----------------------------------
    for e in endpoints.values():
        s = e["sources"]
        spec, traffic, trace = s.get("spec"), s.get("traffic"), s.get("trace")
        observed = bool(traffic or trace or s.get("public_traffic"))
        if spec and spec["deprecated"] and observed:
            e["inventory_status"] = "zombie"
        elif spec and observed:
            e["inventory_status"] = "documented"
        elif observed:
            e["inventory_status"] = "shadow"
        else:
            e["inventory_status"] = "dormant"
        pub = s.get("public_traffic") or {}
        # bodies seen at the backend, else the same bodies seen at the gateway
        resp = (traffic or {}).get("response_shape") or pub.get("response_shape")
        e["data_classes"] = classify_data(resp)
        e["request_data_classes"] = classify_data((traffic or {}).get("request_shape") or pub.get("request_shape")
                                                  or (spec or {}).get("request_fields"))
        # status codes from both capture points (the same request may be in both: take the max)
        e["status_observed"] = {c: max((traffic or {}).get("status_codes", {}).get(c, 0), pub.get("status_codes", {}).get(c, 0))
                                for c in sorted(set((traffic or {}).get("status_codes", {})) | set(pub.get("status_codes", {})))}
        e["returns_collection"] = _is_collection(resp)
        e["owner_fields"] = _owner_fields(resp)
        e["object_id_in_path"] = bool(e["path_params"])
        e["query_params"] = sorted(e["query_params"])
        e["seen_in"] = sorted(k for k in s)
        # observed auth behaviour, from the strongest evidence available
        unauth_ok = sum(n for c, n in (traffic or {}).get("status_without_auth", {}).items() if c.startswith("2"))
        pub_unauth_ok = sum(n for c, n in (s.get("public_traffic") or {}).get("status_without_auth", {}).items() if c.startswith("2"))
        unauth_denied = sum(n for c, n in (traffic or {}).get("status_without_auth", {}).items() if c in ("401", "403"))
        # the same request can be captured twice (at the gateway and again at the
        # backend), so take the larger count instead of adding them up
        e["auth_observed"] = {
            "anonymous_success": max(unauth_ok, pub_unauth_ok),
            "anonymous_success_public": pub_unauth_ok,
            # the backend capture also holds the requests the gateway forwarded
            "anonymous_success_internal": max(0, unauth_ok - pub_unauth_ok),
            "anonymous_denied": unauth_denied + sum(
                n for c, n in (s.get("public_traffic") or {}).get("status_without_auth", {}).items() if c in ("401", "403")),
            "authenticated_calls": max((traffic or {}).get("auth_seen", 0), pub.get("auth_seen", 0)),
            "forbidden_seen": e["status_observed"].get("403", 0),
            "throttled_seen": e["status_observed"].get("429", 0),
        }
        e["auth_required"] = (
            "enforced" if e["auth_observed"]["anonymous_denied"] and not e["auth_observed"]["anonymous_success"]
            else "not_enforced" if e["auth_observed"]["anonymous_success"]
            else "declared" if spec and spec["auth_declared"] == "required"
            else "unknown")

    # ---- 6. services --------------------------------------------------------
    svc_spec = defaultdict(set)
    for s in _recs(oa, "spec"):
        svc_spec[s["service"]].add(s["origin"])
    secrets = {s["name"]: s for s in _recs(inf, "secret")}
    netpols = _recs(inf, "network_policy")
    services = []
    for name in sorted(names):
        w = workloads.get(name)
        levels = {x["level"] for x in exposure.get(name, [])}
        level = "internet" if "internet" in levels else "node" if "node" in levels else "internal" if w else "unknown"
        containers = (w or {}).get("containers", [])
        flags = {
            "privileged": any(c["security_context"].get("privileged") for c in containers),
            "root_not_prevented": any(c["security_context"].get("runAsUser") == 0 for c in containers)
            or (bool(containers) and not any(c["security_context"].get("runAsNonRoot") for c in containers)
                and not (w or {}).get("pod_security_context", {}).get("runAsNonRoot")),
            "explicit_root": any(c["security_context"].get("runAsUser") == 0 for c in containers),
            "mutable_tag": any(c["image_tag"].startswith("latest") for c in containers),
            "no_resource_limits": any(not c["resources"]["limits"] for c in containers),
            "host_network": bool((w or {}).get("host_network")),
        }
        plaintext = [ev["name"] for c in containers for ev in c["env"] if ev["source"] == "plaintext" and ev["sensitive_name"]]
        secret_refs = sorted({ev["ref"] for c in containers for ev in c["env"] if ev["source"] == "secretRef" and ev.get("ref")})
        allowed_from = None
        pols = [p for p in netpols if w and p["pod_selector"] and all(w["labels"].get(k) == v for k, v in p["pod_selector"].items())]
        if pols:
            allowed_from = sorted({v.get("app", json.dumps(v)) for p in pols for peer in p["ingress_from"]
                                   for v in [peer.get("podSelector") or {}] if v})
        services.append({
            "id": f"svc:{name}",
            "name": name,
            "role": "gateway" if name == gateway else "service",
            "in_manifests": bool(w),
            "image": containers[0]["image"] if containers else None,
            "exposure": {"level": level, "via": [" -> ".join(x["via"]) for x in exposure.get(name, []) if x["level"] != "internal"]},
            "node_port": any(x["level"] == "node" for x in exposure.get(name, [])),
            "spec": {"live": "live" in svc_spec[name], "file": "file" in svc_spec[name]},
            "network_policy": {"present": bool(pols), "allowed_from": allowed_from},
            "container_flags": flags,
            "plaintext_sensitive_env": plaintext,
            "secret_refs": secret_refs,
            "endpoint_ids": sorted(e["id"] for e in endpoints.values() if e["service"] == name),
        })

    deps = [{"from": d["from"], "to": d["to"], "calls": d["calls"],
             "operations": [o["operation"] for o in d["operations"]], "evidence": "trace"}
            for d in _recs(cc, "edge")]
    known = {(d["from"], d["to"]) for d in deps}
    for w in workloads.values():  # config-declared dependencies that never showed up in traces
        for c in w["containers"]:
            for ev in c["env"]:
                if ev.get("references_service") and (w["name"], ev["references_service"]) not in known:
                    deps.append({"from": w["name"], "to": ev["references_service"], "calls": 0,
                                 "operations": [], "evidence": f"config ({ev['name']})"})
                    known.add((w["name"], ev["references_service"]))
    for r in routes:
        if gateway and (gateway, r["upstream_service"]) not in known:
            deps.append({"from": gateway, "to": r["upstream_service"], "calls": 0, "operations": [],
                         "evidence": f"gateway route {r['match_prefix']}"})
            known.add((gateway, r["upstream_service"]))

    traced_gateway = gateway in {s_["service"] for s_ in _recs(cc, "service")}

    def _outside_gateway(x) -> bool:
        """A trace that starts at a backend means "the caller is not instrumented". It
        only also means "the call did not come through the gateway" when the gateway
        itself emits spans. With an untraced gateway, an endpoint that receives public
        traffic most likely had the gateway as its caller."""
        if x["service"] == gateway:
            return False
        if traced_gateway:
            return True
        m_, _, p_ = x["operation"].partition(" ")
        e_ = endpoints.get((x["service"], match_key(m_, p_)))
        return not (e_ and "public_traffic" in e_["sources"])

    eps = sorted(endpoints.values(), key=lambda e: (e["service"], e["path"], e["method"]))
    inv = defaultdict(int)
    for e in eps:
        inv[e["inventory_status"]] += 1
    return {
        "schema": SCHEMA,
        "run_id": manifest.get("run_id"),
        "target": manifest.get("target"),
        "generated_at": now_iso(),
        "raw_inputs": {k: {"sha256": v.get("sha256"), "records": v.get("records")} for k, v in manifest.get("sources", {}).items()},
        "gateway": gateway,
        "services": services,
        "endpoints": eps,
        "gateway_routes": [{k: r.get(k) for k in ("match_prefix", "upstream_service", "strip_prefix", "replace_with", "auth",
                                                 "gateway", "defined_in")}
                           for r in sorted(routes, key=lambda r: r["match_prefix"])],
        "dependencies": sorted(deps, key=lambda d: (d["from"], d["to"])),
        "ingress": [{k: i[k] for k in ("host", "path", "tls", "backend_service")} for i in ingresses],
        "secrets": [{"name": s["name"], "keys": s["keys"]} for s in secrets.values()],
        "trace_services": [{"service": s["service"], "spans": s["span_count"]} for s in _recs(cc, "service")],
        "entrypoints": [{"service": x["service"], "operation": x["operation"], "traces": x["traces"],
                         "from_outside_gateway": _outside_gateway(x)} for x in _recs(cc, "entrypoint")],
        "call_chains": [{"traces": c["traces"], "hops": c["hops"]} for c in _recs(cc, "call_chain")],
        "summary": {
            "services": len(services),
            "endpoints": len(eps),
            "inventory": dict(inv),
            "public_endpoints": sum(1 for e in eps if e["public_paths"]),
            "endpoints_with_sensitive_data": sum(1 for e in eps if e["data_classes"]),
            "dependencies": len(deps),
            "reconciled_traffic_paths": stats_norm["reconciled"],
        },
    }
