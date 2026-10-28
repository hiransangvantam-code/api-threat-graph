"""
Mine the API surface of Train Ticket (FudanSELab/train-ticket) from its source.

Produces bench/testbeds/trainticket/topology.yaml, the GROUND TRUTH for the
Train Ticket experiment. Nothing here uses the extractor under test.

  endpoints      Spring @RequestMapping / @Get|Post|Put|Delete|PatchMapping on
                 @RestController classes (Java services); Flask, Express,
                 Tornado and web.go routes for the 4 non-Java services
                 (transcribed from their single route file, see NON_JAVA)
  auth           Spring Security rules in each service's SecurityConfig
                 (antMatchers + permitAll/hasRole/hasAnyRole/authenticated,
                 first match wins, then anyRequest())
  calls          getServiceUrl("ts-x-service") + "/api/v1/..." call sites, mapped
                 to the controller endpoint whose service-layer method makes them
  documentation  services whose Application class has @EnableSwagger2 publish
                 /v2/api-docs (springfox is a parent-POM dependency)
  ports          server.port in application.yml

usage: python bench/miners/trainticket.py <path-to-train-ticket-checkout>
"""
from __future__ import annotations

import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "bench/testbeds/trainticket"

MAP_ANN = re.compile(r"@(Get|Post|Put|Delete|Patch|Request)Mapping\s*(\(([^)]*)\))?")
STR = re.compile(r'"([^"]*)"')
SVC_URL = re.compile(r'getServiceUrl\(\s*"(ts-[a-z0-9-]+)"\s*\)')
HTTP_LIT = re.compile(r'"http://(ts-[a-z0-9-]+)(?::\d+)?"')
METHOD_DEF = re.compile(r"\n\s*(?:public|private|protected)\s+[\w<>\[\], ?]+\s+(\w+)\s*\(")

# The four non-Java services have a single route file each; transcribed by hand.
NON_JAVA = {
    "ts-avatar-service": {"lang": "python/flask", "file": "app.py",
                          "endpoints": [("POST", "/api/v1/avatar")], "calls": []},
    "ts-ticket-office-service": {"lang": "node/express", "file": "bin/router.js",
                                 "endpoints": [("GET", "/office/"), ("GET", "/office/getRegionList"),
                                               ("GET", "/office/getAll"), ("POST", "/office/getSpecificOffices"),
                                               ("POST", "/office/addOffice"), ("POST", "/office/deleteOffice"),
                                               ("POST", "/office/updateOffice")], "calls": []},
    "ts-voucher-service": {"lang": "python/tornado", "file": "server.py",
                           "endpoints": [("POST", "/getVoucher")],
                           "calls": [("POST", "/getVoucher", "ts-order-service", "GET", "/api/v1/orderservice/order/{orderId}"),
                                     ("POST", "/getVoucher", "ts-order-other-service", "GET",
                                      "/api/v1/orderOtherService/orderOther/{orderId}")]},
    "ts-news-service": {"lang": "go/web.go", "file": "src/main/main.go",
                        "endpoints": [("GET", "/{path}")], "calls": []},
}
SKIP = {"ts-gateway-service", "ts-common", "ts-ui-dashboard"}


def norm(p: str) -> str:
    p = "/" + p.strip().strip("/")
    return re.sub(r"/+", "/", p) if p != "/" else "/"


def join(base: str, sub: str) -> str:
    return norm((base or "") + "/" + (sub or "")) if (base or sub) else "/"


def ann_paths(args: str | None) -> list[str]:
    if not args:
        return [""]
    lits = STR.findall(args.split("method")[0] if "method" in args else args)
    return lits or [""]


def ann_method(kind: str, args: str | None) -> list[str]:
    if kind != "Request":
        return [kind.upper()]
    m = re.findall(r"RequestMethod\.(\w+)", args or "")
    return m or ["GET"]


# ---------------------------------------------------------------- Spring Security
def security_rules(svc_dir: Path):
    rules, default = [], None
    for f in svc_dir.glob("src/main/java/**/*.java"):
        txt = f.read_text(encoding="utf-8", errors="ignore")
        if "authorizeRequests" not in txt:
            continue
        consts = dict(re.findall(r'String\s+(\w+)\s*=\s*"([^"]*)"', txt))
        body = txt[txt.index("authorizeRequests"):]
        for m in re.finditer(r"\.antMatchers\(([^)]*)\)\s*\.(permitAll|authenticated|hasRole|hasAnyRole|hasAuthority|hasAnyAuthority)\s*\(([^)]*)\)", body):
            args, action, roles = m.groups()
            meth = re.search(r"HttpMethod\.(\w+)", args)
            pats = []
            for tok in [a.strip() for a in args.split(",")]:
                if tok.startswith('"'):
                    pats.append(tok.strip('"'))
                elif tok in consts:
                    pats.append(consts[tok])
            for p in pats:
                rules.append({"method": meth.group(1) if meth else None, "pattern": p,
                              "auth": "none" if action == "permitAll" else "required",
                              "roles": re.findall(r'"([A-Z_]+)"', roles) + [consts[r] for r in re.findall(r"\b(\w+)\b", roles) if r in consts]})
        d = re.search(r"anyRequest\(\)\s*\.(permitAll|authenticated)", body)
        default = ("none" if d.group(1) == "permitAll" else "required") if d else "required"
    return rules, default


def ant_match(pattern: str, path: str) -> bool:
    rx = ""
    i = 0
    while i < len(pattern):
        if pattern.startswith("/**", i):
            rx += "(/.*)?"
            i += 3
        elif pattern.startswith("**", i):
            rx += ".*"
            i += 2
        elif pattern[i] == "*":
            rx += "[^/]*"
            i += 1
        else:
            rx += re.escape(pattern[i])
            i += 1
    concrete = re.sub(r"\{[^}]+\}", "x", path)
    return re.fullmatch(rx, concrete) is not None or re.fullmatch(rx, concrete.rstrip("/")) is not None


def auth_for(method, path, rules, default):
    if default is None:
        return "none", []
    for r in rules:
        if (r["method"] is None or r["method"] == method) and ant_match(r["pattern"], path):
            return r["auth"], r["roles"]
    return default, []


# ---------------------------------------------------------------- calls
def outbound_calls(svc_dir: Path):
    """[(java method name, target service, http method, path literal)]"""
    calls = []
    for f in svc_dir.glob("src/main/java/**/*.java"):
        txt = f.read_text(encoding="utf-8", errors="ignore")
        if "getServiceUrl" not in txt and "http://ts-" not in txt:
            continue
        starts = [(m.start(), m.group(1)) for m in METHOD_DEF.finditer(txt)]

        def enclosing(pos):
            name = None
            for s, n in starts:
                if s <= pos:
                    name = n
                else:
                    break
            return name

        for m in list(SVC_URL.finditer(txt)) + list(HTTP_LIT.finditer(txt)):
            target = m.group(1)
            if m.re is SVC_URL and txt[max(0, m.start() - 40):m.start()].rstrip().endswith("String getServiceUrl("):
                continue
            window = txt[m.end():m.end() + 700]
            lit = re.search(r'"(/api/v1/[^"]*)"', window)
            hm = re.search(r"HttpMethod\.(GET|POST|PUT|DELETE|PATCH)", window)
            calls.append((enclosing(m.start()), target, hm.group(1) if hm else "GET",
                          lit.group(1) if lit else None, f.name))
    return calls


def resolve_target(path_lit: str | None, method: str, target_eps: list[dict]):
    if not target_eps:
        return None
    if path_lit:
        lit = norm(path_lit)
        best = None
        for e in target_eps:
            pattern = re.sub(r"\{[^}]+\}", "[^/]+", e["path"])
            prefix_ok = e["path"].startswith(lit) or re.fullmatch(pattern, lit) or \
                re.sub(r"\{[^}]+\}.*$", "", e["path"]).rstrip("/") == lit.rstrip("/")
            if prefix_ok:
                score = (e["method"] == method, -len(e["path"]))
                if best is None or score > best[0]:
                    best = (score, e)
        if best:
            return best[1]
    same = [e for e in target_eps if e["method"] == method and "welcome" not in e["path"]]
    return (same or [e for e in target_eps if "welcome" not in e["path"]] or target_eps)[0]


# ---------------------------------------------------------------- main
def mine(repo: Path) -> dict:
    services = {}
    for d in sorted(repo.glob("ts-*-service")):
        name = d.name
        if name in SKIP:
            continue
        port = None
        appyml = d / "src/main/resources/application.yml"
        if appyml.exists():
            mp = re.search(r"server:\s*\n\s*port:\s*(\d+)", appyml.read_text(errors="ignore"))
            port = int(mp.group(1)) if mp else None
        if name in NON_JAVA:
            nj = NON_JAVA[name]
            eps = [{"method": m, "path": p, "auth": "none", "roles": [], "source": f"{name}/{nj['file']}",
                    "handler": None} for m, p in nj["endpoints"]]
            services[name] = {"name": name, "lang": nj["lang"], "port": port, "documented": False,
                              "endpoints": eps, "_raw_calls": nj["calls"]}
            continue
        rules, default = security_rules(d)
        eps = []
        handler_calls = {}
        for f in d.glob("src/main/java/**/*.java"):
            txt = f.read_text(encoding="utf-8", errors="ignore")
            if "@RestController" not in txt and "@Controller" not in txt:
                continue
            cls = re.search(r"\bclass\s+\w+", txt)
            head, body = txt[:cls.start()], txt[cls.start():]
            base = ""
            for m in MAP_ANN.finditer(head):
                if m.group(1) == "Request":
                    base = (ann_paths(m.group(3)) or [""])[0]
            for m in MAP_ANN.finditer(body):
                after = body[m.end():m.end() + 400]
                hm = re.search(r"public\s+[\w<>\[\], ?]+\s+(\w+)\s*\(", after)
                handler = hm.group(1) if hm else None
                # what the handler calls on the service layer: xxxService.method(
                hbody = after[:2000]
                svc_methods = re.findall(r"\w+[Ss]ervice\.(\w+)\(", body[m.end():m.end() + 1500].split("@")[0])
                for meth in ann_method(m.group(1), m.group(3)):
                    for p in ann_paths(m.group(3)):
                        path = join(base, p)
                        auth, roles = auth_for(meth, path, rules, default)
                        eps.append({"method": meth, "path": path, "auth": auth, "roles": roles,
                                    "source": str(f.relative_to(repo)), "handler": handler})
                        handler_calls[(meth, path)] = svc_methods
        seen, uniq = set(), []
        for e in eps:
            k = (e["method"], e["path"])
            if k not in seen:
                seen.add(k)
                uniq.append(e)
        documented = any("EnableSwagger2" in f.read_text(errors="ignore") for f in d.glob("src/main/java/**/*.java"))
        services[name] = {"name": name, "lang": "java/spring", "port": port, "documented": documented,
                          "endpoints": uniq, "_raw_calls": outbound_calls(d), "_handler_calls": handler_calls}

    # map outbound call sites onto endpoints
    for s in services.values():
        for e in s["endpoints"]:
            e["calls"] = []
        if s["lang"] != "java/spring":
            for (sm, sp, tgt, tm, tp) in s["_raw_calls"]:
                src = next(e for e in s["endpoints"] if e["method"] == sm and e["path"] == sp)
                t = resolve_target(tp, tm, services.get(tgt, {}).get("endpoints", []))
                if t:
                    src["calls"].append({"service": tgt, "method": t["method"], "path": t["path"]})
            continue
        unassigned = []
        for (jm, tgt, tm, tp, fname) in s["_raw_calls"]:
            if tgt == s["name"] or tgt not in services:
                continue
            t = resolve_target(tp, tm, services[tgt]["endpoints"])
            if not t:
                continue
            call = {"service": tgt, "method": t["method"], "path": t["path"]}
            owners = [e for e in s["endpoints"] if jm and jm in s["_handler_calls"].get((e["method"], e["path"]), [])]
            if owners:
                for o in owners:
                    if call not in o["calls"]:
                        o["calls"].append(call)
            else:
                unassigned.append(call)
        # calls whose service-layer method could not be tied to a handler: give each
        # to one non-trivial endpoint so the dependency still exists at runtime
        pool = [e for e in s["endpoints"] if "welcome" not in e["path"]] or s["endpoints"]
        for i, call in enumerate(unassigned):
            if pool and call not in sum((e["calls"] for e in s["endpoints"]), []):
                pool[i % len(pool)]["calls"].append(call)
                pool[i % len(pool)].setdefault("calls_assigned", "round-robin")
        del s["_handler_calls"]
    for s in services.values():
        s.pop("_raw_calls", None)
    return services


def gateway_routes(repo: Path) -> list[dict]:
    cfg = yaml.safe_load((repo / "ts-gateway-service/src/main/resources/application.yml").read_text())
    routes = []
    for r in cfg["spring"]["cloud"]["gateway"]["routes"]:
        uri = r["uri"]
        svc = re.search(r":(ts-[a-z0-9-]+)\}?$", uri) or re.search(r"lb://(ts-[a-z0-9-]+)", uri)
        for p in r.get("predicates", []):
            if p.startswith("Path="):
                for pat in p[5:].split(","):
                    routes.append({"id": r["id"], "path": pat.strip(), "service": svc.group(1)})
    return routes


def main():
    if len(sys.argv) < 2:
        sys.exit(f"usage: python bench/miners/trainticket.py PATH_TO_CHECKOUT  (see docs/EXPERIMENT.md for the commit)")
    repo = Path(sys.argv[1]).resolve()
    commit = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    services = mine(repo)
    routes = gateway_routes(repo)
    OUT.mkdir(parents=True, exist_ok=True)
    topo = {
        "name": "trainticket",
        "description": "API surface of FudanSELab Train Ticket, mined from source",
        "source": {"repo": "https://github.com/FudanSELab/train-ticket", "commit": commit},
        "documentation": "live-swagger",   # springfox /v2/api-docs on services with @EnableSwagger2
        "id_style": "uuid",
        "gateway": {"service": "ts-gateway-service", "kind": "spring-cloud-gateway",
                    "config": "gateway/application.yml", "routes": routes},
        "services": list(services.values()),
    }
    (OUT / "topology.yaml").write_text(yaml.safe_dump(topo, sort_keys=False, width=140), encoding="utf-8")
    # copy the real deployment artifacts the extractor will read
    (OUT / "k8s").mkdir(exist_ok=True)
    (OUT / "gateway").mkdir(exist_ok=True)
    src = repo / "deployment/kubernetes-manifests/quickstart-k8s/yamls"
    (OUT / "k8s/deploy.yaml").write_text((src / "deploy.yaml.sample").read_text())
    (OUT / "k8s/svc.yaml").write_text((src / "svc.yaml").read_text())
    (OUT / "gateway/application.yml").write_text((repo / "ts-gateway-service/src/main/resources/application.yml").read_text())
    n_ep = sum(len(s["endpoints"]) for s in services.values())
    n_calls = sum(len(e["calls"]) for s in services.values() for e in s["endpoints"])
    edges = {(s["name"], c["service"]) for s in services.values() for e in s["endpoints"] for c in e["calls"]}
    print(f"services={len(services)} endpoints={n_ep} call-sites={n_calls} service-edges={len(edges)} "
          f"documented-services={sum(s['documented'] for s in services.values())} routes={len(routes)} commit={commit[:10]}")


if __name__ == "__main__":
    main()
