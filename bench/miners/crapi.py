"""
Mine the API surface of OWASP crAPI from its source.

Produces bench/testbeds/crapi/topology.yaml (GROUND TRUTH) and copies the real
deployment artifacts (k8s/base manifests, nginx gateway template, published
OpenAPI document). Nothing here uses the extractor under test.

  identity   Java / Spring  controllers + WebSecurityConfig requestMatchers
  community  Go / gorilla   routes.go HandleFunc(...).Methods(...); auth = wrapped in
                            SetMiddlewareAuthentication; that middleware calls
                            identity POST /identity/api/auth/verify
  workshop   Python/Django  urls.py tree (include / path / re_path) + view classes
                            (ast): HTTP methods and @jwt_auth_required; authenticated
                            views call identity verify; shop orders call the payment
                            gateway (gateway-service /v1/payment)
  chatbot    Python/Flask   blueprint routes
  gateway-service  Go       net/http HandleFunc; Basic auth

documented = the operation appears in crAPI's own published spec
(openapi-spec/crapi-openapi-spec.json). Differences between spec and source are
REAL documentation drift in crAPI, not something we injected.

usage: python bench/miners/crapi.py <path-to-crAPI-checkout>
"""
from __future__ import annotations

import ast
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from trainticket import MAP_ANN, ann_method, ann_paths, join, norm  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "bench/testbeds/crapi"
VERIFY = {"service": "crapi-identity", "method": "POST", "path": "/identity/api/auth/verify"}
PAYMENT = {"service": "gateway-service", "method": "POST", "path": "/v1/payment"}
OWNERSHIP = {"service": "gateway-service", "method": "GET", "path": "/v1/vin/ownership"}


def ant_match(pattern, path):
    rx = re.escape(pattern).replace(r"/\*\*", "(/.*)?").replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
    return re.fullmatch(rx, re.sub(r"\{[^}]+\}", "x", path)) is not None


# ---------------------------------------------------------------- identity (Java)
def identity(svc: Path) -> list[dict]:
    sec = (svc / "src/main/java/com/crapi/config/WebSecurityConfig.java").read_text()
    rules = [(m.group(1), m.group(2)) for m in re.finditer(
        r'\.requestMatchers\(\s*"([^"]+)"\s*\)\s*\.(permitAll|authenticated|hasRole|hasAnyRole|hasAuthority)', sec)]
    default = "required" if re.search(r"anyRequest\(\)\s*\.authenticated", sec) else "none"
    eps = []
    for f in sorted(svc.glob("src/main/java/com/crapi/controller/*.java")):
        txt = f.read_text()
        cls = re.search(r"\bclass\s+\w+", txt)
        base = ""
        for m in MAP_ANN.finditer(txt[:cls.start()]):
            if m.group(1) == "Request":
                base = ann_paths(m.group(3))[0]
        for m in MAP_ANN.finditer(txt[cls.start():]):
            for meth in ann_method(m.group(1), m.group(3)):
                for p in ann_paths(m.group(3)):
                    path = join(base, p)
                    auth = next(("none" if a == "permitAll" else "required" for pat, a in rules if ant_match(pat, path)), default)
                    calls = [OWNERSHIP] if "add_vehicle" in path else []
                    eps.append({"method": meth, "path": path, "auth": auth, "source": str(f.name), "calls": calls})
    return eps


# ---------------------------------------------------------------- community (Go)
def community(svc: Path) -> list[dict]:
    eps = []
    txt = (svc / "api/router/routes.go").read_text()
    for m in re.finditer(r'HandleFunc\("([^"]+)",\s*(.*?)\)\.Methods\(([^)]*)\)', txt):
        path, handler, methods = m.groups()
        auth = "required" if "SetMiddlewareAuthentication" in handler else "none"
        for meth in re.findall(r'"([A-Z]+)"', methods):
            if meth == "OPTIONS":
                continue
            eps.append({"method": meth, "path": norm(path), "auth": auth, "source": "api/router/routes.go",
                        "calls": [VERIFY] if auth == "required" else []})
    return eps


# ---------------------------------------------------------------- workshop (Django)
def _regex_to_template(rx: str) -> str:
    rx = rx.lstrip("^").rstrip("$")
    rx = re.sub(r"\(\?P<(\w+)>[^)]*\)", r"{\1}", rx)
    return rx


def _django_patterns(urls_file: Path, prefix: str, root: Path, out: list):
    tree = ast.parse(urls_file.read_text())
    imports = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imports[a.asname or a.name] = a.name
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "urlpatterns" for t in node.targets)):
            continue
        for call in node.value.elts:
            fn = getattr(call.func, "id", getattr(call.func, "attr", ""))
            route = call.args[0].value if isinstance(call.args[0], ast.Constant) else ""
            target = call.args[1]
            tmpl = route if fn == "path" else _regex_to_template(route)
            tmpl = re.sub(r"<(?:\w+:)?(\w+)>", r"{\1}", tmpl)
            if isinstance(target, ast.Call) and getattr(target.func, "id", "") == "include":
                mod = target.args[0].value
                f = root / (mod.replace(".", "/") + ".py")
                if f.exists():
                    _django_patterns(f, prefix + tmpl, root, out)
                else:  # third-party app (health_check): one endpoint
                    out.append((prefix + tmpl, None, None))
            elif isinstance(target, ast.Call):  # SomeView.as_view()
                v = target.func.value
                mod = imports.get(getattr(v.value, "id", ""), "")
                out.append((prefix + tmpl, mod, v.attr))
            elif isinstance(target, ast.Attribute) and target.attr == "urls":  # admin.site.urls
                out.append((prefix + tmpl, None, None))


def workshop(svc: Path) -> list[dict]:
    pats = []
    _django_patterns(svc / "crapi_site/urls.py", "/", svc, pats)
    eps = []
    for tmpl, mod, cls in pats:
        path = norm(tmpl)
        if mod is None:
            meth_auth = [("GET", "none")]
        else:
            tree = ast.parse((svc / (mod.replace(".", "/") + ".py")).read_text())
            node = next((n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == cls), None)
            meth_auth = []
            for fn in (node.body if node else []):
                if isinstance(fn, ast.FunctionDef) and fn.name in ("get", "post", "put", "delete", "patch"):
                    decos = {getattr(d, "id", getattr(d, "attr", "")) for d in fn.decorator_list}
                    auth = "required" if decos & {"jwt_auth_required", "mechanic_auth_required"} else "none"
                    meth_auth.append((fn.name.upper(), auth))
        for meth, auth in meth_auth:
            calls = [VERIFY] if auth == "required" else []
            if path.endswith("/shop/orders") and meth == "POST":
                calls.append(PAYMENT)
            eps.append({"method": meth, "path": path, "auth": auth, "source": f"{mod or 'urls'}", "calls": calls})
    return eps


# ---------------------------------------------------------------- chatbot, gateway-service
def chatbot(svc: Path) -> list[dict]:
    eps = []
    for f, prefix in ((svc / "src/chatbot/app.py", "/chatbot"), (svc / "src/chatbot/chat_api.py", "/chatbot/genai")):
        for m in re.finditer(r'route\("([^"]*)",\s*methods=\[([^\]]*)\]', f.read_text()):
            for meth in re.findall(r'"([A-Z]+)"', m.group(2)):
                # session-cookie based (get_or_create_session_id), no JWT check on the route;
                # the LLM agent's own calls to crAPI depend on the model, so none are modelled
                eps.append({"method": meth, "path": norm(prefix + m.group(1)), "auth": "none",
                            "source": f.name, "calls": []})
    return eps


def gateway_service(svc: Path) -> list[dict]:
    txt = (svc / "main.go").read_text()
    eps = []
    for path, handler in re.findall(r'HandleFunc\("([^"]+)",\s*(\w+)\)', txt):
        start = txt.find(f"func {handler}(")
        nxt = txt.find("\nfunc ", start + 5)
        body = txt[start:nxt if nxt > 0 else None]
        meth = "POST" if "payment" in path.lower() else "GET"
        eps.append({"method": meth, "path": norm(path), "auth": "required" if "BasicAuth()" in body else "none",
                    "source": "main.go", "calls": []})
    return eps


def spec_ops(spec: dict) -> set[tuple[str, str]]:
    return {(m.upper(), norm(p)) for p, item in spec["paths"].items() for m in item if m in ("get", "post", "put", "delete", "patch")}


def key(m, p):
    return (m, re.sub(r"\{[^}]*\}", "{}", norm(p)))


def main():
    if len(sys.argv) < 2:
        sys.exit(f"usage: python bench/miners/crapi.py PATH_TO_CHECKOUT  (see docs/EXPERIMENT.md for the commit)")
    repo = Path(sys.argv[1]).resolve()
    commit = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    svcs = repo / "services"
    spec = json.loads((repo / "openapi-spec/crapi-openapi-spec.json").read_text())
    documented = {key(m, p) for m, p in spec_ops(spec)}
    services = [
        {"name": "crapi-identity", "lang": "java/spring", "port": 8080, "endpoints": identity(svcs / "identity")},
        {"name": "crapi-community", "lang": "go/gorilla", "port": 8087, "endpoints": community(svcs / "community")},
        {"name": "crapi-workshop", "lang": "python/django", "port": 8000, "endpoints": workshop(svcs / "workshop")},
        {"name": "crapi-chatbot", "lang": "python/flask", "port": 5002, "endpoints": chatbot(svcs / "chatbot")},
        {"name": "gateway-service", "lang": "go/net-http", "port": 443, "endpoints": gateway_service(svcs / "gateway-service")},
    ]
    for s in services:  # a path mapped twice in one controller counts once
        seen, uniq = set(), []
        for e in s["endpoints"]:
            if (e["method"], e["path"]) not in seen:
                seen.add((e["method"], e["path"]))
                uniq.append(e)
        s["endpoints"] = uniq
    impl = set()
    for s in services:
        s["documented"] = "spec-file"
        for e in s["endpoints"]:
            e["documented"] = key(e["method"], e["path"]) in documented
            impl.add(key(e["method"], e["path"]))
    spec_only = sorted(f"{m} {p}" for m, p in spec_ops(spec) if key(m, p) not in impl)
    OUT.mkdir(parents=True, exist_ok=True)
    topo = {
        "name": "crapi",
        "description": "API surface of OWASP crAPI, mined from source; documentation = crAPI's published OpenAPI spec",
        "source": {"repo": "https://github.com/OWASP/crAPI", "commit": commit},
        "documentation": "spec-file",      # one published OpenAPI document for the whole API
        "spec_file": "openapi/crapi-openapi-spec.json",
        "id_style": "int",
        "gateway": {"service": "crapi-web", "kind": "nginx", "config": "gateway/nginx.conf.template",
                    "uninstrumented": True,     # nginx has no OpenTelemetry instrumentation in crAPI
                    "routes": [{"path": "/identity/", "service": "crapi-identity"},
                               {"path": "/community/", "service": "crapi-community"},
                               {"path": "/workshop/", "service": "crapi-workshop"},
                               {"path": "/chatbot/", "service": "crapi-chatbot"}]},
        "spec_only_operations": spec_only,
        "services": services,
    }
    (OUT / "topology.yaml").write_text(yaml.safe_dump(topo, sort_keys=False, width=140), encoding="utf-8")
    for d in ("k8s", "gateway", "openapi"):
        (OUT / d).mkdir(exist_ok=True)
    for part in ("identity", "community", "workshop", "chatbot", "web", "gateway-service"):
        src = repo / "deploy/k8s/base" / part
        if src.exists():
            for f in src.glob("*.yaml"):
                shutil.copy(f, OUT / "k8s" / f"{part}-{f.name}")
    shutil.copy(svcs / "web/nginx.conf.template", OUT / "gateway/nginx.conf.template")
    shutil.copy(repo / "openapi-spec/crapi-openapi-spec.json", OUT / "openapi/crapi-openapi-spec.json")
    n = sum(len(s["endpoints"]) for s in services)
    undoc = sum(1 for s in services for e in s["endpoints"] if not e["documented"])
    edges = {(s["name"], c["service"]) for s in services for e in s["endpoints"] for c in e["calls"]}
    print(f"services={len(services)} endpoints={n} undocumented={undoc} spec-only={len(spec_only)} "
          f"edges={sorted(edges)} commit={commit[:10]}")


if __name__ == "__main__":
    main()
