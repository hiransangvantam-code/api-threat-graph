"""
Phase 4: the risk and hardening report.

The dashboard says how risky the system is. This report says what to do about it, in order:

  1. Summary          the risk now, the risk after each fix, how many fixes take it down by
                      70% and 90%, how fast the scan was and how sure each finding is
  2. Fix plan         one entry per fix action of the remediation planner (atg/analysis.py),
                      in the order that removes the most attack-path risk first. Each entry has
                      what is wrong and where, why it matters (likelihood x impact and the reasons),
                      the fix for the technology this system actually uses (Kong, nginx, Spring
                      Cloud Gateway, Istio, plain Kubernetes...), how to check that the fix works,
                      and how much risk it removes
  3. Hardening        the baseline controls, service by service: done, missing, or not visible
  4. What this review cannot tell you, and what to run next (an active scanner on the
                      inventory, a code review for the "possible" findings)

build_hardening(analysis, eujf, timings) returns (html_body, markdown). docker/pages.py writes
hardening-<scan>.html and atg/export.py writes exports/<scan>/hardening.md.
"""
from __future__ import annotations

import html
from collections import defaultdict

E = html.escape

# ---------------------------------------------------------------- stack-specific fixes
GATEWAY_AUTH = {
    "kong": ("Kong", "plugins:\n  - name: jwt            # or key-auth / openid-connect\nroutes:\n  - paths: [{prefix}]\n    plugins: [{{name: jwt}}]"),
    "nginx": ("nginx", "location {prefix} {{\n    auth_request /_auth;      # sub-request to the token check\n    proxy_pass ...;\n}}"),
    "spring-cloud-gateway": ("Spring Cloud Gateway", "routes:\n  - id: ...\n    predicates: [Path={prefix}/**]\n    filters: [TokenRelay=]   # plus spring-boot-starter-oauth2-resource-server"),
    "istio": ("Istio", "apiVersion: security.istio.io/v1\nkind: AuthorizationPolicy\nmetadata: {{name: require-login}}\nspec:\n  selector: {{matchLabels: {{app: <gateway>}}}}\n  action: ALLOW\n  rules:\n  - from: [{{source: {{requestPrincipals: [\"*\"]}}}}]\n    to: [{{operation: {{paths: [\"{prefix}*\"]}}}}]\n# with a RequestAuthentication for your token issuer, or action: CUSTOM with ext-authz"),
    "configmap": ("the gateway's route table", "routes:\n  - prefix: {prefix}\n    auth: required"),
    "zuul": ("Zuul", "# Zuul has no per-route authentication: add Spring Security to the gateway\n# (spring-boot-starter-oauth2-resource-server) and require a token for {prefix}/**"),
}
GATEWAY_RATE = {
    "kong": "plugins:\n  - name: rate-limiting\n    config: {minute: 10, policy: local}",
    "nginx": "limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;\nlocation /login { limit_req zone=login burst=5 nodelay; ... }",
    "spring-cloud-gateway": "filters:\n  - name: RequestRateLimiter\n    args: {redis-rate-limiter.replenishRate: 1, redis-rate-limiter.burstCapacity: 5}",
    "istio": "# EnvoyFilter with envoy.filters.http.local_ratelimit on the gateway, path descriptor = the login path",
    "configmap": "routes:\n  - prefix: /login\n    rate_limit: 10/m",
    None: "metadata:\n  annotations:\n    nginx.ingress.kubernetes.io/limit-rps: \"5\"     # on the Ingress in front of the login",
}
K8S_FIX = {
    "API8-ROOT": "securityContext:\n  runAsNonRoot: true\n  runAsUser: 10001",
    "API8-PRIV": "securityContext:\n  privileged: false\n  allowPrivilegeEscalation: false\n  capabilities: {drop: [ALL]}",
    "API4": "resources:\n  requests: {cpu: 100m, memory: 128Mi}\n  limits:   {cpu: 500m, memory: 256Mi}",
    "API8-TAG": "image: registry.example/app@sha256:<digest>     # not :latest",
    "API8-NODEPORT": "spec:\n  type: ClusterIP      # publish it through the gateway / Ingress only",
    "TS-04": "env:\n  - name: DB_PASSWORD\n    valueFrom: {secretKeyRef: {name: app-db, key: password}}",
    "TS-05": "spec:\n  tls:\n  - hosts: [api.example.com]\n    secretName: api-tls        # cert-manager can issue it",
    "TS-08": "apiVersion: security.istio.io/v1\nkind: PeerAuthentication\nmetadata: {name: default}\nspec: {mtls: {mode: STRICT}}\n# or: require a service token on the endpoint",
}
VERIFY = {
    "TS-01": "Call {where} with no Authorization header or cookie: expect 401.",
    "TS-02": "Call a path under {where} without a token at the gateway: expect 401 from the gateway itself.",
    "TS-03": "Call {where} without a credential: expect 401, as the API document says.",
    "TS-04": "kubectl get deploy -o yaml | grep -A1 {where}: the value must come from a secretKeyRef.",
    "TS-05": "curl -I http://<host>/ must redirect to https; curl https://<host>/ must succeed.",
    "TS-06": "Search the access logs for the parameter name: no new entries after the change.",
    "TS-07": "Send 20 failed logins to {where} in a minute: expect 429 after the limit.",
    "TS-08": "From another pod, call {where} with no credential: expect 401/403 (or a TLS failure with STRICT mTLS).",
    "API1": "Log in as user A and request user B's object at {where}: expect 403.",
    "API3": "Call {where} anonymously and as an ordinary user: expect 401 / 403, and only the fields the caller needs.",
    "API4": "kubectl describe pod: Limits must show cpu and memory for {where}.",
    "API5": "Call {where} as an ordinary user: expect 403; it should not be routed publicly at all.",
    "API7": "Send an internal address (http://169.254.169.254/) in the URL field of {where}: expect 400.",
    "API8-DEBUG": "Request {where} from outside: expect 404.",
    "API8-PRIV": "kubectl get pod -o jsonpath='{{..securityContext}}' for {where}: privileged must be false.",
    "API8-ROOT": "kubectl exec into {where} and run id: uid must not be 0.",
    "API8-NODEPORT": "kubectl get svc {where}: TYPE must be ClusterIP.",
    "API8-NETPOL": "kubectl get networkpolicy: one must select {where}; a pod not on the allow list must time out.",
    "API8-TAG": "The image reference of {where} must carry a fixed version or digest.",
    "API9-SHADOW": "{where} is in the API document, or returns 404.",
    "API9-ZOMBIE": "No calls to {where} in the next scan; then remove it.",
    "API9-NOSPEC": "GET /openapi.json (or /v3/api-docs) on {where} returns the current document.",
    "API10": "A malformed answer from the outside API makes {where} fail safely (test with a stub).",
    "LT-01": "The next scan shows the caller of {where} in the traces.",
    "LT-02": "The next scan shows spans from {where}.",
    "LT-03": "The next scan shows spans for {where}.",
    "LT-04": "No 5xx for {where} in the next scan, or the errors are handled and alerted on.",
}
CODE_FIX = {
    "TS-01": "Require a verified credential in the service itself (not only at the gateway). Reject requests with no token with 401 before any business logic runs.",
    "TS-03": "Implement the security scheme the API document declares for this operation.",
    "TS-06": "Send the credential in the Authorization header (or a cookie), never in the URL.",
    "API1": "After loading the object, compare its owner with the caller's identity and answer 403 when they differ. Put the check in one place (a guard or repository filter) so new endpoints get it too.",
    "API3": "Return only the fields the caller needs, page the results, and require an admin role for bulk exports.",
    "API5": "Check the caller's role in the handler, and take the function out of public routing.",
    "API7": "Accept only URLs on an allow-list (scheme, host, port); resolve the host and refuse private and link-local addresses.",
    "API8-DEBUG": "Switch the endpoint off in production (for Spring: management.endpoints.web.exposure.include=health; for Go: do not import net/http/pprof in the server; for nginx stub_status: allow 127.0.0.1 only).",
    "API9-SHADOW": "Add the operation to the API document, or remove it.",
    "API9-ZOMBIE": "Move the remaining callers to the new version, then remove the old operation.",
    "API9-NOSPEC": "Publish an up-to-date API document from the code (springdoc, FastAPI, swagger-jsdoc, ...).",
    "API10": "Validate the outside API's answers like user input, with timeouts and a fallback.",
    "LT-01": "Instrument the caller with OpenTelemetry so its calls carry trace context.",
    "LT-02": "Add OpenTelemetry to the service and export to the collector.",
    "LT-03": "Make sure every handler of the service creates a server span.",
    "LT-04": "Handle the error, return a clean 4xx where the client is at fault, and alert on 5xx.",
}

BASELINE = [
    ("Authentication enforced", lambda s, eps: _all(eps, lambda e: e["auth_required"] in ("enforced",) or not _sensitive(e))),
    ("Owner checks seen (403)", lambda s, eps: _all([e for e in eps if e["object_id_in_path"] and e["auth_required"] == "enforced"],
                                                    lambda e: e["auth_observed"]["forbidden_seen"] > 0)),
    ("Not root", lambda s, eps: None if not s["in_manifests"] else not s["container_flags"]["root_not_prevented"]),
    ("Resource limits", lambda s, eps: None if not s["in_manifests"] else not s["container_flags"]["no_resource_limits"]),
    ("Pinned image", lambda s, eps: None if not s["in_manifests"] else not s["container_flags"]["mutable_tag"]),
    ("NetworkPolicy", lambda s, eps: None if not s["in_manifests"] else s["network_policy"]["present"]),
    ("mTLS", lambda s, eps: None if not s["in_manifests"] else s["mtls"]["enforced"]),
    ("API document", lambda s, eps: True if s["role"] == "gateway" else (s["spec"]["live"] or s["spec"]["file"])),
    ("Traced", lambda s, eps: None),   # filled in from trace_services
]


def _sensitive(e):
    return bool(e["data_classes"]) or e["method"] in ("POST", "PUT", "PATCH", "DELETE")


def _all(items, pred):
    items = list(items)
    if not items:
        return None
    return all(pred(i) for i in items)


def _gateway_type(eujf: dict) -> str | None:
    kinds = [r.get("gateway") for r in eujf.get("gateway_routes", []) if r.get("gateway")]
    return max(set(kinds), key=kinds.count) if kinds else None


def stack_fix(f: dict, eujf: dict) -> tuple[str, str | None]:
    """(what to do, config/code snippet) for this finding on this system's technology."""
    gw = _gateway_type(eujf)
    rid = f["rule_id"]
    if rid == "TS-02":
        prefix = f["detail"].split("route ", 1)[-1].split("/**")[0] if "route " in f["detail"] else "/api"
        name, snip = GATEWAY_AUTH.get(gw, GATEWAY_AUTH["configmap"])
        return f"Require a token for this route in {name}, and keep public paths (the login) on their own route.", snip.format(prefix=prefix)
    if rid == "TS-07":
        return ("Rate-limit the login" + (f" in {GATEWAY_AUTH[gw][0]}" if gw in GATEWAY_AUTH else " at the Ingress")
                + " and lock an account out after repeated failures.", GATEWAY_RATE.get(gw, GATEWAY_RATE[None]))
    if rid == "API8-NETPOL":
        traced = next((x.split(":", 1)[1].strip() for x in f["evidence"] if x.startswith("callers seen in traces")), "")
        traced = [a.strip() for a in traced.split(",") if a.strip() and not a.startswith("none")]
        istio = gw == "istio" or any(x.get("source") == "Istio Gateway" for x in eujf.get("edge_tls", []))
        entry = ("    - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: istio-system}}\n"
                 "      podSelector: {matchLabels: {istio: ingressgateway}}") if istio else \
                "    - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: ingress-nginx}}"
        svc = f["target"].split(":", 1)[1]
        # v1.6, from the fix experiment on the open-source systems (results/opensource/fixes):
        #  - callers come from traces, else from the configuration (gateway routes, connection settings),
        #    so an untraced database still lets in the service that uses it
        #  - an entry service keeps its outside traffic (Bank of Anthos' frontend let in only the load
        #    generator, which would have cut off its users)
        #  - the selectors use the pod labels the workloads really have (Acme Air labels pods name: ...)
        allowed = traced or sorted({d["from"] for d in eujf.get("dependencies", []) if d.get("to") == svc and d.get("from") != svc})
        s_rec = next((x for x in eujf.get("services", []) if x["name"] == svc), {}) or {}
        # the front door: exposed to the internet, or the gateway / edge service an Istio Gateway or
        # Ingress sends traffic to (Bookinfo's productpage sits behind an Istio Gateway)
        front = svc in (eujf.get("gateway"), eujf.get("edge"))
        public = (s_rec.get("exposure") or {}).get("level") == "internet" or front or (not s_rec and not allowed)
        lb = s_rec.get("published") or any("LoadBalancer" in v or "NodePort" in v for v in (s_rec.get("exposure") or {}).get("via", []))
        outside = []
        if public:
            outside.append("    - ipBlock: {cidr: 0.0.0.0/0, except: [10.0.0.0/8]}   # its users from outside; put the cluster's pod range in except"
                           if lb and not istio else entry)

        def sel(name: str) -> str:
            lab = next((x.get("pod_labels") for x in eujf.get("services", []) if x["name"] == name), None) or {}
            lab = {"app": lab["app"]} if "app" in lab else lab or {"app": name}
            return "{" + ", ".join(f"{k}: {v}" for k, v in lab.items()) + "}"
        peers = [f"    - podSelector: {{matchLabels: {sel(a)}}}" for a in allowed] + outside
        head = (f"apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {{name: {svc}}}\nspec:\n"
                f"  podSelector: {{matchLabels: {sel(svc)}}}\n  policyTypes: [Ingress]\n")
        outside_who = ["its outside users" if lb and not istio else ("the Istio ingress gateway" if istio else "the ingress controller")] if public else []
        if not peers:
            return ("No caller was seen in traces or in the configuration: the policy below denies everything; "
                    "add the callers you know before applying it.",
                    head + "  ingress: []      # deny all until the callers are listed")
        how = "the traces show" if traced else "the configuration names (no traces)"
        return (f"Allow only the callers {how} ({', '.join(allowed + outside_who)})." if allowed else
                f"Allow only the entry point ({', '.join(outside_who)}).",
                head + "  ingress:\n  - from:\n" + "\n".join(peers))
    if rid in K8S_FIX:
        return f["recommendation"], K8S_FIX[rid]
    return CODE_FIX.get(rid, f["recommendation"]), code_snippet(f, eujf)


# ---------------------------------------------------------------- code fixes in the service's own framework
def framework(service: str, eujf: dict) -> tuple[str | None, str]:
    """Best guess at the service's web framework, with the reason, from what the review saw:
    the image name and where the live API document was served. (None, "") when nothing points anywhere."""
    svc = next((s for s in eujf.get("services", []) if s["name"] == service), {}) or {}
    img = (svc.get("image") or "").lower()
    locs = [d.get("location") or "" for e in eujf.get("endpoints", []) if e["service"] == service
            for d in ((e.get("sources") or {}).get("spec") or {}).get("documents", [])]
    paths = [e["path"] for e in eujf.get("endpoints", []) if e["service"] == service]
    if "spring" in img or any("/v3/api-docs" in l or "/v2/api-docs" in l for l in locs) or any(p.startswith("/actuator") for p in paths):
        return "spring", "Spring Security" + (" (the service serves /v3/api-docs)" if "spring" not in img else "")
    if any("/q/openapi" in l for l in locs) or "quarkus" in img:
        return "quarkus", "Quarkus"
    if any(k in img for k in ("node", "express", "nest")):
        return "express", "Express (from the image name)"
    if any(k in img for k in ("golang", "-go:", "/go-")):
        return "go", "Go net/http (from the image name)"
    if any(l.endswith("/openapi.json") for l in locs) or "fastapi" in img or "python" in img:
        return "fastapi", "FastAPI (the service serves /openapi.json)"
    return None, ""


def _ep(f: dict) -> tuple[str, str, str]:
    """(service, METHOD, /path) of an endpoint finding."""
    parts = f["target"].split(":", 3)
    service = parts[1] if len(parts) > 1 else ""
    api = f.get("affected_api") or ""
    method, _, path = api.partition(" ")
    if not path and len(parts) == 4:
        method, path = parts[2], parts[3]
    return service, method.upper() or "GET", path or "/"


def code_snippet(f: dict, eujf: dict) -> str | None:
    rid = f["rule_id"]
    if rid not in ("TS-01", "TS-03", "API5", "API1", "API3", "TS-06", "API7") or not f["target"].startswith("ep:"):
        return None
    service, m, path = _ep(f)
    fw, why = framework(service, eujf)
    param = (path.split("{", 1)[1].split("}", 1)[0] if "{" in path else "id")
    xpath = "/".join(":" + x[1:-1] if x.startswith("{") else x for x in path.split("/"))
    head = {"spring": "// ", "quarkus": "// ", "express": "// ", "go": "// "}.get(fw, "# ")
    head += f"{m} {path} in {service}" + (f": {why}" if why else ": pseudocode, the framework was not visible")
    role = rid in ("API5", "API3")

    if rid in ("TS-01", "TS-03", "API5", "API3"):
        body = {
            "spring": (f"http.authorizeHttpRequests(a -> a\n"
                       f"        .requestMatchers(HttpMethod.{m}, \"{path}\")"
                       + (".hasRole(\"ADMIN\")" if role else ".authenticated()") + ")\n"
                       "    .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()));   // 401 without a valid token"),
            "quarkus": (("@RolesAllowed(\"admin\")" if role else "@Authenticated") + f"   // on the resource method for {m} {path}"),
            "express": (f"app.{m.lower()}(\"{xpath}\", requireAuth" + (", requireRole(\"admin\")" if role else "")
                        + ", handler);   // requireAuth answers 401 without a valid token"),
            "go": (f"mux.Handle(\"{m} {path}\", requireAuth(" + ("requireRole(\"admin\", " if role else "")
                   + "http.HandlerFunc(handler))" + (")" if role else "") + ")   // 401 without a valid token"),
            "fastapi": (f"@app.{m.lower()}(\"{path}\")\n"
                        "def handler(..., user = Depends(" + ("require_role(\"admin\")" if role else "current_user")
                        + ")):   # 401 without a valid token" + (", 403 without the role" if role else "")),
        }.get(fw, f"{m} {path}:\n    caller = verify_token(request)        # 401 when missing or invalid"
                  + ("\n    if \"admin\" not in caller.roles: 403" if role else ""))
        if rid == "API3":
            body += {"spring": "\n// and return a page of summary objects: Page<Summary> list(Pageable page)",
                     "fastapi": "\n# and return a page of summary objects: size: int = Query(50, le=100) -> list[Summary]",
                     "express": "\n// and return a page of summary objects: .limit(Math.min(+req.query.size || 50, 100))",
                     "go": "\n// and return a page of summary structs, at most 100 per request",
                     "quarkus": "\n// and return a page of summary objects: @QueryParam(\"size\") @Max(100) int size",
                     }.get(fw, "\n    return page(summary(rows), size <= 100)")
        return head + "\n" + body

    if rid == "API1":
        body = {
            "spring": (f"var obj = repository.findById({param}).orElseThrow(() -> new ResponseStatusException(NOT_FOUND));\n"
                       "if (!obj.getOwnerId().equals(jwt.getSubject()))\n"
                       "    throw new ResponseStatusException(HttpStatus.FORBIDDEN);"),
            "quarkus": (f"var obj = repository.findById({param});\n"
                        "if (obj == null || !obj.ownerId.equals(identity.getPrincipal().getName()))\n"
                        "    throw new ForbiddenException();"),
            "express": (f"const obj = await load(req.params.{param});\n"
                        "if (!obj || obj.ownerId !== req.user.id) return res.sendStatus(403);"),
            "go": (f"obj, err := load(r.PathValue(\"{param}\"))\n"
                   "if err != nil || obj.OwnerID != caller(r).ID { http.Error(w, \"forbidden\", 403); return }"),
            "fastapi": (f"obj = load({param})\n"
                        "if obj is None or obj.owner_id != user.id:\n    raise HTTPException(403)"),
        }.get(fw, f"obj = load({param})\nif obj.owner != caller.id: 403")
        return head + "\n" + body

    if rid == "TS-06":
        return head + "\n" + {
            "spring": f"@PostMapping(\"{path}\")   // was a query parameter\npublic Token login(@RequestBody Credentials c) {{ ... }}",
            "express": f"app.post(\"{xpath}\", express.json(), login);   // read req.body, never req.query",
            "fastapi": f"@app.post(\"{path}\")   # was a query parameter\ndef login(c: Credentials): ...",
        }.get(fw, f"POST {path}   with the credential in the body or the Authorization header, not in the URL")

    if rid == "API7":
        return head + "\n" + ("u = urlparse(url)\n"
                              "if u.scheme != \"https\" or u.hostname not in ALLOWED_HOSTS: 400\n"
                              "if ip_address(resolve(u.hostname)).is_private: 400")
    return None


def _where(f):
    return f.get("affected_api") or f["target"]


def build_hardening(analysis: dict, eujf: dict, timings: dict | None = None) -> tuple[str, str]:
    findings = {f["id"]: f for f in analysis["findings"]}
    by_target = defaultdict(list)
    for f in analysis["findings"]:
        by_target[f["target"]].append(f)
    plan = analysis.get("mitigation_plan") or {}
    steps = plan.get("steps", [])
    total = plan.get("total_path_risk", 0)
    sm = analysis["summary"]
    tim = timings or {}

    # ---- entries: planner steps first (they remove attack-path risk), then the rest by score
    entries, covered = [], set()
    for i, st in enumerate(steps, 1):
        fs = [f for f in analysis["findings"] if f["target"] == st["target"] and f["rule_id"] in st.get("rules", [])]
        covered |= {f["id"] for f in fs}
        entries.append({"n": i, "title": st["title"], "findings": fs, "removed": st["risk_removed"],
                        "remaining": st["remaining"], "pct": st["cumulative_reduction_pct"]})
    rest = [f for f in analysis["findings"] if f["id"] not in covered]
    for f in rest:
        entries.append({"n": len(entries) + 1, "title": f"{f['title']}: {_where(f)}", "findings": [f],
                        "removed": 0, "remaining": None, "pct": None})

    # ---- baseline table
    traced = {s["service"] for s in eujf.get("trace_services", [])}
    eps_by = defaultdict(list)
    for e in eujf["endpoints"]:
        eps_by[e["service"]].append(e)
    base_rows = []
    for s in eujf["services"]:
        cells = []
        for name, fn in BASELINE:
            v = (s["name"] in traced) if name == "Traced" else fn(s, eps_by.get(s["name"], []))
            cells.append(v)
        base_rows.append((s["name"], cells))

    conf = defaultdict(int)
    for f in analysis["findings"]:
        conf[f["confidence"]] += 1
    phase_ms = {k: v for k, v in tim.items() if isinstance(v, (int, float))}

    # ---------------------------------------------------------------- Markdown
    md = [f"# Risk and hardening report: {eujf.get('target') or 'system'}", "",
          f"Scan {analysis['run_id']}. {sm['findings']} findings ({', '.join(f'{v} {k}' for k, v in sm['by_severity'].items() if v)}), "
          f"{sm['attack_paths']} attack paths, total path risk {total:g}.", ""]
    if steps:
        md += [f"Applying the first {plan.get('fixes_for_70pct') or len(steps)} fixes removes 70% of the attack-path risk"
               + (f", the first {plan['fixes_for_90pct']} remove 90%." if plan.get("fixes_for_90pct") else "."), ""]
    md += ["## Fix plan (most risk removed first)", ""]
    for en in entries:
        md.append(f"### {en['n']}. {en['title']}")
        if en["pct"] is not None:
            md.append(f"Removes {en['removed']:g} of the path risk; {en['remaining']:g} left ({en['pct']:g}% reduced so far).")
        for f in en["findings"]:
            what, snippet = stack_fix(f, eujf)
            md += ["", f"- **{f['rule_id']} {f['title']}** ({f['severity']}, risk {f['likelihood']}x{f['impact']}={f['score']}, "
                       f"confidence {f['confidence']}): {f['detail']}",
                   f"  - Why: {'; '.join(f['factors']) or f['description']}",
                   f"  - Fix: {what}"]
            if snippet:
                md += ["", "```yaml" if any(k in snippet for k in ("apiVersion", "routes:", "spec:", "env:", "resources:", "securityContext:", "plugins:", "filters:"))
                       else "```", snippet, "```"]
            md.append(f"  - Check: {VERIFY.get(f['rule_id'], 'Run the scan again: the finding must be gone.').format(where=_where(f))}")
            md.append(f"  - References: {f['owasp']}; {', '.join(f['cwe'])}; ATT&CK {', '.join(f['attack'])}")
        md.append("")
    md += ["## Hardening baseline", "", "| Service | " + " | ".join(n for n, _ in BASELINE) + " |",
           "|---|" + "---|" * len(BASELINE)]
    sym = {True: "yes", False: "**no**", None: "-"}
    md += [f"| {n} | " + " | ".join(sym[c] for c in cells) + " |" for n, cells in base_rows]
    md += ["", "\"-\" means the review cannot tell (no manifest for the service, or nothing to check).", "",
           "## Accuracy, speed and what to run next", "",
           f"- Confidence: {conf.get('high', 0)} high, {conf.get('medium', 0)} medium. Medium means the finding is a "
           "design signal that needs a person to confirm it (for example \"possible BOLA\": the owner check was never seen "
           "failing, which a test with two accounts settles).",
           "- Speed: " + (", ".join(f"{k.replace('_ms', '').replace('_', ' ')} {v:.0f} ms" for k, v in phase_ms.items()) or "see the dashboard") + ".",
           "- Not covered by a passive review: injection and other payload flaws, response headers and CORS, business-flow "
           "abuse, the strength of secrets. Run an active scanner (OWASP ZAP, Schemathesis) on the inventory in the "
           "threat graph export, shadow endpoints included, and review the code behind every medium-confidence finding.", ""]
    markdown = "\n".join(md)

    # ---------------------------------------------------------------- HTML
    h = [f"""<header class="head"><div class="eyebrow">Phase 4 · Risk and hardening report</div>
<h1>What to fix, in order</h1>
<p class="muted">{E(str(eujf.get('target') or ''))} · {sm['findings']} findings · {sm['attack_paths']} attack paths · total path risk {total:g}.
Each fix below says what is wrong, why it matters, how to fix it on this system's own technology, and how to check the fix.</p></header>"""]
    if steps:
        bars = "".join(f'<div class="hb"><span style="width:{max(2, 100 - st["cumulative_reduction_pct"]):.0f}%"></span>'
                       f'<em>after fix {i}: {st["remaining"]:g}</em></div>' for i, st in enumerate(steps[:12], 1))
        h.append(f"""<section><h2>Risk after each fix</h2><div class="hbars"><div class="hb"><span style="width:100%"></span><em>now: {total:g}</em></div>{bars}</div>
<p class="muted">{plan.get('fixes_for_70pct') or len(steps)} fixes remove 70% of the attack-path risk{f", {plan['fixes_for_90pct']} remove 90%" if plan.get('fixes_for_90pct') else ''}.</p></section>""")
    h.append("<section><h2>Fix plan</h2>")
    for en in entries:
        gain = (f'<span class="gain">−{en["removed"]:g} risk · {en["pct"]:g}% reduced so far</span>' if en["pct"] is not None else "")
        h.append(f'<details class="fix"{" open" if en["n"] <= 3 else ""}><summary><b>{en["n"]}. {E(en["title"])}</b> {gain}</summary>')
        for f in en["findings"]:
            what, snippet = stack_fix(f, eujf)
            h.append(f"""<div class="ff"><p><span class="sev {f['severity']}">{f['severity']}</span> <b>{E(f['rule_id'])} {E(f['title'])}</b>
· risk {f['likelihood']}×{f['impact']} = {f['score']} · confidence {E(f['confidence'])}</p>
<p>{E(f['detail'])}</p>
<p><b>Why it matters:</b> {E('; '.join(f['factors']) or f['description'])}</p>
<p><b>Fix:</b> {E(what)}</p>{f'<pre>{E(snippet)}</pre>' if snippet else ''}
<p><b>Check the fix:</b> {E(VERIFY.get(f['rule_id'], 'Run the scan again: the finding must be gone.').format(where=_where(f)))}</p>
<p class="muted">{E(f['owasp'])} · {E(', '.join(f['cwe']))} · ATT&amp;CK {E(', '.join(f['attack']))} · NIST {E(', '.join(f['nist']))}</p></div>""")
        h.append("</details>")
    h.append("</section>")
    head = "".join(f"<th>{E(n)}</th>" for n, _ in BASELINE)
    cell = {True: '<td class="ok">yes</td>', False: '<td class="bad">no</td>', None: '<td class="muted">–</td>'}
    rows = "".join(f"<tr><td>{E(n)}</td>{''.join(cell[c] for c in cells)}</tr>" for n, cells in base_rows)
    h.append(f"""<section><h2>Hardening baseline</h2><div class="scroll"><table class="base"><thead><tr><th>Service</th>{head}</tr></thead>
<tbody>{rows}</tbody></table></div><p class="muted">– means the review cannot tell (no manifest for the service, or nothing to check).</p></section>""")
    h.append(f"""<section><h2>Accuracy, speed and what to run next</h2><ul>
<li>Confidence: {conf.get('high', 0)} high, {conf.get('medium', 0)} medium. Medium findings are design signals for a person to confirm,
for example "possible BOLA", which a request with a second account settles.</li>
<li>Speed: {E(', '.join(f"{k.replace('_ms', '').replace('_', ' ')} {v:.0f} ms" for k, v in phase_ms.items()) or 'see the dashboard')}.</li>
<li>Not covered by a passive review: injection and other payload flaws, response headers and CORS, business-flow abuse,
the strength of secrets. Run an active scanner (OWASP ZAP, Schemathesis) on the inventory from the threat graph export,
shadow endpoints included, and review the code behind every medium-confidence finding.</li></ul>
<p class="muted">The same report is in the export folder as hardening.md.</p></section>""")
    return "\n".join(h), markdown


CSS = """
.hbars{display:grid;gap:4px;max-width:720px}
.hb{position:relative;height:22px;background:var(--surface-2);border-radius:4px;overflow:hidden}
.hb span{position:absolute;inset:0 auto 0 0;background:var(--accent);opacity:.75}
.hb em{position:relative;padding-left:8px;font:600 12px/22px var(--f-body);color:var(--fg);font-style:normal}
details.fix{border:1px solid var(--line);border-radius:8px;margin:8px 0;background:var(--surface)}
details.fix summary{cursor:pointer;padding:10px 14px;list-style:none}
details.fix summary::-webkit-details-marker{display:none}
details.fix .gain{float:right;color:var(--ok);font-size:13px}
.ff{border-top:1px solid var(--line);padding:6px 14px}
.ff pre{background:var(--surface-2);padding:8px 10px;border-radius:6px;overflow:auto;font-size:12.5px}
.sev{display:inline-block;padding:1px 7px;border-radius:10px;font:600 11px var(--f-body);text-transform:uppercase}
.sev.critical{background:#b91c1c;color:#fff}.sev.high{background:#ea580c;color:#fff}
.sev.medium{background:#ca8a04;color:#fff}.sev.low{background:#64748b;color:#fff}
table.base td.ok{color:var(--ok)} table.base td.bad{color:var(--crit);font-weight:700}
"""
