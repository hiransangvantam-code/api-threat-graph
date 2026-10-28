"""
Phase 3a - RULE ENGINE

Deterministic rules over the EUJF document. The three groups match the three
boxes in Fig. 1:

    Token security        TS-*   authentication, credentials, token handling
    API OWASP Top 10      API*   OWASP API Security Top 10 (2023) categories
    Logging and tracing   LT-*   visibility gaps that hide an attacker

Where each rule comes from (the professor's question "อิงมาจากไหน"):
every rule cites
    owasp  OWASP API Security Top 10 2023 category
    cwe    MITRE CWE weakness ID (what is wrong in the design/code)
    attack MITRE ATT&CK technique ID (how an attacker uses it)
    nist   NIST guidance it maps to (SP 800-204 microservices security,
           SP 800-207 zero trust, SP 800-190 container security, SP 800-95 web services)
and every rule ships a mitigation, so each finding comes with a recommendation.

Scoring: risk = likelihood (1-5) x impact (1-5), the same model as the paper.
Base values come from the rule; they are then adjusted by context that the
extractors measured (internet exposure, observed anonymous success, sensitive
data). Every adjustment is written into the finding as a "factor" so the
score can be explained line by line.

A rule is a plain function: (Context) -> list[Hit]. Adding a rule = adding
one decorated function. Rules never touch I/O, so the engine is fast and easy
to test.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

LOGIN_PATH = re.compile(r"(^|/)(login|signin|sign-in|token|oauth|register|signup|auth)(/|$)", re.I)
ADMIN_PATH = re.compile(r"(^|/)(admin|internal|manage(ment)?|ops|backoffice|export|dump)(/|$)", re.I)
DEBUG_PATH = re.compile(r"(^|/)(_?debug|actuator|env|_?config|phpinfo|server-status|swagger-resources|heapdump|pprof)(/|$)", re.I)
SSRF_FIELD = re.compile(r"^(url|uri|callback(_?url)?|webhook(_?url)?|redirect(_?uri|_?url)?|endpoint|target|host|image_?url)$", re.I)
CRED_QUERY = re.compile(r"(token|api_?key|apikey|password|passwd|secret|session|access_?key)", re.I)
HIGH_VALUE_DATA = {"pii", "payment_card", "credential", "government_id"}
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}

GROUPS = ["Token security", "API OWASP Top 10", "Logging and tracing"]

RISKS = {
    "data_breach": ("Sensitive data exposure", "Personal or business data read by someone who should not see it"),
    "financial_fraud": ("Financial fraud", "Payments created, refunded or read without authorization"),
    "account_takeover": ("Account takeover", "Attacker acts as another user"),
    "credential_compromise": ("Credential compromise", "Secrets or signing keys leak, so tokens can be forged"),
    "cluster_compromise": ("Container / cluster compromise", "A compromised pod escapes to the node or moves laterally"),
    "service_disruption": ("Service disruption", "The API is slowed down or taken offline"),
    "detection_gap": ("Undetected attacker activity", "Calls happen that monitoring cannot attribute or see"),
    "recon": ("Reconnaissance", "Attacker learns internal structure that makes other attacks easier"),
}


@dataclass
class Rule:
    id: str
    group: str
    title: str
    description: str
    risk: str                     # key of RISKS
    likelihood: int               # base, 1-5
    impact: int                   # base, 1-5
    owasp: str
    cwe: list[str]
    attack: list[str]
    nist: list[str]
    mitigation: list[str]
    snippet: str = ""
    exposure_sensitive: bool = True   # adjust likelihood by how reachable the target is
    check: Callable = None


@dataclass
class Hit:
    target: str                   # EUJF id: "ep:..." or "svc:..."
    detail: str                   # one-line, specific to this target
    evidence: list[str]
    sources: list[str]            # which Phase 1 sources back this up
    recommendation: str
    confidence: str = "high"
    likelihood_adj: list = field(default_factory=list)   # [(delta, reason)]
    impact_adj: list = field(default_factory=list)
    risk: str | None = None       # override rule.risk for this hit


RULES: list[Rule] = []


def rule(**meta):
    def deco(fn):
        RULES.append(Rule(check=fn, **meta))
        return fn
    return deco


class Context:
    def __init__(self, eujf: dict):
        self.d = eujf
        self.endpoints = eujf["endpoints"]
        self.services = {s["name"]: s for s in eujf["services"]}
        self.gateway = eujf.get("gateway")

    def svc(self, e) -> dict:
        return self.services.get(e["service"], {})

    @staticmethod
    def label(e) -> str:
        return f'{e["method"]} {e["path"]} ({e["service"]})'

    @staticmethod
    def is_login(e) -> bool:
        return bool(LOGIN_PATH.search(e["path"]))

    @staticmethod
    def sources_of(e, *wanted) -> list[str]:
        m = {"spec": "openapi", "traffic": "runtime_traffic", "public_traffic": "runtime_traffic",
             "trace": "callchain"}
        got = sorted({m[k] for k in e["sources"] if k in m})
        return sorted(set(got) | set(wanted))


# =============================================================================
# Token security
# =============================================================================
@rule(id="TS-01", group="Token security", title="Sensitive operation answers anonymous callers",
      description="Requests with no credential at all got a 2xx response from an endpoint that returns "
                  "sensitive data or changes state.",
      risk="data_breach", likelihood=4, impact=4, owasp="API2:2023 Broken Authentication",
      cwe=["CWE-306"], attack=["T1190"], nist=["SP 800-204", "SP 800-207"],
      mitigation=["Require a verified token on this operation in the service itself, not only at the gateway.",
                  "Reject requests without Authorization with 401 before any business logic runs.",
                  "Add a test that calls the endpoint anonymously and expects 401."],
      snippet="# FastAPI\n@app.get('/admin/transactions')\ndef admin_tx(user = Depends(require_role('admin'))):\n    ...")
def ts01(ctx: Context):
    for e in ctx.endpoints:
        ao = e["auth_observed"]
        if not ao["anonymous_success"] or ctx.is_login(e) or DEBUG_PATH.search(e["path"]):
            continue
        sensitive = bool(e["data_classes"]) or e["method"] in STATE_CHANGING or ADMIN_PATH.search(e["path"])
        if not sensitive:
            continue
        risk = "financial_fraud" if "financial" in e["data_classes"] or e["service"].startswith("pay") else "data_breach"
        la = [(+1, "anonymous success seen on the public path")] if ao["anonymous_success_public"] else []
        yield Hit(e["id"], f"{ctx.label(e)} returned 2xx to {ao['anonymous_success']} request(s) without a token",
                  [f"{ao['anonymous_success']} anonymous 2xx responses",
                   f"data returned: {', '.join(e['data_classes']) or 'none'}; method {e['method']}"],
                  ctx.sources_of(e), f"Add authentication to {e['method']} {e['path']} in {e['service']}.",
                  likelihood_adj=la, risk=risk)


@rule(id="TS-02", group="Token security", title="Gateway route forwards requests without authentication",
      description="A gateway route is configured with no authentication and forwards to endpoints that are not "
                  "login endpoints, so the gateway is not acting as an authentication boundary.",
      risk="data_breach", likelihood=4, impact=4, owasp="API2:2023 Broken Authentication",
      cwe=["CWE-306"], attack=["T1190"], nist=["SP 800-204"],
      mitigation=["Set auth: required on the route, or split public paths (login) into their own route.",
                  "Deny by default: routes without an explicit auth setting should be rejected at deploy time."],
      snippet="routes:\n  - prefix: /api/payments\n    service: payment-service\n    auth: required      # was: none",
      exposure_sensitive=False)
def ts02(ctx: Context):
    for r in ctx.d["gateway_routes"]:
        if r["auth"] not in ("none", "unspecified"):
            continue
        behind = [e for e in ctx.endpoints if e["gateway_route"] and e["gateway_route"]["prefix"] == r["match_prefix"]]
        exposed = [e for e in behind if not ctx.is_login(e)]
        if not exposed:
            continue
        gw = ctx.services.get(ctx.gateway, {})
        risk = "financial_fraud" if any("financial" in e["data_classes"] for e in exposed) else "data_breach"
        yield Hit(gw.get("id", f"svc:{ctx.gateway}"),
                  f"route {r['match_prefix']}/** -> {r['upstream_service']} has auth: {r['auth']}",
                  [f"defined in {r['defined_in']}",
                   "exposes: " + ", ".join(f"{e['method']} {e['public_paths'][0]}" for e in exposed)],
                  ["infrastructure", "runtime_traffic"],
                  f"Set auth: required on gateway route {r['match_prefix']}.", risk=risk)


@rule(id="TS-03", group="Token security", title="Declared authentication is not enforced",
      description="The API specification says the operation needs a credential, but runtime traffic shows it "
                  "succeeding without one. The documentation and the system disagree.",
      risk="financial_fraud", likelihood=3, impact=4, owasp="API2:2023 Broken Authentication",
      cwe=["CWE-287"], attack=["T1190"], nist=["SP 800-95", "SP 800-204"],
      mitigation=["Implement the security scheme the spec declares (verify the header, return 401 otherwise).",
                  "Add contract tests generated from the spec that call each secured operation without credentials."])
def ts03(ctx: Context):
    for e in ctx.endpoints:
        spec = e["sources"].get("spec")
        if spec and spec["auth_declared"] == "required" and e["auth_observed"]["anonymous_success"]:
            yield Hit(e["id"], f"spec requires auth for {ctx.label(e)}, but {e['auth_observed']['anonymous_success']} "
                      "requests without a token succeeded",
                      [f"spec: {d['location']} (v{d['api_version']})" for d in spec["documents"]] +
                      [f"traffic: {e['auth_observed']['anonymous_success']} anonymous 2xx"],
                      ctx.sources_of(e), f"Enforce the declared security scheme on {e['method']} {e['path']}.")


@rule(id="TS-04", group="Token security", title="Secret stored in plaintext in the deployment manifest",
      description="An environment variable with a secret-looking name has its value written directly in the "
                  "manifest, so anyone with read access to the repo or cluster config has it.",
      risk="credential_compromise", likelihood=3, impact=5, owasp="API8:2023 Security Misconfiguration",
      cwe=["CWE-798", "CWE-312"], attack=["T1552.001"], nist=["SP 800-190", "SP 800-204"],
      mitigation=["Move the value into a Kubernetes Secret (or a vault) and reference it with secretKeyRef.",
                  "Rotate the exposed value: it is already in version control history.",
                  "Add a CI check that fails on plaintext env values with secret-like names."],
      snippet="env:\n  - name: JWT_SECRET\n    valueFrom:\n      secretKeyRef: {name: shoplite-secrets, key: jwt-secret}",
      exposure_sensitive=False)
def ts04(ctx: Context):
    for s in ctx.services.values():
        for name in s["plaintext_sensitive_env"]:
            signing = bool(re.search(r"jwt|sign", name, re.I))
            yield Hit(s["id"], f"{name} is written in plaintext in the {s['name']} manifest",
                      [f"env {name}: source=plaintext (value not copied by the extractor)"],
                      ["infrastructure"], f"Move {name} of {s['name']} into a Secret and rotate it.",
                      impact_adj=[(0, "token signing key: tokens can be forged")] if signing else [],
                      risk="account_takeover" if signing else "credential_compromise")


@rule(id="TS-05", group="Token security", title="Tokens and data cross the internet without TLS",
      description="The public ingress has no TLS, and traffic through it carries Authorization headers and "
                  "personal data, so they can be read or replayed on the network.",
      risk="account_takeover", likelihood=3, impact=4, owasp="API8:2023 Security Misconfiguration",
      cwe=["CWE-319"], attack=["T1557", "T1040"], nist=["SP 800-95", "SP 800-204"],
      mitigation=["Terminate TLS at the ingress (tls: section + certificate) and redirect HTTP to HTTPS.",
                  "Send Strict-Transport-Security so browsers never fall back to HTTP."],
      snippet="spec:\n  tls:\n    - hosts: [shop.example.com]\n      secretName: shop-tls",
      exposure_sensitive=False)
def ts05(ctx: Context):
    for ing in ctx.d["ingress"]:
        if ing["tls"]:
            continue
        with_tokens = [e for e in ctx.endpoints if e["sources"].get("public_traffic") and e["auth_observed"]["authenticated_calls"]]
        with_data = [e for e in ctx.endpoints if e["sources"].get("public_traffic") and e["data_classes"]]
        if not (with_tokens or with_data):
            continue
        gw = ctx.services.get(ing["backend_service"], {})
        yield Hit(gw.get("id", f"svc:{ing['backend_service']}"), f"ingress {ing['host']}{ing['path']} serves the API over plain HTTP",
                  [f"{len(with_tokens)} public endpoint(s) received bearer tokens",
                   f"{len(with_data)} public endpoint(s) returned sensitive data"],
                  ["infrastructure", "runtime_traffic"], f"Enable TLS on ingress {ing['host']}.")


@rule(id="TS-06", group="Token security", title="Credential passed in the URL query string",
      description="A query parameter name looks like a token, key or password. URLs end up in logs, proxies "
                  "and browser history.",
      risk="credential_compromise", likelihood=3, impact=4, owasp="API2:2023 Broken Authentication",
      cwe=["CWE-598"], attack=["T1552"], nist=["SP 800-95"],
      mitigation=["Send credentials in the Authorization header or the request body, never in the URL.",
                  "Strip or mask the parameter in access logs while migrating clients."])
def ts06(ctx: Context):
    for e in ctx.endpoints:
        bad = [q for q in e["query_params"] if CRED_QUERY.search(q)]
        if bad:
            yield Hit(e["id"], f"{ctx.label(e)} takes {', '.join(bad)} in the query string",
                      [f"query params: {', '.join(e['query_params'])}"], ctx.sources_of(e),
                      f"Move {', '.join(bad)} out of the URL of {e['method']} {e['path']}.")


@rule(id="TS-07", group="Token security", title="Login has no visible brute-force protection",
      description="The login endpoint returned failures but never a 429 or lockout, so password guessing is "
                  "not being slowed down.",
      risk="account_takeover", likelihood=3, impact=4, owasp="API2:2023 Broken Authentication",
      cwe=["CWE-307"], attack=["T1110"], nist=["SP 800-63B"],
      mitigation=["Rate-limit login per account and per IP (e.g. 5 failures / 15 min) and return 429.",
                  "Add MFA for privileged accounts and alert on failure spikes."])
def ts07(ctx: Context):
    for e in ctx.endpoints:
        if not ctx.is_login(e) or e["method"] != "POST":
            continue
        codes = e.get("status_observed") or (e["sources"].get("traffic") or {}).get("status_codes", {})
        fails = codes.get("401", 0) + codes.get("403", 0)
        if fails and not e["auth_observed"]["throttled_seen"]:
            yield Hit(e["id"], f"{ctx.label(e)}: {fails} failed logins, no 429 seen",
                      [f"status codes: {codes}"], ctx.sources_of(e),
                      f"Add rate limiting and lockout to {e['path']}.", confidence="medium")


@rule(id="TS-08", group="Token security", title="Service-to-service call accepted without credentials",
      description="Another microservice calls this endpoint without any credential and it succeeds, so any pod "
                  "that can reach it can do the same (no zero-trust between services).",
      risk="financial_fraud", likelihood=2, impact=4, owasp="API2:2023 Broken Authentication",
      cwe=["CWE-306"], attack=["T1210"], nist=["SP 800-207", "SP 800-204"],
      mitigation=["Authenticate workloads to each other: mTLS through a service mesh, or signed service tokens.",
                  "Authorize per caller: only order-service may call /charge, for example."],
      snippet="# Istio: require mTLS and allow only order-service\nkind: AuthorizationPolicy\nspec:\n  rules:\n  - from:\n    - source: {principals: [\"cluster.local/ns/shoplite/sa/order-service\"]}")
def ts08(ctx: Context):
    for e in ctx.endpoints:
        tr = e["sources"].get("trace") or {}
        callers = [c for c in tr.get("callers", []) if c != ctx.gateway]
        if callers and e["auth_observed"]["anonymous_success_internal"]:
            yield Hit(e["id"], f"{', '.join(callers)} -> {ctx.label(e)} with no credential",
                      [f"callers from traces: {', '.join(callers)}",
                       f"{e['auth_observed']['anonymous_success_internal']} east-west calls without Authorization succeeded"],
                      ["callchain", "runtime_traffic"],
                      f"Require service identity (mTLS or a service token) on {e['path']} in {e['service']}.")


# =============================================================================
# API OWASP Top 10
# =============================================================================
@rule(id="API1", group="API OWASP Top 10", title="Possible broken object level authorization (BOLA)",
      description="An authenticated endpoint takes an object ID from the path and returns or changes that object. "
                  "No 403 was ever observed, so there is no sign that ownership is checked.",
      risk="data_breach", likelihood=3, impact=4, owasp="API1:2023 Broken Object Level Authorization",
      cwe=["CWE-639"], attack=["T1078", "T1213"], nist=["SP 800-204"],
      mitigation=["Check that the object belongs to the caller (or that the caller's role allows it) on every access.",
                  "Return 404 for objects the caller does not own, so IDs cannot be enumerated.",
                  "Prefer random IDs (UUIDs) over sequential integers."],
      snippet="order = ORDERS.get(order_id)\nif order is None or order['user_id'] != caller.id:\n    raise HTTPException(404)")
def api1(ctx: Context):
    for e in ctx.endpoints:
        if not e["object_id_in_path"] or e["method"] not in ("GET", "PUT", "PATCH", "DELETE"):
            continue
        if e["auth_required"] not in ("enforced", "declared") or e["auth_observed"]["forbidden_seen"]:
            continue
        reason = (f"response carries owner field {', '.join(e['owner_fields'])}" if e["owner_fields"]
                  else f"returns {', '.join(e['data_classes'])} data" if e["data_classes"]
                  else f"{e['method']} changes the object" if e["method"] != "GET" else None)
        if not reason:
            continue
        hits = (e["sources"].get("traffic") or {}).get("hits", 0)
        yield Hit(e["id"], f"{ctx.label(e)}: object ID from path, {reason}, 0 x 403 in {hits} calls",
                  [f"path params: {', '.join(e['path_params'])}", reason, f"{hits} calls, never 403"],
                  ctx.sources_of(e), f"Add an ownership check to {e['method']} {e['path']} in {e['service']}.",
                  confidence="medium",
                  impact_adj=[(+1, "returns personal data")] if HIGH_VALUE_DATA & set(e["data_classes"]) else [])


@rule(id="API3", group="API OWASP Top 10", title="Bulk sensitive data exposure",
      description="An endpoint returns a list of records with personal or financial fields, and it is either "
                  "reachable without a token or not documented, so nobody reviewed what it hands out.",
      risk="data_breach", likelihood=4, impact=4, owasp="API3:2023 Broken Object Property Level Authorization",
      cwe=["CWE-213", "CWE-359"], attack=["T1213"], nist=["SP 800-204"],
      mitigation=["Return only the fields the client needs (response schema / DTO, not the raw record).",
                  "Paginate with a hard maximum and require an admin role for bulk export.",
                  "Log every bulk export with the caller identity."])
def api3(ctx: Context):
    for e in ctx.endpoints:
        classes = set(e["data_classes"]) & (HIGH_VALUE_DATA | {"financial"})
        if not (e["returns_collection"] and classes):
            continue
        if not (e["auth_observed"]["anonymous_success"] or e["inventory_status"] == "shadow"):
            continue
        fields = sorted({f for c in classes for f in e["data_classes"][c]})
        yield Hit(e["id"], f"{ctx.label(e)} returns a list with {', '.join(sorted(classes))} fields",
                  [f"fields: {', '.join(fields)}", f"inventory: {e['inventory_status']}",
                   f"anonymous 2xx: {e['auth_observed']['anonymous_success']}"],
                  ctx.sources_of(e), f"Reduce fields and require an admin role on {e['path']}.",
                  impact_adj=[(+1, "personal data in bulk")] if "pii" in classes else [],
                  risk="financial_fraud" if classes == {"financial"} else "data_breach")


@rule(id="API4", group="API OWASP Top 10", title="No resource limits on an internet-reachable service",
      description="The container has no CPU/memory limits, so one expensive request pattern can starve the "
                  "node and every service on it.",
      risk="service_disruption", likelihood=2, impact=3, owasp="API4:2023 Unrestricted Resource Consumption",
      cwe=["CWE-770"], attack=["T1499"], nist=["SP 800-190"],
      mitigation=["Set resources.limits and requests for every container.",
                  "Add rate limits at the gateway for expensive operations."],
      snippet="resources:\n  limits: {cpu: 500m, memory: 256Mi}\n  requests: {cpu: 100m, memory: 128Mi}")
def api4(ctx: Context):
    for s in ctx.services.values():
        if s["container_flags"]["no_resource_limits"] and s["exposure"]["level"] in ("internet", "node"):
            yield Hit(s["id"], f"{s['name']} has no resource limits and is reachable from {s['exposure']['level']}",
                      ["resources.limits missing"] + s["exposure"]["via"], ["infrastructure"],
                      f"Add resources.limits to {s['name']}.")


@rule(id="API5", group="API OWASP Top 10", title="Administrative function reachable by ordinary callers",
      description="An admin / internal / export function is reachable from outside its intended audience "
                  "(publicly routed or answered anonymously).",
      risk="data_breach", likelihood=4, impact=5, owasp="API5:2023 Broken Function Level Authorization",
      cwe=["CWE-285"], attack=["T1190"], nist=["SP 800-204"],
      mitigation=["Require an admin role on the function, checked in the service.",
                  "Do not route admin paths through the public gateway; expose them on a separate internal listener."])
def api5(ctx: Context):
    for e in ctx.endpoints:
        if not ADMIN_PATH.search(e["path"]) or DEBUG_PATH.search(e["path"]):
            continue
        public = bool(e["gateway_route"]) or ctx.svc(e).get("node_port")
        ao = e["auth_observed"]
        anon = ao["anonymous_success"]
        # publicly routed is fine IF there is evidence of access control (401 / 403 seen)
        controlled = ao["forbidden_seen"] or ao["anonymous_denied"]
        if not (anon or (public and not controlled)):
            continue
        how = []
        if public:
            how.append("publicly routed as " + ", ".join(e["public_paths"] or ["NodePort"]))
        if anon:
            how.append(f"{anon} anonymous 2xx")
        yield Hit(e["id"], f"{ctx.label(e)}: {'; '.join(how)}", how, ctx.sources_of(e, "infrastructure"),
                  f"Restrict {e['path']} to an admin role and remove it from public routing.",
                  risk="financial_fraud" if "financial" in e["data_classes"] else "data_breach")


@rule(id="API7", group="API OWASP Top 10", title="Request accepts a URL the server may fetch (SSRF)",
      description="A request field looks like a URL or host that the server will contact.",
      risk="cluster_compromise", likelihood=3, impact=4, owasp="API7:2023 Server Side Request Forgery",
      cwe=["CWE-918"], attack=["T1190"], nist=["SP 800-204"],
      mitigation=["Allow-list destinations; block private, link-local and metadata addresses.",
                  "Fetch through an egress proxy that enforces the allow-list."])
def api7(ctx: Context):
    for e in ctx.endpoints:
        fields = set((e["sources"].get("spec") or {}).get("request_fields", {}))
        shape = (e["sources"].get("traffic") or {}).get("request_shape")
        if isinstance(shape, dict):
            fields |= set(shape)
        bad = sorted(f for f in fields if SSRF_FIELD.match(f.rstrip("?")))
        if bad:
            yield Hit(e["id"], f"{ctx.label(e)} accepts {', '.join(bad)}", [f"request fields: {', '.join(sorted(fields))}"],
                      ctx.sources_of(e), f"Validate {', '.join(bad)} against an allow-list in {e['service']}.",
                      confidence="medium")


@rule(id="API8-DEBUG", group="API OWASP Top 10", title="Debug / diagnostic endpoint exposed",
      description="A debug or configuration endpoint answers on the public entry point and leaks internal "
                  "details (routes, hosts, settings).",
      risk="recon", likelihood=4, impact=3, owasp="API8:2023 Security Misconfiguration",
      cwe=["CWE-489", "CWE-215"], attack=["T1595.003"], nist=["SP 800-204"],
      mitigation=["Remove debug handlers from production builds (feature flag off by default).",
                  "If needed for ops, bind them to a separate admin port that is not routed."])
def api8_debug(ctx: Context):
    for e in ctx.endpoints:
        if DEBUG_PATH.search(e["path"]) and (e["public_paths"] or e["auth_observed"]["anonymous_success"]):
            yield Hit(e["id"], f"{ctx.label(e)} is reachable at {', '.join(e['public_paths']) or 'inside the cluster'}",
                      [f"anonymous 2xx: {e['auth_observed']['anonymous_success']}",
                       f"response fields: {', '.join(list((e['sources'].get('traffic') or {}).get('response_shape') or {})[:6])}"],
                      ctx.sources_of(e), f"Remove {e['path']} from {e['service']} in production.")


@rule(id="API8-PRIV", group="API OWASP Top 10", title="Privileged container",
      description="The container runs privileged, so code execution inside it is close to root on the node.",
      risk="cluster_compromise", likelihood=2, impact=5, owasp="API8:2023 Security Misconfiguration",
      cwe=["CWE-250"], attack=["T1611"], nist=["SP 800-190"],
      mitigation=["Remove privileged: true; grant only the specific capability needed, if any.",
                  "Enforce the Kubernetes 'restricted' Pod Security Standard on the namespace."],
      snippet="securityContext:\n  privileged: false\n  allowPrivilegeEscalation: false\n  runAsNonRoot: true\n  capabilities: {drop: [ALL]}")
def api8_priv(ctx: Context):
    for s in ctx.services.values():
        if s["container_flags"]["privileged"]:
            yield Hit(s["id"], f"{s['name']} runs with privileged: true", ["securityContext.privileged: true"],
                      ["infrastructure"], f"Drop privileged mode for {s['name']}.")


@rule(id="API8-ROOT", group="API OWASP Top 10", title="Container can run as root",
      description="Nothing stops the container process from running as UID 0 (runAsUser: 0, or no runAsNonRoot).",
      risk="cluster_compromise", likelihood=2, impact=3, owasp="API8:2023 Security Misconfiguration",
      cwe=["CWE-250"], attack=["T1611"], nist=["SP 800-190"],
      mitigation=["Set runAsNonRoot: true and a non-zero runAsUser.", "Build images with a non-root USER."])
def api8_root(ctx: Context):
    for s in ctx.services.values():
        f = s["container_flags"]
        if f["explicit_root"] or f["root_not_prevented"]:
            yield Hit(s["id"], f"{s['name']} " + ("sets runAsUser: 0" if f["explicit_root"] else "does not set runAsNonRoot"),
                      ["runAsUser: 0" if f["explicit_root"] else "runAsNonRoot missing"], ["infrastructure"],
                      f"Run {s['name']} as a non-root user.",
                      impact_adj=[(+1, "explicitly root")] if f["explicit_root"] else [],
                      confidence="high" if f["explicit_root"] else "medium")


@rule(id="API8-NODEPORT", group="API OWASP Top 10", title="Service exposed directly, bypassing the gateway",
      description="A NodePort / LoadBalancer service makes the backend reachable on every node, skipping the "
                  "gateway's routing and authentication.",
      risk="financial_fraud", likelihood=3, impact=4, owasp="API8:2023 Security Misconfiguration",
      cwe=["CWE-284"], attack=["T1190"], nist=["SP 800-204"],
      mitigation=["Change the Service to ClusterIP; reach it only through the gateway.",
                  "If node access is needed, firewall the node port to known sources."],
      snippet="spec:\n  type: ClusterIP   # was NodePort", exposure_sensitive=False)
def api8_nodeport(ctx: Context):
    for s in ctx.services.values():
        if s["node_port"] and s["role"] != "gateway":
            yield Hit(s["id"], f"{s['name']} is published on every node", [v for v in s["exposure"]["via"] if "NodePort" in v or "LoadBalancer" in v],
                      ["infrastructure"], f"Make {s['name']} ClusterIP-only.",
                      risk="financial_fraud" if s["name"].startswith("pay") else "data_breach")


@rule(id="API8-NETPOL", group="API OWASP Top 10", title="No network segmentation for the service",
      description="No NetworkPolicy selects this workload, so every pod in the cluster can call it. One "
                  "compromised pod can move laterally.",
      risk="cluster_compromise", likelihood=2, impact=3, owasp="API8:2023 Security Misconfiguration",
      cwe=["CWE-284"], attack=["T1210"], nist=["SP 800-207", "SP 800-204"],
      mitigation=["Add a default-deny NetworkPolicy for the namespace, then allow only the callers seen in traces."],
      snippet="kind: NetworkPolicy\nspec:\n  podSelector: {matchLabels: {app: payment-service}}\n  ingress:\n  - from:\n    - podSelector: {matchLabels: {app: order-service}}",
      exposure_sensitive=False)
def api8_netpol(ctx: Context):
    callers = {}
    for d in ctx.d["dependencies"]:
        callers.setdefault(d["to"], set()).add(d["from"])
    for s in ctx.services.values():
        if s["in_manifests"] and not s["network_policy"]["present"]:
            allowed = sorted(callers.get(s["name"], []))
            yield Hit(s["id"], f"{s['name']} accepts traffic from any pod",
                      ["no NetworkPolicy selects this workload",
                       f"callers seen in traces: {', '.join(allowed) or 'none (only external clients)'}"],
                      ["infrastructure", "callchain"],
                      f"Add a NetworkPolicy for {s['name']} allowing only: {', '.join(allowed) or 'the ingress controller'}.")


@rule(id="API8-TAG", group="API OWASP Top 10", title="Mutable image tag",
      description="The image uses :latest (or no tag), so what runs can change without a deploy and cannot be "
                  "traced to a reviewed build.",
      risk="cluster_compromise", likelihood=2, impact=3, owasp="API8:2023 Security Misconfiguration",
      cwe=["CWE-1357"], attack=["T1525"], nist=["SP 800-190"],
      mitigation=["Pin images by version and digest (image@sha256:...).", "Admit only signed images."],
      exposure_sensitive=False)
def api8_tag(ctx: Context):
    for s in ctx.services.values():
        if s["container_flags"]["mutable_tag"]:
            yield Hit(s["id"], f"{s['name']} uses image {s['image']}", [f"image: {s['image']}"], ["infrastructure"],
                      f"Pin the {s['name']} image to a digest.")


@rule(id="API9-SHADOW", group="API OWASP Top 10", title="Shadow endpoint (running, not documented)",
      description="The endpoint receives traffic but is in no API specification, so it was never part of a "
                  "design review.",
      risk="recon", likelihood=3, impact=3, owasp="API9:2023 Improper Inventory Management",
      cwe=["CWE-1059"], attack=["T1190"], nist=["SP 800-204"],
      mitigation=["Either document the endpoint (and review it) or remove it.",
                  "Fail CI when a service serves routes missing from its spec (compare traffic with spec)."])
def api9_shadow(ctx: Context):
    for e in ctx.endpoints:
        if e["inventory_status"] == "shadow":
            sens = HIGH_VALUE_DATA & set(e["data_classes"]) or ("financial" in e["data_classes"])
            yield Hit(e["id"], f"{ctx.label(e)} is served but in no spec",
                      [f"seen in: {', '.join(e['seen_in'])}", "spec: none"], ctx.sources_of(e, "openapi"),
                      f"Document or remove {e['method']} {e['path']} in {e['service']}.",
                      impact_adj=[(+1, "returns sensitive data")] if sens else [],
                      risk="data_breach" if sens else "recon")


@rule(id="API9-ZOMBIE", group="API OWASP Top 10", title="Deprecated endpoint still in use",
      description="The spec marks the operation deprecated, but clients still call it, so it cannot be removed "
                  "and keeps receiving less attention.",
      risk="data_breach", likelihood=2, impact=3, owasp="API9:2023 Improper Inventory Management",
      cwe=["CWE-477"], attack=["T1190"], nist=["SP 800-204"],
      mitigation=["Find the remaining callers (traces show them), migrate them, then remove the operation.",
                  "Add a sunset date and log every call until removal."])
def api9_zombie(ctx: Context):
    for e in ctx.endpoints:
        if e["inventory_status"] == "zombie":
            hits = (e["sources"].get("traffic") or {}).get("hits", 0)
            yield Hit(e["id"], f"{ctx.label(e)} is deprecated but got {hits} calls",
                      ["spec: deprecated: true", f"{hits} calls observed"], ctx.sources_of(e),
                      f"Migrate callers off {e['method']} {e['path']} and remove it.")


@rule(id="API9-NOSPEC", group="API OWASP Top 10", title="Service publishes no current API specification",
      description="The service exposes no live spec. Any spec file in the repo is out of date, so reviews work "
                  "from the wrong picture.",
      risk="recon", likelihood=2, impact=2, owasp="API9:2023 Improper Inventory Management",
      cwe=["CWE-1059"], attack=["T1190"], nist=["SP 800-95"], exposure_sensitive=False,
      mitigation=["Generate the spec from code and publish it on an internal path.",
                  "Check spec vs. traffic in CI so the spec cannot drift."])
def api9_nospec(ctx: Context):
    for s in ctx.services.values():
        if s["role"] == "gateway" or s["spec"]["live"]:
            continue
        eps = [e for e in ctx.endpoints if e["service"] == s["name"]]
        documented = [e for e in eps if "spec" in e["sources"]]
        yield Hit(s["id"], f"{s['name']}: no live spec; {len(documented)} of {len(eps)} endpoints documented anywhere",
                  ["live probes: no spec found", "spec file: " + ("present but stale" if s["spec"]["file"] else "none")],
                  ["openapi", "runtime_traffic"], f"Publish an up-to-date spec for {s['name']}.")


@rule(id="API10", group="API OWASP Top 10", title="Calls to a third-party API seen in traces",
      description="A service calls a host outside the system. Data from it should be validated like user input.",
      risk="data_breach", likelihood=2, impact=3, owasp="API10:2023 Unsafe Consumption of APIs",
      cwe=["CWE-20"], attack=["T1195"], nist=["SP 800-204"], exposure_sensitive=False,
      mitigation=["Validate and size-limit third-party responses; use TLS and timeouts.",
                  "Keep an inventory of third-party APIs and their data."])
def api10(ctx: Context):
    for d in ctx.d["dependencies"]:
        if d["to"] not in ctx.services and d["evidence"] == "trace":
            s = ctx.services.get(d["from"], {})
            yield Hit(s.get("id", f"svc:{d['from']}"), f"{d['from']} calls external {d['to']}",
                      [f"{d['calls']} calls: {', '.join(d['operations'])}"], ["callchain"],
                      f"Validate responses from {d['to']} in {d['from']}.", confidence="medium")


# =============================================================================
# Logging and tracing
# =============================================================================
@rule(id="LT-01", group="Logging and tracing", title="Calls from an unidentified internal caller",
      description="Traces start at this backend endpoint, so the caller is not instrumented and did not come "
                  "through the gateway. Monitoring cannot say who made these calls.",
      risk="detection_gap", likelihood=3, impact=3, owasp="API9:2023 Improper Inventory Management",
      cwe=["CWE-778"], attack=["T1210"], nist=["SP 800-204", "SP 800-207"], exposure_sensitive=False,
      mitigation=["Instrument every job and client that calls internal APIs (propagate traceparent).",
                  "Require caller identity on internal endpoints so logs name the caller."])
def lt01(ctx: Context):
    for ent in ctx.d["entrypoints"]:
        if not ent["from_outside_gateway"]:
            continue
        method, _, path = ent["operation"].partition(" ")
        e = next((x for x in ctx.endpoints if x["service"] == ent["service"] and x["method"] == method and x["path"] == path), None)
        target = e["id"] if e else ctx.services.get(ent["service"], {}).get("id", f"svc:{ent['service']}")
        sens = e and (HIGH_VALUE_DATA & set(e["data_classes"]))
        yield Hit(target, f"{ent['traces']} trace(s) start at {ent['service']} {ent['operation']} with no traced caller",
                  [f"{ent['traces']} root spans at {ent['service']}", "no parent span from the gateway or another service"],
                  ["callchain"], f"Identify and instrument the caller of {ent['operation']}.",
                  impact_adj=[(+1, "the unidentified caller reads personal data")] if sens else [])


@rule(id="LT-02", group="Logging and tracing", title="Workload not visible in traces",
      description="The service is deployed but produced no spans, so its activity is invisible to tracing.",
      risk="detection_gap", likelihood=2, impact=2, owasp="API9:2023 Improper Inventory Management",
      cwe=["CWE-778"], attack=["T1562"], nist=["SP 800-204"], exposure_sensitive=False,
      mitigation=["Add OpenTelemetry instrumentation (auto-instrumentation is usually enough)."])
def lt02(ctx: Context):
    traced = {s["service"] for s in ctx.d.get("trace_services", [])} or {
        e["service"] for e in ctx.endpoints if "trace" in e["sources"]} | {d["from"] for d in ctx.d["dependencies"] if d["evidence"] == "trace"}
    for s in ctx.services.values():
        if s["in_manifests"] and s["name"] not in traced:
            yield Hit(s["id"], f"{s['name']} is deployed but emitted no spans", ["0 spans in trace data"],
                      ["infrastructure", "callchain"], f"Instrument {s['name']} with OpenTelemetry.")


@rule(id="LT-03", group="Logging and tracing", title="Endpoint seen in traffic but missing from traces",
      description="Requests reached the endpoint but no span recorded them: a blind spot in tracing.",
      risk="detection_gap", likelihood=2, impact=2, owasp="API9:2023 Improper Inventory Management",
      cwe=["CWE-778"], attack=["T1562"], nist=["SP 800-204"], exposure_sensitive=False,
      mitigation=["Make sure the tracing middleware wraps every route, including error and fallback handlers."])
def lt03(ctx: Context):
    for e in ctx.endpoints:
        pub = e["sources"].get("public_traffic")
        # gateway-only evidence counts when some request got past the gateway (not only 401/403 there)
        reached = pub if pub and set(pub["status_codes"]) - {"401", "403", "404", "405", "None"} else None
        seen = e["sources"].get("traffic") or reached
        if seen and "trace" not in e["sources"]:
            yield Hit(e["id"], f"{ctx.label(e)}: {seen['hits']} requests, 0 spans",
                      ["traffic: yes", "trace: no"], ["runtime_traffic", "callchain"],
                      f"Add tracing to {e['path']} in {e['service']}.")


@rule(id="LT-04", group="Logging and tracing", title="Server errors observed",
      description="The endpoint returned 5xx responses or error spans; errors can leak details and hide failures.",
      risk="service_disruption", likelihood=2, impact=2, owasp="API8:2023 Security Misconfiguration",
      cwe=["CWE-755"], attack=["T1499"], nist=["SP 800-204"],
      mitigation=["Return generic error bodies; log the detail server-side with the trace ID.",
                  "Alert on 5xx rate per endpoint."])
def lt04(ctx: Context):
    for e in ctx.endpoints:
        codes = e.get("status_observed") or (e["sources"].get("traffic") or {}).get("status_codes", {})
        n5 = sum(v for k, v in codes.items() if k.startswith("5"))
        nerr = (e["sources"].get("trace") or {}).get("errors", 0)
        if n5 or nerr:
            yield Hit(e["id"], f"{ctx.label(e)}: {n5} x 5xx, {nerr} error spans", [f"status codes: {codes}"],
                      ctx.sources_of(e), f"Handle errors in {e['path']} and alert on them.")


def catalog() -> list[dict]:
    return [{k: getattr(r, k) for k in ("id", "group", "title", "description", "risk", "likelihood", "impact",
                                         "owasp", "cwe", "attack", "nist", "mitigation", "snippet")} for r in RULES]
