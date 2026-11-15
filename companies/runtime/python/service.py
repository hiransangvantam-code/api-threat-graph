"""
One service of a test company, Python version (Starlette + the OpenTelemetry SDK).

Every company in companies/ is described by a company.json file (written by
companies/build.py). Each container runs this program with SERVICE=<name> and
plays that service:

  gateway        the company's API gateway: routes by path prefix, checks that a
                 credential is present on routes that need one (asking the auth
                 service whose session it is), applies rate limits, and forwards to
                 the backend through MESH_PROXY (the review sidecar)
  auth service   POST /auth/session and GET /auth/introspect, plus any routes it has
  any other      the routes listed for it: authentication and role checks, owner
                 checks, calls to other services and to outside APIs, errors

Users are c1..c20 (customers), staff1..staff3 and p1..p3 (partners). The demo login
takes only a user name, so the test harness holds no passwords; sessions are random
values made at run time and kept in the auth service's memory. Personal fields in
responses are always "***".

Spans go to OTEL_EXPORTER_OTLP_ENDPOINT over OTLP/HTTP (protobuf), with the current
semantic-convention attribute names (http.request.method, http.route, url.path).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import time
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlencode

import httpx
import uvicorn
from opentelemetry import propagate, trace
from opentelemetry.trace import SpanKind, Status, StatusCode
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

CFG = json.loads(Path(os.environ.get("COMPANY", "/company/company.json")).read_text(encoding="utf-8"))
NAME = os.environ["SERVICE"]
GW = CFG.get("gateway") or {"name": None, "routes": []}    # a system may have no gateway workload
AUTH = CFG.get("auth_service") or {}                          # ... and no login at all
AUTH_LOGIN = AUTH.get("login", {"method": "POST", "path": "/auth/session"})
AUTH_CHECK = AUTH.get("introspect", "/auth/introspect")
COOKIE = AUTH.get("cookie", "sid")
# "signed" sessions (like a JWT): user.role.signature, checked locally by every service with a
# key that a start-up container wrote at random into a shared volume. Nothing is pre-shared.
SIGNED = AUTH.get("token") == "signed"
SERVICE_KEY = secrets.token_hex(16)        # this process's own key for "key"-protected services


def _key() -> bytes:
    return Path(os.environ.get("TOKEN_KEY_FILE", "/keys/token-key")).read_bytes().strip()


def sign(user: str, role: str) -> str:
    return f"{user}.{role}." + hmac.new(_key(), f"{user}|{role}".encode(), hashlib.sha256).hexdigest()[:32]


def verify(token: str):
    parts = token.split(".")
    if len(parts) == 3 and hmac.compare_digest(sign(parts[0], parts[1]), token):
        return parts[0], parts[1]
    return None
ME = GW if NAME == GW["name"] else CFG["services"][NAME]
PORT = int(os.environ.get("PORT") or ME["port"])
MESH = os.environ.get("MESH_PROXY") or None
USER_RE = re.compile(r"^(c([1-9]|1[0-9]|20)|staff[1-3]|p[1-3])$")

# ---------------------------------------------------------------- tracing
if ME.get("traced", True) and os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    _provider = TracerProvider(resource=Resource.create({"service.name": NAME, "service.namespace": CFG["id"]}))
    _provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(), schedule_delay_millis=500))
    TRACER = _provider.get_tracer(f"{CFG['id']}-runtime-python")
    TRACED = True
else:
    TRACER = trace.NoOpTracer()
    TRACED = False

mesh = httpx.AsyncClient(proxy=MESH, trust_env=False, timeout=10)   # east-west calls: through the sidecar
direct = httpx.AsyncClient(trust_env=False, timeout=5)               # outside APIs: straight out


# ---------------------------------------------------------------- helpers shared with the other runtimes
def role_of(user: str) -> str:
    return "staff" if user.startswith("staff") else "partner" if user.startswith("p") else "customer"


def owner_of(value: str) -> str:
    """Objects belong to customers by number: id 1000 -> c1, 1001 -> c2, ..., 1020 -> c1."""
    digits = re.sub(r"\D", "", str(value))
    return f"c{int(digits) % 20 + 1}" if digits else "c1"


def render(t, params: dict, owner: str, user: str, n: int):
    if isinstance(t, dict):
        return {k: render(v, params, owner, user, n) for k, v in t.items()}
    if isinstance(t, list):
        return [render(t[0], params, owner, user, n * 10 + i) for i in range(2)] if t else []
    if isinstance(t, str) and t.startswith("$"):
        key = t[1:]
        if key == "owner":
            return owner
        if key == "user":
            return user or "anonymous"
        if key == "n":
            return n
        v = params.get(key, t)
        return int(v) if isinstance(v, str) and v.isdigit() else v
    return t


def fill(path: str, params: dict) -> str:
    return re.sub(r"{([^}]+)}", lambda m: str(params.get(m.group(1), "1")), path)


def server_span(req: Request, route: str):
    ctx = propagate.extract(dict(req.headers)) if TRACED else None
    return TRACER.start_as_current_span(f"{req.method} {route}", context=ctx, kind=SpanKind.SERVER)


def end_server_span(span, req: Request, route: str, status: int) -> None:
    span.set_attribute("http.request.method", req.method)
    span.set_attribute("http.route", route)
    span.set_attribute("url.path", req.url.path)
    span.set_attribute("http.response.status_code", status)
    span.set_attribute("user_agent.original", req.headers.get("user-agent", ""))
    if status >= 500:
        span.set_status(Status(StatusCode.ERROR))


async def call(client: httpx.AsyncClient, method: str, url: str, peer: str, headers: dict, body=None) -> httpx.Response:
    u = httpx.URL(url)
    with TRACER.start_as_current_span(f"{method} {peer}", kind=SpanKind.CLIENT) as span:
        headers = dict(headers)
        if TRACED:
            propagate.inject(headers)
        span.set_attribute("http.request.method", method)
        span.set_attribute("peer.service", peer)
        span.set_attribute("server.address", u.host)
        span.set_attribute("server.port", u.port or 80)
        span.set_attribute("url.full", str(u.copy_with(query=None)))
        try:
            r = await client.request(method, url, headers=headers, json=body)
        except httpx.HTTPError:
            span.set_status(Status(StatusCode.ERROR))
            return httpx.Response(502)
        span.set_attribute("http.response.status_code", r.status_code)
        if r.status_code >= 500:
            span.set_status(Status(StatusCode.ERROR))
        return r


def json_response(status: int, body, headers: dict | None = None) -> Response:
    return JSONResponse(body, status_code=status, headers=headers)


# ---------------------------------------------------------------- the auth service's own endpoints
SESSIONS: dict[str, tuple[str, str]] = {}


def bearer(req: Request) -> str | None:
    h = req.headers.get("authorization", "")
    return h[7:] if h.lower().startswith("bearer ") else None


async def login(req: Request) -> Response:
    with server_span(req, AUTH_LOGIN["path"]) as span:
        field = AUTH.get("user_field", "user")
        user = req.query_params.get(field, "")
        if not user and req.method != "GET":
            try:
                body = await req.json()
            except ValueError:
                body = dict(await req.form())
            user = str(body.get(field, ""))
        if not USER_RE.match(user):
            status, resp = 401, json_response(401, {"error": "unknown user"})
        else:
            token = sign(user, role_of(user)) if SIGNED else secrets.token_hex(16)
            SESSIONS[token] = (user, role_of(user))
            if CFG["credential"] == "cookie":
                body = {"user": user, "role": role_of(user)}
                if AUTH.get("token_in_body"):     # the auth service answers a front end, which sets the cookie
                    body["access_token"] = token
                resp = json_response(200, body)
                resp.set_cookie(COOKIE, token, httponly=True, samesite="lax")
            else:
                resp = json_response(200, {"user": user, "role": role_of(user), "access_token": token, "token_type": "Bearer"})
            status = 200
        end_server_span(span, req, AUTH_LOGIN["path"], status)
        return resp


async def introspect(req: Request) -> Response:
    with server_span(req, AUTH_CHECK) as span:
        who = SESSIONS.get(bearer(req) or "")
        status = 200 if who else 401
        end_server_span(span, req, AUTH_CHECK, status)
        return json_response(status, {"user": who[0], "role": who[1], "active": True} if who else {"active": False})


# ---------------------------------------------------------------- a backend route
COUNT: dict[str, int] = defaultdict(int)


def make_handler(r: dict):
    async def handler(req: Request) -> Response:
        with server_span(req, r["path"]) as span:
            status, body = await serve(req, r)
            end_server_span(span, req, r["path"], status)
            if r.get("login_proxy") and status == 200 and CFG["credential"] == "cookie" and "access_token" in body:
                resp = json_response(status, {k: v for k, v in body.items() if k != "access_token"})
                resp.set_cookie(COOKIE, body["access_token"], httponly=True, samesite="lax")
                return resp
            return json_response(status, body)
    return handler


async def serve(req: Request, r: dict):
    key = f"{r['method']} {r['path']}"
    COUNT[key] += 1
    n = COUNT[key]
    params = dict(req.path_params)
    if r.get("errors_every") and n % r["errors_every"] == 0:
        return 500, {"error": "internal error"}
    if r.get("login_proxy"):     # a front end that forwards the login to the auth service
        return await proxy_login(req)
    if r["auth"] == "key" and not req.headers.get("authorization"):
        return 401, {"error": "API key required"}
    user, role = req.headers.get("x-user-id", ""), req.headers.get("x-user-role", "")
    if not user and ME.get("verify") == "self" and r["auth"] != "none":
        # no gateway in front that checked the session: the service checks it itself
        token = credential(req)
        who = await identify(token) if token else None
        if who:
            user, role = who
    if r["auth"] not in ("none", "key"):
        if not user:
            return 401, {"error": "authentication required"}
        if (r["auth"] == "admin" and role != "staff") or (r["auth"] == "partner" and role != "partner"):
            return 403, {"error": "forbidden"}
    owner = owner_of(params[r["owner"]]) if r.get("owner") else (user or "c1")
    if r.get("owner") and r.get("owner_check", True) and role == "customer" and owner != user:
        return 403, {"error": "not your object"}
    fwd = {k: v for k, v in req.headers.items()
           if k in ("authorization", "cookie", "x-api-key", "x-user-id", "x-user-role")}
    for c in r.get("calls", []):
        hdrs = fwd if c.get("forward_auth") else {}
        if c.get("service_key"):
            hdrs = {**hdrs, "authorization": f"Bearer {SERVICE_KEY}"}
        res = await call(mesh, c["method"], f"http://{c['service']}:{c['port']}{fill(c['path'], params)}", c["service"],
                         hdrs, c.get("body"))
        if res.status_code >= 500:
            return 502, {"error": f"{c['service']} failed"}
    for x in r.get("external", []):
        await call(direct, x["method"], f"http://{x['host']}:{x['port']}{x['path']}", x["host"], {})
    return r.get("status", 200), render(r.get("returns") or {"status": "ok"}, params, owner, user, n)


async def proxy_login(req: Request):
    field = AUTH.get("user_field", "user")
    try:
        body = await req.json()
    except ValueError:
        body = dict(await req.form())
    fields = {field: body.get(field, req.query_params.get(field, "")), **AUTH.get("login_extra", {})}
    url = f"http://{AUTH['name']}:{AUTH['port']}{AUTH_LOGIN['path']}"
    r = await call(mesh, AUTH_LOGIN["method"], url + ("?" + urlencode(fields) if AUTH_LOGIN["method"] == "GET" else ""),
                   AUTH["name"], {}, None if AUTH_LOGIN["method"] == "GET" else fields)
    if r.status_code != 200:
        return r.status_code, {"error": "login failed"}
    return 200, r.json()


# ---------------------------------------------------------------- the gateway
RATE: dict[str, list] = defaultdict(lambda: [0.0, 0])
IDENT: dict[str, tuple[str, str] | None] = {}


def credential(req: Request) -> str | None:
    return (bearer(req) or req.headers.get("x-api-key") or req.cookies.get(COOKIE)
            or req.query_params.get("access_token") or None)


async def identify(token: str):
    if SIGNED:
        return verify(token)
    if token not in IDENT:
        r = await call(mesh, "GET", f"http://{AUTH['name']}:{AUTH['port']}{AUTH_CHECK}", AUTH["name"],
                       {"authorization": f"Bearer {token}"})
        IDENT[token] = (r.json()["user"], r.json()["role"]) if r.status_code == 200 else None
    return IDENT[token]


async def gateway(req: Request) -> Response:
    path = req.url.path
    if path == "/health":
        return json_response(200, {"status": "ok"})
    r = next((x for x in GW["routes"] if (path == x["prefix"] or path.startswith(x["prefix"].rstrip("/") + "/"))
              and req.method in x.get("methods", [req.method])), None)
    if r is None:
        return json_response(404, {"error": "no route"})
    route = r["prefix"].rstrip("/") + "/**"
    with server_span(req, route) as span:
        resp = await forward(req, r, path)
        end_server_span(span, req, route, resp.status_code)
        return resp


async def forward(req: Request, r: dict, path: str) -> Response:
    if r.get("limit_per_min"):
        w = RATE[r["prefix"]]
        if time.time() - w[0] > 60:
            w[0], w[1] = time.time(), 0
        w[1] += 1
        if w[1] > r["limit_per_min"]:
            return json_response(429, {"error": "too many requests"})
    token = credential(req)
    ident = await identify(token) if token else None
    if r["auth"] and not ident:
        return json_response(401, {"error": "authentication required"})
    headers = {k: v for k, v in req.headers.items()
               if k in ("authorization", "cookie", "x-api-key", "content-type", "user-agent", "accept")}
    if ident:
        headers["x-user-id"], headers["x-user-role"] = ident
    backend = (r["to"] + path[len(r["from"]):]) or "/"
    url = f"http://{r['service']}:{r['port']}{backend if backend.startswith('/') else '/' + backend}"
    if req.url.query:
        url += "?" + req.url.query
    u = httpx.URL(url)
    with TRACER.start_as_current_span(f"{req.method} {r['service']}", kind=SpanKind.CLIENT) as span:
        if TRACED:
            propagate.inject(headers)
        span.set_attribute("http.request.method", req.method)
        span.set_attribute("peer.service", r["service"])
        span.set_attribute("server.address", u.host)
        span.set_attribute("server.port", u.port or 80)
        try:
            up = await mesh.request(req.method, url, headers=headers, content=await req.body())
        except httpx.HTTPError:
            span.set_status(Status(StatusCode.ERROR))
            return json_response(502, {"error": "upstream unavailable"})
        span.set_attribute("http.response.status_code", up.status_code)
    out = Response(up.content, status_code=up.status_code, media_type=up.headers.get("content-type"))
    if "set-cookie" in up.headers:
        out.headers["set-cookie"] = up.headers["set-cookie"]
    return out


# ---------------------------------------------------------------- app
async def health(_req: Request) -> Response:
    return json_response(200, {"status": "ok", "service": NAME})


def spec_route() -> list[Route]:
    spec = ME.get("spec")
    if not spec:
        return []
    text = Path("/company", spec["file"]).read_bytes()

    async def serve_spec(_req: Request) -> Response:
        return Response(text, media_type=spec["type"])
    return [Route(spec["path"], serve_spec, methods=["GET"])]


def build() -> Starlette:
    if NAME == GW["name"]:
        # the gateway's own handlers (an aggregator endpoint, say) first, then routing
        own = [Route(r["path"], make_handler(r), methods=[r["method"]]) for r in GW.get("own_routes", [])]
        return Starlette(routes=own + [Route("/{path:path}", gateway, methods=["GET", "POST", "PUT", "PATCH", "DELETE"])])
    routes = [Route("/health", health, methods=["GET"])] + spec_route()
    if NAME == AUTH.get("name"):
        routes += [Route(AUTH_LOGIN["path"], login, methods=[AUTH_LOGIN["method"]]),
                   Route(AUTH_CHECK, introspect, methods=["GET"])]
    # literal paths before parameterised ones, so /orders/export wins over /orders/{order_id}
    by_path: dict[str, list] = defaultdict(list)
    for r in ME.get("routes", []):
        by_path[r["path"]].append(r)
    for path in sorted(by_path, key=lambda p: (p.count("{"), -len(p))):
        for r in by_path[path]:
            routes.append(Route(path, make_handler(r), methods=[r["method"]]))
    return Starlette(routes=routes)


app = build()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="warning", access_log=False)
