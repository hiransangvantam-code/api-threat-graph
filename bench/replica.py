"""
API-surface replica of a mined testbed (bench/testbeds/<name>/topology.yaml).

Every service of the original system becomes an HTTP server on its own port
that:
  - serves exactly the routes mined from the original source code
  - answers 401 to requests without an Authorization header on routes the
    original's security configuration protects
  - makes the downstream calls found at the original's call sites
    (through the mesh proxy when the service has a "sidecar")
  - emits OpenTelemetry server/client spans with http.route templates, unless
    the service is listed as uninstrumented
  - publishes /v2/api-docs (Swagger 2.0, as springfox does) when the original
    service enables Swagger
A gateway forwards public paths using the original route table (Spring Cloud
Gateway or nginx). Business logic is NOT replicated.

Each server also writes its own access log (--gt-log): the ground truth of what
actually ran, independent of the extractors under evaluation.

usage: python bench/replica.py --testbed trainticket --base-port 9200 --run-dir DIR
                              [--mesh-proxy URL] [--untraced a,b] [--no-sidecar a,b]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import re
import signal
import sys
import time
import zlib
from pathlib import Path

import httpx
import uvicorn
from opentelemetry import propagate
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.trace import NoOpTracer, SpanKind, Status, StatusCode
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "demo_target/services"))
sys.path.insert(0, str(ROOT))
from common import OTLPJsonFileExporter  # noqa: E402  (demo_target/services/common.py)

from bench.common import fill, load_topology, response_body, route_matches  # noqa: E402

CALLER_HEADER = "x-bench-caller"


class Service:
    def __init__(self, name, port, endpoints, run_dir: Path, traced: bool, mesh: str | None,
                 ports: dict, swagger: bool, ids: str, namespace: str):
        self.name, self.port, self.endpoints = name, port, endpoints
        self.ports, self.ids, self.swagger = ports, ids, swagger
        self.traced = traced
        self.rnd = random.Random(zlib.crc32(name.encode()))
        self.log = (run_dir / "gt" / f"{name}.jsonl").open("a", encoding="utf-8", buffering=1)
        if traced:
            provider = TracerProvider(resource=Resource.create({"service.name": name, "service.namespace": namespace}))
            provider.add_span_processor(SimpleSpanProcessor(OTLPJsonFileExporter(run_dir / "telemetry" / f"{name}.jsonl")))
            self.tracer = provider.get_tracer("bench-replica")
        else:
            self.tracer = NoOpTracer()
        self.http = httpx.AsyncClient(proxy=mesh, trust_env=False, timeout=15,
                                      limits=httpx.Limits(max_connections=50))

    # ---------------------------------------------------------------- server side
    def app(self) -> Starlette:
        by_path: dict[str, dict] = {}
        for e in self.endpoints:
            by_path.setdefault(e["path"], {})[e["method"]] = e
        # literal segments before {params}, so /orders/all wins over /orders/{id}
        order = sorted(by_path, key=lambda p: (p.count("{"), [s.startswith("{") for s in p.split("/")], -len(p)))
        routes = [Route(p, self.handler(p, by_path[p]), methods=list(by_path[p])) for p in order]
        if self.swagger:
            routes.insert(0, Route("/v2/api-docs", self.api_docs, methods=["GET"]))
        app = Starlette(routes=routes)
        app.add_exception_handler(404, self.not_found)
        app.add_exception_handler(405, self.not_found)
        return app

    async def not_found(self, request: Request, exc):
        self._log(request, "(no route)", 404, None)
        return JSONResponse({"error": "not found"}, status_code=404)

    def _log(self, request: Request, route: str, status: int, caller):
        self.log.write(json.dumps({
            "ts": time.time(), "service": self.name, "method": request.method, "route": route,
            "path": request.url.path, "status": status, "auth": "authorization" in request.headers,
            "caller": caller, "ua": request.headers.get("user-agent", "")[:60]}) + "\n")

    def handler(self, path: str, methods: dict):
        async def handle(request: Request):
            ep = methods[request.method]
            caller = request.headers.get(CALLER_HEADER)
            ctx = propagate.extract(dict(request.headers)) if self.traced else None
            with self.tracer.start_as_current_span(f"{request.method} {path}", context=ctx, kind=SpanKind.SERVER) as span:
                if ep.get("auth") == "required" and "authorization" not in request.headers:
                    status, body = 401, {"error": "unauthorized"}
                else:
                    for c in ep.get("calls", []):
                        await self.call(c, request.headers.get("authorization"))
                    status, body = 200, response_body(request.method, path)
                span.set_attribute("http.request.method", request.method)
                span.set_attribute("http.route", path)
                span.set_attribute("url.path", request.url.path)
                span.set_attribute("http.response.status_code", status)
                span.set_attribute("user_agent.original", request.headers.get("user-agent", ""))
            self._log(request, path, status, caller)
            return JSONResponse(body, status_code=status)
        return handle

    async def api_docs(self, request: Request):
        paths: dict = {}
        for e in self.endpoints:
            params = [{"name": n, "in": "path", "required": True, "type": "string"} for n in re.findall(r"\{([^}]*)\}", e["path"])]
            paths.setdefault(e["path"], {})[e["method"].lower()] = {
                "operationId": f"{e['method'].lower()}_{re.sub(r'[^a-zA-Z0-9]+', '_', e['path']).strip('_')}",
                "parameters": params, "responses": {"200": {"description": "OK"}}}
        self._log(request, "/v2/api-docs", 200, None)
        return JSONResponse({"swagger": "2.0", "info": {"title": self.name, "version": "1.0"},
                             "host": f"{self.name}:{self.port}", "basePath": "/", "paths": paths})

    # ---------------------------------------------------------------- client side
    async def call(self, c: dict, auth: str | None):
        port = self.ports.get(c["service"])
        if not port:
            return
        url = f"http://127.0.0.1:{port}{fill(c['path'], self.rnd, self.ids)}"
        headers = {CALLER_HEADER: self.name, "user-agent": f"{self.name}/replica"}
        if auth:
            headers["authorization"] = auth
        with self.tracer.start_as_current_span(f"{c['method']} {c['service']}", kind=SpanKind.CLIENT) as span:
            if self.traced:
                propagate.inject(headers)
            span.set_attribute("http.request.method", c["method"])
            span.set_attribute("peer.service", c["service"])
            span.set_attribute("server.address", "127.0.0.1")
            span.set_attribute("server.port", port)
            try:
                r = await self.http.request(c["method"], url, headers=headers,
                                            json={"ref": "bench"} if c["method"] in ("POST", "PUT", "PATCH") else None)
                span.set_attribute("http.response.status_code", r.status_code)
            except httpx.HTTPError:
                span.set_status(Status(StatusCode.ERROR))


class Gateway(Service):
    def __init__(self, name, port, routes, run_dir, traced, mesh, ports, namespace):
        super().__init__(name, port, [], run_dir, traced, mesh, ports, False, "uuid", namespace)
        self.routes = sorted(routes, key=lambda r: len(r["path"]), reverse=True)

    def app(self) -> Starlette:
        async def ready(request: Request):
            return JSONResponse({"ok": True})

        async def forward(request: Request):
            path = request.url.path
            r = next((r for r in self.routes if route_matches(r["path"], path)), None)
            if r is None:
                self._log(request, "(no route)", 404, None)
                return JSONResponse({"error": "no route"}, status_code=404)
            pattern = r["path"] if r["path"].endswith("**") else r["path"].rstrip("/") + "/**"
            ctx = propagate.extract(dict(request.headers)) if self.traced else None
            with self.tracer.start_as_current_span(f"{request.method} {pattern}", context=ctx, kind=SpanKind.SERVER) as span:
                headers = {k: v for k, v in request.headers.items() if k in ("authorization", "content-type", "accept", "user-agent")}
                headers[CALLER_HEADER] = self.name
                with self.tracer.start_as_current_span(f"{request.method} {r['service']}", kind=SpanKind.CLIENT) as cs:
                    if self.traced:
                        propagate.inject(headers)
                    cs.set_attribute("peer.service", r["service"])
                    try:
                        resp = await self.http.request(request.method, f"http://127.0.0.1:{self.ports[r['service']]}{path}",
                                                       params=dict(request.query_params), headers=headers,
                                                       content=await request.body())
                        status, content, ctype = resp.status_code, resp.content, resp.headers.get("content-type")
                    except (httpx.HTTPError, KeyError):
                        status, content, ctype = 502, b'{"error":"bad gateway"}', "application/json"
                span.set_attribute("http.request.method", request.method)
                span.set_attribute("http.route", pattern)
                span.set_attribute("url.path", path)
                span.set_attribute("http.response.status_code", status)
                span.set_attribute("user_agent.original", request.headers.get("user-agent", ""))
            self._log(request, pattern, status, None)
            return Response(content, status_code=status, media_type=ctype)

        return Starlette(routes=[Route("/__replica/ready", ready),
                                 Route("/{p:path}", forward, methods=["GET", "POST", "PUT", "DELETE", "PATCH"])])


class _Server(uvicorn.Server):
    def capture_signals(self):  # several servers share one process; we handle signals ourselves
        import contextlib
        return contextlib.nullcontext()


async def main_async(a):
    topo = load_topology(a.testbed)
    run_dir = Path(a.run_dir)
    for d in ("gt", "telemetry"):
        (run_dir / d).mkdir(parents=True, exist_ok=True)
    untraced = set(filter(None, a.untraced.split(",")))
    no_sidecar = set(filter(None, a.no_sidecar.split(",")))
    gw = topo["gateway"]
    names = [gw["service"]] + [s["name"] for s in topo["services"]]
    ports = {n: a.base_port + i for i, n in enumerate(names)}
    (run_dir / "ports.json").write_text(json.dumps(ports, indent=1))
    ids = topo.get("id_style", "uuid")
    ns = topo["name"]
    mesh = lambda n: None if (not a.mesh_proxy or n in no_sidecar) else a.mesh_proxy  # noqa: E731
    apps = [(Gateway(gw["service"], ports[gw["service"]], gw["routes"], run_dir,
                     gw["service"] not in untraced and not gw.get("uninstrumented"), mesh(gw["service"]), ports, ns))]
    for s in topo["services"]:
        live = s.get("documented") is True and topo.get("documentation") == "live-swagger"
        apps.append(Service(s["name"], ports[s["name"]], s["endpoints"], run_dir, s["name"] not in untraced,
                            mesh(s["name"]), ports, live, ids, ns))
    servers = [_Server(uvicorn.Config(svc.app(), host="127.0.0.1", port=svc.port, log_level="warning",
                                      access_log=False, lifespan="off")) for svc in apps]

    def stop(*_):
        for s in servers:
            s.should_exit = True
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop)
        except NotImplementedError:  # Windows
            signal.signal(sig, stop)
    await asyncio.gather(*(s.serve() for s in servers))
    for svc in apps:
        svc.log.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--testbed", required=True)
    ap.add_argument("--base-port", type=int, default=9200)
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--mesh-proxy", default="")
    ap.add_argument("--untraced", default="")
    ap.add_argument("--no-sidecar", default="")
    asyncio.run(main_async(ap.parse_args()))


if __name__ == "__main__":
    main()
