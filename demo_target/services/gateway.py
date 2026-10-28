"""
api-gateway  (port 8000) - the only thing the Ingress exposes.

Routing rules are NOT hardcoded. They are read from the same Kubernetes
ConfigMap the infra extractor parses (demo_target/k8s/gateway.yaml), so the
"gateway discovery" output and the gateway's real behaviour cannot drift.
"""
import os
from pathlib import Path

import yaml
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from common import HARDENED, ServiceKit

app = FastAPI(title="api-gateway", openapi_url=None, docs_url=None)
kit = ServiceKit(app, "api-gateway")

CONFIG_PATH = Path(os.environ.get("GATEWAY_CONFIG", "demo_target/k8s/gateway.yaml"))


def load_routes() -> list[dict]:
    for doc in yaml.safe_load_all(CONFIG_PATH.read_text()):
        if not doc:
            continue
        if "routes" in doc:  # mounted routes.yaml inside a real cluster
            return doc["routes"]
        if doc.get("kind") == "ConfigMap" and "routes.yaml" in doc.get("data", {}):
            return yaml.safe_load(doc["data"]["routes.yaml"])["routes"]
    raise RuntimeError(f"no gateway routes ConfigMap in {CONFIG_PATH}")


ROUTES = sorted(load_routes(), key=lambda r: len(r["prefix"]), reverse=True)
FORWARD_HEADERS = {"authorization", "content-type", "accept"}  # never forward X-Service-Token from outside


@app.get("/health")
def health():
    return {"ok": True}


# Leftover debug endpoint: dumps the routing table, including upstream hosts.
# The hardened build does not register it.
if not HARDENED:
    @app.get("/_debug/config")
    def debug_config():
        return {"routes": ROUTES, "service_hosts": os.environ.get("SERVICE_HOSTS", "")}


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy(full_path: str, request: Request):
    path = "/" + full_path
    route = next((r for r in ROUTES if path.startswith(r["prefix"])), None)
    if route is None:
        request.state.route_override = "(no route)"
        return JSONResponse({"error": "no route"}, status_code=404)
    request.state.route_override = route["prefix"] + "/**"

    if route.get("auth") == "required" and "authorization" not in request.headers:
        request.state.gt_denied = True
        return JSONResponse({"error": "missing token"}, status_code=401)

    upstream_path = path[len(route.get("strip_prefix", "")):] or "/"
    headers = {k: v for k, v in request.headers.items() if k.lower() in FORWARD_HEADERS}
    resp = kit.call(
        request.method,
        route["upstream"].rstrip("/") + upstream_path,
        route["service"],
        headers=headers,
        params=dict(request.query_params),
        content=await request.body(),
    )
    return Response(
        content=resp.content,
        status_code=resp.status_code,
        media_type=resp.headers.get("content-type"),
    )
