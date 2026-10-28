"""
Shared plumbing for the ShopLite demo services.

Two things live here:
  1. Tracing: every service emits OpenTelemetry spans. In Docker they go over
     OTLP/HTTP to an OpenTelemetry Collector (set OTEL_EXPORTER_OTLP_ENDPOINT);
     otherwise they are written as OTLP/JSON lines, the same shape the
     Collector's "file" exporter produces, so the call-chain extractor reads
     one real format either way.
  2. Service-to-service HTTP: outgoing calls go through MESH_PROXY when it
     is set. In the demo that is mitmproxy, which plays the role of a
     sidecar and lets us capture east-west traffic too.

Nothing in here is part of the extractor. It only exists so the demo target
behaves like a small, real microservice system.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Sequence

import httpx
from fastapi import FastAPI, Request
from opentelemetry import propagate, trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import (
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
)
from opentelemetry.trace import SpanKind, Status, StatusCode

# ---------------------------------------------------------------------------
# Service discovery for the demo.
#   Local mode : SERVICE_HOSTS="user-service=127.0.0.1:8001,order-service=..."
#   Docker/K8s : leave it unset, DNS resolves the names directly.
# ---------------------------------------------------------------------------
_HOST_MAP: dict[str, str] = {}
for pair in filter(None, os.environ.get("SERVICE_HOSTS", "").split(",")):
    name, _, addr = pair.partition("=")
    _HOST_MAP[name.strip()] = addr.strip()


def resolve(url: str) -> str:
    """Rewrite http://user-service:8001/x to the local address if mapped."""
    u = httpx.URL(url)
    addr = _HOST_MAP.get(u.host)
    if not addr:
        return url
    host, _, port = addr.partition(":")
    return str(u.copy_with(host=host, port=int(port) if port else None))


# ---------------------------------------------------------------------------
# OTLP/JSON file exporter
# ---------------------------------------------------------------------------
_KIND = {
    SpanKind.INTERNAL: 1,
    SpanKind.SERVER: 2,
    SpanKind.CLIENT: 3,
    SpanKind.PRODUCER: 4,
    SpanKind.CONSUMER: 5,
}


def _attr(key, value):
    if isinstance(value, bool):
        v = {"boolValue": value}
    elif isinstance(value, int):
        v = {"intValue": str(value)}
    elif isinstance(value, float):
        v = {"doubleValue": value}
    else:
        v = {"stringValue": str(value)}
    return {"key": key, "value": v}


class OTLPJsonFileExporter(SpanExporter):
    """Writes one {"resourceSpans": [...]} object per line."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        if not spans:
            return SpanExportResult.SUCCESS
        resource = spans[0].resource
        out_spans = []
        for s in spans:
            ctx = s.get_span_context()
            out_spans.append(
                {
                    "traceId": format(ctx.trace_id, "032x"),
                    "spanId": format(ctx.span_id, "016x"),
                    "parentSpanId": format(s.parent.span_id, "016x") if s.parent else "",
                    "name": s.name,
                    "kind": _KIND.get(s.kind, 1),
                    "startTimeUnixNano": str(s.start_time),
                    "endTimeUnixNano": str(s.end_time),
                    "attributes": [_attr(k, v) for k, v in (s.attributes or {}).items()],
                    "status": {"code": s.status.status_code.value},
                }
            )
        line = {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [_attr(k, v) for k, v in resource.attributes.items()]
                    },
                    "scopeSpans": [{"scope": {"name": "shoplite"}, "spans": out_spans}],
                }
            ]
        }
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line) + "\n")
        return SpanExportResult.SUCCESS

    def shutdown(self):
        pass


# ---------------------------------------------------------------------------
# Service bootstrap
# ---------------------------------------------------------------------------
class ServiceKit:
    """Tracing middleware + traced HTTP client for one service."""

    def __init__(self, app: FastAPI, service_name: str):
        self.app = app
        self.name = service_name
        # experiment knobs (bench/): services listed in ATG_UNTRACED emit no spans and
        # do not propagate trace context; ATG_NO_SIDECAR services bypass the mesh proxy;
        # ATG_GT_LOG is the testbed's own access log, used only as ground truth
        untraced = set(filter(None, os.environ.get("ATG_UNTRACED", "").split(",")))
        no_sidecar = set(filter(None, os.environ.get("ATG_NO_SIDECAR", "").split(",")))
        self.traced = service_name not in untraced
        gt = os.environ.get("ATG_GT_LOG")
        self.gt_log = Path(gt) / f"{service_name}.jsonl" if gt else None
        if self.gt_log:
            self.gt_log.parent.mkdir(parents=True, exist_ok=True)
        telemetry_dir = Path(os.environ.get("TELEMETRY_DIR", "output/telemetry"))
        provider = TracerProvider(
            resource=Resource.create(
                {"service.name": service_name, "service.namespace": "shoplite"}
            )
        )
        if os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT") or os.environ.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"):
            # Docker deployment: standard OTLP/HTTP export to an OpenTelemetry Collector
            # (the ATG platform runs one); W3C traceparent is the default propagator
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
            from opentelemetry.sdk.trace.export import BatchSpanProcessor
            provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        else:
            # local demo and experiment: the same OTLP/JSON lines, written straight to a file
            provider.add_span_processor(
                SimpleSpanProcessor(OTLPJsonFileExporter(telemetry_dir / f"{service_name}.jsonl"))
            )
        self.tracer = provider.get_tracer("shoplite") if self.traced else trace.NoOpTracer()
        proxy = (os.environ.get("MESH_PROXY") or None) if service_name not in no_sidecar else None
        # trust_env=False: ignore any machine-wide proxy settings, only use ours
        self.http = httpx.Client(proxy=proxy, trust_env=False, timeout=10)
        app.middleware("http")(self._trace_middleware)

    def _route_template(self, request: Request) -> str:
        override = getattr(request.state, "route_override", None)
        if override:
            return override
        route = request.scope.get("route")
        if route is not None and getattr(route, "path", None):
            return route.path
        for r in self.app.routes:
            match, _ = r.matches(request.scope)
            if match.name == "FULL":
                return getattr(r, "path", request.url.path)
        return request.url.path

    def _gt(self, request: Request, route: str, status: int):
        if self.gt_log:
            import time as _t
            rec = {"ts": _t.time(), "service": self.name, "method": request.method, "route": route,
                   "path": request.url.path, "status": status, "auth": "authorization" in request.headers,
                   "caller": request.headers.get("x-bench-caller"),
                   "ua": request.headers.get("user-agent", "")[:60],
                   # the status was produced here (not relayed from an upstream service)
                   "denied_here": bool(getattr(request.state, "gt_denied", False))}
            with self.gt_log.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec) + "\n")

    async def _trace_middleware(self, request: Request, call_next):
        if not self.traced:
            response = await call_next(request)
            self._gt(request, self._route_template(request), response.status_code)
            return response
        parent_ctx = propagate.extract(dict(request.headers))
        with self.tracer.start_as_current_span(
            f"{request.method} {request.url.path}",
            context=parent_ctx,
            kind=SpanKind.SERVER,
        ) as span:
            response = await call_next(request)
            route = self._route_template(request)
            span.update_name(f"{request.method} {route}")
            span.set_attribute("http.request.method", request.method)
            span.set_attribute("http.route", route)
            span.set_attribute("url.path", request.url.path)
            span.set_attribute("user_agent.original", request.headers.get("user-agent", ""))
            span.set_attribute("http.response.status_code", response.status_code)
            span.set_attribute(
                "http.request.header.authorization_present",
                "authorization" in request.headers,
            )
            if response.status_code >= 500:
                span.set_status(Status(StatusCode.ERROR))
            self._gt(request, route, response.status_code)
            return response

    def call(self, method: str, url: str, peer_service: str, **kwargs) -> httpx.Response:
        """Traced outgoing call to another service (CLIENT span)."""
        target = resolve(url)
        parsed = httpx.URL(target)
        with self.tracer.start_as_current_span(
            f"{method} {peer_service}", kind=SpanKind.CLIENT
        ) as span:
            headers = dict(kwargs.pop("headers", {}) or {})
            if self.traced:
                propagate.inject(headers)
            if self.gt_log:  # experiment only: lets the callee's ground-truth log name the caller
                headers["x-bench-caller"] = self.name
            span.set_attribute("http.request.method", method)
            span.set_attribute("peer.service", peer_service)
            span.set_attribute("server.address", parsed.host)
            span.set_attribute("server.port", parsed.port or 80)
            span.set_attribute("url.full", str(parsed.copy_with(query=None)))
            resp = self.http.request(method, target, headers=headers, **kwargs)
            span.set_attribute("http.response.status_code", resp.status_code)
            if resp.status_code >= 500:
                span.set_status(Status(StatusCode.ERROR))
            return resp


# ---------------------------------------------------------------------------
# Scenario switch. SHOPLITE_HARDENED=1 turns on the fixes the dashboard
# recommends, so the same demo can show "before" and "after" in Trend & insight.
# ---------------------------------------------------------------------------
import hashlib as _hashlib
import hmac as _hmac

HARDENED = os.environ.get("SHOPLITE_HARDENED") == "1"
JWT_SECRET = os.environ.get("JWT_SECRET", "changeme123").encode()
SERVICE_TOKEN = os.environ.get("SERVICE_TOKEN", "svc-demo-token")


def make_token(uid: int, role: str) -> str:
    sig = _hmac.new(JWT_SECRET, f"{uid}.{role}".encode(), _hashlib.sha256).hexdigest()[:16]
    return f"{uid}.{role}.{sig}"


def verify_token(raw: str) -> dict | None:
    try:
        uid, role, sig = raw.split(".")
        ok = _hmac.compare_digest(make_token(int(uid), role).split(".")[2], sig)
    except ValueError:
        return None
    return {"id": int(uid), "role": role} if ok else None
