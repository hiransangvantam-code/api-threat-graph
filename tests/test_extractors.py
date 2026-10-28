"""Fast unit tests for Phase 1. Run:  python -m pytest -q"""
import json
from pathlib import Path

import pytest

from extractor import callchain_discovery, infra_discovery, openapi_discovery, runtime_traffic
from extractor.common import match_key, shape, template_path

ROOT = Path(__file__).resolve().parent.parent


def test_path_templating():
    assert template_path("/api/users/17/addresses")[0] == "/api/users/{int}/addresses"
    assert template_path("/pay/pay_851bc1badcf1")[0] == "/pay/{id}"
    assert template_path("/x/3f2b8c1e-1d2a-4b7e-9c11-0a1b2c3d4e5f")[0] == "/x/{uuid}"
    assert template_path("/api/v1/health")[0] == "/api/v1/health"
    assert match_key("get", "/users/{user_id}") == match_key("GET", "/users/{int}")


def test_shape_never_keeps_values():
    s = shape({"email": "a@b.co", "card": "4111 1111 1111 1111", "phone": "0812345678",
               "token": "secret-value", "n": 3, "items": [{"id": 1}]})
    assert s == {"email": "string:email", "card": "string:card_number", "phone": "string:phone",
                 "token": "string", "n": "integer", "items": [{"id": "integer"}]}
    assert "secret-value" not in json.dumps(s)


def test_swagger2_and_security_levels(tmp_path):
    spec = {
        "swagger": "2.0", "info": {"title": "legacy", "version": "1"}, "host": "legacy:80",
        "securityDefinitions": {"key": {"type": "apiKey", "in": "header", "name": "X-Key"}},
        "security": [{"key": []}],
        "paths": {
            "/a": {"get": {"responses": {"200": {}}}},
            "/b": {"post": {"security": [], "parameters": [
                {"in": "body", "name": "b", "schema": {"properties": {"x": {"type": "string"}}, "required": ["x"]}}],
                "responses": {"201": {}}}},
            "/c": {"get": {"security": [{}, {"key": []}], "responses": {"200": {}}}},
        },
    }
    f = tmp_path / "legacy.json"
    f.write_text(json.dumps(spec))
    out = openapi_discovery.extract({"live_targets": [], "spec_files": [{"path": str(f)}]}, {}, "t")
    ops = {o["path"]: o for o in out["records"][0]["operations"]}
    assert ops["/a"]["auth_declared"] == "required"      # inherited from global
    assert ops["/b"]["auth_declared"] == "none"          # explicitly opened
    assert ops["/c"]["auth_declared"] == "optional"
    assert ops["/b"]["request_body"]["fields"] == {"x": "string"}


def test_infra_demo_manifests():
    out = infra_discovery.extract({"manifest_paths": [str(ROOT / "demo_target/k8s")]}, {}, "t")
    st = out["stats"]
    assert st["workloads"] == 4 and st["gateway_routes"] == 4
    assert "payment-service" in st["node_exposed_workloads"]
    assert st["plaintext_env_with_sensitive_name"] == 2
    blob = json.dumps(out)
    assert "changeme123" not in blob and "sk_live" not in blob   # secret values never copied


def test_jaeger_format(tmp_path):
    jaeger = {"data": [{"traceID": "t1", "processes": {"p1": {"serviceName": "web"}, "p2": {"serviceName": "api"}},
                        "spans": [
        {"traceID": "t1", "spanID": "s1", "processID": "p1", "operationName": "GET /",
         "references": [], "startTime": 1, "duration": 10,
         "tags": [{"key": "span.kind", "value": "server"}, {"key": "http.method", "value": "GET"}]},
        {"traceID": "t1", "spanID": "s2", "processID": "p2", "operationName": "GET /items",
         "references": [{"refType": "CHILD_OF", "spanID": "s1"}], "startTime": 2, "duration": 5,
         "tags": [{"key": "span.kind", "value": "server"}, {"key": "http.method", "value": "GET"},
                  {"key": "http.route", "value": "/items"}]}]}]}
    f = tmp_path / "jaeger.json"
    f.write_text(json.dumps(jaeger))
    out = callchain_discovery.extract({"trace_paths": [str(f)]}, {}, "t")
    edges = [r for r in out["records"] if r["kind"] == "edge"]
    assert edges and edges[0]["from"] == "web" and edges[0]["to"] == "api"


def test_har_input(tmp_path):
    har = {"log": {"entries": [{
        "request": {"method": "GET", "url": "https://shop.example.com/api/users/42?expand=1",
                    "headers": [{"name": "Authorization", "value": "Bearer abc.def.ghi"}],
                    "queryString": [{"name": "expand", "value": "1"}]},
        "response": {"status": 200, "content": {"mimeType": "application/json",
                                                 "text": "{\"email\": \"x@y.com\"}"}},
        "time": 12}]}}
    f = tmp_path / "session.har"
    f.write_text(json.dumps(har))
    out = runtime_traffic.extract({"capture_files": [str(f)]}, {"shop.example.com:443": "web"}, "t")
    r = out["records"][0]
    assert r["service"] == "web" and r["path_template"] == "/api/users/{int}"
    assert r["auth"]["schemes"] == ["Bearer"]
    assert r["response"]["body_shape"] == {"email": "string:email"}
    assert "abc.def.ghi" not in json.dumps(out) and "x@y.com" not in json.dumps(out)


@pytest.mark.skipif(not (ROOT / "output/raw/manifest.json").exists(), reason="run scripts/run_demo.py first")
def test_demo_output_has_no_sensitive_values():
    blob = "".join(p.read_text() for p in (ROOT / "output").rglob("*.json*") if "telemetry" not in p.parts)
    for needle in ("@example.com", "changeme123", "sk_live", "tok_demo"):
        assert needle not in blob
