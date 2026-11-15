"""Version 1.4: configuration styles and credentials the ten-company test showed ATG read
wrongly. One test per fix, on small inputs written in each product's own format."""
from __future__ import annotations

from pathlib import Path

import yaml

from atg.normalizer import _to_backend, _to_public
from extractor import infra_discovery
from extractor.runtime_traffic import _auth_scheme


def _routes(tmp_path: Path, docs: list[dict], gateway_configs=None) -> list[dict]:
    (tmp_path / "m.yaml").write_text(yaml.safe_dump_all(docs), encoding="utf-8")
    cfg = {"manifest_paths": [str(tmp_path / "m.yaml")], "gateway_configs": gateway_configs or []}
    return [r for r in infra_discovery.extract(cfg, {}, "t")["records"] if r["kind"] == "gateway_route"]


def test_kong_service_url_with_a_path(tmp_path):
    kong = {"_format_version": "3.0", "services": [
        {"name": "wallets", "url": "http://wallet-service:8080/wallets",
         "routes": [{"paths": ["/api/wallets"], "strip_path": True, "plugins": [{"name": "jwt"}]}]},
        {"name": "legacy", "url": "http://legacy:8080/v1",
         "routes": [{"paths": ["/old"], "strip_path": False}]},
        {"name": "plain", "url": "http://catalog:8080", "routes": [{"paths": ["/api/catalog"]}]}]}
    r = {x["upstream_service"]: x for x in _routes(tmp_path, [kong])}
    assert _to_backend(r["wallet-service"], "/api/wallets/7") == "/wallets/7"
    assert _to_public(r["wallet-service"], "/wallets/7") == "/api/wallets/7"
    assert _to_backend(r["legacy"], "/old/x") == "/v1/old/x"
    assert _to_backend(r["catalog"], "/api/catalog/titles") == "/titles"   # unchanged behaviour


def test_istio_rewrite_gateway_policy_and_rate_limit(tmp_path):
    docs = [
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "edge", "namespace": "shop"},
         "spec": {"template": {"metadata": {"labels": {"app": "edge"}}, "spec": {"containers": [{"name": "c", "image": "x:1"}]}}}},
        {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "edge", "namespace": "shop"},
         "spec": {"type": "LoadBalancer", "selector": {"app": "edge"}, "ports": [{"port": 443}]}},
        {"apiVersion": "networking.istio.io/v1beta1", "kind": "Gateway", "metadata": {"name": "gw", "namespace": "shop"},
         "spec": {"selector": {"app": "edge"}}},
        {"apiVersion": "networking.istio.io/v1beta1", "kind": "VirtualService", "metadata": {"name": "vs", "namespace": "shop"},
         "spec": {"gateways": ["gw"], "http": [
             {"match": [{"uri": {"prefix": "/api/orders"}}], "rewrite": {"uri": "/orders"},
              "route": [{"destination": {"host": "orders.shop.svc.cluster.local"}}]},
             {"match": [{"uri": {"prefix": "/api/login"}}], "rewrite": {"uri": "/login"},
              "route": [{"destination": {"host": "auth.shop.svc.cluster.local"}}]}]}},
        {"apiVersion": "security.istio.io/v1beta1", "kind": "AuthorizationPolicy", "metadata": {"name": "p", "namespace": "shop"},
         "spec": {"selector": {"matchLabels": {"app": "edge"}}, "action": "CUSTOM", "provider": {"name": "ext"},
                  "rules": [{"to": [{"operation": {"paths": ["/api/orders*"]}}]}]}},
        {"apiVersion": "networking.istio.io/v1alpha3", "kind": "EnvoyFilter", "metadata": {"name": "rl", "namespace": "shop"},
         "spec": {"workloadSelector": {"labels": {"app": "edge"}}, "configPatches": [{"patch": {"value": {
             "name": "envoy.filters.http.local_ratelimit",
             "descriptors": [{"entries": [{"key": "path", "value": "/api/login"}]}]}}}]}},
    ]
    r = {x["upstream_service"]: x for x in _routes(tmp_path, docs)}
    assert _to_backend(r["orders"], "/api/orders/9") == "/orders/9"
    assert r["orders"]["gateway_service"] == "edge" and r["auth"]["gateway_service"] == "edge"
    assert r["orders"]["auth"] == "required" and r["auth"]["auth"] == "unspecified"
    assert r["auth"]["rate_limit"] and not r["orders"]["rate_limit"]


def test_spring_cloud_gateway_rewrite_path(tmp_path):
    app = tmp_path / "application.yml"
    app.write_text(yaml.safe_dump({"spring": {"cloud": {"gateway": {"routes": [
        {"id": "bills", "uri": "http://billing:8080", "predicates": ["Path=/api/bills/**"],
         "filters": ["RewritePath=/api/(?<segment>.*), /${segment}", "TokenRelay="]},
        {"id": "v2", "uri": "http://users:8080", "predicates": ["Path=/api/users/**"],
         "filters": ["RewritePath=/api/users/(?<rest>.*), /v2/users/${rest}"]}]}}}}), encoding="utf-8")
    r = {x["upstream_service"]: x for x in _routes(tmp_path, [{"kind": "ConfigMap", "metadata": {"name": "x"}}],
                                                   [{"path": str(app), "type": "spring-cloud-gateway", "service": "gw"}])}
    assert _to_backend(r["billing"], "/api/bills/3") == "/bills/3"
    assert _to_backend(r["users"], "/api/users/3") == "/v2/users/3"
    assert r["billing"]["auth"] == "required"


def test_session_cookie_and_query_credentials():
    assert _auth_scheme({"authorization": "<Bearer>"}) == "Bearer"
    assert _auth_scheme({"cookie": "<_ga,sid>"}) == "cookie(sid)"
    assert _auth_scheme({"cookie": "<JSESSIONID>"}) == "cookie(JSESSIONID)"
    assert _auth_scheme({"cookie": "<_ga,theme>"}) is None          # no session cookie
    assert _auth_scheme({}, ["access_token", "page"]) == "query(access_token)"
    assert _auth_scheme({}, ["page", "q"]) is None


def test_scg_and_zuul_read_every_spring_profile(tmp_path):
    """v1.5: application.yml files with several documents (---) were not read at all."""
    from extractor.infra_discovery import _routes_from_scg, _routes_from_zuul
    f = tmp_path / "application.yml"
    f.write_text("spring:\n  cloud:\n    gateway:\n      routes:\n      - id: a\n        uri: lb://customers-service\n"
                 "        predicates: [Path=/api/customer/**]\n        filters: [StripPrefix=2]\n---\n"
                 "spring:\n  config:\n    activate:\n      on-profile: docker\n", encoding="utf-8")
    r = _routes_from_scg(f, "api-gateway", {})
    assert [x["upstream_service"] for x in r] == ["customers-service"]
    z = tmp_path / "gateway.yml"
    z.write_text("zuul:\n  routes:\n    account-service:\n      path: /accounts/**\n      serviceId: account-service\n"
                 "---\nzuul:\n  routes:\n    auth-service:\n      path: /uaa/**\n      url: http://auth-service:5000\n",
                 encoding="utf-8")
    assert {x["upstream_service"] for x in _routes_from_zuul(z, "gateway", {})} == {"account-service", "auth-service"}
