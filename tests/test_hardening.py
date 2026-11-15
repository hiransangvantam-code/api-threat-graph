"""Phase 4 report: every code fix must name the finding's own endpoint, in the service's own framework when it is visible."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from atg.hardening import build_hardening, code_snippet, framework  # noqa: E402

SHOPLITE_RUNS = sorted((ROOT / "results" / "grid").glob("shoplite-*/raw"))


def eujf_with(image=None, doc=None, paths=("/x",)):
    eps = [{"service": "svc", "path": p, "method": "GET",
            "sources": {"spec": {"documents": [{"location": doc}]}} if doc else {}} for p in paths]
    return {"services": [{"name": "svc", "image": image}], "endpoints": eps}


@pytest.mark.parametrize("image,doc,paths,want", [
    ("springcommunity/spring-petclinic-api-gateway", None, ("/x",), "spring"),
    ("lakesidemutual/customer-core", "http://customer-core:8110/v3/api-docs", ("/x",), "spring"),
    ("acme/orders", None, ("/actuator/env",), "spring"),
    ("node:20-slim", None, ("/x",), "express"),
    ("shop/payment", "http://payment:8000/openapi.json", ("/x",), "fastapi"),
    ("robotshop/rs-cart", None, ("/x",), None),
])
def test_framework_guess(image, doc, paths, want):
    assert framework("svc", eujf_with(image, doc, paths))[0] == want


def finding(rule, method, path, service="svc"):
    return {"rule_id": rule, "target": f"ep:{service}:{method}:{path}", "affected_api": f"{method} {path}"}


def test_snippet_uses_the_findings_endpoint():
    e = eujf_with("springcommunity/spring-petclinic-customers-service")
    s = code_snippet(finding("TS-01", "POST", "/owners/{ownerId}/pets"), e)
    assert 'HttpMethod.POST, "/owners/{ownerId}/pets"' in s and ".authenticated()" in s
    s = code_snippet(finding("API5", "GET", "/admin/stats"), e)
    assert 'hasRole("ADMIN")' in s
    s = code_snippet(finding("API1", "GET", "/owners/{ownerId}"), e)
    assert "findById(ownerId)" in s and "FORBIDDEN" in s


def test_express_path_params_and_unknown_framework():
    s = code_snippet(finding("API1", "GET", "/carts/{cartId}"), eujf_with("node:20-slim"))
    assert "req.params.cartId" in s
    s = code_snippet(finding("TS-01", "DELETE", "/cart/{id}"), eujf_with("robotshop/rs-cart"))
    assert "pseudocode" in s and "DELETE /cart/{id}" in s


def test_no_snippet_for_service_findings():
    assert code_snippet({"rule_id": "LT-02", "target": "svc:svc"}, eujf_with()) is None


@pytest.mark.skipif(not SHOPLITE_RUNS, reason="results/grid not present")
def test_report_on_a_recorded_run():
    from atg.analysis import analyze
    from atg.graphstore import GraphStore
    from atg.normalizer import normalize

    eujf = normalize(SHOPLITE_RUNS[0])
    a = analyze(eujf, GraphStore("sqlite:///:memory:"))
    html_body, md = build_hardening(a, eujf, {"scan_ms": 1000})
    assert "What to fix, in order" in html_body and "## Fix plan" in md
    # the ShopLite example handler must not show up under another endpoint's finding
    for f in a["findings"]:
        if f["rule_id"] == "TS-01" and f.get("affected_api") and "/admin/transactions" not in f["affected_api"]:
            snip = code_snippet(f, eujf)
            assert snip and f["affected_api"].split(" ", 1)[1] in snip and "admin_tx" not in snip


def test_networkpolicy_without_callers_admits_the_entry_point():
    from atg.hardening import stack_fix
    f = {"rule_id": "API8-NETPOL", "target": "svc:productpage", "evidence": ["callers seen in traces: none"],
         "recommendation": ""}
    istio = {"edge_tls": [{"source": "Istio Gateway", "name": "bookinfo-gateway", "tls": False}], "gateway_routes": []}
    what, snip = stack_fix(f, istio)
    assert "entry point" in what and "istio: ingressgateway" in snip
    what, snip = stack_fix(f, {"edge_tls": [], "gateway_routes": []})
    assert "ingress-nginx" in snip
    f["evidence"] = ["callers seen in traces: details, reviews"]
    what, snip = stack_fix(f, istio)
    assert "app: details" in snip and "app: reviews" in snip and "ingressgateway" not in snip
