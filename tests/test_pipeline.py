"""
Regression tests for Phases 2-4 on the ShopLite demo.

These need a demo run first:  python scripts/run_demo.py --scenario both
They check that
  - every weakness planted in ShopLite is reported (expected rule on the expected target)
  - nothing else is reported
  - the hardened build clears everything except the two weaknesses it keeps on purpose
  - the attack path SQL gives the same answer on SQLite and (if available) PostgreSQL

This is a regression test for the demo, not an accuracy evaluation. Real precision /
recall numbers for the paper need labelled benchmarks (Train Ticket, Sock Shop, ...).
"""
import json
import os
from pathlib import Path

import pytest

from atg.analysis import analyze
from atg.graphstore import GraphStore

ROOT = Path(__file__).resolve().parent.parent
RUNS = sorted((ROOT / "output/runs").glob("*")) if (ROOT / "output/runs").exists() else []

# (rule, affected API) for every weakness in the vulnerable ShopLite build.
# Derived from the service code and manifests in demo_target/, see docs/PHASE1_DESIGN.md.
EXPECTED_VULNERABLE = {
    ("API5", "GET /admin/transactions"), ("API3", "GET /admin/transactions"), ("TS-01", "GET /admin/transactions"),
    ("API9-SHADOW", "GET /admin/transactions"),
    ("TS-01", "POST /charge"), ("TS-03", "POST /charge"), ("TS-08", "POST /charge"),
    ("TS-01", "POST /refund"), ("API9-SHADOW", "POST /refund"),
    ("TS-01", "GET /internal/users/export"), ("API5", "GET /internal/users/export"),
    ("API3", "GET /internal/users/export"), ("API9-SHADOW", "GET /internal/users/export"),
    ("LT-01", "GET /internal/users/export"),
    ("API1", "GET /users/{user_id}"), ("API1", "GET /users/{user_id}/addresses"),
    ("API1", "GET /orders/{order_id}"), ("API1", "DELETE /orders/{order_id}"),
    ("API9-ZOMBIE", "DELETE /orders/{order_id}"),
    ("TS-02", "api-gateway"), ("TS-05", "api-gateway"), ("API8-NETPOL", "api-gateway"),
    ("API8-DEBUG", "GET /_debug/config"), ("API9-SHADOW", "GET /_debug/config"),
    ("TS-07", "POST /auth/login"),
    ("TS-04", "order-service"), ("API4", "order-service"), ("API8-ROOT", "order-service"), ("API8-NETPOL", "order-service"),
    ("TS-04", "payment-service"), ("API4", "payment-service"), ("API8-ROOT", "payment-service"),
    ("API8-PRIV", "payment-service"), ("API8-TAG", "payment-service"), ("API8-NODEPORT", "payment-service"),
    ("API8-NETPOL", "payment-service"), ("API9-NOSPEC", "payment-service"),
}
# the hardened build still has a deprecated endpoint in use and an untraced cron job
EXPECTED_HARDENED = {("API9-ZOMBIE", "DELETE /orders/{order_id}"), ("LT-01", "GET /internal/users/export")}


def _run(label):
    for d in RUNS:
        a = json.loads((d / "analysis.json").read_text())
        if a["summary"].get("label") == label:
            return a, json.loads((d / "eujf.json").read_text())
    pytest.skip(f"no '{label}' run yet: python scripts/run_demo.py --scenario both")


def _got(a):
    return {(f["rule_id"], f["affected_api"]) for f in a["findings"]}


def test_vulnerable_findings_match_planted_weaknesses():
    a, _ = _run("vulnerable")
    got = _got(a)
    assert EXPECTED_VULNERABLE - got == set(), "missed"
    assert got - EXPECTED_VULNERABLE == set(), "unexpected"


def test_hardened_build_clears_findings():
    a, _ = _run("hardened")
    assert _got(a) == EXPECTED_HARDENED
    v, _ = _run("vulnerable")
    assert a["summary"]["total_path_risk"] < 0.1 * v["summary"]["total_path_risk"]


def test_every_finding_is_explained_and_has_a_fix():
    a, _ = _run("vulnerable")
    for f in a["findings"]:
        assert f["owasp"] and f["cwe"] and f["attack"] and f["nist"], f["id"]
        assert f["mitigation"] and f["recommendation"], f["id"]
        assert f["score"] == f["likelihood"] * f["impact"]
        assert f["factors"][0].startswith("likelihood base")


def test_attack_paths_end_in_risk_and_start_at_actor():
    a, _ = _run("vulnerable")
    types = {n["id"]: n["type"] for n in a["graph"]["nodes"]}
    for p in a["attack_paths"]:
        assert types[p["nodes"][0]] == "Actor" and types[p["nodes"][-1]] == "Risk"
        assert sum(types[n] == "Vulnerability" for n in p["nodes"]) == 1


def test_internal_endpoint_not_reachable_from_internet():
    """/internal/users/export is not routed: no internet path may reach it."""
    a, e = _run("vulnerable")
    ep = next(x["id"] for x in e["endpoints"] if x["path"] == "/internal/users/export")
    for p in a["attack_paths"]:
        if p["entry"] == "actor:internet":
            assert ep not in p["nodes"]


@pytest.mark.skipif(not os.environ.get("ATG_TEST_PG"), reason="set ATG_TEST_PG=postgresql://... to compare backends")
def test_sqlite_and_postgresql_agree(tmp_path):
    _, e = _run("vulnerable")
    a1 = analyze(e, GraphStore(f"sqlite:///{tmp_path / 'x.db'}"))
    a2 = analyze(e, GraphStore(os.environ["ATG_TEST_PG"]))
    assert [(p["finding_id"], p["nodes"]) for p in a1["attack_paths"]] == [(p["finding_id"], p["nodes"]) for p in a2["attack_paths"]]
