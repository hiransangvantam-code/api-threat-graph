"""Checks on the evaluation harness itself (bench/). Run:  python -m pytest -q"""
from bench.common import load_topology, public_path, shape
from bench.evaluate import ground_truth, match, subsets
from extractor.common import template_path


def test_word_with_digit_is_not_an_id():
    # found in the Train Ticket pilot: "travel2service" was templated to {id}
    assert template_path("/api/v1/travel2service/trips")[0] == "/api/v1/travel2service/trips"
    assert template_path("/oauth2callback/x")[0] == "/oauth2callback/x"
    assert template_path("/orders/ORD20240117")[0] == "/orders/{id}"


def test_fifteen_source_subsets():
    combos = list(subsets())
    assert len(combos) == 15 and combos[-1] == "OTKC"


def test_ground_truth_loads_for_every_testbed():
    for tb, n_min in (("shoplite", 12), ("trainticket", 250), ("crapi", 70)):
        gt = ground_truth(tb)
        assert len(gt["endpoints"]) >= n_min
        assert gt["edges"], tb
        assert all(e["key"][2] == shape(e["path"]) for e in gt["endpoints"])


def test_public_path_strips_prefix():
    topo = load_topology("shoplite")
    assert public_path(topo, "/users/{user_id}") == "/api/users/{user_id}"
    assert public_path(topo, "/charge") == "/api/payments/charge"


def test_match_counts_duplicates_once():
    gt = ground_truth("shoplite")
    entry = {"service": "user-service", "method": "GET", "path": "/users/{int}", "public_paths": []}
    gw_entry = {"service": "api-gateway", "method": "GET", "path": "/api/users/{int}", "public_paths": []}
    pairs, unmatched, _ = match({"endpoints": [entry, gw_entry]}, gt)
    assert len(pairs) == 2 and not unmatched
    assert len({g["key"] for _, g in pairs}) == 1   # strict precision will count one of them only


def test_duplicate_spans_are_dropped(tmp_path):
    import json
    from extractor.callchain_discovery import load_spans
    span = {"traceId": "a" * 32, "spanId": "b" * 16, "name": "GET /x", "kind": 2,
            "startTimeUnixNano": "1", "endTimeUnixNano": "2", "attributes": []}
    line = json.dumps({"resourceSpans": [{"resource": {"attributes": [
        {"key": "service.name", "value": {"stringValue": "svc"}}]}, "scopeSpans": [{"spans": [span]}]}]})
    (tmp_path / "t.jsonl").write_text(line + "\n" + line + "\n")
    spans, _, warnings = load_spans([str(tmp_path)])
    assert len(spans) == 1 and any("duplicate" in w for w in warnings)
