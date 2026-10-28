"""
Extractor 1d - DISTRIBUTED TRACE / CALL-CHAIN DISCOVERY  (source: OpenTelemetry)

Input : OTLP/JSON (what the OTel Collector "file" exporter writes, one
        {"resourceSpans": [...]} object per line) or a Jaeger JSON export
        ({"data": [{"traceID", "spans", "processes"}]}).
Output:
  service     every service seen in traces + the routes it serves
  edge        caller -> callee with the operations used on that hop
  entrypoint  routes that start a trace (nobody upstream called them)
  call_chain  distinct end-to-end paths, e.g.
              api-gateway POST /api/orders/** -> order-service POST /orders
                 -> user-service GET /users/{user_id}
                 -> payment-service POST /charge

This is the only source that shows *who calls whom* as it really happens.
"""
from __future__ import annotations

import json
import statistics
import time
from collections import Counter, defaultdict
from pathlib import Path

from .common import DEFAULT_IGNORE_PATHS, envelope, is_ignored, iter_files

SOURCE = "callchain"
SERVER, CLIENT = 2, 3
_JAEGER_KIND = {"server": SERVER, "client": CLIENT, "internal": 1, "producer": 4, "consumer": 5}


def _otlp_value(v: dict):
    for k in ("stringValue", "intValue", "doubleValue", "boolValue"):
        if k in v:
            return int(v[k]) if k == "intValue" else v[k]
    return None


def _attrs(lst) -> dict:
    return {a["key"]: _otlp_value(a.get("value", {})) for a in lst or []}


def _kind(k) -> int:
    if isinstance(k, int):
        return k
    s = str(k).upper().replace("SPAN_KIND_", "")
    return {"SERVER": 2, "CLIENT": 3, "INTERNAL": 1, "PRODUCER": 4, "CONSUMER": 5}.get(s, 1)


def _load_otlp(obj: dict) -> list[dict]:
    spans = []
    for rs in obj.get("resourceSpans", []):
        res = _attrs((rs.get("resource") or {}).get("attributes"))
        svc = res.get("service.name", "unknown")
        for ss in rs.get("scopeSpans", rs.get("instrumentationLibrarySpans", [])):
            for s in ss.get("spans", []):
                spans.append({
                    "trace": s["traceId"], "id": s["spanId"], "parent": s.get("parentSpanId") or None,
                    "service": svc, "name": s.get("name", ""), "kind": _kind(s.get("kind", 1)),
                    "start": int(s.get("startTimeUnixNano", 0)), "end": int(s.get("endTimeUnixNano", 0)),
                    "attrs": _attrs(s.get("attributes")),
                    "error": (s.get("status") or {}).get("code") in (2, "STATUS_CODE_ERROR"),
                })
    return spans


def _load_jaeger(obj: dict) -> list[dict]:
    spans = []
    for tr in obj.get("data", []):
        procs = {k: v.get("serviceName", "unknown") for k, v in (tr.get("processes") or {}).items()}
        for s in tr.get("spans", []):
            tags = {t["key"]: t.get("value") for t in s.get("tags", [])}
            parent = next((r["spanID"] for r in s.get("references", []) if r.get("refType") == "CHILD_OF"), None)
            spans.append({
                "trace": s["traceID"], "id": s["spanID"], "parent": parent,
                "service": procs.get(s.get("processID"), "unknown"), "name": s.get("operationName", ""),
                "kind": _JAEGER_KIND.get(str(tags.get("span.kind", "internal")).lower(), 1),
                "start": int(s.get("startTime", 0)) * 1000, "end": (int(s.get("startTime", 0)) + int(s.get("duration", 0))) * 1000,
                "attrs": tags, "error": bool(tags.get("error")),
            })
    return spans


def load_spans(paths: list[str]) -> tuple[list[dict], list[str], list[str]]:
    spans, inputs, warnings = [], [], []
    for f in iter_files(paths, (".jsonl", ".json")):
        inputs.append(str(f))
        text = f.read_text(encoding="utf-8").strip()
        chunks = [text] if text.startswith("{\"data\"") else text.splitlines()
        for line in chunks:
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                warnings.append(f"{f}: unparseable line skipped")
                continue
            spans.extend(_load_jaeger(obj) if "data" in obj else _load_otlp(obj))
    # exporters retry, and the same file can be collected twice: keep one copy of
    # each (trace, span) id, or the call-chain walk below fans out on duplicates
    seen, unique = set(), []
    for s in spans:
        k = (s["trace"], s["id"])
        if k not in seen:
            seen.add(k)
            unique.append(s)
    if len(unique) < len(spans):
        warnings.append(f"{len(spans) - len(unique)} duplicate spans dropped")
    return unique, inputs, warnings


def _method(a: dict) -> str:
    return str(a.get("http.request.method") or a.get("http.method") or "").upper()


def _route(sp: dict) -> str:
    a = sp["attrs"]
    return str(a.get("http.route") or a.get("url.path") or a.get("http.target") or
               a.get("rpc.method") or sp["name"])


def _op(sp: dict) -> str:
    a = sp["attrs"]
    if a.get("rpc.service"):
        return f"RPC {a['rpc.service']}/{a.get('rpc.method', '')}"
    m = _method(a)
    return f"{m} {_route(sp)}" if m else sp["name"]


def _status(sp: dict):
    a = sp["attrs"]
    return a.get("http.response.status_code") or a.get("http.status_code")


def extract(cfg: dict, service_map: dict[str, str], run_id: str) -> dict:
    t0 = time.perf_counter()
    spans, inputs, warnings = load_spans(cfg.get("trace_paths", []))
    # drop traces that the extractor itself caused, and health checks
    ignore = cfg.get("ignore_paths", DEFAULT_IGNORE_PATHS)
    noisy = {s["trace"] for s in spans if s["kind"] == SERVER and not s["parent"] and is_ignored(
        str(s["attrs"].get("url.path") or s["attrs"].get("http.target") or s["attrs"].get("http.route") or ""),
        str(s["attrs"].get("user_agent.original") or s["attrs"].get("http.user_agent") or ""), ignore)}
    total = len(spans)
    spans = [s for s in spans if s["trace"] not in noisy]
    by_id = {(s["trace"], s["id"]): s for s in spans}
    children = defaultdict(list)
    for s in spans:
        if s["parent"]:
            children[(s["trace"], s["parent"])].append(s)

    services: dict[str, dict] = defaultdict(lambda: {"routes": Counter(), "errors": Counter(), "spans": 0})
    edges: dict[tuple, dict] = {}
    entry = Counter()

    def add_edge(src, dst, op, dur_ms, err, via):
        e = edges.setdefault((src, dst), {"ops": defaultdict(lambda: {"count": 0, "errors": 0, "lat": []}), "via": set()})
        o = e["ops"][op]
        o["count"] += 1
        o["errors"] += int(err)
        o["lat"].append(dur_ms)
        e["via"].add(via)

    for s in spans:
        services[s["service"]]["spans"] += 1
        if s["kind"] != SERVER and not (s["kind"] == CLIENT and not children.get((s["trace"], s["id"]))):
            continue
        dur = (s["end"] - s["start"]) / 1e6
        if s["kind"] == SERVER:
            services[s["service"]]["routes"][_op(s)] += 1
            if s["error"] or (_status(s) or 0) >= 500:
                services[s["service"]]["errors"][_op(s)] += 1
            parent = by_id.get((s["trace"], s["parent"])) if s["parent"] else None
            if parent is None:
                entry[(s["service"], _op(s), "missing-parent" if s["parent"] else "root")] += 1
            elif parent["service"] != s["service"]:
                add_edge(parent["service"], s["service"], _op(s), dur, s["error"], "client->server span")
        else:
            # CLIENT span whose callee is not instrumented (database, 3rd party, ...)
            a = s["attrs"]
            dst = (a.get("peer.service") or a.get("db.system") or a.get("server.address") or
                   a.get("net.peer.name") or "external")
            dst = service_map.get(f"{a.get('server.address')}:{a.get('server.port')}", dst)
            add_edge(s["service"], f"{dst}", _op(s), dur, s["error"], "uninstrumented callee")

    # --- distinct call chains (tree signature per trace) -----------------
    def sig(sp, depth=0) -> list[tuple[int, str, str]]:
        rows = []
        if sp["kind"] == SERVER:
            rows.append((depth, sp["service"], _op(sp)))
            depth += 1
        for ch in sorted(children.get((sp["trace"], sp["id"]), []), key=lambda x: x["start"]):
            rows.extend(sig(ch, depth))
        return rows

    roots = [s for s in spans if not s["parent"] or (s["trace"], s["parent"]) not in by_id]
    chains = Counter()
    for r in roots:
        rows = tuple(sig(r))
        if rows:
            chains[rows] += 1

    records = []
    for name, info in sorted(services.items()):
        records.append({
            "kind": "service", "service": name, "span_count": info["spans"],
            "served_operations": [{"operation": op, "count": n, "errors": info["errors"].get(op, 0)}
                                  for op, n in sorted(info["routes"].items())],
        })
    for (src, dst), e in sorted(edges.items()):
        ops = []
        for op, o in sorted(e["ops"].items()):
            ops.append({"operation": op, "count": o["count"], "errors": o["errors"],
                        "p50_ms": round(statistics.median(o["lat"]), 2) if o["lat"] else None})
        records.append({"kind": "edge", "from": src, "to": dst, "calls": sum(o["count"] for o in ops),
                        "evidence": sorted(e["via"]), "operations": ops})
    for (svc, op, why), n in sorted(entry.items()):
        records.append({"kind": "entrypoint", "service": svc, "operation": op, "traces": n,
                        "note": "trace starts here" if why == "root" else "parent span not in data (caller not instrumented?)"})
    for rows, n in chains.most_common():
        records.append({"kind": "call_chain", "traces": n, "depth": max(d for d, _, _ in rows) + 1,
                        "hops": [{"depth": d, "service": s, "operation": op} for d, s, op in rows]})

    trace_ids = {s["trace"] for s in spans}
    stats = {
        "spans": len(spans),
        "spans_ignored": total - len(spans),
        "traces": len(trace_ids),
        "services": len(services),
        "edges": len(edges),
        "distinct_call_chains": len(chains),
        "max_chain_depth": max((max(d for d, _, _ in rows) + 1 for rows in chains), default=0),
    }
    if not spans:
        warnings.append("no spans found; is the OTel exporter writing to trace_paths?")
    return envelope(SOURCE, "opentelemetry", run_id, inputs, records, stats, warnings,
                    (time.perf_counter() - t0) * 1000)
