"""
Extractor 1a - RUNTIME TRAFFIC  (source: mitmproxy capture, or a HAR file)

Input : JSON-lines written by extractor/mitm_addon.py, and/or .har exports
        (browser DevTools, Burp, ZAP all export HAR).
Output: one record per observed endpoint
        (service + method + templated path), aggregated over all hits.

This is the source that sees what *actually* runs, including endpoints no
spec mentions (shadow APIs) and calls between internal services.
"""
from __future__ import annotations

import json
import re
import statistics
import time
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit

from .common import DEFAULT_IGNORE_PATHS, envelope, is_ignored, header_summary, iter_files, merge_shapes, shape, template_path

SOURCE = "runtime_traffic"


def _from_har(path: Path) -> list[dict]:
    """Convert HAR entries into the same flat flow format the addon writes."""
    data = json.loads(path.read_text(encoding="utf-8"))
    flows = []
    for e in data.get("log", {}).get("entries", []):
        req, resp = e.get("request", {}), e.get("response", {})
        u = urlsplit(req.get("url", ""))
        rh = {h["name"]: h["value"] for h in req.get("headers", [])}
        body = (req.get("postData") or {}).get("text")
        rbody = (resp.get("content") or {}).get("text")

        def _shape(txt, ct):
            if txt and "json" in (ct or ""):
                try:
                    return shape(json.loads(txt))
                except ValueError:
                    return None
            return None

        rct = (resp.get("content") or {}).get("mimeType", "")
        qct = (req.get("postData") or {}).get("mimeType", "")
        flows.append({
            "capture_point": "har",
            "host_header": u.netloc,
            "upstream": u.netloc if ":" in u.netloc else f"{u.hostname}:{443 if u.scheme == 'https' else 80}",
            "scheme": u.scheme,
            "method": req.get("method", "GET"),
            "path": u.path or "/",
            "query_keys": sorted({q["name"] for q in req.get("queryString", [])}),
            "req_headers": header_summary(rh),
            "req_content_type": qct,
            "req_body_shape": _shape(body, qct),
            "status": resp.get("status"),
            "resp_content_type": rct,
            "resp_body_shape": _shape(rbody, rct),
            "duration_ms": e.get("time"),
            "ts": None,
        })
    return flows


def load_flows(paths: list[str]) -> tuple[list[dict], list[str], list[str]]:
    flows, inputs, warnings = [], [], []
    for f in iter_files(paths, (".jsonl", ".har", ".json")):
        inputs.append(str(f))
        if f.suffix == ".har":
            flows.extend(_from_har(f))
            continue
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                flows.append(json.loads(line))
            except ValueError:
                warnings.append(f"{f}:{n} is not valid JSON, skipped")
    if not inputs:
        warnings.append("no capture files found; did mitmproxy run with the addon?")
    return flows, inputs, warnings


_KEY_HEADER = re.compile(r"(token|api[-_]?key|apikey|secret|signature)", re.I)
_ASSET = re.compile(r"\.(js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|txt|webmanifest)$|^/static/", re.I)


def _auth_scheme(headers: dict) -> str | None:
    """Authorization header scheme ("Bearer"), or an API-key style header
    (X-Service-Token, X-API-Key) that the addon redacted."""
    v = headers.get("authorization")
    if v:
        return v.strip("<>")
    for name, val in headers.items():
        if val == "<redacted>" and _KEY_HEADER.search(name):
            return f"apiKey({name})"
    return None


def extract(cfg: dict, service_map: dict[str, str], run_id: str) -> dict:
    t0 = time.perf_counter()
    flows, inputs, warnings = load_flows(cfg.get("capture_files", []))
    ignore = cfg.get("ignore_paths", DEFAULT_IGNORE_PATHS)
    total = len(flows)
    flows = [f for f in flows if not is_ignored(f.get("path"), f.get("user_agent", ""), ignore)]
    if cfg.get("skip_web_assets"):
        # a browser session also loads the single-page app itself: scripts, styles,
        # images and HTML shells for client-side routes. None of that is API surface.
        flows = [f for f in flows if not (
            f.get("method") == "GET" and (
                _ASSET.search(f.get("path", "")) or
                str(f.get("resp_content_type", "")).startswith("text/html")))]
    dropped = total - len(flows)

    groups: dict[tuple, dict] = {}
    for fl in flows:
        upstream = fl.get("upstream", "")
        service = service_map.get(upstream) or service_map.get(fl.get("host_header", "")) or upstream
        tmpl, params = template_path(fl.get("path", "/"))
        key = (service, fl.get("method", "GET"), tmpl)
        g = groups.setdefault(key, {
            "service": service,
            "hosts": set(),
            "capture_points": set(),
            "method": key[1],
            "path_template": tmpl,
            "path_params": params,
            "query_params": set(),
            "status": Counter(),
            "auth_present": 0,
            "unauth_status": Counter(),
            "auth_schemes": set(),
            "cookie_names": set(),
            "req_ct": set(),
            "resp_ct": set(),
            "req_shape": None,
            "resp_shape": None,
            "lat": [],
            "examples": [],
            "first": None,
            "last": None,
            "errors": 0,
        })
        g["hosts"].add(upstream)
        g["capture_points"].add(fl.get("capture_point", "unknown"))
        g["query_params"].update(fl.get("query_keys", []))
        g["status"][str(fl.get("status"))] += 1
        if fl.get("error"):
            g["errors"] += 1
        hdr = fl.get("req_headers", {}) or {}
        scheme = _auth_scheme(hdr)
        if scheme:
            g["auth_present"] += 1
            g["auth_schemes"].add(scheme)
        else:
            g["unauth_status"][str(fl.get("status"))] += 1
        if "cookie" in hdr:
            g["cookie_names"].update(hdr["cookie"].strip("<>").split(","))
        if fl.get("req_content_type"):
            g["req_ct"].add(fl["req_content_type"].split(";")[0])
        if fl.get("resp_content_type"):
            g["resp_ct"].add(fl["resp_content_type"].split(";")[0])
        g["req_shape"] = merge_shapes(g["req_shape"], fl.get("req_body_shape"))
        g["resp_shape"] = merge_shapes(g["resp_shape"], fl.get("resp_body_shape"))
        if fl.get("duration_ms") is not None:
            g["lat"].append(float(fl["duration_ms"]))
        if len(g["examples"]) < 3 and fl.get("path") not in g["examples"]:
            g["examples"].append(fl.get("path"))
        ts = fl.get("ts")
        if ts:
            g["first"] = min(g["first"] or ts, ts)
            g["last"] = max(g["last"] or ts, ts)

    records = []
    for g in sorted(groups.values(), key=lambda x: (x["service"], x["path_template"], x["method"])):
        hits = sum(g["status"].values())
        lat = sorted(g["lat"])
        records.append({
            "kind": "endpoint",
            "service": g["service"],
            "method": g["method"],
            "path_template": g["path_template"],
            "path_params": g["path_params"],
            "query_params": sorted(g["query_params"]),
            "hosts": sorted(g["hosts"]),
            "capture_points": sorted(g["capture_points"]),
            "hits": hits,
            "status_codes": dict(sorted(g["status"].items())),
            "transport_errors": g["errors"],
            "auth": {
                "authorization_header_seen": g["auth_present"],
                "authorization_header_missing": hits - g["auth_present"],
                # status codes of the requests that carried no credential:
                # 2xx here means the endpoint answered an anonymous caller
                "status_codes_without_auth": dict(sorted(g["unauth_status"].items())),
                "schemes": sorted(g["auth_schemes"]),
                "cookie_names": sorted(g["cookie_names"]),
            },
            "request": {"content_types": sorted(g["req_ct"]), "body_shape": g["req_shape"]},
            "response": {"content_types": sorted(g["resp_ct"]), "body_shape": g["resp_shape"]},
            "latency_ms": {
                "p50": round(statistics.median(lat), 2) if lat else None,
                "max": round(lat[-1], 2) if lat else None,
            },
            "example_paths": g["examples"],
            "first_seen": g["first"],
            "last_seen": g["last"],
        })

    by_point = Counter(fl.get("capture_point", "unknown") for fl in flows)
    stats = {
        "flows": len(flows),
        "flows_ignored": dropped,
        "endpoints": len(records),
        "services": len({r["service"] for r in records}),
        "flows_by_capture_point": dict(by_point),
        "unmapped_hosts": sorted({r["service"] for r in records if ":" in r["service"]}),
    }
    if stats["unmapped_hosts"]:
        warnings.append(
            "some hosts are not in target.service_map, so they show up as host:port: "
            + ", ".join(stats["unmapped_hosts"])
        )
    return envelope(SOURCE, "mitmproxy", run_id, inputs, records, stats, warnings,
                    (time.perf_counter() - t0) * 1000)
