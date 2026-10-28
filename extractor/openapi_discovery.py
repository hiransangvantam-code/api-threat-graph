"""
Extractor 1b - OPENAPI DISCOVERY  (source: OpenAPI / Swagger documents)

Two ways to find specs:
  live  - probe each running service on the usual spec URLs
          (/openapi.json, /v3/api-docs, /swagger.json, ...)
  files - read spec files checked into the repo

Output: one "spec" record per service/document with every documented
operation flattened (method, path, params, request body fields, declared
security). This is the "what the team *says* the API is" view. Comparing it
with runtime traffic later is how shadow and zombie APIs get found.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import httpx
import yaml

from .common import SELF_USER_AGENT, envelope, iter_files

SOURCE = "openapi"
DEFAULT_PROBE_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/v3/api-docs",
    "/swagger.json",
    "/v2/api-docs",
    "/api-docs",
    "/swagger/v1/swagger.json",
    "/api/openapi.json",
]
METHODS = ("get", "put", "post", "delete", "patch", "head", "options", "trace")


def _parse(text: str) -> dict | None:
    try:
        doc = json.loads(text)
    except ValueError:
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            return None
    if isinstance(doc, dict) and ("openapi" in doc or "swagger" in doc) and "paths" in doc:
        return doc
    return None


def _deref(doc: dict, node, depth: int = 0):
    """Resolve local $ref pointers like #/components/schemas/User (bounded)."""
    if depth > 6 or not isinstance(node, dict):
        return node
    ref = node.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/"):
        target = doc
        for part in ref[2:].split("/"):
            target = target.get(part, {}) if isinstance(target, dict) else {}
        return _deref(doc, target, depth + 1)
    return node


def _schema_fields(doc: dict, schema) -> dict:
    s = _deref(doc, schema or {})
    for combo in ("allOf", "anyOf", "oneOf"):
        if combo in s:
            merged = {}
            for sub in s[combo]:
                merged.update(_schema_fields(doc, sub))
            return merged
    props = s.get("properties") or {}
    req = set(s.get("required") or [])
    out = {}
    for name, p in props.items():
        p = _deref(doc, p)
        typ = p.get("type") or ("object" if "properties" in p else "any")
        if p.get("format"):
            typ += ":" + p["format"]
        out[name] = typ + ("" if name in req else "?")
    return out


def _security_scheme_summary(doc: dict) -> dict:
    schemes = (doc.get("components") or {}).get("securitySchemes") or doc.get("securityDefinitions") or {}
    out = {}
    for name, s in schemes.items():
        s = _deref(doc, s)
        out[name] = {k: s[k] for k in ("type", "scheme", "in", "name", "bearerFormat") if k in s}
        if "flows" in s:
            out[name]["flows"] = sorted(s["flows"])
    return out


def _auth_level(sec) -> str:
    """'required' | 'optional' | 'none' from an OpenAPI security requirement list."""
    if not sec:
        return "none"
    non_empty = [r for r in sec if r]
    if not non_empty:
        return "none"
    return "required" if len(non_empty) == len(sec) else "optional"


def _operations(doc: dict) -> list[dict]:
    is_v2 = "swagger" in doc
    global_sec = doc.get("security")
    ops = []
    for path, item in (doc.get("paths") or {}).items():
        item = _deref(doc, item)
        shared_params = item.get("parameters", [])
        for m in METHODS:
            op = item.get(m)
            if not isinstance(op, dict):
                continue
            params = []
            for p in shared_params + op.get("parameters", []):
                p = _deref(doc, p)
                if is_v2 and p.get("in") == "body":
                    continue
                schema = p.get("schema") or p
                params.append({
                    "name": p.get("name"),
                    "in": p.get("in"),
                    "required": bool(p.get("required")),
                    "type": schema.get("type", "any") + (":" + schema["format"] if schema.get("format") else ""),
                })
            body = None
            if not is_v2 and op.get("requestBody"):
                rb = _deref(doc, op["requestBody"])
                content = rb.get("content") or {}
                first = next(iter(content.values()), {})
                body = {
                    "required": bool(rb.get("required")),
                    "content_types": sorted(content),
                    "fields": _schema_fields(doc, first.get("schema")),
                }
            elif is_v2:
                bp = next((_deref(doc, p) for p in op.get("parameters", []) if _deref(doc, p).get("in") == "body"), None)
                if bp:
                    body = {
                        "required": bool(bp.get("required")),
                        "content_types": op.get("consumes") or doc.get("consumes") or [],
                        "fields": _schema_fields(doc, bp.get("schema")),
                    }
            # security: None in the op means "inherit global"; [] means explicitly open
            sec = op.get("security", global_sec)
            ops.append({
                "method": m.upper(),
                "path": path,
                "operation_id": op.get("operationId"),
                "summary": op.get("summary"),
                "tags": op.get("tags", []),
                "deprecated": bool(op.get("deprecated")),
                "parameters": params,
                "request_body": body,
                "responses": sorted(str(c) for c in (op.get("responses") or {})),
                "security": sec,
                "auth_declared": _auth_level(sec),
            })
    return ops


def _spec_record(service: str, origin: str, location: str, doc: dict) -> dict:
    info = doc.get("info") or {}
    if "servers" in doc:
        servers = [s.get("url") for s in doc.get("servers", [])]
    else:
        servers = [f"{(doc.get('schemes') or ['http'])[0]}://{doc.get('host', '')}{doc.get('basePath', '')}"] if doc.get("host") else []
    ops = _operations(doc)
    return {
        "kind": "spec",
        "service": service,
        "origin": origin,
        "location": location,
        "spec_version": str(doc.get("openapi") or doc.get("swagger")),
        "title": info.get("title"),
        "api_version": info.get("version"),
        "servers": servers,
        "security_schemes": _security_scheme_summary(doc),
        "global_security": doc.get("security"),
        "operation_count": len(ops),
        "operations": ops,
    }


def extract(cfg: dict, service_map: dict[str, str], run_id: str) -> dict:
    t0 = time.perf_counter()
    records, inputs, warnings, probes = [], [], [], []
    probe_paths = cfg.get("probe_paths") or DEFAULT_PROBE_PATHS

    # live targets default to every service in the service map
    targets = cfg.get("live_targets")
    if targets is None:
        targets = [{"service": svc, "base_url": f"http://{hostport}"}
                   for hostport, svc in service_map.items()]

    with httpx.Client(timeout=cfg.get("timeout_s", 3), trust_env=False, follow_redirects=True,
                      headers={"User-Agent": SELF_USER_AGENT + " (openapi-prober)"}) as client:
        for t in targets:
            found = False
            for pp in probe_paths:
                url = t["base_url"].rstrip("/") + pp
                try:
                    r = client.get(url)
                    status = r.status_code
                except httpx.HTTPError as e:
                    probes.append({"service": t["service"], "url": url, "result": f"error: {type(e).__name__}"})
                    break  # host is down, no point trying the other paths
                doc = _parse(r.text) if status == 200 else None
                probes.append({"service": t["service"], "url": url, "result": status if not doc else "spec"})
                if doc:
                    inputs.append(url)
                    records.append(_spec_record(t["service"], "live", url, doc))
                    found = True
                    break
            if not found:
                warnings.append(f"{t['service']}: no live spec at any probed path")

    file_cfg = cfg.get("spec_files", [])
    for entry in file_cfg:
        entry = entry if isinstance(entry, dict) else {"path": entry}
        for f in iter_files([entry["path"]], (".json", ".yaml", ".yml")):
            doc = _parse(f.read_text(encoding="utf-8"))
            if not doc:
                continue
            inputs.append(str(f))
            by_prefix = entry.get("service_by_prefix")
            if by_prefix:
                # one document for the whole API (published at the gateway):
                # split its paths per backend service by path prefix
                groups: dict[str, dict] = {}
                for path, item in (doc.get("paths") or {}).items():
                    svc = next((s for pre, s in sorted(by_prefix.items(), key=lambda kv: -len(kv[0]))
                                if path.startswith(pre)), None)
                    if svc:
                        groups.setdefault(svc, {})[path] = item
                for svc, paths in groups.items():
                    records.append(_spec_record(svc, "file", str(f), {**doc, "paths": paths}))
                continue
            svc = entry.get("service") or (doc.get("info") or {}).get("title") or f.stem
            records.append(_spec_record(svc, "file", str(f), doc))

    # a service can have both a live and a file spec; that is useful, keep both
    stats = {
        "specs": len(records),
        "services_with_spec": sorted({r["service"] for r in records}),
        "services_without_live_spec": sorted(
            {t["service"] for t in targets} - {r["service"] for r in records if r["origin"] == "live"}
        ),
        "operations": sum(r["operation_count"] for r in records),
        "probes": len(probes),
    }
    out = envelope(SOURCE, "openapi-prober", run_id, inputs, records, stats, warnings,
                   (time.perf_counter() - t0) * 1000)
    out["probe_log"] = probes
    return out
