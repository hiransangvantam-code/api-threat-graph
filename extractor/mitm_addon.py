"""
mitmproxy addon: capture API traffic as privacy-safe JSON lines.

Run it with mitmdump, for example (two listeners in one process):

    mitmdump -s extractor/mitm_addon.py \
        --mode reverse:http://127.0.0.1:8000@8080 \   # north-south, in front of the gateway
        --mode regular@8081 \                          # east-west, services use it as a proxy
        --set atg_capture=output/capture/flows.jsonl

What gets written per request:
  - method, host, port, path, query parameter NAMES
  - header NAMES, plus the auth scheme only (e.g. "Bearer"), never the token
  - JSON body *shape* (keys + value types such as "string:email"), never values
  - status code, content types, timing

So the capture can be shared with the team or kept on disk without leaking
customer data. That matters for the paper's "zero data exfiltration" claim.
"""
from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from urllib.parse import parse_qsl

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mitmproxy import ctx, http  # noqa: E402

from extractor.common import header_summary, shape  # noqa: E402

def _mode_name(flow: http.HTTPFlow) -> str:
    mode = getattr(flow.client_conn, "proxy_mode", None)
    name = type(mode).__name__.lower() if mode else ""
    if "reverse" in name:
        return "north-south"
    if "regular" in name or "upstream" in name:
        return "east-west"
    return name or "unknown"


def _body_shape(content_type: str, raw: bytes | None):
    if not raw:
        return None
    ct = (content_type or "").lower()
    try:
        if "json" in ct:
            return shape(json.loads(raw))
        if "x-www-form-urlencoded" in ct:
            return shape(dict(parse_qsl(raw.decode("utf-8", "replace"))))
    except (ValueError, UnicodeDecodeError):
        return {"_unparsed": f"{len(raw)} bytes"}
    return {"_opaque": f"{ct or 'unknown'} {len(raw)} bytes"}


class APICapture:
    def __init__(self):
        self._lock = threading.Lock()
        self.count = 0

    def load(self, loader):
        loader.add_option(
            "atg_capture", str, "output/capture/flows.jsonl",
            "Where to append captured API flows (JSON lines).",
        )

    def _write(self, rec: dict):
        path = Path(ctx.options.atg_capture)
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
        self.count += 1

    def _base(self, flow: http.HTTPFlow) -> dict:
        req = flow.request
        return {
            "ts": req.timestamp_start,
            "capture_point": _mode_name(flow),
            "scheme": req.scheme,
            "host_header": req.host_header or req.pretty_host,   # what the client asked for
            "upstream": f"{req.host}:{req.port}",                # where it really went
            "method": req.method,
            "path": req.path.split("?", 1)[0],
            "query_keys": sorted({k for k, _ in req.query.items(multi=True)}),
            "req_headers": header_summary(req.headers.items(multi=True)),
            "user_agent": req.headers.get("user-agent", "")[:120],
            "req_content_type": req.headers.get("content-type", ""),
            "req_body_shape": _body_shape(req.headers.get("content-type", ""), req.raw_content),
            "http_version": req.http_version,
        }

    def response(self, flow: http.HTTPFlow):
        rec = self._base(flow)
        resp = flow.response
        rec.update(
            status=resp.status_code,
            resp_content_type=resp.headers.get("content-type", ""),
            resp_headers=header_summary(resp.headers.items(multi=True)),
            resp_body_shape=_body_shape(resp.headers.get("content-type", ""), resp.raw_content),
            duration_ms=round(((resp.timestamp_end or resp.timestamp_start) - flow.request.timestamp_start) * 1000, 2),
        )
        self._write(rec)

    def error(self, flow: http.HTTPFlow):
        rec = self._base(flow)
        rec.update(status=None, error=str(flow.error))
        self._write(rec)


addons = [APICapture()]
