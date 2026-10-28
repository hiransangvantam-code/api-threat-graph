"""Shared helpers for the experiment harness (bench/). Not part of the tool under test."""
from __future__ import annotations

import random
import re
import uuid
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
TESTBEDS = ROOT / "bench/testbeds"
IGNORED = {"/health", "/healthz", "/readyz", "/livez", "/metrics"}   # same list the extractor skips


def load_topology(name: str) -> dict:
    return yaml.safe_load((TESTBEDS / name / "topology.yaml").read_text(encoding="utf-8"))


def shape(path: str) -> str:
    """/orders/{order_id} and /orders/{int} -> /orders/{}"""
    p = re.sub(r"\{[^}]*\}", "{}", path.rstrip("/") or "/")
    return p if p.startswith("/") else "/" + p


def route_matches(pattern: str, path: str) -> bool:
    """Gateway route pattern: Spring '/api/v1/x/**', nginx location '/identity/', ShopLite prefix."""
    prefix = re.sub(r"/\*\*$", "", pattern)
    return path == prefix or path.startswith(prefix.rstrip("/") + "/") or (pattern.endswith("/") and path.startswith(pattern))


def public_path(topo: dict, path: str, service: str | None = None) -> str | None:
    """Path a client uses at the gateway for a backend endpoint of `service`, or None if
    not routed. Only routes to that service count (a strip-prefix route would otherwise
    accept any backend path)."""
    for r in (topo.get("gateway") or {}).get("routes", []):
        if service and r["service"] != service:
            continue
        candidate = (r.get("strip_prefix") or "") + path
        if route_matches(r["path"], candidate):
            return candidate
    return None


def routed_service(topo: dict, public: str) -> tuple[str, str] | None:
    """(service, backend path) for a public path."""
    best = None
    for r in (topo.get("gateway") or {}).get("routes", []):
        if route_matches(r["path"], public):
            plen = len(re.sub(r"/\*\*$", "", r["path"]))
            if best is None or plen > best[0]:
                strip = r.get("strip_prefix") or ""
                best = (plen, r["service"], public[len(strip):] if strip and public.startswith(strip) else public)
    return (best[1], best[2]) if best else None


def returns_list(method: str, path: str) -> bool:
    last = path.rstrip("/").split("/")[-1]
    return method == "GET" and not last.startswith("{") and (last.endswith("s") or last in ("all", "list", "recent"))


def response_body(method: str, path: str) -> dict:
    """Replica responses carry generic fields only."""
    if returns_list(method, path):
        return {"count": 2, "items": [{"id": str(uuid.uuid4()), "status": "ok"} for _ in range(2)]}
    return {"id": str(uuid.uuid4()), "status": "ok"}


STATIONS = ["shanghai", "beijing", "nanjing", "suzhou", "taiyuan", "wuxi"]
TRAINS = ["G1234", "G1235", "D1345", "Z1234", "T1235", "K1235"]


def param_value(name: str, rnd: random.Random, ids: str = "uuid") -> str:
    """A plausible value for a path parameter, chosen by its name. `ids` is the
    identifier style of the system under test ('uuid' or 'int')."""
    n = name.lower()
    if "date" in n:
        return f"2026-10-{rnd.randint(10, 28)}"
    if "trainnumber" in n or n in ("tripid",):
        return rnd.choice(TRAINS)
    if "station" in n or n.endswith("name") or n in ("from", "to", "city"):
        return rnd.choice(STATIONS)
    if n == "vin":
        return "".join(rnd.choice("ABCDEFGHJKLMNPRSTUVWXYZ0123456789") for _ in range(17))
    if n == "postid":
        return "".join(rnd.choice("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(22))
    if "code" in n:
        return "".join(rnd.choice("abcdefghjkmnpqrstuvwxyz23456789") for _ in range(5))
    if n == "path":
        return "latest"
    if ids == "uuid" and (n.endswith("id") or n in ("id",)):
        return str(uuid.UUID(int=rnd.getrandbits(128)))
    return str(rnd.randint(1, 5000))


def fill(path: str, rnd: random.Random, ids: str = "uuid") -> str:
    return re.sub(r"\{([^}]*)\}", lambda m: param_value(m.group(1), rnd, ids), path)
