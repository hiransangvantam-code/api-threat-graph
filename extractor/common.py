"""
Shared helpers for every extractor.

The most important thing in this file is `envelope()`. Every extractor writes
its output in the same wrapper, which is the "RAW API DATA" contract that
Phase 2 (the API Normalizer) reads. See docs/RAW_DATA_CONTRACT.md.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
from pathlib import Path
from typing import Any, Iterable

import yaml

SCHEMA = "atg.raw/v1"
EXTRACTOR_VERSION = "0.1.0"
# The extractor's own requests (OpenAPI probes, health checks) carry this
# User-Agent so the traffic/trace extractors can drop them from results.
SELF_USER_AGENT = f"atg-extractor/{EXTRACTOR_VERSION}"
DEFAULT_IGNORE_PATHS = ["/health", "/healthz", "/readyz", "/livez", "/metrics"]


def is_ignored(path: str, user_agent: str, ignore_paths: list[str]) -> bool:
    if (user_agent or "").startswith("atg-extractor"):
        return True
    p = (path or "").split("?")[0].rstrip("/") or "/"
    return p in ignore_paths


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def envelope(
    source: str,
    collector: str,
    run_id: str,
    inputs: list[str],
    records: list[dict],
    stats: dict,
    warnings: list[str] | None = None,
    duration_ms: float | None = None,
) -> dict:
    return {
        "schema": SCHEMA,
        "source": source,
        "collector": collector,
        "extractor_version": EXTRACTOR_VERSION,
        "run_id": run_id,
        "collected_at": now_iso(),
        "duration_ms": round(duration_ms, 1) if duration_ms is not None else None,
        "inputs": inputs,
        "stats": stats,
        "warnings": warnings or [],
        "records": records,
    }


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def iter_files(paths: Iterable[str | Path], suffixes: tuple[str, ...]) -> list[Path]:
    """Expand a mix of files and directories into a sorted file list."""
    out: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            out.extend(f for f in sorted(p.rglob("*")) if f.suffix.lower() in suffixes)
        elif p.is_file():
            out.append(p)
    return out


def load_yaml_docs(path: Path) -> list[dict]:
    try:
        return [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if isinstance(d, dict)]
    except yaml.YAMLError:
        return []


# ---------------------------------------------------------------------------
# Path templating: /api/users/17/addresses  ->  /api/users/{id}/addresses
# ---------------------------------------------------------------------------
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX = re.compile(r"^[0-9a-f]{12,}$", re.I)
_INT = re.compile(r"^\d+$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_TOKENISH = re.compile(r"^(?=.*\d)(?=.*[a-z])[a-z0-9_\-]{8,}$", re.I)


def _looks_random(seg: str) -> bool:
    """Letters and digits mixed like an identifier ("a8f3k2q9", "ORD20240117"),
    not a word that happens to contain a digit ("travel2service", "oauth2callback")."""
    digits = sum(c.isdigit() for c in seg)
    switches = sum(1 for a, b in zip(seg, seg[1:]) if a.isdigit() != b.isdigit())
    return digits / len(seg) >= 0.25 or switches >= 4


def classify_segment(seg: str) -> str | None:
    if _INT.match(seg):
        return "int"
    if _DATE.match(seg):
        return "date"
    if _UUID.match(seg):
        return "uuid"
    if _HEX.match(seg):
        return "hex"
    if _TOKENISH.match(seg) and _looks_random(seg):
        return "id"
    return None


def template_path(path: str) -> tuple[str, list[dict]]:
    """Return (template, params). Literal segments are kept as they are."""
    segs = path.split("?")[0].split("/")
    out, params = [], []
    for i, seg in enumerate(segs):
        kind = classify_segment(seg) if seg else None
        if kind:
            # numeric ids collapse to {id} (paper III-C); uuid/date/hex keep their own name
            out.append("{" + ("id" if kind == "int" else kind) + "}")
            params.append({"position": i, "kind": kind})
        else:
            out.append(seg)
    return "/".join(out) or "/", params


def match_key(method: str, path: str) -> str:
    """Comparison key that ignores parameter names: GET /users/{}"""
    return f"{method.upper()} " + re.sub(r"\{[^}]*\}", "{}", path.rstrip("/") or "/")


# ---------------------------------------------------------------------------
# Body "shape": keep structure and value *types*, never the values.
# This is what keeps the prototype privacy-preserving: the capture file never
# contains a real email, token or card number, only that one was there.
# ---------------------------------------------------------------------------
_FORMATS = [
    ("email", re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.I)),
    ("uuid", _UUID),
    ("datetime", re.compile(r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2})?")),
    ("url", re.compile(r"^https?://", re.I)),
    ("jwt", re.compile(r"^eyJ[\w-]+\.[\w-]+\.[\w-]*$")),
    ("ipv4", re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")),
]


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for d in reversed(digits):
        n = int(d)
        if alt:
            n = n * 2 - 9 if n * 2 > 9 else n * 2
        total += n
        alt = not alt
    return total % 10 == 0


def string_format(v: str) -> str:
    for name, rx in _FORMATS:
        if rx.match(v):
            return name
    digits = re.sub(r"[\s\-+()]", "", v)
    if digits.isdigit():
        if 13 <= len(digits) <= 19 and _luhn(digits):
            return "card_number"
        if 9 <= len(digits) <= 12:
            return "phone"
    return ""


def shape(value: Any, depth: int = 0) -> Any:
    if depth > 5:
        return "..."
    if isinstance(value, dict):
        return {str(k): shape(v, depth + 1) for k, v in list(value.items())[:60]}
    if isinstance(value, list):
        return [shape(value[0], depth + 1)] if value else []
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if value is None:
        return "null"
    fmt = string_format(str(value))
    return f"string:{fmt}" if fmt else "string"


def merge_shapes(a: Any, b: Any) -> Any:
    """Union of two shapes so 25 observations collapse into one schema."""
    if a is None:
        return b
    if b is None:
        return a
    if isinstance(a, dict) and isinstance(b, dict):
        return {k: merge_shapes(a.get(k), b.get(k)) for k in {**a, **b}}
    if isinstance(a, list) and isinstance(b, list):
        if not a or not b:
            return a or b
        return [merge_shapes(a[0], b[0])]
    if a == b:
        return a
    if isinstance(a, str) and isinstance(b, str):
        return "|".join(sorted(set(a.split("|")) | set(b.split("|"))))
    return a  # dict vs scalar etc.: keep the first, rare in practice


SENSITIVE_NAME = re.compile(r"secret|passw|pwd|token|api[_-]?key|private|credential|auth", re.I)


def header_summary(pairs) -> dict:
    """Header names only. For auth headers keep the scheme ("Bearer"), never the
    credential; for cookies keep cookie names only."""
    if isinstance(pairs, dict):
        pairs = pairs.items()
    out = {}
    for name, value in pairs:
        key = name.lower()
        value = str(value)
        if key in ("authorization", "proxy-authorization"):
            out[key] = "<" + (value.split(" ", 1)[0] if " " in value else "opaque") + ">"
        elif key == "cookie":
            out[key] = "<" + ",".join(sorted(c.split("=", 1)[0].strip() for c in value.split(";"))) + ">"
        elif SENSITIVE_NAME.search(key):
            out[key] = "<redacted>"
        else:
            out[key] = "<present>"
    return out
