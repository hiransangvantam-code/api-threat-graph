"""The ten test companies (companies/): generated files are current, the ground truth
points at things that exist, ATG's parsers read every company's gateway configuration,
and no file holds anything that looks like a credential."""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "companies"))
import build  # noqa: E402

from extractor import infra_discovery  # noqa: E402


def test_generated_files_are_current():
    r = subprocess.run([sys.executable, str(ROOT / "companies" / "build.py"), "--check"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout


@pytest.mark.parametrize("cid", build.COMPANIES)
def test_ground_truth_points_at_real_things(cid):
    gt = json.loads((ROOT / "companies" / cid / "ground-truth.json").read_text(encoding="utf-8"))
    c = build.load(cid)
    endpoints = {e["id"] for e in gt["endpoints"]}
    workloads = {f"svc:{n}" for n in c["services"]} | {f"svc:{c['gateway']['name']}"}
    assert gt["planted"], "every company has planted weaknesses"
    for item in gt["planted"] + gt["not_flaws"]:
        assert item["target"] in endpoints | workloads, item
        assert item["why"]
    assert len(endpoints) == len(gt["endpoints"]), "endpoint ids are unique"


@pytest.mark.parametrize("cid", build.COMPANIES)
def test_atg_reads_every_gateway_route(cid):
    folder = ROOT / "companies" / cid
    cfg = yaml.safe_load((folder / "atg-target.yaml").read_text(encoding="utf-8"))["sources"]["infrastructure"]
    cfg["manifest_paths"] = [str(folder / "k8s")]
    for g in cfg.get("gateway_configs", []):
        g["path"] = str(folder / g["path"])
        g["env_from"] = [str(folder / p) for p in g.get("env_from", [])]
    out = infra_discovery.extract(cfg, {}, "test")
    prefixes = {r["match_prefix"] for r in out["records"] if r["kind"] == "gateway_route"}
    wanted = {r["prefix"] for r in build.load(cid)["gateway"]["routes"]}
    assert wanted <= prefixes, wanted - prefixes
    workloads = {r["name"] for r in out["records"] if r["kind"] == "workload"}
    assert set(build.load(cid)["services"]) <= workloads


CREDENTIAL_LOOKING = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),          # a JWT
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                                  # an AWS key id
    re.compile(r"(?i)(password|passwd|secret|api[_-]?key|token)\w*['\"]?\s*[:=]\s*['\"](?!password['\"])[A-Za-z0-9+/_\-]{8,}['\"]"),  # a value, not a key name
    re.compile(r"(?im)^\s*-?\s*(password|passwd|secret|api[_-]?key|token)\s*:\s*(?!password\s*$)[A-Za-z0-9+/_\-]{8,}\s*$"),
    re.compile(r"\b(?:\d[ -]?){13,16}\b"),                                # a card-number-like digit run
]


def test_no_credentials_or_personal_data_in_company_files():
    for p in (ROOT / "companies").rglob("*"):
        if not p.is_file() or "node_modules" in p.parts or p.suffix in (".lock",) or p.name == "package-lock.json":
            continue
        text = p.read_text(encoding="utf-8", errors="ignore")
        for rx in CREDENTIAL_LOOKING:
            m = rx.search(text)
            assert not m, f"{p.relative_to(ROOT)}: {m.group(0)!r}"
