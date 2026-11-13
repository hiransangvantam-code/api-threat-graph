"""The faster fix planner must produce exactly the plan of the original one (bench/planner_v1.py)."""
from __future__ import annotations

import copy
import json
import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from atg.analysis import ACTION_OF_RULE, analyze, mitigation_plan  # noqa: E402
from atg.graphstore import GraphStore  # noqa: E402
from atg.normalizer import normalize  # noqa: E402
from bench.planner_v1 import mitigation_plan_v1  # noqa: E402
from bench.stress import clone_eujf  # noqa: E402

SHOPLITE_RUNS = sorted((ROOT / "results" / "grid").glob("shoplite-*/raw"))


def same_plan(findings, paths):
    a = mitigation_plan(copy.deepcopy(findings), copy.deepcopy(paths))
    b = mitigation_plan_v1(copy.deepcopy(findings), copy.deepcopy(paths))
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    return a


def analysis_of(eujf):
    return analyze(eujf, GraphStore("sqlite:///:memory:"))


@pytest.mark.skipif(not SHOPLITE_RUNS, reason="results/grid not present")
@pytest.mark.parametrize("raw", SHOPLITE_RUNS, ids=lambda p: p.parent.name)
def test_same_plan_on_recorded_runs(raw):
    a = analysis_of(normalize(raw))
    plan = same_plan(a["findings"], a["attack_paths"])
    assert plan["steps"]


@pytest.mark.skipif(not SHOPLITE_RUNS, reason="results/grid not present")
@pytest.mark.parametrize("k,d", [(2, 0), (5, 0), (10, 0), (5, 1.0), (5, 2.0)])
def test_same_plan_on_larger_systems(k, d):
    a = analysis_of(clone_eujf(normalize(SHOPLITE_RUNS[0]), k, d))
    same_plan(a["findings"], a["attack_paths"])


def test_same_plan_on_random_inputs_with_ties():
    rnd = random.Random(7)
    rules = list(ACTION_OF_RULE) + ["TS-07", "LT-01", "API7"]
    apcr = [25.0, 20.0, 19.0, 16.0, 15.2, 12.0, 10.0, 9.5, 8.0, 7.6, 6.0, 4.75, 2.0]  # few values -> many ties
    for _ in range(300):
        targets = [f"ep:s{rnd.randint(1, 4)}:GET:/x{rnd.randint(1, 5)}" for _ in range(8)] + [f"svc:s{i}" for i in range(1, 5)]
        findings = []
        for i in range(rnd.randint(1, 25)):
            t = rnd.choice(targets)
            findings.append({"id": f"F-{i + 1:03d}", "rule_id": rnd.choice(rules), "target": t,
                             "target_kind": "service" if t.startswith("svc:") else "endpoint",
                             "affected_api": t.split(":")[-1], "service": t.split(":")[1], "recommendation": "fix it",
                             "mitigation": ["m"]})
        paths = []
        for f in findings:
            for _ in range(rnd.randint(0, 4)):
                actor = rnd.choice(["actor:internet", "actor:in-cluster"])
                first = rnd.choice([f["target"], f"svc:s{rnd.randint(1, 4)}"])
                paths.append({"nodes": [actor, first, f"vuln:{f['id']}", "risk:x"], "rels": [], "finding_id": f["id"],
                              "apcr": rnd.choice(apcr)})
        same_plan(findings, paths)
