"""
Graph store for the threat graph ("POSTGRESQL GRAPH" in Fig. 1), and the
place where Phase 2 persists the normalized API inventory in the Extended
Universal JSON Format (paper III-C).

Two backends with the same schema and the same SQL:
  postgresql://user:pass@host/db   real PostgreSQL (needs: pip install "psycopg[binary]")
  sqlite:///output/atg.db          default, built into Python, nothing to install

The attack path search is a recursive CTE that runs inside the database, so
the same query works on a laptop (SQLite) and on the team's PostgreSQL server.

Tables (every row is tagged with run_id, so runs can be compared over time):
  atg_runs      one row per pipeline run + summary JSON (feeds "Trend & insight")
  atg_eujf      Phase 2: one EUJF record per API (api_id, service, endpoint, method,
                auth, evidence confidence) + the full record as JSON
  atg_nodes     id, type (Actor/API/Endpoint/Dependency/Vulnerability/Risk), label, risk, props
  atg_edges     src -> dst, rel, props
  atg_findings  one row per vulnerability finding
  atg_paths     ranked attack paths with their APCR score
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS atg_runs (
         run_id TEXT PRIMARY KEY, target TEXT, created_at TEXT, summary TEXT)""",
    """CREATE TABLE IF NOT EXISTS atg_eujf (
         run_id TEXT NOT NULL, api_id TEXT NOT NULL, service TEXT, endpoint TEXT, method TEXT, auth TEXT,
         confidence TEXT, inventory_status TEXT, record TEXT, PRIMARY KEY (run_id, api_id))""",
    """CREATE TABLE IF NOT EXISTS atg_nodes (
         run_id TEXT NOT NULL, id TEXT NOT NULL, type TEXT NOT NULL, label TEXT,
         own_risk REAL, propagated_risk REAL, props TEXT, PRIMARY KEY (run_id, id))""",
    """CREATE TABLE IF NOT EXISTS atg_edges (
         run_id TEXT NOT NULL, src TEXT NOT NULL, dst TEXT NOT NULL, rel TEXT NOT NULL, props TEXT)""",
    "CREATE INDEX IF NOT EXISTS atg_edges_src ON atg_edges (run_id, src)",
    """CREATE TABLE IF NOT EXISTS atg_findings (
         run_id TEXT NOT NULL, id TEXT NOT NULL, rule_id TEXT, severity TEXT, score REAL,
         target TEXT, data TEXT, PRIMARY KEY (run_id, id))""",
    """CREATE TABLE IF NOT EXISTS atg_paths (
         run_id TEXT NOT NULL, id TEXT NOT NULL, apcr REAL, finding_id TEXT, nodes TEXT, rels TEXT,
         PRIMARY KEY (run_id, id))""",
]

# Walk from every Actor along attack-relevant edges until a Risk node.
# After a RUNS_ON hop (endpoint -> its service) only HAS_FINDING may follow,
# so reaching one endpoint never "teleports" you to the service's other endpoints.
ATTACK_PATH_SQL = """
WITH RECURSIVE walk(node, path, rels, last_rel, depth) AS (
    SELECT n.id, CAST('|' || n.id || '|' AS TEXT), CAST('' AS TEXT), CAST('' AS TEXT), 0
    FROM atg_nodes n WHERE n.run_id = {p} AND n.type = 'Actor'
  UNION ALL
    SELECT e.dst, w.path || e.dst || '|', w.rels || e.rel || ',', e.rel, w.depth + 1
    FROM walk w
    JOIN atg_edges e ON e.run_id = {p} AND e.src = w.node
    WHERE w.depth < {p}
      AND e.rel IN ('REACHES', 'EXPOSES', 'ROUTES_TO', 'CALLS', 'RUNS_ON', 'HAS_FINDING', 'LEADS_TO')
      AND (w.last_rel <> 'RUNS_ON' OR e.rel = 'HAS_FINDING')
      AND {notin}
)
SELECT w.path, w.rels FROM walk w
JOIN atg_nodes n ON n.run_id = {p} AND n.id = w.node
WHERE n.type = 'Risk'
"""


class GraphStore:
    def __init__(self, url: str | None):
        url = url or "sqlite:///output/atg.db"
        self.url = url
        if url.startswith(("postgresql://", "postgres://")):
            try:
                import psycopg
            except ImportError as exc:
                raise SystemExit('PostgreSQL store needs: pip install "psycopg[binary]"') from exc
            self.conn = psycopg.connect(url, autocommit=False, client_encoding="utf8")  # text, never bytes
            self.kind, self.p = "postgresql", "%s"
            self.notin = "strpos(w.path, '|' || e.dst || '|') = 0"
        else:
            path = Path(url.replace("sqlite:///", "", 1))
            path.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(path)
            self.kind, self.p = "sqlite", "?"
            self.notin = "instr(w.path, '|' || e.dst || '|') = 0"
        cur = self.conn.cursor()
        for stmt in SCHEMA:
            cur.execute(stmt)
        self.conn.commit()

    @property
    def label(self) -> str:
        if self.kind == "sqlite":
            return f"SQLite ({self.url.replace('sqlite:///', '')})"
        return "PostgreSQL (" + self.url.split("@")[-1] + ")"

    def _q(self, sql: str) -> str:
        return sql.replace("?", self.p)

    def save_eujf(self, eujf: dict) -> int:
        """Phase 2 output -> table atg_eujf (one row per API)."""
        cur = self.conn.cursor()
        cur.execute(self._q("DELETE FROM atg_eujf WHERE run_id = ?"), (eujf["run_id"],))
        rows = [(eujf["run_id"], e["api_id"], e["service"], e["endpoint"], e["method"], e["auth"],
                 e["evidence"]["confidence"], e["inventory_status"], json.dumps(e)) for e in eujf["endpoints"]]
        cur.executemany(self._q("INSERT INTO atg_eujf (run_id, api_id, service, endpoint, method, auth, confidence, "
                                "inventory_status, record) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"), rows)
        self.conn.commit()
        return len(rows)

    def save_graph(self, run_id: str, target: str, created_at: str, nodes: list[dict], edges: list[dict]) -> None:
        cur = self.conn.cursor()
        for t in ("atg_nodes", "atg_edges", "atg_findings", "atg_paths"):
            cur.execute(self._q(f"DELETE FROM {t} WHERE run_id = ?"), (run_id,))
        cur.execute(self._q("DELETE FROM atg_runs WHERE run_id = ?"), (run_id,))
        cur.execute(self._q("INSERT INTO atg_runs (run_id, target, created_at, summary) VALUES (?, ?, ?, ?)"),
                    (run_id, target, created_at, "{}"))
        cur.executemany(self._q("INSERT INTO atg_nodes (run_id, id, type, label, own_risk, propagated_risk, props) "
                                "VALUES (?, ?, ?, ?, ?, ?, ?)"),
                        [(run_id, n["id"], n["type"], n["label"], n.get("own_risk", 0), n.get("propagated_risk", 0),
                          json.dumps(n.get("props", {}))) for n in nodes])
        cur.executemany(self._q("INSERT INTO atg_edges (run_id, src, dst, rel, props) VALUES (?, ?, ?, ?, ?)"),
                        [(run_id, e["src"], e["dst"], e["rel"], json.dumps(e.get("props", {}))) for e in edges])
        self.conn.commit()

    def attack_paths(self, run_id: str, max_depth: int = 9) -> list[tuple[list[str], list[str]]]:
        sql = ATTACK_PATH_SQL.replace("{notin}", self.notin).replace("{p}", self.p)
        cur = self.conn.cursor()
        # parameters in order of appearance: actor run, edge run, depth, risk-node run
        cur.execute(sql, (run_id, run_id, max_depth, run_id))
        out = []
        for path, rels in cur.fetchall():
            out.append((path.strip("|").split("|"), rels.rstrip(",").split(",")))
        return out

    def update_risk(self, run_id: str, risks: dict[str, tuple[float, float]]) -> None:
        cur = self.conn.cursor()
        cur.executemany(self._q("UPDATE atg_nodes SET own_risk = ?, propagated_risk = ? WHERE run_id = ? AND id = ?"),
                        [(o, p, run_id, nid) for nid, (o, p) in risks.items()])
        self.conn.commit()

    def save_results(self, run_id: str, findings: list[dict], paths: list[dict], summary: dict) -> None:
        cur = self.conn.cursor()
        cur.executemany(self._q("INSERT INTO atg_findings (run_id, id, rule_id, severity, score, target, data) "
                                "VALUES (?, ?, ?, ?, ?, ?, ?)"),
                        [(run_id, f["id"], f["rule_id"], f["severity"], f["score"], f["target"], json.dumps(f))
                         for f in findings])
        cur.executemany(self._q("INSERT INTO atg_paths (run_id, id, apcr, finding_id, nodes, rels) VALUES (?, ?, ?, ?, ?, ?)"),
                        [(run_id, p["id"], p["apcr"], p["finding_id"], json.dumps(p["nodes"]), json.dumps(p["rels"]))
                         for p in paths])
        cur.execute(self._q("UPDATE atg_runs SET summary = ? WHERE run_id = ?"), (json.dumps(summary), run_id))
        self.conn.commit()

    def history(self, target: str, limit: int = 20) -> list[dict]:
        cur = self.conn.cursor()
        cur.execute(self._q("SELECT run_id, created_at, summary FROM atg_runs WHERE target = ? ORDER BY created_at"),
                    (target,))
        rows = [{"run_id": r, "created_at": c, **json.loads(s or "{}")} for r, c, s in cur.fetchall()]
        return [r for r in rows if "total_path_risk" in r][-limit:]

    def close(self):
        self.conn.close()
