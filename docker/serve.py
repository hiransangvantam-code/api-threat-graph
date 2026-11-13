"""
Entry point of the `atg` container (ATG platform).

    serves output/site on port 8888 (http://localhost:8080 on your machine)
    until the first scan: a live status page of both Dockers (target and ATG)
    scans are started with:  docker compose exec atg python docker/scan.py --label <name>

Every start is a fresh review. Pages of an earlier review and any working files an
older version left on disk are deleted, and the graph store starts empty.

Two kinds of pages:
    /...        output/site on disk: the report pages and the threat graph exports. They stay
                after STOP so they can be handed over, until CLEAN deletes them.
    /live/...   the in-memory folder /work/live: Phase 1 report, Phase 1 JSON, EUJF JSON and
                analysis JSON of each scan. Readable while the review runs; gone at STOP.
"""
from __future__ import annotations

import functools
import http.server
import os
import shutil
import signal
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pages import LIVE, OUT, SITE, WORK, capture_files, health_checks, load_state, save_state, status_page  # noqa: E402

PORT = int(os.environ.get("ATG_SERVE_PORT", "8888"))
PUBLIC_URL = os.environ.get("ATG_PUBLIC_URL", "http://localhost:8080")
NOTE = ("Start script steps: the customers' traffic goes through the ATG sidecar, then "
        "<code class='cmd'>docker compose exec atg python docker/scan.py --label vulnerable</code> runs Phases 1-4. "
        "By hand: <code class='cmd'>docker compose -f target/docker-compose.yml run --rm users</code>, then the scan command.")

# what versions before 1.3 wrote to disk (raw traffic copies, Phase 1 files, the SQLite store)
OLD_ON_DISK = ["runs", "scan-input", "raw", "capture", "telemetry", "report.html", "eujf.json", "analysis.json",
               "dashboard.html", "atg.db", "scan-state.json"]


class Handler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def translate_path(self, path):
        if path == "/live" or path.startswith(("/live/", "/live?")):
            site, self.directory = self.directory, str(LIVE)
            try:
                return super().translate_path(path[len("/live"):] or "/")
            finally:
                self.directory = site
        return super().translate_path(path)

    def log_message(self, *args):
        pass


def remove(p: Path) -> None:
    if p.is_dir():
        shutil.rmtree(p, ignore_errors=True)
    else:
        p.unlink(missing_ok=True)


def fresh_store() -> str | None:
    url = os.environ.get("ATG_GRAPH_STORE", "")
    if not url.startswith(("postgresql://", "postgres://")):
        return None
    import psycopg
    deadline, last = time.time() + 90, None
    while time.time() < deadline:
        try:
            with psycopg.connect(url, connect_timeout=3) as c:
                for t in ("atg_paths", "atg_findings", "atg_edges", "atg_nodes", "atg_eujf", "atg_runs"):
                    c.execute(f"DROP TABLE IF EXISTS {t}")
            print(f"graph store: PostgreSQL at {url.split('@')[-1]} (in memory, empty)", flush=True)
            return url
        except Exception as exc:  # not up yet
            last = exc
            time.sleep(1.5)
    print(f"PostgreSQL not reachable ({last}); scans will use an in-memory SQLite store", flush=True)
    return None


def main() -> int:
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
    for name in OLD_ON_DISK + ["site"]:
        remove(OUT / name)
    for p in WORK.glob("*") if WORK.exists() else []:
        remove(p)
    SITE.mkdir(parents=True, exist_ok=True)
    LIVE.mkdir(parents=True, exist_ok=True)
    st = {"offsets": {str(f): f.stat().st_size for f in capture_files()},  # skip what an earlier start captured
          "store": None, "started": time.time(), "scanning": None}
    save_state(st)
    httpd = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), functools.partial(Handler, directory=str(SITE)))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    status_page(health_checks(st), note=NOTE)
    print(f"\n  ATG platform is up: {PUBLIC_URL}\n", flush=True)
    st["store"] = fresh_store()
    save_state(st)
    while True:  # keep the status page live until the first scan has built the results
        st = load_state()
        if not st.get("scanning") and not any((WORK / "runs").glob("*/scan.json")):
            status_page(health_checks(st), note=NOTE)
        time.sleep(3)


if __name__ == "__main__":
    sys.exit(main())
