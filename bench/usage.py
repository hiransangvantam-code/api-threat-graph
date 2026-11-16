"""
Computing resources of ATG's four containers during one review, read from Docker's own counters.

demo-all and BENCH start it next to ATG and stop it after the scan:

    docker run -d --name atg-usage --network none -v /var/run/docker.sock:/var/run/docker.sock \
        -v "$PWD:/repo" api-threat-graph:1.6 python /repo/bench/usage.py /repo/results/opensource/atg-laptop/usage/<name>.json
    echo scan > results/opensource/atg-laptop/usage/<name>.stage      (just before the scan)
    docker rm -f atg-usage                                             (after the scan)

Twice a second it asks the Docker Engine, for every container of the Compose project "atg" (the sidecar
atg-proxy, the OpenTelemetry Collector atg-collector, atg-postgres and atg itself), how much CPU time the
container has used since it started (also split into user and kernel mode), how much memory it holds now (the
number `docker stats` shows: memory in use minus the inactive file cache; the in-memory volumes with the captured
traffic count), its network and disk bytes and its number of processes. After every reading it rewrites the
output file with, per stage, the CPU seconds each container used, its highest and average memory, the network
and disk megabytes it moved and the most processes it ran. The stage is the word in <out>.stage: "users" (the default) while the system's users send requests,
"scan" during the scan. CPU used before the first reading (the containers starting) is kept as "start".

Only the Docker Engine API over its socket is used, so the same command works with Docker Desktop on Windows
and macOS and with Docker on Linux. It reads the counters; it never changes a container.
"""
from __future__ import annotations

import http.client
import json
import os
import signal
import socket
import sys
import time
import urllib.parse
from pathlib import Path

SOCK = os.environ.get("DOCKER_SOCK", "/var/run/docker.sock")
PROJECT = os.environ.get("ATG_PROJECT", "atg")
INTERVAL = 0.5


class _Unix(http.client.HTTPConnection):
    def __init__(self, path: str):
        super().__init__("localhost", timeout=10)
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(self._path)
        self.sock = s


def api(path: str):
    c = _Unix(SOCK)
    try:
        c.request("GET", path)
        r = c.getresponse()
        body = r.read()
        if r.status != 200:
            raise OSError(f"Docker API {path}: HTTP {r.status}")
        return json.loads(body)
    finally:
        c.close()


def containers() -> dict[str, str]:
    """{compose service name: container id} for the running containers of the ATG project."""
    f = urllib.parse.quote(json.dumps({"label": [f"com.docker.compose.project={PROJECT}"]}))
    return {c["Labels"].get("com.docker.compose.service", c["Names"][0].strip("/")): c["Id"]
            for c in api(f"/containers/json?filters={f}")}


def reading(cid: str) -> dict:
    """The container's counters, as `docker stats` reads them: CPU seconds used since it started (in total, in
    user mode and in kernel mode), memory in use now (MB), network bytes received and sent, bytes read from and
    written to block devices, and the number of processes and threads now."""
    s = api(f"/containers/{cid}/stats?stream=false&one-shot=true")
    cu = s.get("cpu_stats", {}).get("cpu_usage", {})
    m = s.get("memory_stats", {})
    st = m.get("stats", {}) or {}
    cache = st.get("inactive_file", st.get("total_inactive_file", 0))   # cgroup v2, else v1
    net = s.get("networks") or {}
    blk = (s.get("blkio_stats") or {}).get("io_service_bytes_recursive") or []
    return {"cpu": cu.get("total_usage", 0) / 1e9, "user": cu.get("usage_in_usermode", 0) / 1e9,
            "kernel": cu.get("usage_in_kernelmode", 0) / 1e9, "mem": max(0, m.get("usage", 0) - cache) / 2**20,
            "rx": sum(n.get("rx_bytes", 0) for n in net.values()), "tx": sum(n.get("tx_bytes", 0) for n in net.values()),
            "blk_r": sum(b.get("value", 0) for b in blk if str(b.get("op", "")).lower() == "read"),
            "blk_w": sum(b.get("value", 0) for b in blk if str(b.get("op", "")).lower() == "write"),
            "pids": (s.get("pids_stats") or {}).get("current", 0)}


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    out = Path(sys.argv[1])
    out.parent.mkdir(parents=True, exist_ok=True)
    stage_file = out.with_suffix(".stage")      # written by demo-all / BENCH, not here (it may run as root)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))   # PID 1 in its container: stop on docker stop
    last: dict[str, dict] = {}
    COUNTERS = {"cpu": "cpu_s", "user": "user_s", "kernel": "kernel_s"}
    BYTES = {"rx": "net_in_mb", "tx": "net_out_mb", "blk_r": "disk_read_mb", "blk_w": "disk_write_mb"}
    res = {"project": PROJECT, "interval_s": INTERVAL, "samples": 0, "start": {"cpu_s": {}}, "stages": {}}
    t_last = time.time()
    while True:
        try:
            stage = (stage_file.read_text(encoding="utf-8").strip() or "users") if stage_file.exists() else "users"
            now = time.time()
            st = res["stages"].setdefault(stage, {"seconds": 0.0, "cpu_s": {}, "user_s": {}, "kernel_s": {}, "mem_peak_mb": {},
                                                  "mem_sum_mb": {}, "mem_avg_mb": {}, "samples": 0, "net_in_mb": {},
                                                  "net_out_mb": {}, "disk_read_mb": {}, "disk_write_mb": {},
                                                  "pids_peak": {}, "mem_peak_total_mb": 0.0})
            if res["samples"]:
                st["seconds"] = round(st["seconds"] + now - t_last, 2)
            t_last = now
            total = 0.0
            st["samples"] += 1
            for name, cid in sorted(containers().items()):
                try:
                    r = reading(cid)
                except (OSError, ValueError):
                    continue
                if name not in last:              # first reading of this container: what it used while starting
                    res["start"]["cpu_s"][name] = round(r["cpu"], 3)
                else:
                    for k, key in COUNTERS.items():
                        st[key][name] = round(st[key].get(name, 0.0) + max(0.0, r[k] - last[name][k]), 3)
                    for k, key in BYTES.items():
                        st[key][name] = round(st[key].get(name, 0.0) + max(0, r[k] - last[name][k]) / 2**20, 3)
                last[name] = r
                mem = r["mem"]
                st["mem_peak_mb"][name] = round(max(st["mem_peak_mb"].get(name, 0.0), mem), 1)
                st["mem_sum_mb"][name] = st["mem_sum_mb"].get(name, 0.0) + mem
                st["mem_avg_mb"][name] = round(st["mem_sum_mb"][name] / st["samples"], 1)
                st["pids_peak"][name] = max(st["pids_peak"].get(name, 0), r["pids"])
                total += mem
            st["mem_peak_total_mb"] = round(max(st["mem_peak_total_mb"], total), 1)
            res["samples"] += 1
            res["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
            tmp = out.with_suffix(".tmp")
            tmp.write_text(json.dumps(res, indent=1), encoding="utf-8")
            os.replace(tmp, out)
        except (OSError, ValueError) as exc:     # Docker busy or the project not up yet: try again
            print("usage:", exc, file=sys.stderr, flush=True)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    sys.exit(main())
