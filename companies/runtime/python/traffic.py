"""
Customers, staff and partners of a test company use its API, so the ATG platform
has traffic and traces to review. Reads the same company.json as the services.

    python traffic.py --gateway http://atg-proxy:8080 --mesh-proxy http://atg-proxy:8081

What it sends, for every public route (round after round, seeded so a run repeats):
  - normal use by the right kind of user (customers on their own objects, staff on
    staff functions, partners on partner routes, anonymous visitors on open routes)
  - a customer asking for another customer's object          (403 unless the check is missing)
  - a request with no credential on a route that needs one   (401 unless it is missing)
  - a customer calling a staff-only or partner-only route    (403 unless it is missing)
  - failed logins with unknown user names                    (401)
and the internal jobs listed under "cron", which call services directly through the
sidecar without a trace, like a script on an operations server.

Sessions come from the company's own login (POST .../auth/session), so every
credential is a random value made at run time. No passwords exist anywhere.
"""
from __future__ import annotations

import argparse
import json
import random
import re
import sys
import time
from collections import Counter
from pathlib import Path

import httpx

CFG = json.loads(Path("/company/company.json").read_text(encoding="utf-8")) if Path("/company/company.json").exists() else None


def public_path(cfg: dict, service: str, backend: str) -> str | None:
    """The path a client uses at the gateway for a backend path (longest matching route).
    A system with no gateway workload is reached at its edge service directly."""
    if not cfg.get("gateway"):
        edges = cfg.get("edge") or []
        return backend if service in ([edges] if isinstance(edges, str) else edges) else None
    best = None
    for r in cfg["gateway"]["routes"]:
        if r["service"] != service:
            continue
        to = r["to"]
        if to and not (backend == to or backend.startswith(to.rstrip("/") + "/")):
            continue
        if best is None or len(to) > len(best["to"]):
            best = r
    if best is None:
        return None
    return best["from"] + backend[len(best["to"]):]


def owned_id(user: str, rnd: random.Random) -> int:
    k = int(user[1:]) if user.startswith("c") else rnd.randint(1, 20)
    return 1000 + 20 * rnd.randint(0, 4) + (k - 1)


def other_id(user: str, rnd: random.Random) -> int:
    k = int(user[1:]) if user.startswith("c") else 1
    other = (k + rnd.randint(1, 19) - 1) % 20 + 1
    return 1000 + 20 * rnd.randint(0, 4) + (other - 1)


class Client:
    def __init__(self, a, cfg: dict):
        self.cfg = cfg
        self.rnd = random.Random(a.seed)
        self.gw = httpx.Client(base_url=a.gateway, trust_env=False, timeout=15)
        self.mesh = httpx.Client(proxy=a.mesh_proxy, trust_env=False, timeout=15) if a.mesh_proxy else None
        self.sessions: dict[str, str] = {}
        self.status = Counter()
        self.sent = 0
        self.ua = f"{cfg['name']}-app/4.2"
        self.auth = cfg.get("auth_service") or {}
        login = self.auth.get("login", {"method": "POST", "path": "/auth/session"})
        entry = self.auth.get("entry") or {"service": self.auth.get("name"), **login}   # where users log in
        self.login_method = entry["method"]
        self.login_path = public_path(cfg, entry["service"], entry["path"]) if self.auth else None
        self.login_base = self.edge_base(entry["service"]) if self.auth else None
        self.cookie = self.auth.get("cookie", "sid")

    # ------------------------------------------------------------ sessions
    def edge_base(self, service: str) -> str | None:
        """Systems with several public services and no gateway: reach each one through the
        sidecar's east-west port (the one gateway address cannot front them all)."""
        edges = self.cfg.get("edge") or []
        if self.cfg.get("gateway") or isinstance(edges, str) or len(edges) < 2:
            return None
        return f"http://{service}:{self.cfg['services'][service]['port']}"

    def login_request(self, user: str, count: bool = True):
        fields = {self.auth.get("user_field", "user"): user, **self.auth.get("login_extra", {})}
        if self.login_method == "GET":
            return self.request("GET", self.login_path, None, params=fields, ua=self.ua, headers={}, count=count,
                                internal=self.login_base)
        return self.request(self.login_method, self.login_path, None, json=fields, ua=self.ua, headers={}, count=count,
                            internal=self.login_base)

    def login(self, user: str, count: bool = True) -> str | None:
        if not self.login_path:
            return None
        r = self.login_request(user, count)
        if r is None or r.status_code != 200:
            return None
        if self.cfg["credential"] == "cookie":
            return r.cookies.get(self.cookie)
        return r.json().get("access_token")

    def session(self, user: str) -> str | None:
        if user not in self.sessions:
            for _ in range(5):
                tok = self.login(user)
                if tok:
                    self.sessions[user] = tok
                    break
                time.sleep(1)
        return self.sessions.get(user)

    def cred_headers(self, user: str | None) -> dict:
        if not user:
            return {}
        tok = self.session(user)
        if not tok:
            return {}
        if user.startswith("p") and not user.startswith("staff"):
            return {"x-api-key": tok}
        if self.cfg["credential"] == "cookie":
            return {"cookie": f"{self.cookie}={tok}"}
        return {"authorization": f"Bearer {tok}"}

    # ------------------------------------------------------------ requests
    def request(self, method, path, user, json=None, params=None, ua=None, headers=None, count=True, internal=None):
        h = {"user-agent": ua or self.ua, **(headers if headers is not None else self.cred_headers(user))}
        try:
            if internal:
                r = self.mesh.request(method, internal + path, headers=h, json=json, params=params)
            else:
                r = self.gw.request(method, path, headers=h, json=json, params=params)
        except httpx.HTTPError as e:
            self.status[type(e).__name__] += 1
            return None
        finally:
            # httpx keeps cookies the server set and sends them again; every request here
            # must carry exactly the credential chosen above (or none), so forget them
            self.gw.cookies.clear()
        if count:
            self.sent += 1
            self.status[r.status_code] += 1
        return r

    def fill(self, template, user, ids: dict):
        if isinstance(template, dict):
            return {k: self.fill(v, user, ids) for k, v in template.items()}
        if isinstance(template, list):
            return [self.fill(v, user, ids) for v in template]
        if isinstance(template, str) and template.startswith("$"):
            key = template[1:]
            if key == "token":
                return self.session(user) if user else ""
            if key == "user":
                return user or ""
            if key == "owned":
                return owned_id(user or "c1", self.rnd)
            if key == "n":
                return self.rnd.randint(1, 500)
            if key in ids:
                return ids[key]
        return template

    def call_route(self, svc: str, r: dict, user: str | None, steal: bool = False, anon: bool = False):
        t = r.get("traffic", {})
        ids = {}
        for p in re.findall(r"{([^}]+)}", r["path"]):
            if p == r.get("owner"):
                ids[p] = other_id(user or "c1", self.rnd) if steal else owned_id(user or "c1", self.rnd)
            else:
                ids[p] = self.rnd.randint(100, 140)
        backend = re.sub(r"{([^}]+)}", lambda m: str(ids[m.group(1)]), r["path"])
        path = public_path(self.cfg, svc, backend)
        if path is None:
            return None
        cred_user = None if anon else user
        query = self.fill(t.get("query"), cred_user, ids) if t.get("query") else None
        body = self.fill(t.get("body"), cred_user, ids) if t.get("body") is not None else None
        headers = {} if (anon or t.get("credential_in_query")) else None
        return self.request(r["method"], path, cred_user, json=body, params=query, ua=t.get("ua"), headers=headers,
                            internal=self.edge_base(svc))


def run(a) -> int:
    cfg = CFG if a.company is None else json.loads(Path(a.company).read_text(encoding="utf-8"))
    c = Client(a, cfg)
    rnd = c.rnd
    deadline = time.time() + a.wait
    while True:
        try:
            if c.gw.get(cfg.get("health_path", "/health"), headers={"user-agent": "atg-extractor (wait)"}).status_code < 500:
                break
        except httpx.HTTPError:
            pass
        if time.time() > deadline:
            print("gateway did not answer through the ATG sidecar", file=sys.stderr)
            return 1
        time.sleep(2)

    customers = [f"c{i}" for i in range(1, a.customers + 1)]
    staff = ["staff1", "staff2"]
    partners = ["p1", "p2"]
    public = []   # (service, route)
    for svc, s in cfg["services"].items():
        if s.get("external"):
            continue
        for r in s.get("routes", []):
            if public_path(cfg, svc, re.sub(r"{[^}]+}", "1", r["path"])) is not None and r.get("traffic", {}).get("client") != "none":
                public.append((svc, r))

    def caller(r) -> str | None:
        kind = r.get("traffic", {}).get("client") or {"user": "customer", "admin": "staff", "partner": "partner",
                                                       "none": "anonymous"}[r["auth"]]
        return {"customer": rnd.choice(customers), "staff": rnd.choice(staff), "partner": rnd.choice(partners),
                "anonymous": None}[kind]

    t0 = time.time()
    for rnd_i in range(a.rounds):
        for svc, r in public:
            t = r.get("traffic", {})
            for _ in range(t.get("weight", 2)):
                c.call_route(svc, r, caller(r))
            if r.get("owner") and r["auth"] == "user" and rnd.random() < 0.5:
                c.call_route(svc, r, rnd.choice(customers), steal=True)
            if r["auth"] != "none" and rnd.random() < 0.3:
                c.call_route(svc, r, rnd.choice(customers), anon=True)
            if r["auth"] in ("admin", "partner") and rnd.random() < 0.4:
                c.call_route(svc, r, rnd.choice(customers))
        for _ in range(a.failed_logins if c.login_path else 0):
            c.login_request(f"x{rnd.randint(1, 99)}")
        for job in cfg.get("cron", []):
            if rnd_i % job.get("every", 1) == 0:
                for call in job["calls"]:
                    c.request(call["method"], call["path"], None, headers={},
                              ua=f"{job['name']}/1.0", internal=f"http://{call['service']}:{call['port']}",
                              json=call.get("body"))
    dt = time.time() - t0
    print(f"{cfg['name']}: {c.sent} requests in {dt:.1f} s, {len(c.sessions)} sessions; status codes: "
          + ", ".join(f"{k} x{v}" for k, v in sorted(c.status.items(), key=lambda kv: str(kv[0]))))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gateway", default="http://atg-proxy:8080", help="the company's API, through the ATG sidecar")
    ap.add_argument("--mesh-proxy", default="http://atg-proxy:8081", help="the sidecar's east-west port, for cron jobs")
    ap.add_argument("--company", default=None, help="company.json (default /company/company.json)")
    ap.add_argument("--rounds", type=int, default=20)
    ap.add_argument("--customers", type=int, default=12)
    ap.add_argument("--failed-logins", type=int, default=1)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--wait", type=float, default=90, help="seconds to wait for the gateway")
    return run(ap.parse_args())


if __name__ == "__main__":
    sys.exit(main())
