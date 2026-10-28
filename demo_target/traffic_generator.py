"""
Simulates users (and one internal cron job) using ShopLite, so the runtime
traffic and trace extractors have something realistic to read.

North-south traffic goes to the mitmproxy reverse proxy in front of the
gateway. The cron job talks to user-service directly through the mesh proxy,
the way an in-cluster job would.
"""
import argparse
import random
import time

import httpx


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gateway", default="http://127.0.0.1:8080")
    ap.add_argument("--mesh-proxy", default="http://127.0.0.1:8081")
    ap.add_argument("--user-service", default="http://127.0.0.1:8001")
    ap.add_argument("--rounds", type=int, default=25)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--wait", type=float, default=0, help="seconds to wait for the gateway to come up")
    a = ap.parse_args()
    rnd = random.Random(a.seed)

    gw = httpx.Client(base_url=a.gateway, trust_env=False, timeout=10)
    deadline = time.time() + a.wait
    while True:  # used by docker compose, where containers start in any order
        try:
            ok = gw.get("/health", headers={"User-Agent": "atg-extractor/demo-healthcheck"}).status_code == 200
        except httpx.HTTPError:
            ok = False
        if ok:
            break
        if time.time() > deadline:
            raise SystemExit(f"gateway at {a.gateway} is not answering /health")
        time.sleep(1)
    sent = 0

    def hit(method, path, **kw):
        nonlocal sent
        sent += 1
        return gw.request(method, path, **kw)

    for _ in range(a.rounds):
        c = rnd.randint(2, 50)
        r = hit("POST", "/api/auth/login", json={"username": f"customer{c}", "password": "pw"})
        tok = r.json()["token"]
        h = {"Authorization": f"Bearer {tok}"}

        hit("GET", f"/api/users/{c}", headers=h)
        if rnd.random() < 0.6:
            hit("GET", f"/api/users/{c}/addresses", headers=h)
        hit("GET", "/api/orders", params={"user_id": c}, headers=h)
        if rnd.random() < 0.7:
            hit("POST", "/api/orders", headers=h,
                json={"user_id": c, "items": ["sku-" + str(rnd.randint(1, 99))],
                      "total": round(rnd.uniform(50, 900), 2)})
        # sometimes look at an order that is not yours (nobody stops you)
        hit("GET", f"/api/orders/{rnd.randint(1000, 1039)}", headers=h)
        if rnd.random() < 0.15:
            hit("DELETE", f"/api/orders/{rnd.randint(1000, 1039)}", headers=h)
        if rnd.random() < 0.2:
            hit("GET", f"/api/users/{c}")  # forgot the token -> 401 at gateway
        if rnd.random() < 0.1:
            hit("POST", "/api/auth/login", json={"username": "nobody", "password": "x"})
        if rnd.random() < 0.12:
            hit("GET", "/api/payments/admin/transactions", params={"limit": 5})
        if rnd.random() < 0.08:
            hit("POST", "/api/payments/refund", json={"payment_id": "pay_123", "reason": "dup"})
        if rnd.random() < 0.06:
            hit("GET", "/_debug/config")
        if rnd.random() < 0.25:  # curious customer: look at someone else's profile
            other = rnd.randint(2, 50)
            hit("GET", f"/api/users/{other}", headers=h)
            hit("GET", f"/api/users/{other}/addresses", headers=h)
        if rnd.random() < 0.1:   # customer tries the admin listing with their own token
            hit("GET", "/api/payments/admin/transactions", headers=h)

    # the real admin checks transactions
    adm = hit("POST", "/api/auth/login", json={"username": "customer1", "password": "pw"}).json()["token"]
    hit("GET", "/api/payments/admin/transactions", params={"limit": 10},
        headers={"Authorization": f"Bearer {adm}"})

    # someone guessing passwords for one account
    for _ in range(6):
        hit("POST", "/api/auth/login", json={"username": "nobody", "password": f"guess{_}"})

    # nightly reporting job inside the cluster
    cron = httpx.Client(proxy=a.mesh_proxy or None, trust_env=False, timeout=10)
    for _ in range(2):
        cron.get(f"{a.user_service}/internal/users/export")
        sent += 1

    print(f"traffic generator: sent {sent} requests")


if __name__ == "__main__":
    main()
