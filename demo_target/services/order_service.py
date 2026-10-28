"""
order-service  (port 8002)

Calls user-service and payment-service while creating an order, so it gives
the call-chain extractor a real multi-hop path:

    gateway -> order-service -> user-service
                             -> payment-service
"""
import os
import random

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from common import HARDENED, SERVICE_TOKEN, ServiceKit, verify_token

app = FastAPI(title="order-service", version="2.1.0")
kit = ServiceKit(app, "order-service")
bearer = HTTPBearer()

USER_SVC = os.environ.get("USER_SERVICE_URL", "http://user-service:8001")
PAY_SVC = os.environ.get("PAYMENT_SERVICE_URL", "http://payment-service:8003")

ORDERS: dict[int, dict] = {
    1000 + i: {"id": 1000 + i, "user_id": (i % 50) + 1, "total": 100 + i, "status": "paid"}
    for i in range(40)
}


class OrderIn(BaseModel):
    user_id: int
    items: list[str]
    total: float


def caller(cred: HTTPAuthorizationCredentials) -> dict:
    user = verify_token(cred.credentials)
    if not user:
        raise HTTPException(401, "bad token")
    return user


def check_owner(cred, order: dict):
    """Hardened build only: you may touch your own orders (admins: any)."""
    me = caller(cred)
    if HARDENED and order["user_id"] != me["id"] and me["role"] != "admin":
        raise HTTPException(403, "not your order")


@app.get("/orders/{order_id}", tags=["orders"])
def get_order(order_id: int, cred: HTTPAuthorizationCredentials = Depends(bearer)):
    # Vulnerable build: no check that the order belongs to the caller (BOLA).
    if order_id not in ORDERS:
        raise HTTPException(404)
    check_owner(cred, ORDERS[order_id])
    return ORDERS[order_id]


@app.get("/orders", tags=["orders"])
def list_orders(user_id: int, cred: HTTPAuthorizationCredentials = Depends(bearer)):
    return [o for o in ORDERS.values() if o["user_id"] == user_id]


@app.post("/orders", tags=["orders"], status_code=201)
def create_order(body: OrderIn, cred: HTTPAuthorizationCredentials = Depends(bearer)):
    auth = {"Authorization": f"Bearer {cred.credentials}"}
    user = kit.call("GET", f"{USER_SVC}/users/{body.user_id}", "user-service", headers=auth)
    if user.status_code != 200:
        raise HTTPException(400, "unknown user")
    charge = kit.call(
        "POST",
        f"{PAY_SVC}/charge",
        "payment-service",
        json={"user_id": body.user_id, "amount": body.total, "card_token": "tok_demo"},
        headers={"X-Service-Token": SERVICE_TOKEN} if HARDENED else None,
    )
    if charge.status_code != 200:
        raise HTTPException(402, "payment failed")
    oid = max(ORDERS) + 1
    ORDERS[oid] = {"id": oid, "user_id": body.user_id, "total": body.total,
                   "status": "paid", "payment_id": charge.json()["payment_id"]}
    return ORDERS[oid]


@app.delete("/orders/{order_id}", tags=["orders"], deprecated=True)
def cancel_order(order_id: int, cred: HTTPAuthorizationCredentials = Depends(bearer)):
    if order_id in ORDERS:
        check_owner(cred, ORDERS[order_id])
    ORDERS.pop(order_id, None)
    return {"cancelled": order_id}


@app.get("/health", include_in_schema=False)
def health():
    return {"ok": True}
