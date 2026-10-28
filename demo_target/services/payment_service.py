"""
payment-service  (port 8003)

Vulnerable build: openapi_url=None, so the service publishes no spec at all.
The only spec is a stale file in the repo (demo_target/specs/payment-service.v1.yaml)
that documents /charge and nothing else. /charge, /refund and
/admin/transactions accept anyone.

Hardened build (SHOPLITE_HARDENED=1): publishes a live spec, /charge and
/refund need the service token, /admin/transactions needs an admin user token.
"""
import uuid

from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from common import HARDENED, SERVICE_TOKEN, ServiceKit, verify_token

app = FastAPI(title="payment-service", version="1.0.0" if HARDENED else "0.9.3",
              openapi_url="/openapi.json" if HARDENED else None, docs_url=None)
kit = ServiceKit(app, "payment-service")

TX: list[dict] = []
service_key = APIKeyHeader(name="X-Service-Token", auto_error=False)
bearer = HTTPBearer(auto_error=False)


def require_service(key: str | None = Security(service_key)):
    if HARDENED and key != SERVICE_TOKEN:
        raise HTTPException(401, "service token required")


def require_admin(cred: HTTPAuthorizationCredentials | None = Depends(bearer)):
    if not HARDENED:
        return
    user = verify_token(cred.credentials) if cred else None
    if not user:
        raise HTTPException(401, "missing token")
    if user["role"] != "admin":
        raise HTTPException(403, "admin only")


class ChargeIn(BaseModel):
    user_id: int
    amount: float
    card_token: str


class RefundIn(BaseModel):
    payment_id: str
    reason: str = ""


@app.post("/charge", dependencies=[Depends(require_service)])
def charge(body: ChargeIn):
    pid = f"pay_{uuid.uuid4().hex[:12]}"
    TX.append({"payment_id": pid, "user_id": body.user_id, "amount": body.amount})
    return {"payment_id": pid, "status": "captured"}


@app.post("/refund", dependencies=[Depends(require_service)])
def refund(body: RefundIn):
    return {"payment_id": body.payment_id, "status": "refunded"}


# Vulnerable build: admin listing with no authentication at all.
@app.get("/admin/transactions", dependencies=[Depends(require_admin)])
def admin_transactions(limit: int = 20):
    return {"count": len(TX), "items": TX[-limit:]}


@app.get("/health", include_in_schema=False)
def health():
    return {"ok": True}
