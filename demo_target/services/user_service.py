"""
user-service  (port 8001)

Documented in OpenAPI:  /auth/login, /users/{user_id}, /users/{user_id}/addresses
Hidden from OpenAPI:    /internal/users/export   <- shadow endpoint, no auth

SHOPLITE_HARDENED=1: ownership checks (403), login throttling (429),
export documented and admin-only.
"""
import time
from collections import defaultdict

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from common import HARDENED, ServiceKit, make_token, verify_token

app = FastAPI(title="user-service", version="1.5.0" if HARDENED else "1.4.0")
kit = ServiceKit(app, "user-service")
bearer = HTTPBearer()

USERS = {
    i: {
        "id": i,
        "name": f"customer{i}",
        "email": f"customer{i}@example.com",
        "role": "admin" if i == 1 else "customer",
        "phone": f"08{i:08d}",
    }
    for i in range(1, 51)
}
FAILED: dict[str, list[float]] = defaultdict(list)


def current_user(cred: HTTPAuthorizationCredentials = Depends(bearer)) -> dict:
    user = verify_token(cred.credentials)
    if not user:
        raise HTTPException(401, "bad token")
    return user


def check_owner(me: dict, user_id: int):
    if HARDENED and me["id"] != user_id and me["role"] != "admin":
        raise HTTPException(403, "not your account")


class LoginIn(BaseModel):
    username: str
    password: str


class LoginOut(BaseModel):
    token: str
    user_id: int


@app.post("/auth/login", response_model=LoginOut, tags=["auth"])
def login(body: LoginIn):
    now = time.time()
    if HARDENED:
        FAILED[body.username] = [t for t in FAILED[body.username] if now - t < 900]
        if len(FAILED[body.username]) >= 3:
            raise HTTPException(429, "too many attempts, try again later")
    for u in USERS.values():
        if u["name"] == body.username:
            return {"token": make_token(u["id"], u["role"]), "user_id": u["id"]}
    FAILED[body.username].append(now)
    raise HTTPException(401, "invalid credentials")


@app.get("/users/{user_id}", tags=["users"])
def get_user(user_id: int, me: dict = Depends(current_user)):
    check_owner(me, user_id)
    if user_id not in USERS:
        raise HTTPException(404)
    return USERS[user_id]


@app.get("/users/{user_id}/addresses", tags=["users"])
def get_addresses(user_id: int, me: dict = Depends(current_user)):
    check_owner(me, user_id)
    return [{"line1": f"{user_id} Sukhumvit Rd", "city": "Bangkok", "zip": "10110"}]


# Vulnerable build: not in the OpenAPI spec and no auth. Used by a nightly
# "reporting job". Only runtime traffic and traces will ever see it.
# Hardened build: documented, admin role required.
def _export_guard(cred: HTTPAuthorizationCredentials | None = Depends(HTTPBearer(auto_error=False))):
    if not HARDENED:
        return None
    user = verify_token(cred.credentials) if cred else None
    if not user:
        raise HTTPException(401, "missing token")
    if user["role"] != "admin":
        raise HTTPException(403, "admin only")
    return user


@app.get("/internal/users/export", include_in_schema=HARDENED, tags=["admin"])
def export_users(_=Depends(_export_guard)):
    return {"count": len(USERS), "users": list(USERS.values())}


@app.get("/health", include_in_schema=False)
def health():
    return {"ok": True}
