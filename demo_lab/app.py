"""RideShop: a DELIBERATELY VULNERABLE API used to demonstrate and evaluate ShadowAPI.

All data and secrets are fake. Run it on 127.0.0.1 only.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse, Response

HERE = Path(__file__).parent
app = FastAPI(title="RideShop (vulnerable demo)", docs_url=None, redoc_url=None, openapi_url=None)

ALICE = "3f1c2a9e-7b44-4d2a-9c11-5a8e0f6b1d01"
BOB = "9a7d4c15-2e83-4f6b-8d20-1c3b7e9a4f02"
ADMIN = "c05e8b72-91af-4a3d-b6e4-7f2d9c0a8e03"

USERS = {
    ALICE: {"id": ALICE, "name": "Alice Rao", "email": "alice@rideshop.test",
            "phone": "+91-90000-00001", "vehicle_id": "veh_a81f3c"},
    BOB: {"id": BOB, "name": "Bob Iyer", "email": "bob@rideshop.test",
          "phone": "+91-90000-00002", "vehicle_id": "veh_b47d9e"},
    ADMIN: {"id": ADMIN, "name": "Site Admin", "email": "admin@rideshop.test",
            "phone": "+91-90000-00009", "vehicle_id": None},
}
TOKENS = {"demo-alice-token": ALICE, "demo-bob-token": BOB, "demo-admin-token": ADMIN}
VEHICLES = {
    "veh_a81f3c": {"vehicle_id": "veh_a81f3c", "owner_id": ALICE,
                   "latitude": 17.4474, "longitude": 78.3762},
    "veh_b47d9e": {"vehicle_id": "veh_b47d9e", "owner_id": BOB,
                   "latitude": 12.9716, "longitude": 77.5946},
}
ORDERS = {
    "ord_5001aa": {"id": "ord_5001aa", "user_id": ALICE, "product_id": 1, "total": 499,
                   "shipping_address": "12 Lake View, Hyderabad"},
    "ord_5002bb": {"id": "ord_5002bb", "user_id": BOB, "product_id": 2, "total": 899,
                   "shipping_address": "44 Park Street, Bengaluru"},
}
POSTS = [
    {"id": 101, "title": "Weekend road trip", "author_id": ALICE},
    {"id": 102, "title": "Best charging spots", "author_id": BOB},
]
PRODUCTS = [{"id": 1, "name": "Phone mount", "price": 499},
            {"id": 2, "name": "Dash camera", "price": 899}]


def current_user(authorization: str | None) -> dict:
    token = (authorization or "").removeprefix("Bearer ")
    if token not in TOKENS:
        raise HTTPException(401, "Authentication required")
    return USERS[TOKENS[token]]


def find(collection: dict, key: str) -> dict:
    if key not in collection:
        raise HTTPException(404, "Not found")
    return collection[key]


# ---------------------------------------------------------------- front end
@app.get("/", response_class=HTMLResponse)
def home():
    return (HERE / "index.html").read_text(encoding="utf-8")


@app.get("/static/app.js")
def script():
    return Response((HERE / "app.js").read_text(encoding="utf-8"),
                    media_type="application/javascript")


# ---------------------------------------------------------------- documented
@app.get("/api/v1/health")
def health():
    return {"status": "ok"}


@app.get("/api/v1/products")
def products():
    return {"products": PRODUCTS}


@app.get("/api/v1/me")
def me(authorization: str | None = Header(None)):
    user = current_user(authorization)
    return {"id": user["id"], "name": user["name"], "email": user["email"]}


@app.get("/api/v1/posts")
def posts(authorization: str | None = Header(None)):
    current_user(authorization)
    return {"posts": POSTS}  # leaks other users' internal IDs


@app.get("/api/v1/posts/{post_id}")
def post(post_id: int, authorization: str | None = Header(None)):
    current_user(authorization)  # posts are shared by design: NOT a vulnerability
    for item in POSTS:
        if item["id"] == post_id:
            return item
    raise HTTPException(404, "Not found")


@app.get("/api/v1/orders")
def orders(authorization: str | None = Header(None)):
    user = current_user(authorization)
    return {"orders": [o for o in ORDERS.values() if o["user_id"] == user["id"]]}


@app.get("/api/v1/orders/{order_id}")
def order(order_id: str, authorization: str | None = Header(None)):
    user = current_user(authorization)
    item = find(ORDERS, order_id)
    if item["user_id"] != user["id"]:  # SECURE: ownership is checked
        raise HTTPException(403, "Forbidden")
    return item


@app.get("/api/v1/vehicles/{vehicle_id}/location")
def location(vehicle_id: str, authorization: str | None = Header(None)):
    current_user(authorization)  # VULNERABLE (BOLA): no ownership check
    return find(VEHICLES, vehicle_id)


@app.get("/api/v1/admin/stats")
def stats(authorization: str | None = Header(None)):
    if current_user(authorization)["id"] != ADMIN:  # SECURE: role is checked
        raise HTTPException(403, "Forbidden")
    return {"user_count": len(USERS), "order_count": len(ORDERS)}


# ---------------------------------------------------------------- shadow
@app.get("/api/internal/users/{user_id}")
def internal_user(user_id: str, authorization: str | None = Header(None)):
    current_user(authorization)  # VULNERABLE (BOLA)
    return find(USERS, user_id)


@app.post("/api/internal/users/{user_id}/reset-password")
def reset_password(user_id: str):
    return {"status": "disabled in demo"}


@app.get("/api/internal/admin/users")
def admin_users(authorization: str | None = Header(None)):
    current_user(authorization)  # VULNERABLE (BFLA): no role check
    return {"users": [{"id": u["id"], "name": u["name"], "email": u["email"]}
                      for u in USERS.values()]}


@app.get("/api/internal/reports")
def reports(authorization: str | None = Header(None)):
    # VULNERABLE: only checks that a bearer token is present, not that it is valid
    if not (authorization or "").startswith("Bearer "):
        raise HTTPException(401, "Authentication required")
    return {"reports": [{"name": "Monthly summary", "status": "ready"}]}


@app.get("/api/debug/config")
def debug_config():
    # VULNERABLE: unauthenticated and leaks (fake) secrets
    return {"environment": "demo", "db_password": "fake-demo-password",
            "jwt_secret": "fake-demo-secret"}


# ---------------------------------------------------------------- zombie
@app.get("/api/v0/orders/{order_id}")
def legacy_order(order_id: str):
    return find(ORDERS, order_id)  # VULNERABLE: the old version has no authentication
