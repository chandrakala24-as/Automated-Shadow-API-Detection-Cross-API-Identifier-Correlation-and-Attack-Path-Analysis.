"""False-positive and safety checks on situations that commonly mislead scanners."""
import pytest
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse

from app.engine.discovery import ImportError_, extract_js_routes, parse_har, parse_spec
from app.engine.models import Identity
from app.engine.normalize import Inventory, build_template
from app.engine.pipeline import ScanConfig, run_scan
from app.engine.scope import ScopedClient, ScopeError, is_unsafe_route, validate_base_url
from lab import running

USERS = [Identity("a", "user", {"Authorization": "Bearer ta"}),
         Identity("b", "user", {"Authorization": "Bearer tb"}),
         Identity("root", "admin", {"Authorization": "Bearer tr"})]
SPEC = """
openapi: 3.0.0
paths:
  /api/v1/notes: {get: {}}
  /api/v1/notes/{noteId}: {get: {}}
  /api/v1/settings/{userId}: {get: {}}
  /api/v1/me: {get: {}}
  /api/v1/admin/stats: {get: {}}
  /api/v1/catalog: {get: {security: []}}
"""
IDS = {"a": 1, "b": 2, "root": 3}


def secure_app() -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    def who(auth):
        name = {"Bearer ta": "a", "Bearer tb": "b", "Bearer tr": "root"}.get(auth)
        if not name:
            raise HTTPException(401, "no")
        return name

    @app.get("/")
    def home():
        return {"ok": True}

    @app.get("/api/v1/me")
    def me(authorization: str | None = Header(None)):
        name = who(authorization)
        return {"id": IDS[name], "email": f"{name}@x.test"}

    @app.get("/api/v1/notes")
    def notes(authorization: str | None = Header(None)):
        return {"notes": [{"id": IDS[who(authorization)] * 10, "text": "private"}]}

    @app.get("/api/v1/notes/{note_id}")
    def note(note_id: int, authorization: str | None = Header(None)):
        if note_id != IDS[who(authorization)] * 10:
            raise HTTPException(404, "no")
        return {"id": note_id, "text": "private"}

    @app.get("/api/v1/settings/{user_id}")
    def settings(user_id: int, authorization: str | None = Header(None)):
        # Ignores the path ID and always returns the caller's own record: not BOLA.
        name = who(authorization)
        return {"user_id": IDS[name], "theme": name}

    @app.get("/api/v1/admin/stats")
    def stats(authorization: str | None = Header(None)):
        if who(authorization) != "root":
            raise HTTPException(403, "no")
        return {"count": 3}

    @app.get("/api/v1/catalog")
    def catalog():
        return {"items": [{"id": 5, "name": "x"}]}

    return app


def test_secure_application_has_no_findings():
    with running(secure_app()) as url:
        result = run_scan(ScanConfig(url, SPEC, "", USERS, rate=0))
    assert [(f.type, f.endpoint) for f in result.findings] == []
    assert result.paths == []
    assert result.stats["shadow"] == 0


def test_catch_all_site_does_not_invent_endpoints():
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/{path:path}", response_class=HTMLResponse)
    def anything(path: str):
        return "<html><body>single page app</body></html>"

    with running(app) as url:
        result = run_scan(ScanConfig(url, "", "", USERS, rate=0))
    assert result.endpoints == [] and result.findings == []


def test_unreachable_target_fails_clearly():
    with pytest.raises(ConnectionError):
        run_scan(ScanConfig("http://127.0.0.1:1", rate=0))


def test_request_budget_is_enforced():
    with running(secure_app()) as url:
        result = run_scan(ScanConfig(url, SPEC, "", USERS, rate=0, max_requests=15))
    assert result.stats["requests"] <= 15
    assert any("limit" in w for w in result.warnings)


@pytest.mark.parametrize("url", ["ftp://x", "localhost:8000", "http://u:p@host",
                                 "http://host/api", "http://host:abc"])
def test_bad_target_urls_are_rejected(url):
    with pytest.raises(ScopeError):
        validate_base_url(url)


def test_cloud_metadata_address_is_blocked():
    with pytest.raises(ScopeError):
        ScopedClient("http://169.254.169.254")


@pytest.mark.parametrize("path", ["//evil.test/x", "http://evil.test/", "\\\\evil.test"])
def test_client_cannot_leave_the_target_origin(path):
    client = ScopedClient("http://127.0.0.1:9")
    assert client.get(path) is None and client.count == 0


def test_side_effect_routes_are_unsafe():
    assert is_unsafe_route("/api/v1/logout")
    assert is_unsafe_route("/api/users/{id}/reset-password")
    assert not is_unsafe_route("/api/v1/orders/{orderId}")


def test_path_normalisation_and_merging():
    template, inputs, values = build_template("/api/v2/users/42/orders/ord_9f31ab")
    assert template == "/api/v2/users/{userId}/orders/{orderId}"
    assert [i.entity for i in inputs] == ["user", "order"]
    assert values == {"userId": "42", "orderId": "ord_9f31ab"}
    inventory = Inventory()
    inventory.add("GET", "/api/users/{uid}", "spec")
    inventory.add("GET", "/api/users/7", "traffic")
    inventory.add("GET", "/api/users/me", "javascript")
    assert {e.template for e in inventory.all()} == {"/api/users/{uid}", "/api/users/me"}
    assert inventory.find("GET", "/api/users/7")[0].samples == {"uid": {"7"}}


def test_javascript_route_extraction():
    source = '''fetch(`/api/a/${user.id}/b`); axios.post("/api/c", x);
      fetch("/api/d/" + id + "/e"); const css = "/static/app.css";
      fetch('/api/f', { method: 'DELETE' });'''
    assert set(extract_js_routes(source)) == {
        ("GET", "/api/a/${user.id}/b"), ("POST", "/api/c"),
        ("GET", "/api/d/{id}/e"), ("DELETE", "/api/f")}


@pytest.mark.parametrize("parser,text", [(parse_spec, "[1, 2]"), (parse_spec, "{bad"),
                                         (parse_har, "{}"), (parse_har, "nope")])
def test_invalid_imports_are_rejected(parser, text):
    with pytest.raises(ImportError_):
        parser(text)


def test_shared_item_referenced_by_a_private_record_is_not_confirmed_bola():
    """A product ID inside my order does not make the product my private object."""
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    def who(auth):
        name = {"Bearer ta": "a", "Bearer tb": "b", "Bearer tr": "root"}.get(auth)
        if not name:
            raise HTTPException(401, "no")
        return name

    @app.get("/")
    def home():
        return {"ok": True}

    @app.get("/api/v1/orders")
    def orders(authorization: str | None = Header(None)):
        n = IDS[who(authorization)]
        return {"orders": [{"id": 100 + n, "product_id": 500 + n}]}

    @app.get("/api/v1/products/{product_id}")
    def product(product_id: int, authorization: str | None = Header(None)):
        who(authorization)
        return {"id": product_id, "name": "Catalogue item"}

    spec = "openapi: 3.0.0\npaths:\n  /api/v1/orders: {get: {}}\n  /api/v1/products/{productId}: {get: {}}\n"
    with running(app) as url:
        result = run_scan(ScanConfig(url, spec, "", USERS, rate=0))
    assert [f for f in result.findings if f.confidence == "confirmed"] == []
    assert [(f.type, f.confidence) for f in result.findings] == [("BOLA", "review")]
    assert result.paths == []
