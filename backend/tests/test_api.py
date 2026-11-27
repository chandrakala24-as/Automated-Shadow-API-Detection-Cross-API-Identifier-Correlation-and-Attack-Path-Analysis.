"""REST API: authentication, isolation between users, and a full scan through the database."""
import pytest
from fastapi.testclient import TestClient

from app.demo import DEMO_IDENTITIES, demo_files
from app.main import create_app
from demo_lab.app import app as lab_app
from lab import running

HEADERS = {"X-Requested-With": "ShadowAPI"}


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("SHADOWAPI_DATA_DIR", str(tmp_path))
    return create_app(f"sqlite:///{tmp_path / 'test.db'}")


def signed_in(app, email="one@test.dev"):
    client = TestClient(app, headers=HEADERS)
    response = client.post("/api/auth/register", json={
        "name": "Tester", "email": email, "password": "a-long-password"})
    assert response.status_code == 201, response.text
    return client


def project_body(url, **changes):
    spec, har = demo_files(url)
    return {"name": "Lab", "base_url": url, "spec_text": spec, "har_text": har,
            "identities": DEMO_IDENTITIES, "authorized": True,
            "options": {"rate": 100}, **changes}


def test_protected_routes_need_a_session(app):
    client = TestClient(app)
    for path in ("/api/projects", "/api/dashboard", "/api/scans/1", "/api/scans/1/report.html"):
        assert client.get(path).status_code == 401


def test_csrf_header_is_required(app):
    response = TestClient(app).post("/api/auth/login", json={"email": "a@b.co", "password": "x"})
    assert response.status_code == 403


def test_unknown_host_is_rejected(app):
    assert TestClient(app).get("/api/auth/me", headers={"Host": "evil.test"}).status_code == 400


def test_login_logout_and_throttling(app):
    client = signed_in(app)
    assert client.get("/api/auth/me").json()["email"] == "one@test.dev"
    client.post("/api/auth/logout")
    assert client.get("/api/auth/me").status_code == 401
    wrong = {"email": "one@test.dev", "password": "wrong-password"}
    codes = [client.post("/api/auth/login", json=wrong).status_code for _ in range(9)]
    assert codes[:8] == [401] * 8 and codes[8] == 429


def test_project_validation(app):
    client = signed_in(app)
    for changes in ({"authorized": False}, {"base_url": "file:///etc"}, {"spec_text": "junk"},
                    {"identities": [{"name": "x", "headers": {"Host": "a"}}]},
                    {"identities": [{"name": "anonymous", "headers": {"A": "b"}}]}):
        response = client.post("/api/projects", json=project_body("http://127.0.0.1:9", **changes))
        assert response.status_code == 422, changes
    leaked = client.post("/api/projects", json=project_body(
        "http://127.0.0.1:9", identities=[{"name": "x", "headers": {"A": "secret-value\r\n"}}]))
    assert "secret-value" not in leaked.text


def test_credentials_are_hidden_and_do_not_follow_a_new_host(app, tmp_path):
    client = signed_in(app)
    created = client.post("/api/projects", json=project_body("http://127.0.0.1:9"))
    assert created.status_code == 201 and "demo-alice-token" not in created.text
    project_id = created.json()["id"]
    assert b"demo-alice-token" not in (tmp_path / "test.db").read_bytes()
    keep = [{"name": i["name"], "role": i["role"]} for i in DEMO_IDENTITIES]
    same = project_body("http://127.0.0.1:9", identities=keep, spec_text=None, har_text=None)
    assert client.put(f"/api/projects/{project_id}", json=same).json()["has_spec"]
    moved = {**same, "base_url": "http://127.0.0.1:10"}
    assert client.put(f"/api/projects/{project_id}", json=moved).status_code == 422


def test_full_scan_and_user_isolation(app):
    client = signed_in(app)
    with running(lab_app) as url:
        project = client.post("/api/projects", json=project_body(url)).json()
        scan = client.post(f"/api/projects/{project['id']}/scans").json()
        app.state.scanner.wait(scan["id"])
    data = client.get(f"/api/scans/{scan['id']}/results").json()
    assert data["scan"]["status"] == "completed", data["scan"]
    assert data["scan"]["stats"]["shadow"] == 4 and len(data["findings"]) == 12
    assert len(data["paths"]) == 4

    finding = data["findings"][0]
    updated = client.patch(f"/api/findings/{finding['id']}", json={"triage": "fixed"})
    assert updated.json()["triage"] == "fixed"
    report = client.get(f"/api/scans/{scan['id']}/report.html")
    assert report.status_code == 200 and "Attack paths" in report.text
    assert "fake-demo-password" not in report.text
    assert client.get("/api/dashboard").json()["totals"]["shadow"] == 4

    other = signed_in(app, "two@test.dev")
    assert other.get("/api/projects").json() == []
    for path in (f"/api/projects/{project['id']}", f"/api/scans/{scan['id']}",
                 f"/api/scans/{scan['id']}/results", f"/api/scans/{scan['id']}/report.html"):
        assert other.get(path).status_code == 404, path
    assert other.patch(f"/api/findings/{finding['id']}",
                       json={"triage": "open"}).status_code == 404
    assert other.delete(f"/api/scans/{scan['id']}").status_code == 404

    assert client.delete(f"/api/projects/{project['id']}").status_code == 204
    assert client.get(f"/api/scans/{scan['id']}").status_code == 404


def test_scan_of_unreachable_target_reports_why(app):
    client = signed_in(app)
    project = client.post("/api/projects", json=project_body("http://127.0.0.1:1")).json()
    scan = client.post(f"/api/projects/{project['id']}/scans").json()
    app.state.scanner.wait(scan["id"])
    state = client.get(f"/api/scans/{scan['id']}").json()
    assert state["status"] == "failed" and "Cannot connect" in state["message"]
