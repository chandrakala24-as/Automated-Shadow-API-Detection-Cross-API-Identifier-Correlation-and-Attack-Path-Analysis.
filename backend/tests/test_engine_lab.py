"""Accuracy test against the demo lab, whose correct answers are known."""
import pytest

from app.demo import DEMO_IDENTITIES, demo_files
from app.engine.models import Identity
from app.engine.pipeline import ScanConfig, run_scan
from demo_lab.app import app as lab_app
from lab import running

EXPECTED_VULNERABILITIES = {
    ("BOLA", "GET /api/internal/users/{userId}"),
    ("BOLA", "GET /api/v1/vehicles/{vehicleId}/location"),
    ("BFLA", "GET /api/internal/admin/users"),
    ("MISSING_AUTHENTICATION", "GET /api/v0/orders/{orderId}"),
    ("MISSING_AUTHENTICATION", "GET /api/debug/config"),
    ("SECRET_EXPOSURE", "GET /api/debug/config"),
    ("INVALID_TOKEN_ACCEPTED", "GET /api/internal/reports"),
}
EXPECTED_SHADOW = {"GET /api/internal/users/{userId}", "GET /api/internal/admin/users",
                   "GET /api/internal/reports", "GET /api/debug/config"}
EXPECTED_ZOMBIE = {"GET /api/v0/orders/{orderId}"}


@pytest.fixture(scope="module")
def result():
    with running(lab_app) as url:
        spec, har = demo_files(url)
        config = ScanConfig(url, spec, har, [Identity(**i) for i in DEMO_IDENTITIES], rate=0)
        yield run_scan(config)


def test_vulnerabilities_match_ground_truth_exactly(result):
    found = {(f.type, f.endpoint) for f in result.findings
             if f.type not in ("SHADOW_API", "ZOMBIE_API")}
    assert found - EXPECTED_VULNERABILITIES == set(), "false positives"
    assert EXPECTED_VULNERABILITIES - found == set(), "false negatives"
    assert all(f.confidence == "confirmed" for f in result.findings)


def test_classification(result):
    by_class = {}
    for endpoint in result.endpoints:
        by_class.setdefault(endpoint.classification, set()).add(endpoint.label)
    assert by_class.get("shadow") == EXPECTED_SHADOW
    assert by_class.get("zombie") == EXPECTED_ZOMBIE
    assert "GET /api/v1/invoices" in by_class["unverified"]
    assert "POST /api/internal/users/{userId}/reset-password" in by_class["candidate"]


def test_non_get_routes_are_never_requested(result):
    post = next(e for e in result.endpoints if e.method == "POST")
    assert not post.live and "read-only" in post.skip_reason


def test_identifier_links(result):
    links = {(l.producer, l.consumer, l.entity) for l in result.links}
    assert ("GET /api/v1/posts", "GET /api/internal/users/{userId}", "user") in links
    assert ("GET /api/internal/users/{userId}",
            "GET /api/v1/vehicles/{vehicleId}/location", "vehicle") in links


def test_three_step_attack_path(result):
    wanted = ["GET /api/v1/posts", "GET /api/internal/users/{userId}",
              "GET /api/v1/vehicles/{vehicleId}/location"]
    path = next(p for p in result.paths if [s["endpoint"] for s in p.steps] == wanted)
    assert path.attacker in ("alice", "bob") and path.victim != path.attacker
    assert "location" in path.data_categories


def test_evidence_never_contains_secret_values(result):
    text = str([f.evidence for f in result.findings])
    assert "fake-demo-password" not in text and "alice@rideshop.test" not in text
    assert "demo-alice-token" not in text
