"""Ready-made configuration for the bundled demo lab."""
from __future__ import annotations

from pathlib import Path

LAB_DIR = Path(__file__).resolve().parents[2] / "demo_lab"
LAB_URL = "http://127.0.0.1:8001"

DEMO_IDENTITIES = [
    {"name": "alice", "role": "user", "headers": {"Authorization": "Bearer demo-alice-token"}},
    {"name": "bob", "role": "user", "headers": {"Authorization": "Bearer demo-bob-token"}},
    {"name": "admin", "role": "admin", "headers": {"Authorization": "Bearer demo-admin-token"}},
]


def demo_files(base_url: str = LAB_URL) -> tuple[str, str]:
    spec = (LAB_DIR / "openapi.yaml").read_text(encoding="utf-8")
    har = (LAB_DIR / "traffic.har").read_text(encoding="utf-8")
    return spec, har.replace(LAB_URL, base_url)
