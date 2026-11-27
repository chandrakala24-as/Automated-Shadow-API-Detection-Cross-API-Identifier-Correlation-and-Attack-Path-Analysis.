"""Application settings."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SESSION_HOURS = 12
MAX_UPLOAD_CHARS = 8_000_000


def data_dir() -> Path:
    path = Path(os.environ.get("SHADOWAPI_DATA_DIR", ROOT / "data"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def allowed_hosts() -> list[str]:
    """Host header allowlist. It protects the local server against DNS rebinding."""
    return os.environ.get("SHADOWAPI_ALLOWED_HOSTS", "127.0.0.1,localhost,testserver").split(",")
