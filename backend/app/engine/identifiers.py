"""Identifier extraction, sensitive field detection and redaction."""
from __future__ import annotations

import re
from typing import Any

from .models import Endpoint, IdRef
from .normalize import (PARAM_RE, UUID_RE, VERSION_RE, canonical_entity, entity_from_name,
                        is_id_name, split_path)

WRAPPER_KEYS = {"data", "items", "results", "records", "list", "payload", "result", "response"}
USER_REF_KEYS = {"createdby", "created_by", "owner", "author"}

SENSITIVE_FIELDS = {
    "secrets": {"password", "passwordhash", "passwd", "secret", "secretkey", "clientsecret",
                "apikey", "apisecret", "privatekey", "accesskey", "dbpassword",
                "databaseurl", "jwtsecret", "ssn", "cardnumber", "cvv"},
    "location": {"latitude", "longitude", "lat", "lng", "gps", "coordinates"},
    "financial": {"iban", "balance", "bankaccount", "accountnumber", "cardlast4",
                  "paymentmethod", "salary", "total", "totalamount"},
    "personal": {"email", "phone", "phonenumber", "address", "shippingaddress",
                 "dob", "dateofbirth", "fullname"},
}
MAX_NODES = 5000


def _flat(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def root_entity(endpoint: Endpoint) -> str:
    """The kind of object an endpoint returns, judged from its route."""
    parts = split_path(endpoint.template)
    for part in reversed(parts):
        if not PARAM_RE.match(part) and not VERSION_RE.match(part):
            return canonical_entity(part)
    return ""


def _scalar_id(value: Any) -> str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str) and 0 < len(value) <= 128 and not re.search(r"[\s/\\?#]", value):
        return value
    return None


def extract(body: Any, endpoint: Endpoint) -> tuple[list[IdRef], dict[str, list[str]]]:
    ids: list[IdRef] = []
    sensitive: dict[str, set[str]] = {}
    seen = 0

    def walk(node: Any, context: str, path: str, depth: int) -> None:
        nonlocal seen
        seen += 1
        if seen > MAX_NODES or depth > 12:
            return
        if isinstance(node, list):
            for item in node[:200]:
                walk(item, context, path + "[]", depth + 1)
            return
        if not isinstance(node, dict):
            return
        for key, value in node.items():
            key = str(key)
            here = f"{path}.{key}"
            if value not in (None, "", [], {}):
                for category, names in SENSITIVE_FIELDS.items():
                    if _flat(key) in names:
                        sensitive.setdefault(category, set()).add(key)
            scalar = _scalar_id(value)
            if scalar is not None and (is_id_name(key) or key.lower() in USER_REF_KEYS):
                entity = entity_from_name(key) or ("user" if key.lower() in USER_REF_KEYS else "")
                primary = not entity or entity == context
                entity = entity or context
                if entity:
                    ids.append(IdRef(entity, scalar, key, here, primary))
            elif isinstance(value, (dict, list)):
                child = context if key.lower() in WRAPPER_KEYS else canonical_entity(key)
                walk(value, child, here, depth + 1)

    walk(body, root_entity(endpoint), "$", 0)
    return ids, {k: sorted(v) for k, v in sensitive.items()}


def specificity(value: str) -> float:
    """How unlikely it is that two matching values are a coincidence."""
    if UUID_RE.match(value):
        return 1.0
    if value.isdigit():
        return 0.6 if len(value) >= 6 else 0.15
    return 0.9 if len(value) >= 8 else 0.5


def redact(body: Any, depth: int = 0) -> Any:
    """Copy of a response with sensitive values masked and large structures trimmed."""
    if depth > 6:
        return "…"
    if isinstance(body, list):
        trimmed = [redact(item, depth + 1) for item in body[:3]]
        if len(body) > 3:
            trimmed.append(f"… {len(body) - 3} more items")
        return trimmed
    if isinstance(body, dict):
        result = {}
        for key, value in list(body.items())[:30]:
            flat = _flat(str(key))
            hidden = any(flat in names for names in SENSITIVE_FIELDS.values()) or "token" in flat
            if hidden and not isinstance(value, (dict, list)):
                result[key] = "[REDACTED]"
            else:
                result[key] = redact(value, depth + 1)
        return result
    if isinstance(body, str) and len(body) > 120:
        return body[:120] + "…"
    return body
