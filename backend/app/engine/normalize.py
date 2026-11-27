"""Path normalisation and identifier naming."""
from __future__ import annotations

import re

from .models import Endpoint, Input

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)
PREFIXED_RE = re.compile(r"^[a-z]{1,8}[_-](?=[a-z0-9]*\d)[a-z0-9]{3,}$", re.I)
VERSION_RE = re.compile(r"^v(\d+)$", re.I)
PARAM_RE = re.compile(r"^\{([^{}]*)\}$")

# Fixed route names that must never be read as an example value of a parameter.
RESERVED_SEGMENTS = {"me", "self", "current", "search", "count", "all", "new", "export"}

# Words that name the same kind of object.
ALIASES = {
    "author": "user", "owner": "user", "creator": "user", "customer": "user",
    "member": "user", "account": "user", "profile": "user", "me": "user",
    "createdby": "user", "driver": "user", "seller": "user", "buyer": "user",
}


def looks_like_value(segment: str) -> bool:
    """True when a concrete path segment is an identifier and not a route name."""
    if VERSION_RE.match(segment):
        return False
    return bool(
        segment.isdigit() or UUID_RE.match(segment)
        or HEX_RE.match(segment) or PREFIXED_RE.match(segment)
    )


def singular(word: str) -> str:
    if word.endswith("ies") and len(word) > 3:
        return word[:-3] + "y"
    if word.endswith(("sses", "xes", "ches", "shes")):
        return word[:-2]
    if word.endswith("s") and not word.endswith(("ss", "us", "is")):
        return word[:-1]
    return word


def canonical_entity(word: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]", "", word.lower())
    cleaned = singular(cleaned)
    return ALIASES.get(cleaned, cleaned)


def entity_from_name(name: str) -> str:
    """'userId' -> 'user', 'author_id' -> 'user', 'id' -> ''."""
    stem = re.sub(r"(?:[_-]?(?:uuid|guid|id))$", "", name, flags=re.I)
    if stem == name and name.lower() not in ALIASES:
        return ""
    return canonical_entity(stem) if stem else ""


def is_id_name(name: str) -> bool:
    return bool(
        re.search(r"(?:^|[_-])(?:id|uuid|guid)$", name, re.I)
        or re.search(r"[a-z0-9](?:Id|ID|Uuid|UUID|Guid)$", name)
    )


def split_path(path: str) -> list[str]:
    return [part for part in path.split("?")[0].split("#")[0].split("/") if part]


def _param_entity(name: str, previous: str) -> str:
    return entity_from_name(name) or canonical_entity(previous) or "unknown"


def build_template(path: str) -> tuple[str, list[Input], dict[str, str]]:
    """Normalise a concrete or templated path.

    Accepts `{x}`, `:x` and `${x}` placeholders. Returns the template, its inputs and
    any concrete values that were replaced by placeholders.
    """
    parts: list[str] = []
    inputs: list[Input] = []
    values: dict[str, str] = {}
    used: set[str] = set()
    previous = ""
    for segment in split_path(path):
        placeholder = re.match(r"^(?:\$?\{([^{}]*)\}|:([A-Za-z_]\w*))$", segment)
        if placeholder or looks_like_value(segment):
            if placeholder:
                raw = placeholder.group(1) or placeholder.group(2) or "id"
                name = re.sub(r"\W", "", raw.split(".")[-1]) or "id"
            else:
                base = canonical_entity(previous)
                name = f"{base}Id" if base else "id"
            candidate, n = name, 2
            while candidate in used:
                candidate, n = f"{name}{n}", n + 1
            used.add(candidate)
            inputs.append(Input("path", candidate, _param_entity(name, previous)))
            if not placeholder:
                values[candidate] = segment
            parts.append("{" + candidate + "}")
        else:
            parts.append(segment)
            previous = segment
    return "/" + "/".join(parts), inputs, values


def shape(template: str) -> str:
    """Comparison form of a template: parameter names do not matter."""
    return "/" + "/".join("{}" if PARAM_RE.match(p) else p for p in split_path(template))


def match_template(template: str, path: str) -> dict[str, str] | None:
    expected, actual = split_path(template), split_path(path)
    if len(expected) != len(actual):
        return None
    values: dict[str, str] = {}
    for want, got in zip(expected, actual):
        param = PARAM_RE.match(want)
        if param:
            if re.match(r"^(\$?\{.*\}|:\w+)$", got):
                continue
            if got.lower() in RESERVED_SEGMENTS:
                return None
            values[param.group(1)] = got
        elif want != got:
            return None
    return values


class Inventory:
    """Collects endpoints from all discovery sources and merges duplicates."""

    def __init__(self, limit: int = 400) -> None:
        self._items: dict[tuple[str, str], Endpoint] = {}
        self.limit = limit

    def all(self) -> list[Endpoint]:
        return sorted(self._items.values(), key=lambda e: (e.template, e.method))

    def find(self, method: str, path: str) -> tuple[Endpoint, dict[str, str]] | None:
        """Best existing match for a path. Routes with more fixed segments win."""
        matches = []
        for (m, _), endpoint in self._items.items():
            if m != method:
                continue
            values = match_template(endpoint.template, path)
            if values is not None:
                fixed = sum(not PARAM_RE.match(p) for p in split_path(endpoint.template))
                matches.append((fixed, endpoint, values))
        if not matches:
            return None
        _, endpoint, values = max(matches, key=lambda item: item[0])
        return endpoint, values

    def add(self, method: str, path: str, source: str,
            query: dict[str, str] | None = None) -> Endpoint | None:
        method = method.upper()
        found = self.find(method, path)
        if found:
            endpoint, values = found
        else:
            template, inputs, values = build_template(path)
            key = (method, shape(template))
            endpoint = self._items.get(key)
            if endpoint is None:
                if len(self._items) >= self.limit:
                    return None
                endpoint = Endpoint(method, template, inputs)
                self._items[key] = endpoint
            else:
                # Same shape, possibly different parameter names: align the sample values.
                renamed = {}
                for old, new in zip(inputs, [i for i in endpoint.inputs if i.location == "path"]):
                    if old.name in values:
                        renamed[new.name] = values[old.name]
                values = renamed
        endpoint.sources.add(source)
        for name, value in values.items():
            endpoint.samples.setdefault(name, set()).add(value)
        for name, value in (query or {}).items():
            if not is_id_name(name):
                continue
            if not any(i.location == "query" and i.name == name for i in endpoint.inputs):
                previous = [p for p in split_path(endpoint.template) if not PARAM_RE.match(p)]
                endpoint.inputs.append(
                    Input("query", name, _param_entity(name, previous[-1] if previous else "")))
            if value and not value.startswith(("{", ":", "$")):
                endpoint.samples.setdefault(name, set()).add(value)
        return endpoint
