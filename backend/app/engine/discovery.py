"""Endpoint discovery: OpenAPI, HAR, crawling, JavaScript analysis and path probing."""
from __future__ import annotations

import json
import re
from collections import deque
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit

import yaml

from .normalize import Inventory
from .scope import ScopedClient

HTTP_METHODS = ("get", "post", "put", "patch", "delete")
API_HINT = re.compile(r"^/(?:api|rest|graphql|internal|v\d+)(?:/|$)", re.I)
STATIC_EXT = re.compile(r"\.(?:js|mjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|html?)$", re.I)
# Quoted or template-literal paths, optionally followed by `+ variable` concatenation.
JS_PATH = re.compile(
    r"""(?P<q>["'`])(?P<path>/[A-Za-z0-9_\-./{}$:?=&]*)(?P=q)"""
    r"""(?P<tail>(?:\s*\+\s*(?:[A-Za-z_$][\w$.]*|["'`][A-Za-z0-9_\-./?=&]*["'`]))*)""")
JS_TAIL = re.compile(r"""\+\s*(?:(?P<var>[A-Za-z_$][\w$.]*)|["'`](?P<lit>[^"'`]*)["'`])""")
JS_METHOD = re.compile(
    r"""^\s*,\s*\{[^{}]{0,200}?method\s*:\s*["'`](GET|POST|PUT|PATCH|DELETE)["'`]""", re.I)
JS_CALL = re.compile(r"\.(get|post|put|patch|delete)\(\s*$", re.I)

DEFAULT_WORDLIST = [
    "/api", "/api/health", "/api/status", "/api/version", "/api/config", "/api/debug",
    "/api/debug/config", "/api/debug/vars", "/api/internal", "/api/internal/config",
    "/api/internal/health", "/api/internal/users", "/api/admin", "/api/admin/users",
    "/api/users", "/api/v0/users", "/api/v1/users", "/api/v2/users", "/api/v0/orders",
    "/api/v1/admin", "/api/v1/debug", "/api/test", "/api/dev", "/api/backup",
    "/api/export", "/api/logs", "/api/metrics", "/internal/status", "/debug/vars",
    "/actuator", "/actuator/env", "/actuator/health", "/metrics", "/health", "/status",
    "/server-status", "/api/env", "/api/swagger.json", "/api/openapi.json",
]


class ImportError_(ValueError):
    pass


def parse_spec(text: str) -> dict:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ImportError_("The specification is not valid JSON or YAML.") from exc
    if not isinstance(data, dict) or not isinstance(data.get("paths"), dict):
        raise ImportError_("This is not an OpenAPI/Swagger document (no 'paths' object).")
    return data


def parse_har(text: str) -> list[dict]:
    try:
        entries = json.loads(text)["log"]["entries"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ImportError_("This is not a valid HAR file (expected log.entries).") from exc
    if not isinstance(entries, list):
        raise ImportError_("HAR log.entries must be a list.")
    return entries


def _base_path(spec: dict) -> str:
    if spec.get("basePath"):
        return str(spec["basePath"]).rstrip("/")
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        path = urlsplit(str(servers[0].get("url", ""))).path.rstrip("/")
        if "{" not in path:
            return path
    return ""


def load_spec(spec: dict, inventory: Inventory) -> int:
    base, total = _base_path(spec), 0
    global_security = spec.get("security")
    for raw_path, item in spec["paths"].items():
        if not isinstance(item, dict):
            continue
        for method in HTTP_METHODS:
            operation = item.get(method)
            if not isinstance(operation, dict):
                continue
            params = list(item.get("parameters") or []) + list(operation.get("parameters") or [])
            query = {p["name"]: "" for p in params if isinstance(p, dict)
                     and p.get("in") == "query" and p.get("required") and p.get("name")}
            endpoint = inventory.add(method, base + str(raw_path), "spec", query)
            if endpoint is None:
                continue
            total += 1
            endpoint.in_spec = True
            security = operation.get("security", global_security)
            # Only an explicit empty requirement counts as "intentionally public".
            endpoint.spec_public = security == [] or (isinstance(security, list) and {} in security)
            endpoint.spec_deprecated = bool(operation.get("deprecated"))
            tags = [str(t).lower() for t in operation.get("tags") or []]
            endpoint.spec_admin = (operation.get("x-required-role") == "admin" or "admin" in tags)
    return total


def load_har(entries: list[dict], base_url: str, inventory: Inventory) -> tuple[int, int]:
    """Return (imported, skipped_out_of_scope)."""
    target = urlsplit(base_url)
    imported = skipped = 0
    for entry in entries:
        try:
            request = entry["request"]
            url = urlsplit(request["url"])
            method = str(request["method"]).upper()
            status = int(entry.get("response", {}).get("status", 0))
        except (KeyError, TypeError, ValueError, AttributeError):
            continue
        if url.netloc.lower() != target.netloc.lower():
            skipped += 1
            continue
        if method.lower() not in HTTP_METHODS or STATIC_EXT.search(url.path) or url.path in ("", "/"):
            continue
        mime = str(entry.get("response", {}).get("content", {}).get("mimeType", ""))
        if status == 404 or not (API_HINT.match(url.path) or "json" in mime):
            continue
        # Request headers are deliberately ignored: captured tokens are never stored.
        if inventory.add(method, url.path, "traffic", dict(parse_qsl(url.query))):
            imported += 1
    return imported, skipped


def extract_js_routes(source: str) -> list[tuple[str, str]]:
    """Return (method, path) pairs for API routes referenced in JavaScript."""
    routes: list[tuple[str, str]] = []
    for match in JS_PATH.finditer(source):
        path = match.group("path")
        for part in JS_TAIL.finditer(match.group("tail") or ""):
            if part.group("var"):
                if not path.split("?")[0].endswith("/") and "?" not in path:
                    break
                path += "{" + part.group("var").split(".")[-1] + "}"
            else:
                path += part.group("lit")
        if not API_HINT.match(path) or STATIC_EXT.search(path.split("?")[0]):
            continue
        if path.endswith("/") and path.count("/") > 1:
            path = path.rstrip("/")
        method = "GET"
        explicit = JS_METHOD.match(source[match.end():match.end() + 260])
        call = JS_CALL.search(source[max(0, match.start() - 12):match.start()])
        if explicit:
            method = explicit.group(1).upper()
        elif call:
            method = call.group(1).upper()
        routes.append((method, path))
    return routes


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.scripts: list[str] = []
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "script":
            self._in_script = True
            if values.get("src"):
                self.links.append(values["src"])
        elif tag in ("a", "link") and values.get("href"):
            self.links.append(values["href"])

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script:
            self.scripts.append(data)


def _add_route(inventory: Inventory, method: str, path: str, source: str) -> None:
    parsed = urlsplit(path)
    inventory.add(method, parsed.path, source, dict(parse_qsl(parsed.query, keep_blank_values=True)))


def crawl(client: ScopedClient, inventory: Inventory, headers: dict[str, str],
          max_pages: int = 60) -> int:
    """Breadth-first crawl of same-origin HTML and JavaScript. Returns pages fetched."""
    origin = urlsplit(client.base_url).netloc
    queue, seen, fetched = deque(["/"]), {"/"}, 0
    while queue and fetched < max_pages:
        path = queue.popleft()
        result = client.get(path, headers=headers)
        if result is None or result[0] != 200:
            continue
        fetched += 1
        _, content_type, text = result
        scripts = []
        if "html" in content_type:
            parser = _LinkParser()
            parser.feed(text)
            scripts = parser.scripts
            for link in parser.links:
                target = urlsplit(urljoin(client.base_url + path, link))
                if target.netloc != origin or API_HINT.match(target.path):
                    continue
                if not (target.path.endswith((".js", ".mjs", ".html")) or "." not in target.path):
                    continue
                if target.path and target.path not in seen:
                    seen.add(target.path)
                    queue.append(target.path)
        elif "javascript" in content_type or path.endswith((".js", ".mjs")):
            scripts = [text]
        for script in scripts:
            for method, route in extract_js_routes(script):
                _add_route(inventory, method, route, "javascript")
    return fetched
