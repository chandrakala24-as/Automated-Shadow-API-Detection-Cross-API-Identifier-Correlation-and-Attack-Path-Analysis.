"""Safe HTTP access: one origin only, GET only, rate limited and budgeted."""
from __future__ import annotations

import ipaddress
import socket
import threading
import time
from urllib.parse import urlsplit

import httpx

MAX_BODY = 1_000_000
# GET requests whose route suggests a side effect are never sent.
UNSAFE_WORDS = ("logout", "signout", "delete", "remove", "destroy", "reset", "shutdown",
                "restart", "revoke", "disable", "deactivate", "purge", "drop", "unsubscribe")


class ScopeError(ValueError):
    pass


class ScanCancelled(Exception):
    pass


class BudgetExceeded(Exception):
    pass


def validate_base_url(url: str) -> str:
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ScopeError("Target URL must start with http:// or https:// and include a host.")
    if parts.username or parts.password:
        raise ScopeError("Do not put credentials in the target URL.")
    if parts.query or parts.fragment or parts.path not in ("", "/"):
        raise ScopeError("Enter only the origin, for example http://localhost:8001")
    try:
        parts.port  # raises for an invalid port
    except ValueError as exc:
        raise ScopeError("The port in the target URL is invalid.") from exc
    return f"{parts.scheme}://{parts.netloc}".rstrip("/")


def check_destination(url: str) -> None:
    """Refuse link-local and cloud metadata addresses."""
    host = urlsplit(url).hostname or ""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ScopeError(f"Cannot resolve host '{host}'.") from exc
    for info in infos:
        address = ipaddress.ip_address(info[4][0].split("%")[0])
        mapped = getattr(address, "ipv4_mapped", None)
        address = mapped or address
        if address.is_link_local or address.is_multicast or address.is_unspecified:
            raise ScopeError(f"Scanning {address} is not allowed.")


def is_unsafe_route(path: str) -> bool:
    lowered = path.lower().replace("-", "").replace("_", "")
    return any(word in segment for segment in lowered.split("/") for word in UNSAFE_WORDS)


class ScopedClient:
    def __init__(self, base_url: str, rate: float = 25.0, max_requests: int = 3000,
                 timeout: float = 10.0, cancel: threading.Event | None = None,
                 transport: httpx.BaseTransport | None = None) -> None:
        self.base_url = validate_base_url(base_url)
        if transport is None:
            check_destination(self.base_url)
        self.interval = 1.0 / rate if rate > 0 else 0.0
        self.max_requests = max_requests
        self.count = 0
        self.errors = 0
        self.cancel = cancel or threading.Event()
        self._last = 0.0
        self._client = httpx.Client(timeout=timeout, follow_redirects=False,
                                    transport=transport, trust_env=False)

    def close(self) -> None:
        self._client.close()

    def get(self, path: str, headers: dict[str, str] | None = None,
            params: dict[str, str] | None = None) -> tuple[int, str, str] | None:
        """Return (status, content_type, text) or None if the request failed."""
        if self.cancel.is_set():
            raise ScanCancelled()
        if self.count >= self.max_requests:
            raise BudgetExceeded()
        if not path.startswith("/") or path.startswith("//") or "\\" in path:
            return None
        wait = self.interval - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()
        self.count += 1
        request_headers = {"User-Agent": "ShadowAPI-Scanner/1.0",
                           "Accept": "application/json, */*;q=0.5", **(headers or {})}
        try:
            url = httpx.URL(self.base_url + path)
            if params:
                url = url.copy_merge_params(params)
            self._client.cookies.clear()  # identities must never share session state
            with self._client.stream("GET", url, headers=request_headers) as response:
                chunks, size = [], 0
                for chunk in response.iter_bytes():
                    chunks.append(chunk)
                    size += len(chunk)
                    if size >= MAX_BODY:
                        break
                text = b"".join(chunks)[:MAX_BODY].decode("utf-8", errors="replace")
                return response.status_code, response.headers.get("content-type", ""), text
        except (httpx.HTTPError, httpx.InvalidURL, ValueError, UnicodeError):
            self.errors += 1
            return None
