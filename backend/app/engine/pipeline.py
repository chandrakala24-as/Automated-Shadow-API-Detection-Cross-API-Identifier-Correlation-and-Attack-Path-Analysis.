"""Runs every stage of a scan in order."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable

import httpx

from .analysis import analyse, classify
from .attackpaths import find_paths
from .correlation import correlate
from .discovery import DEFAULT_WORDLIST, crawl, load_har, load_spec, parse_har, parse_spec
from .models import ANONYMOUS, Endpoint, Identity, ScanResult
from .normalize import Inventory
from .ownership import compute_owners
from .prober import Prober
from .risk import score_finding
from .scope import BudgetExceeded, ScopedClient


@dataclass
class ScanConfig:
    base_url: str
    spec_text: str = ""
    har_text: str = ""
    identities: list[Identity] = field(default_factory=list)
    enable_crawl: bool = True
    enable_wordlist: bool = True
    rate: float = 25.0
    max_requests: int = 3000


Progress = Callable[[str, int, str], None]


def run_scan(config: ScanConfig, progress: Progress = lambda *a: None,
             cancel: threading.Event | None = None,
             transport: httpx.BaseTransport | None = None) -> ScanResult:
    started = time.monotonic()
    warnings: list[str] = []
    inventory = Inventory()
    client = ScopedClient(config.base_url, rate=config.rate, max_requests=config.max_requests,
                          cancel=cancel, transport=transport)
    try:
        progress("Importing", 5, "Reading the specification and traffic")
        if config.spec_text.strip():
            load_spec(parse_spec(config.spec_text), inventory)
        else:
            warnings.append("No specification was provided, so APIs cannot be classified "
                            "as documented or shadow.")
        if config.har_text.strip():
            _, skipped = load_har(parse_har(config.har_text), client.base_url, inventory)
            if skipped:
                warnings.append(f"Traffic entries for other hosts that were ignored: {skipped}.")

        users = [i for i in config.identities if i.role == "user"]
        if len(users) < 2:
            warnings.append("Fewer than two normal-user accounts: cross-user (BOLA) tests and "
                            "cross-user attack paths cannot run.")
        if not any(i.role == "admin" for i in config.identities):
            warnings.append("No administrator account: admin-route findings can only be marked "
                            "for review.")

        prober = Prober(client, inventory, config.identities)
        try:
            progress("Discovering", 12, "Checking that the target responds")
            if client.get("/") is None:
                raise ConnectionError(f"Cannot connect to {client.base_url}. Is the target running?")
            prober.calibrate()
            if config.enable_crawl:
                progress("Discovering", 18, "Crawling pages and analysing JavaScript")
                headers = users[0].headers if users else {}
                crawl(client, inventory, headers)
            if config.enable_wordlist:
                progress("Discovering", 30, "Probing common hidden paths")
                _probe_wordlist(prober, inventory, users[0].name if users else ANONYMOUS)
            progress("Testing", 40, "Testing access as each identity")
            prober.run(lambda done: progress(
                "Testing", 40 + int(35 * done), f"{client.count} requests sent"))
        except BudgetExceeded:
            warnings.append(f"The limit of {config.max_requests} requests was reached. "
                            "Results are partial.")
        if client.errors:
            warnings.append(f"{client.errors} requests failed (timeout or connection error).")

        progress("Analysing", 78, "Classifying APIs and checking access control")
        endpoints = inventory.all()
        by_label = {e.label: e for e in endpoints}
        classify(endpoints, bool(config.spec_text.strip()))
        owners = compute_owners(by_label, prober.observations, config.identities)
        findings = analyse(endpoints, prober.observations, config.identities, owners)
        for finding in findings:
            score_finding(finding, by_label[finding.endpoint])
        findings.sort(key=lambda f: (-f.score, f.endpoint, f.type))
        progress("Correlating", 88, "Linking identifiers across APIs")
        links = correlate(endpoints, prober.observations)
        progress("Building paths", 94, "Searching for attack paths")
        paths = find_paths(endpoints, prober.observations, findings, config.identities, owners)

        stats = {"requests": client.count, "duration_seconds": round(time.monotonic() - started, 1),
                 "endpoints": len(endpoints), "live": sum(e.live for e in endpoints),
                 "shadow": sum(e.classification == "shadow" for e in endpoints),
                 "zombie": sum(e.classification == "zombie" for e in endpoints),
                 "findings": len(findings), "links": len(links), "paths": len(paths)}
        return ScanResult(endpoints, findings, links, paths, warnings, stats)
    finally:
        client.close()


def _probe_wordlist(prober: Prober, inventory: Inventory, identity: str) -> None:
    """Add common paths only when the target shows that they exist."""
    for path in DEFAULT_WORDLIST:
        if inventory.find("GET", path):
            continue
        probe = Endpoint("GET", path)
        obs = prober.request(probe, identity, {}, record=False)
        # Redirects are not accepted as proof because catch-all redirects are common.
        if obs and probe.live and (obs.ok or obs.status in (401, 403)):
            inventory.add("GET", path, "wordlist")
