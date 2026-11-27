"""Runs scans on background threads and saves their results."""
from __future__ import annotations

import logging
import threading
from dataclasses import asdict

from sqlalchemy import select

from .db import EndpointRow, FindingRow, LinkRow, PathRow, Project, Scan, utcnow
from .engine.discovery import ImportError_
from .engine.models import Identity, ScanResult
from .engine.pipeline import ScanConfig, run_scan
from .engine.scope import ScanCancelled, ScopeError
from .security import decrypt_json

log = logging.getLogger("shadowapi")
ACTIVE = ("queued", "running")


class ScanService:
    def __init__(self, session_factory) -> None:
        self.sessions = session_factory
        self._cancel: dict[int, threading.Event] = {}
        self._threads: dict[int, threading.Thread] = {}

    def recover(self) -> None:
        """Scans cannot survive a restart, so mark leftovers as failed."""
        with self.sessions() as db:
            for scan in db.scalars(select(Scan).where(Scan.status.in_(ACTIVE))):
                scan.status, scan.stage = "failed", "Interrupted"
                scan.message = "The server stopped while this scan was running."
                scan.finished_at = utcnow()
            db.commit()

    def start(self, scan_id: int) -> None:
        event = threading.Event()
        self._cancel[scan_id] = event
        thread = threading.Thread(target=self._run, args=(scan_id, event), daemon=True)
        self._threads[scan_id] = thread
        thread.start()

    def cancel(self, scan_id: int) -> None:
        if scan_id in self._cancel:
            self._cancel[scan_id].set()

    def wait(self, scan_id: int, timeout: float = 60) -> None:
        thread = self._threads.get(scan_id)
        if thread:
            thread.join(timeout)

    def _update(self, scan_id: int, **fields) -> None:
        with self.sessions() as db:
            scan = db.get(Scan, scan_id)
            if scan:
                for name, value in fields.items():
                    setattr(scan, name, value)
                db.commit()

    def _run(self, scan_id: int, cancel: threading.Event) -> None:
        try:
            with self.sessions() as db:
                scan = db.get(Scan, scan_id)
                if scan is None:
                    return
                config = self._config(db.get(Project, scan.project_id))
            self._update(scan_id, status="running")
            result = run_scan(
                config, cancel=cancel,
                progress=lambda stage, percent, message: self._update(
                    scan_id, stage=stage, progress=percent, message=message))
            self._save(scan_id, result)
        except ScanCancelled:
            self._finish(scan_id, "cancelled", "Cancelled", "The scan was cancelled.")
        except (ScopeError, ImportError_, ConnectionError) as exc:
            self._finish(scan_id, "failed", "Failed", str(exc))
        except Exception:  # unexpected errors are logged; the UI gets a safe message
            log.exception("Scan %s failed", scan_id)
            self._finish(scan_id, "failed", "Failed",
                         "The scan stopped because of an internal error. See the server log.")
        finally:
            self._cancel.pop(scan_id, None)

    def _finish(self, scan_id: int, status: str, stage: str, message: str) -> None:
        self._update(scan_id, status=status, stage=stage, message=message, finished_at=utcnow())

    @staticmethod
    def _config(project: Project) -> ScanConfig:
        options = project.options or {}
        return ScanConfig(
            base_url=project.base_url, spec_text=project.spec_text, har_text=project.har_text,
            identities=[Identity(**i) for i in decrypt_json(project.identities_encrypted)],
            enable_crawl=options.get("enable_crawl", True),
            enable_wordlist=options.get("enable_wordlist", True),
            rate=options.get("rate", 25), max_requests=options.get("max_requests", 3000))

    def _save(self, scan_id: int, result: ScanResult) -> None:
        with self.sessions() as db:
            scan = db.get(Scan, scan_id)
            if scan is None:  # deleted while running
                return
            for e in result.endpoints:
                scan.endpoints.append(EndpointRow(
                    method=e.method, path=e.template, classification=e.classification, data={
                        "sources": sorted(e.sources), "in_spec": e.in_spec, "live": e.live,
                        "statuses": sorted(e.statuses), "sensitive": e.sensitive,
                        "skip_reason": e.skip_reason,
                        "inputs": [asdict(i) for i in e.inputs]}))
            for f in result.findings:
                scan.findings.append(FindingRow(
                    type=f.type, endpoint=f.endpoint, severity=f.severity, score=f.score,
                    data=asdict(f)))
            scan.links = [LinkRow(data=asdict(link)) for link in result.links]
            scan.paths = [PathRow(data=asdict(path)) for path in result.paths]
            scan.status, scan.stage, scan.progress = "completed", "Completed", 100
            scan.message = "Scan finished."
            scan.warnings, scan.stats = result.warnings, result.stats
            scan.finished_at = utcnow()
            db.commit()
