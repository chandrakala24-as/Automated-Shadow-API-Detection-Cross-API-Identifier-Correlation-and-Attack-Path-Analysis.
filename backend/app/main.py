"""ShadowAPI web application: REST API plus the built frontend."""
from __future__ import annotations

import time
from datetime import timedelta

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import config, schemas
from .db import FindingRow, LoginSession, Project, Scan, User, make_session_factory, utcnow
from .demo import DEMO_IDENTITIES, LAB_URL, demo_files
from .engine.discovery import ImportError_, parse_har, parse_spec
from .report import build_report
from .scan_service import ACTIVE, ScanService
from .security import (decrypt_json, encrypt_json, hash_password, new_token, token_hash,
                       verify_password)

COOKIE = "shadowapi_session"
DIST = config.ROOT / "frontend" / "dist"
DUMMY_HASH = hash_password("not-a-real-password")
router = APIRouter(prefix="/api")


# ------------------------------------------------------------------ dependencies
def get_db(request: Request):
    with request.app.state.sessions() as db:
        yield db


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get(COOKIE)
    if token:
        session = db.get(LoginSession, token_hash(token))
        if session and session.expires_at > utcnow():
            user = db.get(User, session.user_id)
            if user:
                return user
    raise HTTPException(401, "Please sign in.")


def own_project(project_id: int, user: User = Depends(current_user),
                db: Session = Depends(get_db)) -> Project:
    project = db.get(Project, project_id)
    if project is None or project.user_id != user.id:
        raise HTTPException(404, "Project not found.")
    return project


def own_scan(scan_id: int, user: User = Depends(current_user),
             db: Session = Depends(get_db)) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.project.user_id != user.id:
        raise HTTPException(404, "Scan not found.")
    return scan


# ------------------------------------------------------------------ serialisers
def user_out(user: User) -> dict:
    return {"id": user.id, "name": user.name, "email": user.email}


def scan_out(scan: Scan) -> dict:
    return {"id": scan.id, "project_id": scan.project_id, "project_name": scan.project.name,
            "base_url": scan.project.base_url, "status": scan.status, "stage": scan.stage,
            "progress": scan.progress, "message": scan.message, "warnings": scan.warnings,
            "stats": scan.stats, "created_at": scan.created_at.isoformat() + "Z",
            "finished_at": scan.finished_at.isoformat() + "Z" if scan.finished_at else None}


def project_out(project: Project) -> dict:
    identities = decrypt_json(project.identities_encrypted)
    return {"id": project.id, "name": project.name, "base_url": project.base_url,
            "options": project.options, "is_demo": project.is_demo,
            "has_spec": bool(project.spec_text.strip()), "has_har": bool(project.har_text.strip()),
            # Header values are write-only: only their names are returned.
            "identities": [{"name": i["name"], "role": i["role"],
                            "header_names": list(i["headers"])} for i in identities],
            "created_at": project.created_at.isoformat() + "Z",
            "scan_count": len(project.scans),
            "last_scan": scan_out(project.scans[0]) if project.scans else None}


def finding_out(row: FindingRow) -> dict:
    return {**row.data, "id": row.id, "triage": row.triage}


# ------------------------------------------------------------------ authentication
def _start_session(response: Response, db: Session, user: User) -> dict:
    token = new_token()
    db.execute(delete(LoginSession).where(LoginSession.expires_at < utcnow()))
    db.add(LoginSession(token_hash=token_hash(token), user_id=user.id,
                        expires_at=utcnow() + timedelta(hours=config.SESSION_HOURS)))
    db.commit()
    response.set_cookie(COOKIE, token, httponly=True, samesite="strict",
                        max_age=config.SESSION_HOURS * 3600)
    return user_out(user)


@router.post("/auth/register", status_code=201)
def register(body: schemas.RegisterIn, response: Response, db: Session = Depends(get_db)):
    email = body.email.strip().lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, "An account with this email already exists.")
    user = User(name=body.name.strip(), email=email, password_hash=hash_password(body.password))
    db.add(user)
    db.commit()
    return _start_session(response, db, user)


@router.post("/auth/login")
def login(body: schemas.LoginIn, request: Request, response: Response,
          db: Session = Depends(get_db)):
    email = body.email.strip().lower()
    attempts = request.app.state.login_attempts
    recent = [t for t in attempts.get(email, []) if time.monotonic() - t < 300]
    if len(recent) >= 8:
        raise HTTPException(429, "Too many failed attempts. Try again in a few minutes.")
    user = db.scalar(select(User).where(User.email == email))
    valid = verify_password(body.password, user.password_hash if user else DUMMY_HASH)
    if not user or not valid:
        attempts[email] = recent + [time.monotonic()]
        raise HTTPException(401, "Incorrect email or password.")
    attempts.pop(email, None)
    return _start_session(response, db, user)


@router.post("/auth/logout", status_code=204)
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    token = request.cookies.get(COOKIE)
    if token:
        db.execute(delete(LoginSession).where(LoginSession.token_hash == token_hash(token)))
        db.commit()
    response.delete_cookie(COOKIE)


@router.get("/auth/me")
def me(user: User = Depends(current_user)):
    return user_out(user)


# ------------------------------------------------------------------ projects
def _apply(project: Project, body: schemas.ProjectIn) -> None:
    stored = {i["name"]: i for i in decrypt_json(project.identities_encrypted)} \
        if project.identities_encrypted else {}
    # Stored credentials must not silently follow a project to a different host.
    moved = project.base_url is not None and project.base_url != body.base_url
    identities = []
    for item in body.identities:
        headers = item.headers
        if headers is None:
            if moved:
                raise HTTPException(422, "The target URL changed. Enter the account headers again.")
            if item.name not in stored:
                raise HTTPException(422, f"Enter the headers for account '{item.name}'.")
            headers = stored[item.name]["headers"]
        identities.append({"name": item.name, "role": item.role, "headers": headers})
    for text, parser, attribute in ((body.spec_text, parse_spec, "spec_text"),
                                    (body.har_text, parse_har, "har_text")):
        if text is None:  # unchanged
            continue
        if text.strip():
            try:
                parser(text)
            except ImportError_ as exc:
                raise HTTPException(422, str(exc)) from exc
        setattr(project, attribute, text)
    project.name, project.base_url = body.name.strip(), body.base_url
    project.options = body.options.model_dump()
    project.identities_encrypted = encrypt_json(identities)


@router.get("/projects")
def list_projects(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(Project).where(Project.user_id == user.id)
                      .order_by(Project.id.desc()))
    return [project_out(p) for p in rows]


@router.post("/projects", status_code=201)
def create_project(body: schemas.ProjectIn, user: User = Depends(current_user),
                   db: Session = Depends(get_db)):
    project = Project(user_id=user.id, spec_text="", har_text="", identities_encrypted="")
    _apply(project, body)
    db.add(project)
    db.commit()
    return project_out(project)


@router.post("/demo", status_code=201)
def create_demo(user: User = Depends(current_user), db: Session = Depends(get_db)):
    existing = db.scalar(select(Project).where(Project.user_id == user.id, Project.is_demo))
    if existing:
        return project_out(existing)
    spec, har = demo_files()
    project = Project(
        user_id=user.id, name="RideShop demo lab", base_url=LAB_URL, spec_text=spec,
        har_text=har, identities_encrypted=encrypt_json(DEMO_IDENTITIES),
        options=schemas.OptionsIn(rate=60).model_dump(), is_demo=True)
    db.add(project)
    db.commit()
    return project_out(project)


@router.get("/projects/{project_id}")
def read_project(project: Project = Depends(own_project)):
    return {**project_out(project), "scans": [scan_out(s) for s in project.scans]}


@router.put("/projects/{project_id}")
def update_project(body: schemas.ProjectIn, project: Project = Depends(own_project),
                   db: Session = Depends(get_db)):
    _apply(project, body)
    db.commit()
    return project_out(project)


@router.delete("/projects/{project_id}", status_code=204)
def delete_project(request: Request, project: Project = Depends(own_project),
                   db: Session = Depends(get_db)):
    for scan in project.scans:
        request.app.state.scanner.cancel(scan.id)
    db.delete(project)
    db.commit()


# ------------------------------------------------------------------ scans
@router.post("/projects/{project_id}/scans", status_code=201)
def start_scan(request: Request, project: Project = Depends(own_project),
               db: Session = Depends(get_db)):
    if any(s.status in ACTIVE for s in project.scans):
        raise HTTPException(409, "A scan is already running for this project.")
    running = db.scalar(select(func.count()).select_from(Scan).where(Scan.status.in_(ACTIVE)))
    if running >= 3:
        raise HTTPException(429, "Three scans are already running. Please wait.")
    scan = Scan(project=project)
    db.add(scan)
    db.commit()
    request.app.state.scanner.start(scan.id)
    return scan_out(scan)


@router.get("/scans/{scan_id}")
def read_scan(scan: Scan = Depends(own_scan)):
    return scan_out(scan)


@router.get("/scans/{scan_id}/results")
def results(scan: Scan = Depends(own_scan)):
    return {
        "scan": scan_out(scan),
        "endpoints": [{**e.data, "id": e.id, "method": e.method, "path": e.path,
                       "classification": e.classification} for e in scan.endpoints],
        "findings": [finding_out(f) for f in sorted(scan.findings, key=lambda f: -f.score)],
        "links": [{**r.data, "id": r.id} for r in scan.links],
        "paths": [{**r.data, "id": r.id} for r in scan.paths],
    }


@router.post("/scans/{scan_id}/cancel", status_code=202)
def cancel_scan(request: Request, scan: Scan = Depends(own_scan)):
    request.app.state.scanner.cancel(scan.id)
    return {"status": "cancelling"}


@router.delete("/scans/{scan_id}", status_code=204)
def delete_scan(request: Request, scan: Scan = Depends(own_scan), db: Session = Depends(get_db)):
    request.app.state.scanner.cancel(scan.id)
    db.delete(scan)
    db.commit()


@router.patch("/findings/{finding_id}")
def triage(finding_id: int, body: schemas.TriageIn, user: User = Depends(current_user),
           db: Session = Depends(get_db)):
    row = db.get(FindingRow, finding_id)
    scan = db.get(Scan, row.scan_id) if row else None
    if scan is None or scan.project.user_id != user.id:
        raise HTTPException(404, "Finding not found.")
    row.triage = body.triage
    db.commit()
    return finding_out(row)


@router.get("/scans/{scan_id}/report.html", response_class=HTMLResponse)
def html_report(scan: Scan = Depends(own_scan)):
    if scan.status != "completed":
        raise HTTPException(409, "The report is available after the scan completes.")
    return HTMLResponse(build_report(scan), headers={
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})


@router.get("/scans/{scan_id}/report.json")
def json_report(scan: Scan = Depends(own_scan)):
    return JSONResponse(results(scan), headers={
        "Content-Disposition": f'attachment; filename="shadowapi-scan-{scan.id}.json"'})


@router.get("/dashboard")
def dashboard(user: User = Depends(current_user), db: Session = Depends(get_db)):
    projects = list(db.scalars(select(Project).where(Project.user_id == user.id)))
    totals = {"projects": len(projects), "live": 0, "shadow": 0, "zombie": 0, "paths": 0}
    severity = dict.fromkeys(("critical", "high", "medium", "low"), 0)
    top, recent = [], []
    for project in projects:
        recent.extend(project.scans[:5])
        latest = next((s for s in project.scans if s.status == "completed"), None)
        if not latest:
            continue
        for key in ("live", "shadow", "zombie", "paths"):
            totals[key] += latest.stats.get(key, 0)
        for finding in latest.findings:
            if finding.triage == "open":
                severity[finding.severity] += 1
                top.append({"id": finding.id, "scan_id": latest.id, "project": project.name,
                            "title": finding.data["title"], "endpoint": finding.endpoint,
                            "severity": finding.severity, "score": finding.score})
    return {"totals": totals, "severity": severity,
            "top_findings": sorted(top, key=lambda f: -f["score"])[:6],
            "recent_scans": [scan_out(s) for s in
                             sorted(recent, key=lambda s: -s.id)[:6]]}


# ------------------------------------------------------------------ application
def create_app(database_url: str | None = None) -> FastAPI:
    app = FastAPI(title="ShadowAPI", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.sessions = make_session_factory(database_url)
    app.state.scanner = ScanService(app.state.sessions)
    app.state.scanner.recover()
    app.state.login_attempts = {}

    @app.middleware("http")
    async def guard(request: Request, call_next):
        # Cross-site pages cannot add this header without a CORS preflight, which is refused.
        if (request.url.path.startswith("/api/") and request.method not in ("GET", "HEAD")
                and request.headers.get("x-requested-with") != "ShadowAPI"):
            return JSONResponse({"detail": "Missing request header."}, 403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "object-src 'none'; frame-ancestors 'none'; base-uri 'self'")
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    app.add_middleware(TrustedHostMiddleware, allowed_hosts=config.allowed_hosts())

    @app.exception_handler(RequestValidationError)
    async def invalid(_: Request, exc: RequestValidationError):
        # Submitted values are not echoed back, because they may contain credentials.
        messages = []
        for error in exc.errors():
            field = ".".join(str(p) for p in error["loc"][1:])
            text = error["msg"].removeprefix("Value error, ")
            messages.append(f"{field}: {text}" if field else text)
        return JSONResponse({"detail": " ".join(messages)}, 422)

    app.include_router(router)

    @app.get("/{path:path}", include_in_schema=False)
    def frontend(path: str):
        if path.startswith("api/"):
            raise HTTPException(404, "Not found.")
        target = (DIST / path).resolve()
        if path and target.is_file() and target.is_relative_to(DIST.resolve()):
            return FileResponse(target)
        index = DIST / "index.html"
        if index.is_file():
            return FileResponse(index)
        return HTMLResponse("<p>The frontend is not built yet. Run setup.ps1.</p>", 503)

    return app
