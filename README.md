# ShadowAPI

**Automated Shadow API Detection, Cross-API Identifier Correlation and Attack-Path Analysis**

## Quick start (Windows)

Requirements: Python 3.12 or newer and Node.js 20 or newer (developed on Python 3.14 and Node 25).

```powershell
.\setup.ps1     # once
.\start.ps1     # opens http://127.0.0.1:8000
```

If PowerShell blocks scripts, run `powershell -ExecutionPolicy Bypass -File .\setup.ps1`
(and the same for `start.ps1`).

Then: **Create an account → Try the demo lab → Run scan**.

`start.ps1` also starts the demo lab on port 8001. The lab is **deliberately vulnerable**, uses fake
data and listens on this computer only. Use `.\start.ps1 --no-demo` to leave it off.

## Features

| Area | What it does |
|---|---|
| Discovery | OpenAPI/Swagger import, HAR traffic import, same-origin crawl, JavaScript route extraction, common path probing |
| Classification | Documented, shadow, zombie, unverified, candidate |
| Security tests | Missing authentication, invalid token accepted, BOLA/IDOR, function-level access (BFLA), secret exposure |
| Correlation | Links the API that returns an identifier to the API that accepts it, with a confidence score and reasons |
| Attack paths | Multi-step chains built only from requests that succeeded during the scan |
| Risk | 0–100 score with a visible breakdown |
| Web app | Accounts, projects, live scan progress, dashboard, graphs, finding triage, HTML (print to PDF) and JSON reports, light and dark themes |

## How it works

```
spec + HAR + crawl + JavaScript + path probing
        ↓  normalise paths (/users/42 → /users/{userId})
request each GET route as: every test account, no credentials, a made-up token
        ↓  identifiers found in responses feed the next round
infer ownership by comparing what different users see
        ↓
classify → analyse access control → correlate identifiers → search attack paths → score
```

**Ownership.** An identifier belongs to a user when a route with no parameters shows it to that user
and not to the others. Identifiers inside that user's own objects inherit the owner. Items that a
documented, non-sensitive listing shows to several users are treated as shared.

**BOLA.** Another normal user must receive the same data as the owner. A finding is *confirmed* only
with extra proof that the object is private: sensitive fields, a reference to the owner's user ID, or
the object being a record in the owner's own listing. Otherwise it is marked *needs review*.

**Attack paths.** The search tracks which of the victim's identifiers the attacker has learned. A
request is possible only when all its inputs are known. Only confirmed weaknesses create paths.

## Scanning your own application

Scan only systems you own or have written permission to test. Prefer a test environment.

1. Upload the OpenAPI specification. Without it, APIs cannot be called "shadow".
2. Add two normal test users that own different data, and ideally one administrator.
3. Upload a HAR capture recorded while using the application.
4. Mark intentionally public routes with `security: []`.
5. Check each finding's evidence before acting on it.

## Accuracy: what has and has not been measured

| Test | Result |
|---|---|
| Demo lab with spec, HAR and three accounts: 7 planted vulnerabilities | All 7 reported, no other vulnerabilities |
| Demo lab: 4 shadow and 1 zombie API | Classified as expected |
| Secured test application | No findings |
| Catch-all website returning 200 for every path | No endpoints invented |
| Catalogue item referenced by a private order | Marked *needs review*, not confirmed |

**These results do not show real-world accuracy.** The test applications were written together with
the scanner. Before reporting precision or recall in a paper or project review, evaluate it on
applications it was not developed against, such as OWASP crAPI and VAmPI. Expect some false positives
and missed issues there.

Results depend on the inputs. In the demo lab, one route appears only in the traffic capture, so a
scan without the HAR file does not find that route or its vulnerability.

## Limitations

- Only GET requests are sent. Flaws in POST, PUT, PATCH and DELETE are not tested.
- The crawler reads HTML and JavaScript but does not run a browser. It uses pattern matching, so routes
  built dynamically can be missed. mitmproxy is not built in; import a HAR file.
- Ownership cannot be inferred when both users see identical data. Data that is meant to be visible to
  all signed-in users can be reported if the specification and responses give no sign of that.
- Sensitive data is recognised by field names.
- Only a few sample values are tested per owner, and an inventory is limited to 400 routes.
- No GraphQL, gRPC or WebSocket support, and no tests for expired tokens, injection or rate limits.
- No findings does not mean that an application is secure.

## Security of ShadowAPI itself

It is a **local, single-machine tool**. `run.py` listens on 127.0.0.1 only. Do not expose it to a
network or the internet: anyone with an account can make it send requests to hosts your computer can
reach, and the session cookie is not marked HTTPS-only.

- Passwords are hashed with scrypt; sessions use HttpOnly, SameSite=Strict cookies.
- Test-account headers are encrypted and never returned by the API. The key is `data/secret.key`, next
  to the database, so protect the whole `data` folder.
- Sensitive-named fields are masked in saved evidence. Other fields and identifiers are kept, so treat
  reports and uploaded spec/HAR files as confidential. The HAR file is stored as uploaded, including
  any tokens it contains.
- The scanner stays on one origin, does not follow redirects, skips routes such as logout or delete,
  limits request rate and count, and blocks link-local (cloud metadata) addresses.

## Project layout

```
backend/app/engine/   scanner (no web or database code)
backend/app/          REST API, database, reports
backend/tests/        accuracy, false-positive, safety and API tests
frontend/src/         React + TypeScript interface
demo_lab/             vulnerable demo application, its spec and traffic
data/                 database and encryption key (created on first run)
```

## Development

```powershell
.\.venv\Scripts\python.exe -m pytest backend\tests    # tests
cd frontend; npm run dev                              # UI with reload (keep start.ps1 running)
```

Database: SQLite through SQLAlchemy. There are no schema migrations yet.

**Stack:** Python, FastAPI, SQLAlchemy, httpx, SQLite, React, TypeScript, Vite, Cytoscape.js.
The attack-path search is custom code, so NetworkX from the original plan was not needed.
