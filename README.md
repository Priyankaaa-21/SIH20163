# World Monitor Security Assessment Platform (SIH 26163)



An authenticated platform for running, tracking and presenting a security assessment of the World Monitor application. It runs automated checks, stores findings with evidence, proves each fix with a before/after test, and shows everything in a dashboard.

> **Authorized, local use only.** All checks and proofs run on local files and in-memory test clients. No production systems or real user data are tested. See [docs/scope-and-limitations.md](docs/scope-and-limitations.md).

---

## What it does

```
DISCOVER → ANALYZE → DETECT → VALIDATE → COLLECT EVIDENCE → ASSESS RISK → REMEDIATE → RE-TEST → REPORT
```

| Stage | How it is done here |
| :--- | :--- |
| **Discover** | `backend/targets/worldmonitor_review.py` inventories routes, Docker services and config files of a local World Monitor clone and flags routes without auth, rate limiting or RBAC |
| **Detect** | Modular checks in `backend/security/` (code audit, config audit, data privacy, secret scan, dependency audit) |
| **Validate / Evidence** | Before/after proofs in `backend/poc/`. Each run stores its output, a timestamp and a SHA-256 hash as evidence |
| **Assess risk** | CVSS v3.1 scores are computed from the vector (`backend/security/cvss.py`), never typed by hand. CWE and OWASP API labels on every finding |
| **Remediate / Re-test** | Original vulnerable code is kept in `backend/baseline/` (with a hash manifest) so the BEFORE result is reproducible without git history |
| **Report** | `SECURITY_REPORT.md` and `report.html` are generated from the database |

Each finding moves through a lifecycle: **DISCOVERED → VALIDATED → CONFIRMED → REMEDIATED → RETESTED**. Confidence is tracked separately from severity.

---

## Features

### Dashboard (React + Vite)
- Metric cards, severity chart, remediation progress, filterable and sortable findings table
- Finding details with evidence, CVSS, CWE/OWASP tags and lifecycle
- Attack surface page, scope and authorization page, admin-only audit log
- Map of facilities using synthetic demo data (not real facility locations)
- Download buttons for the Markdown and HTML reports

### API (FastAPI)
- JWT login with mandatory expiry, bcrypt password hashing
- Role-based access: only admins can create users or findings
- Rate limiting (SlowAPI) and 15-minute account lockout after 5 failed logins
- Audit log of logins, failed logins and finding views
- Role-based map precision: non-admins receive coordinates rounded to a 0.5° grid with deterministic HMAC jitter
- The server refuses to start without a `SECRET_KEY` and a strong `ADMIN_PASSWORD`

### Quality
- 14 pytest security regression tests
- 4 before/after PoC proofs (open registration, token expiry, non-admin write, login lockout)
- GitHub Actions: tests, PoCs, attack surface review, report regeneration, pip-audit, npm audit, frontend build

---

## Quick start (Docker)

**Prerequisites:** Docker and Docker Compose.

```bash
cp backend/.env.template backend/.env
# Edit backend/.env: set SECRET_KEY (openssl rand -hex 32) and a strong ADMIN_PASSWORD (10+ characters)
docker-compose up --build
```

- **Dashboard:** [http://localhost:5173](http://localhost:5173)
- **API:** [http://localhost:8000](http://localhost:8000)

Log in as `admin` with the `ADMIN_PASSWORD` you set in `backend/.env`. The scanner runs automatically before the API starts, so the dashboard is populated on first load.

---

## Manual setup

**Prerequisites:** Python 3.11+, Node.js 22+ (Vite 8 does not run on Node 18).

```bash
# Backend (run from the repository root)
python3 -m venv backend/.venv
source backend/.venv/bin/activate
pip install -r backend/requirements.txt
cp backend/.env.template backend/.env # then edit it
python -m backend.run_scan # populate findings
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

# Frontend (second terminal)
cd frontend
npm ci
npm run dev
```

---

## Environment variables (`backend/.env`)

| Variable | Purpose |
| :--- | :--- |
| `SECRET_KEY` | Signs JWTs. Required, no default. |
| `ALGORITHM` | JWT algorithm (`HS256`) |
| `ADMIN_PASSWORD` | Initial admin password. Required, 10+ characters. |
| `FRONTEND_URL` | Allowed CORS origin |

> **Security Note:** Never commit real values. Only `backend/.env.template` belongs in git.

---

## Verify the claims yourself

```bash
export SECRET_KEY="any-long-test-secret-32-chars-min" ALGORITHM=HS256 \
       ADMIN_PASSWORD="A-Strong-Test-Password-1!" FRONTEND_URL=http://localhost:5173 \
       PYTHONPATH=.

pytest tests/ -v                       # 14 security regression tests
python -m backend.poc.run_all          # 4 before/after proofs, evidence saved to the database
python -m backend.report_generator     # regenerate SECURITY_REPORT.md and report.html
pip-audit -r backend/requirements.txt  # Python dependency audit
(cd frontend && npm audit)             # frontend dependency audit
```

---

## Reviewing a local World Monitor clone

```bash
git clone https://github.com/koala73/worldmonitor /path/to/worldmonitor
python -m backend.targets.worldmonitor_review --path /path/to/worldmonitor
```

The review is static and read-only: it reads files and makes no network requests. Flagged routes start as `DISCOVERED` with confidence "Needs Validation". Each one still has to be checked by hand before it is treated as a real finding.

---

## API overview

| Method | Path | Access |
| :--- | :--- | :--- |
| `POST` | `/token` | Public, rate limited, lockout after 5 failures |
| `POST` | `/users/` | Admin only |
| `GET` | `/findings/` | Logged in. Filters: severity, status, category, q, sort, order |
| `GET` | `/findings/{id}` | Logged in |
| `POST` | `/findings/` | Admin only |
| `GET` | `/facilities/` | Logged in. Precision depends on role |
| `GET` | `/attack-surface/` | Logged in |
| `GET` | `/audit/` | Admin only |
| `GET` | `/reports/markdown`, `/reports/html` | Logged in |

*Interactive API docs are intentionally disabled.*

---

## Project structure

```text
backend/
  main.py                 FastAPI app, auth, routes
  models.py, schemas.py   Database tables and API schemas
  run_scan.py             Runs all checks and stores findings
  report_generator.py     Builds SECURITY_REPORT.md and report.html
  security/               code_audit, config_audit, data_privacy, secret_scanner, dependency_audit, cvss
  poc/                    Before/after proofs and run_all.py
  baseline/               Preserved original (vulnerable) code and hash manifest
  targets/                worldmonitor_review.py
frontend/src/components/
  Dashboard, Login, MapWidget, VulnerabilityDetails, AttackSurface, AuditLog, ScopeAuthorization
dataset/                  Input datasets (synthetic map data, OSINT channel lists)
docs/                     methodology, architecture, remediation, retest, scope-and-limitations, demo-script
tests/                    pytest suite
.github/workflows/        security_ci.yml
```

To add a check, create a class in `backend/security/` that extends `SecurityCheck`, returns findings matching the `FindingCreate` schema (including `cwe`, `owasp` and `cvss`), and register it in `backend/run_scan.py`.

---

## Documentation

| Document | Contents |
| :--- | :--- |
| [`docs/methodology.md`](docs/methodology.md) | Workflow and finding lifecycle |
| [`docs/architecture.md`](docs/architecture.md) | Components and data flow |
| [`docs/remediation.md`](docs/remediation.md) | What was fixed and how |
| [`docs/retest.md`](docs/retest.md) | How fixes were re-tested |
| [`docs/scope-and-limitations.md`](docs/scope-and-limitations.md) | Authorization and non-claims |
| [`docs/demo-script.md`](docs/demo-script.md) | Click-through for judges |

---

## Limitations

- Map data is synthetic. It does not show real facility locations.
- The attack surface review is heuristic. It points to routes worth checking and does not prove exploitability.
- Before/after proofs run against preserved copies of this project's own code, not against production systems.
- SQLite and the development Docker setup are for demonstration. There is no HTTPS termination in `docker-compose.yml`.
- Findings about the World Monitor application depend on a local clone and manual validation.

---

## Tech stack

`React`, `Vite`, `Recharts`, `React-Leaflet`, `Lucide` · `Python 3.11`, `FastAPI`, `SQLAlchemy`, `PyJWT`, `SlowAPI`, `SQLite` · `Docker`, `Docker Compose`, `GitHub Actions`
