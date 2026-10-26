# System Architecture & Technical Specifications

## 1. Architectural Overview

The SIH 26163 Security Assessment Platform is built as a modular, containerized multi-tier application comprising a hardened FastAPI backend, an SQLite audit store with dynamic schema migration, an evidence-backed security scanner engine, a deterministic Before/After PoC test harness, and a high-performance React dashboard.

```mermaid
graph TD
    subgraph Frontend ["Frontend Web Layer (Port 80 / 5173)"]
        UI[React 18 + Vite Dashboard]
        Router[React Router DOM]
        Details[Vulnerability Details & Stepper]
        PoCPanel[Side-by-Side PoC Comparison]
        AtkSurface[Attack Surface & Inventory View]
        ScopeView[Scope & Non-Claims View]
    end

    subgraph Backend ["Backend API & Security Core (Port 8000)"]
        FastAPI[FastAPI Application (backend/main.py)]
        Auth[JWT & Bcrypt Auth Handler]
        Lockout[SlowAPI & Account Lockout Engine]
        CoordFuzz[HMAC Deterministic Coordinate Masking]
        Scanners[Modular Security Engine (backend/security/*)]
        TargetReview[Attack Surface Review (backend/targets/*)]
        ReportGen[Report Generator (Markdown & HTML)]
    end

    subgraph PoCHarness ["Deterministic PoC Verification Harness"]
        Baseline[Pre-Patch Code (backend/baseline/*)]
        Manifest[SHA-256 Manifest (manifest.json)]
        TestClient[FastAPI TestClient Runner (backend/poc/*)]
    end

    subgraph Storage ["Data & Audit Layer"]
        DB[(sih_assessment.db)]
        PrivateDir[(private/ Isolated Storage)]
    end

    UI --> FastAPI
    FastAPI --> DB
    Scanners --> DB
    TargetReview --> DB
    TestClient --> Baseline
    TestClient --> FastAPI
    TestClient --> DB
    FastAPI --> PrivateDir
```

---

## 2. Component Specifications

### 2.1 Backend Application (`backend/main.py`)
- **Framework:** FastAPI on Uvicorn (ASGI).
- **Python Version:** Python 3.11+ (running in `python:3.11-slim` container).
- **Authentication:** OAuth2 Password Bearer with HS256 JWT tokens. Enforces mandatory `exp` claim validation via PyJWT options `{"require": ["exp"]}`.
- **Brute-Force Protection:** IP-based rate limiting via SlowAPI (`10/minute` on `/token`) combined with in-database failed attempt tracking (`failed_login_attempts >= 5` triggers 15-minute account lockout).
- **Authorization:** Strict role-based access control requiring `current_user.get("role") == "admin"` on all modifying POST endpoints (`/users/`, `/findings/`) and administrative audit queries (`/audit/`).
- **Geospatial Coordinate Masking:** Standard users querying `/facilities/` receive coordinates rounded to a 0.5-degree grid with deterministic HMAC-seeded jitter. Exact coordinates are strictly isolated to `private/iaea_diif_*.json` accessible only to administrators.

### 2.2 Security Scanner Engine (`backend/security/`)
- All checks inherit from the abstract base class `SecurityCheck` in `base.py`.
- **`code_audit.py`:** Python AST traversal verifying defensive programming standards.
- **`config_audit.py`:** Intelligence feed JSON schema and trust boundary auditor.
- **`data_privacy.py`:** Nuclear and critical infrastructure dataset coordinate exposure auditor.
- **`secret_scanner.py`:** Recursive regex credential pattern scanner.
- **`dependency_audit.py`:** Automated npm audit vulnerability extractor.

### 2.3 Baseline Isolation & PoC Suite (`backend/baseline/` and `backend/poc/`)
- **`backend/baseline/`:** Contains isolated, pre-patch copies of vulnerable endpoints (`baseline_endpoints.py`) and a cryptographic SHA-256 manifest (`manifest.json`), eliminating any requirement for Git branch switching.
- **`backend/poc/`:** Standalone executable test harnesses using FastAPI `TestClient` against baseline and hardened endpoints. Each script prints side-by-side Before/After execution traces and persists cryptographically signed Evidence records in the database.

### 2.4 Database Schema (`backend/models.py`)
- **`findings`:** Stores security findings with `lifecycle` (`DISCOVERED`, `VALIDATED`, `CONFIRMED`, `REMEDIATED`, `RETESTED`), `lifecycle_history` (JSON event trail), `cvss_primary`, `cvss_conservative`, `confidence`, and CWE/OWASP metadata.
- **`evidence`:** Stores code execution output with `collected_at` (UTC datetime), `environment` (e.g. `poc-testclient`), and `sha256` digest.
- **`attack_surfaces`:** Stores route inventories, flagged endpoint records, and container architecture metadata.
- **`audit_logs`:** Append-only security audit trail tracking authentication, account locks, and state modifications.
- **`users`:** User accounts with bcrypt password hashes, roles, and lockout state.

### 2.5 Dynamic Schema Migration (`backend/database.py`)
- The `ensure_db_schema()` routine automatically inspects existing SQLite table metadata via `PRAGMA table_info` and issues `ALTER TABLE` statements for any newly introduced columns without dropping data.
