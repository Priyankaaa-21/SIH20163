# Backend Documentation - SIH 26163 Security Assessment Platform

This backend is built using **Python 3**, **FastAPI**, and **SQLAlchemy**. It serves as the core engine that ingests application data, runs modular security checks, stores findings in a local SQLite database, and serves those findings via a RESTful API to the frontend dashboard.

## 📂 Directory Structure

```text
backend/
├── main.py                  # The FastAPI application entry point and API route definitions
├── database.py              # SQLAlchemy database connection and session management
├── models.py                # Database schema definitions (Tables: findings, evidence, audit_logs)
├── schemas.py               # Pydantic v2 models for request/response validation
├── run_scan.py              # Standalone script to trigger data ingestion and security scans
├── report_generator.py      # Script to export findings into a Markdown report
│
├── ingestion/               
│   └── dataset_ingestor.py  # Logic to load and parse the SIH JSON datasets
│
└── security/                # Modular Security Engine
    ├── base.py              # Base class for all security modules and CVSS helper
    ├── cvss.py              # CVSS v3.1 base score calculation engine
    ├── code_audit.py        # AST static code analysis of backend/main.py
    ├── config_audit.py      # Audits OSINT feed configurations
    ├── data_privacy.py      # Module checking for exposed infrastructure coordinates
    ├── secret_scanner.py    # Hardcoded credentials and secret scanner
    └── dependency_audit.py  # Dependency vulnerability scanner
```

## 🚀 Running the Server

From the repository root directory, execute:

```bash
# Activate virtual environment
source backend/.venv/bin/activate

# Execute security scan
python -m backend.run_scan

# Start uvicorn server from repo root
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

## 🧩 The Modular Security Engine

The security engine is designed to be easily extensible. 

### How to add a new Security Module:
1. Create a new file in `backend/security/` (e.g., `custom_check.py`).
2. Import `SecurityCheck` and `format_cvss` from `.base`.
3. Create a class that inherits from `SecurityCheck` and implement the `run_check` method.
4. The `run_check` method receives the parsed `dataset` dictionary and must return a list of finding dictionaries that match the `FindingCreate` Pydantic schema (including `cwe`, `owasp`, and `cvss`).
5. Import and add your new class to the `checks` array in `backend/run_scan.py`.

## 🗄️ Database Management

We use **SQLite** (`sih_assessment.db`) for lightweight, portable data storage.
- The `Finding` table stores vulnerability metadata (Title, CVSS, Remediation, CWE, OWASP, scan_run_id, status, etc.).
- The `Evidence` table stores raw code and config snippets that substantiate each finding.
- The `AuditLog` table stores immutable audit trail entries (login attempts, failed logins, finding views).
