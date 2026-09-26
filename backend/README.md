# Backend Documentation - SIH 26163 Security Assessment Platform

This backend is built using **Python 3**, **FastAPI**, and **SQLAlchemy**. It serves as the core engine that ingests application data, runs modular security checks, stores findings in a local SQLite database, and serves those findings via a RESTful API to the frontend dashboard.

## 📂 Directory Structure

```text
backend/
├── main.py                  # The FastAPI application entry point and API route definitions
├── database.py              # SQLAlchemy database connection and session management
├── models.py                # Database schema definitions (Tables: findings, evidence)
├── schemas.py               # Pydantic models for request/response validation
├── run_scan.py              # Standalone script to trigger data ingestion and security scans
├── report_generator.py      # Script to export findings into a Markdown report
│
├── ingestion/               
│   └── dataset_ingestor.py  # Logic to load and parse the SIH JSON datasets
│
└── security/                # Modular Security Engine
    ├── base.py              # Base class for all security modules
    ├── data_privacy.py      # Module checking for exposed infrastructure coordinates
    ├── simulated_auth.py    # Simulated module checking for JWT expiration
    └── authorization.py     # Simulated module checking for RBAC on admin routes
```

## 🚀 Live API Documentation (Swagger UI)

FastAPI automatically generates interactive API documentation. While the backend server is running, you can access the live documentation in your browser:

- **Swagger UI (Interactive):** [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc (Alternative format):** [http://localhost:8000/redoc](http://localhost:8000/redoc)

## 🧩 The Modular Security Engine

The security engine is designed to be easily extensible. If the hackathon judges provide actual source code or new datasets, you can quickly add a new check.

### How to add a new Security Module:
1. Create a new file in `backend/security/` (e.g., `api_rate_limiting.py`).
2. Import `SecurityCheck` from `.base`.
3. Create a class that inherits from `SecurityCheck` and implement the `run_check` method.
4. The `run_check` method receives the parsed `dataset` dictionary and must return a list of finding dictionaries that match the `FindingCreate` Pydantic schema.
5. Import and add your new class to the `checks` array in `backend/run_scan.py`.

## 🗄️ Database Management

We use **SQLite** (`sih_assessment.db`) for lightweight, portable data storage suitable for a hackathon environment.
- The `Finding` table stores the vulnerability metadata (Title, CVSS, Remediation, etc.).
- The `Evidence` table has a One-to-Many relationship with Findings, storing the exact raw data snippet that triggered the alert.

If you modify the models in `models.py`, simply delete `sih_assessment.db` and run `python run_scan.py` again to cleanly recreate the tables.
