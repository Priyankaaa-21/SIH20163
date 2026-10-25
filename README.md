# World Monitor Security Assessment (SIH 26163) 🛡️

A fully containerized, secure, and interactive platform for monitoring global vulnerabilities and radiological facilities. Built for the Smart India Hackathon (SIH 26163).

## ✨ Key Features
*   **Interactive Global Map:** A Leaflet-powered 2D map plotting secure facility locations from sanitized datasets.
*   **Clean Dashboard UI:** A dynamic React (Vite) frontend featuring subtle glass panels, Recharts data visualization, and responsive metrics.
*   **Hardened Security:** 
    *   JWT-based Authentication & Authorization with mandatory token expiration checks (`exp`).
    *   Cryptographic password hashing (`bcrypt` & `passlib`).
    *   Strict Pydantic Enum data validation with model serialization.
    *   API Rate Limiting (`slowapi`) and automated 15-minute account lockout after 5 failed login attempts.
    *   Role-Based Access Control (RBAC) on all state-modifying endpoints and user registration.
    *   Persistent security audit logging (`/audit/`).
*   **Containerized Orchestration:** Non-root Docker execution with Docker Compose.

## 🚀 Quick Start (Recommended)

The easiest way to run the entire stack (Frontend, Backend, and Database) is using Docker.

```bash
# Build and run the containers (automatically executes run_scan before starting API)
docker-compose up --build
```
*   **Frontend UI:** `http://localhost:5173`
*   **Backend API:** `http://localhost:8000`

## 🛠️ Manual Local Development

If you prefer to run the components manually without Docker, run commands from the repository root:

### 1. Backend Setup (FastAPI)
```bash
# Create and activate virtual environment
python3 -m venv backend/.venv
source backend/.venv/bin/activate
pip install -r backend/requirements.txt

# Configure your .env file in backend/
cp backend/.env.template backend/.env
# Edit backend/.env with a strong ADMIN_PASSWORD (min 10 characters)

# Run scanner to populate findings
python -m backend.run_scan

# Start the server from the repo root
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

### 2. Frontend Setup (React/Vite)
```bash
cd frontend
npm install
npm run dev
```

### 3. Running Automated Tests & Security Audits
```bash
# Run pytest test suite
source backend/.venv/bin/activate
pytest tests/ -v

# Run Python dependency vulnerability audit
pip-audit

# Run Frontend dependency audit
cd frontend && npm audit
```

## 🔒 Security Posture
This application is continuously audited against:
1.  Unauthenticated/Unauthorized API surfaces (RBAC enforced).
2.  Narrowed CORS configurations (no wildcard methods or headers).
3.  Strict schema validations.
4.  Committed plaintext secrets and credentials scanning.
5.  Exposure of precise critical infrastructure coordinates with role-based masking.
6.  Brute-force protection with account lockout and audit logging.

## ⚙️ Tech Stack
*   **Frontend:** React, Vite, Lucide-React, Recharts, React-Leaflet
*   **Backend:** Python, FastAPI, SQLAlchemy, PyJWT, SlowAPI, SQLite
*   **Deployment:** Docker, Docker Compose
