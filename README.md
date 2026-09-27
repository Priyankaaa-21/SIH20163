# World Monitor Security Assessment (SIH 26163) 🛡️

A fully containerized, secure, and interactive platform for monitoring global vulnerabilities and radiological facilities. Built for the Smart India Hackathon (SIH 26163).

## ✨ Key Features
*   **Interactive Global Map:** A Leaflet-powered 2D/3D map plotting secure facility locations from sanitized datasets.
*   **Premium Dashboard UI:** A dynamic React (Vite) frontend featuring modern glassmorphism design, Recharts data visualization, and responsive metrics.
*   **Hardened Security:** 
    *   JWT-based Authentication & Authorization.
    *   Cryptographic password hashing (`bcrypt` & `passlib`).
    *   Strict Pydantic Enum data validation.
    *   API Rate Limiting (`slowapi`) to prevent DoS and brute-force attacks.
    *   Role-Based Access Control (RBAC) on critical endpoints.
*   **Containerized Orchestration:** One-command setup using Docker Compose.

## 🚀 Quick Start (Recommended)

The easiest way to run the entire stack (Frontend, Backend, and Database) is using Docker.

```bash
# Build and run the containers
docker-compose up --build
```
*   **Frontend UI:** `http://localhost:5173`
*   **Backend API:** `http://localhost:8000`

## 🛠️ Manual Local Development

If you prefer to run the components manually without Docker:

### 1. Backend Setup (FastAPI)
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Create your .env file
echo 'SECRET_KEY="your-secure-random-key"' > .env
echo 'ALGORITHM="HS256"' >> .env

# Start the server
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
*Note: A default `admin` user (password: `admin123`) is automatically provisioned in the SQLite database on first startup.*

### 2. Frontend Setup (React/Vite)
```bash
cd frontend
npm install
npm run dev
```

## 🔒 Security Posture
This application was actively audited and patched against the following critical vulnerabilities:
1.  Unauthenticated/Unauthorized API surfaces.
2.  Insecure wildcard CORS configurations.
3.  Lack of strict schema validations.
4.  Committed plaintext AWS secrets.
5.  Exposure of precise critical infrastructure coordinates.

## ⚙️ Tech Stack
*   **Frontend:** React, Vite, Lucide-React, Recharts, React-Leaflet
*   **Backend:** Python, FastAPI, SQLAlchemy, PyJWT, SlowAPI, SQLite
*   **Deployment:** Docker, Docker Compose
