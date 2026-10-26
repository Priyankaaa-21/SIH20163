# Judges Click-Through Demo Script

This numbered walkthrough provides an evaluation roadmap for judges to inspect the SIH 26163 World Monitor Security Assessment Platform.

---

## Pre-Demo Quick Verification (Terminal)
Before launching the UI, demonstrate automated tests and PoC verification from the terminal:
```bash
# 1. Run all 4 Before/After PoC Proofs
python -m backend.poc.run_all

# 2. Run the full pytest security regression suite (14/14 tests pass)
pytest tests/ -v

# 3. Launch the containerized application
docker-compose up --build
```

---

## Step-by-Step UI Click-Through for Judges

### 1. Secure Authentication & Startup Enforcement
1. Open the browser to **`http://localhost:5173`** (or the live URL).
2. Note the credentials prompt:
   - **Username:** `admin`
   - **Password:** `SecureAdminPassword2026!` (or `admin123` in demo mode).
3. **Judge Observation:** The backend strictly enforces strong password configuration via environment variables and refuses to boot if `ADMIN_PASSWORD` is unset or left at weak defaults.
4. Click **Sign In**.

### 2. Executive Dashboard & Metrics Overview
1. Upon login, notice the **4 Equal-Height Metric Cards**:
   - Total Findings
   - High & Critical
   - Open & Confirmed
   - Remediated & Retested
2. **Interactive Severity Donut & Remediation Progress Bar:** Shows real-time remediation metrics computed from the database.
3. **Filter Bar:** Filter findings by Severity (`High`, `Critical`), Status (`Remediated`), or Category.

### 3. Geospatial Critical Infrastructure Masking
1. Scroll down to the **Facilities Map Widget**.
2. Notice the facility markers (IAEA irradiation and research facilities).
3. Click any facility marker:
   - As `admin`, exact coordinates are accessible.
   - For standard users, coordinates are coarsened to a 0.5-degree grid with deterministic HMAC-seeded noise.
   - Raw database files are isolated in `private/` and excluded from the Docker build context.

### 4. Vulnerability Lifecycle Stepper
1. In the Findings Table, click on **"Missing 'exp' Enforcement in JWT Token Verification"** (or any finding).
2. Observe the **Lifecycle Timeline Stepper**:
   - `DISCOVERED` -> `VALIDATED` -> `CONFIRMED` -> `REMEDIATED` -> `RETESTED`.
   - The active stage (`RETESTED`) is highlighted with visual status indicators.
3. **Lifecycle History Table:** Displays exact UTC timestamps, actors (e.g. `AST Code Auditor`, `Test Harness`), and verification notes.

### 5. Confidence vs. Severity Separation & Dual CVSS Scoring
1. On the Finding Details page, inspect the header:
   - **Severity** (`High`) is clearly separated from **Confidence** (`High` / `Needs Validation`).
2. In the right-hand metadata panel, inspect the **Dual CVSS v3.1 Scoring**:
   - **CVSS Primary:** Realistic operational score (e.g., `9.1`).
   - **CVSS Conservative:** Worst-case score assuming scope changes or elevated impact (e.g., `10.0`).
   - Both scores are computed programmatically via the CVSS helper.

### 6. Side-by-Side Before/After PoC Comparative Panel
1. Still on the finding details page, scroll down to the **Before vs. After Execution Evidence** card:
   - **Left Panel (BEFORE):** Baseline vulnerable output with red frame and cryptographic SHA-256 badge.
   - **Right Panel (AFTER):** Remediated protection output with green frame, showing HTTP 401/403 rejection and SHA-256 badge.
2. Note that all evidence items display `collected_at`, `environment`, and an independent `sha256` digest produced by running code.

### 7. Attack Surface & Route Inventory Page
1. Click **"Attack Surface"** in the top navigation bar (`/attack-surface`).
2. Observe the inventory metrics:
   - Total API Routes Discovered (13)
   - Flagged Routes Requiring Security Hardening (8)
   - Container Services (6)
   - Config Surfaces (2)
3. Inspect the **Flagged Routes Table**:
   - Badges indicate missing controls (`Missing Authentication`, `Missing Rate Limiting`, `Missing RBAC`).
   - Demonstrates read-only static analysis without external network calls.

### 8. Scope, Authorization & Non-Claims Page
1. Click **"Scope & Auth"** in the top navigation bar (`/scope`).
2. Note the prominent glowing badge: **`Authorized, local environment`**.
3. Point out the **"Explicit Claims This Project DOES NOT Make"** section:
   - No live external system exploitation.
   - No real-world secret exfiltration.
   - No physical or SCADA/OT intrusion claims.
   - Local air-gapped testbed verification only.

### 9. Report Generation & Download (Markdown & HTML)
1. Return to the **Dashboard** (`/`).
2. In the action bar, click **"Report (MD)"**:
   - Downloads `SECURITY_REPORT.md` generated dynamically from the database.
3. Click **"Report (HTML)"**:
   - Downloads/opens `report.html`—a styled dark-mode report with print stylesheets, metrics, and evidence tables.

### 10. Administrative Security Audit Log
1. Click **"Audit Log"** in the navigation header (available to administrator role only).
2. Review the append-only security events:
   - `LOGIN_SUCCESS`
   - `FINDING_VIEWED`
   - `ACCOUNT_LOCKED` / `LOGIN_LOCKED`
   - `USER_CREATED`
3. Click **"Logout"** to verify session termination.
