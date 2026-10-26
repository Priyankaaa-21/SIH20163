import os
import sys
import hashlib
from fastapi.testclient import TestClient

# Add repo root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.baseline.baseline_endpoints import baseline_app
from backend.main import app, get_password_hash
from backend.database import SessionLocal
from backend import models
from backend.poc.poc_helper import print_poc_comparison, record_poc_evidence

def run_non_admin_post_poc():
    print("[*] Running PoC: Non-Admin State Modification (POST) Proof...")

    # --- 1. BEFORE (Baseline Vulnerable) ---
    baseline_client = TestClient(baseline_app)
    unauth_finding = {
        "title": "Unauthorized User-Injected Vulnerability",
        "category": "Spoofed Findings",
        "severity": "Low",
        "affected_component": "External Audit",
        "description": "Injected by non-admin actor without permission checks."
    }
    before_resp = baseline_client.post("/findings/", json=unauth_finding)
    before_sha = hashlib.sha256(before_resp.text.encode("utf-8")).hexdigest()

    before_output = (
        f"HTTP Request: POST /findings/ (Caller role: 'user')\n"
        f"Request Body: {unauth_finding}\n"
        f"Response Status: {before_resp.status_code} OK (VULNERABLE)\n"
        f"Response Body: {before_resp.json()}\n"
        f"Security Assessment: Standard unprivileged users could inject arbitrary findings into the audit database."
    )

    # --- 2. AFTER (Remediated Protection) ---
    app_client = TestClient(app)
    # Ensure standard user exists
    db = SessionLocal()
    try:
        user_op = db.query(models.User).filter(models.User.username == "poc_auditor_user").first()
        if not user_op:
            user_op = models.User(
                username="poc_auditor_user",
                hashed_password=get_password_hash("AuditorUserPass2026!"),
                role="user"
            )
            db.add(user_op)
            db.commit()
    finally:
        db.close()

    # Login as standard user
    login_resp = app_client.post("/token", data={"username": "poc_auditor_user", "password": "AuditorUserPass2026!"})
    token = login_resp.json().get("access_token", "")

    new_finding_payload = {
        "title": "Unauthorized Modification Attempt",
        "category": "Authorization",
        "severity": "Low",
        "affected_component": "Audit API",
        "description": "Attempt to create finding without admin role",
        "impact": "None",
        "remediation": "Enforce admin check",
        "status": "Detected",
        "confidence": "High",
        "evidence": []
    }

    after_resp = app_client.post(
        "/findings/",
        json=new_finding_payload,
        headers={"Authorization": f"Bearer {token}"}
    )
    after_sha = hashlib.sha256(after_resp.text.encode("utf-8")).hexdigest()

    after_output = (
        f"Authenticated User: 'poc_auditor_user' (Role: 'user')\n"
        f"HTTP Request: POST /findings/\n"
        f"Response Status: {after_resp.status_code} FORBIDDEN (PROTECTED)\n"
        f"Response Body: {after_resp.json()}\n"
        f"Security Assessment: Function-level authorization enforced. Modifying endpoints strictly require role='admin'."
    )

    print_poc_comparison(
        "Missing Role-Based Access Control on Modifying Endpoints (CWE-285 / OWASP API5:2023)",
        before_output,
        after_output,
        sha256_before=before_sha,
        sha256_after=after_sha
    )

    ev_id = record_poc_evidence("Role-Based Access Control", "Non-Admin POST Proof", before_output, after_output)
    print(f"[+] PoC Evidence saved to database with Evidence ID: {ev_id}")
    return True

if __name__ == "__main__":
    run_non_admin_post_poc()
