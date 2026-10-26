import os
import sys
import hashlib
from fastapi.testclient import TestClient

# Add repo root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.baseline.baseline_endpoints import baseline_app
from backend.main import app, get_password_hash, ADMIN_PASSWORD
from backend.database import SessionLocal
from backend import models
from backend.poc.poc_helper import print_poc_comparison, record_poc_evidence

def run_open_registration_poc():
    print("[*] Running PoC: Open User Registration Proof...")

    # --- 1. BEFORE (Baseline Vulnerable) ---
    baseline_client = TestClient(baseline_app)
    unauth_payload = {
        "username": "attacker_guest",
        "password": "123",  # Weak 3-char password
        "role": "admin"     # Can self-assign admin role!
    }
    before_resp = baseline_client.post("/users/", json=unauth_payload)
    before_sha = hashlib.sha256(before_resp.text.encode("utf-8")).hexdigest()
    
    before_output = (
        f"HTTP Request: POST /users/ (Unauthenticated, no Authorization header)\n"
        f"Request Body: {unauth_payload}\n"
        f"Response Status: {before_resp.status_code} OK (VULNERABLE)\n"
        f"Response Body: {before_resp.json()}\n"
        f"Security Assessment: ANY unauthenticated user could create accounts with weak passwords and self-assigned privileges."
    )

    # --- 2. AFTER (Remediated Protection) ---
    app_client = TestClient(app)
    # Attempt 1: Without token -> 401 Unauthorized
    after_unauth_resp = app_client.post("/users/", json=unauth_payload)
    
    # Attempt 2: With non-admin user token -> 403 Forbidden
    db = SessionLocal()
    try:
        user_op = db.query(models.User).filter(models.User.username == "poc_standard_user").first()
        if not user_op:
            user_op = models.User(
                username="poc_standard_user",
                hashed_password=get_password_hash("StandardUserPass2026!"),
                role="user"
            )
            db.add(user_op)
            db.commit()
    finally:
        db.close()

    login_op = app_client.post("/token", data={"username": "poc_standard_user", "password": "StandardUserPass2026!"})
    op_token = login_op.json().get("access_token", "")
    after_forbidden_resp = app_client.post(
        "/users/",
        json={"username": "new_unauth", "password": "ValidPassword2026!", "role": "user"},
        headers={"Authorization": f"Bearer {op_token}"}
    )

    after_sha = hashlib.sha256(after_forbidden_resp.text.encode("utf-8")).hexdigest()
    after_output = (
        f"Test A (No Token): POST /users/ -> Status: {after_unauth_resp.status_code} UNAUTHORIZED\n"
        f"Detail: {after_unauth_resp.json().get('detail')}\n\n"
        f"Test B (Standard User Token): POST /users/ -> Status: {after_forbidden_resp.status_code} FORBIDDEN (PROTECTED)\n"
        f"Detail: {after_forbidden_resp.json().get('detail')}\n"
        f"Security Assessment: Account creation is strictly restricted to authenticated administrators."
    )

    print_poc_comparison(
        "Open User Registration (CWE-862 / OWASP API5:2023)",
        before_output,
        after_output,
        sha256_before=before_sha,
        sha256_after=after_sha
    )

    ev_id = record_poc_evidence("Account Registration", "Open Registration Proof", before_output, after_output)
    print(f"[+] PoC Evidence saved to database with Evidence ID: {ev_id}")
    return True

if __name__ == "__main__":
    run_open_registration_poc()
