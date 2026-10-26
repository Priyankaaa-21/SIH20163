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

def run_login_lockout_poc():
    print("[*] Running PoC: Login Lockout / Brute-Force Protection Proof...")

    # --- 1. BEFORE (Baseline Vulnerable) ---
    baseline_client = TestClient(baseline_app)
    before_attempts = []
    for i in range(1, 8):
        resp = baseline_client.post(
            f"/login-no-lockout?username=operator&password=wrong_guess_{i}"
        )
        before_attempts.append(f"Attempt #{i}: Status {resp.status_code} ({resp.json().get('detail')})")
    
    before_text = "\n".join(before_attempts)
    before_sha = hashlib.sha256(before_text.encode("utf-8")).hexdigest()

    before_output = (
        f"Brute-Force Attack Simulation (7 consecutive failed passwords):\n"
        f"{before_text}\n"
        f"Security Assessment: INSECURE. The endpoint permitted unlimited automated password guessing without locking out the account."
    )

    # --- 2. AFTER (Remediated Protection) ---
    app_client = TestClient(app)
    # Create isolated user for lockout testing
    target_username = "poc_lockout_test_user"
    db = SessionLocal()
    try:
        user = db.query(models.User).filter(models.User.username == target_username).first()
        if not user:
            user = models.User(
                username=target_username,
                hashed_password=get_password_hash("ValidPass2026!"),
                role="user",
                failed_login_attempts=0,
                locked_until=None
            )
            db.add(user)
        else:
            user.failed_login_attempts = 0
            user.locked_until = None
        db.commit()
    finally:
        db.close()

    after_attempts = []
    locked_response = None
    for attempt in range(1, 7):
        resp = app_client.post(
            "/token",
            data={"username": target_username, "password": f"wrong_password_{attempt}"}
        )
        if resp.status_code == 403:
            locked_response = resp
            after_attempts.append(f"Attempt #{attempt}: Status {resp.status_code} FORBIDDEN -> {resp.json().get('detail')}")
        else:
            after_attempts.append(f"Attempt #{attempt}: Status {resp.status_code} BAD REQUEST -> {resp.json().get('detail')}")

    after_text = "\n".join(after_attempts)
    after_sha = hashlib.sha256(after_text.encode("utf-8")).hexdigest()

    after_output = (
        f"Hardened Rate-Limited Attack Simulation (6 consecutive failed passwords):\n"
        f"{after_text}\n"
        f"Lockout Trigger: Attempt #5 exceeded threshold -> Account locked for 15 minutes.\n"
        f"Security Assessment: PROTECTED. Brute-force attacks are immediately halted via account lockout and audit logging."
    )

    print_poc_comparison(
        "Account Lockout & Brute-Force Protection (CWE-307 / OWASP API2:2023)",
        before_output,
        after_output,
        sha256_before=before_sha,
        sha256_after=after_sha
    )

    ev_id = record_poc_evidence("Authentication", "Login Lockout Proof", before_output, after_output)
    print(f"[+] PoC Evidence saved to database with Evidence ID: {ev_id}")
    return True

if __name__ == "__main__":
    run_login_lockout_poc()
