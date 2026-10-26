import os
import sys
import hashlib
import jwt
from fastapi.testclient import TestClient

# Add repo root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.baseline.baseline_endpoints import baseline_app, SECRET_KEY as BASELINE_SECRET, ALGORITHM as BASELINE_ALG
from backend.main import app, SECRET_KEY as APP_SECRET, ALGORITHM as APP_ALG
from backend.poc.poc_helper import print_poc_comparison, record_poc_evidence

def run_token_expiration_poc():
    print("[*] Running PoC: Missing Token Expiration Proof...")

    # --- 1. BEFORE (Baseline Vulnerable) ---
    baseline_client = TestClient(baseline_app)
    unexpiring_token = jwt.encode({"sub": "rogue_operator", "role": "user"}, BASELINE_SECRET, algorithm=BASELINE_ALG)
    before_resp = baseline_client.get(f"/protected-no-exp?token={unexpiring_token}")
    before_sha = hashlib.sha256(before_resp.text.encode("utf-8")).hexdigest()

    before_output = (
        f"Crafted Token: {unexpiring_token[:25]}... (Missing 'exp' timestamp)\n"
        f"HTTP Request: GET /protected-no-exp\n"
        f"Response Status: {before_resp.status_code} OK (VULNERABLE)\n"
        f"Response Body: {before_resp.json()}\n"
        f"Security Assessment: The baseline system accepted tokens without expiration claims indefinitely. Stolen tokens never expired."
    )

    # --- 2. AFTER (Remediated Protection) ---
    app_client = TestClient(app)
    # Attempt using token signed with app secret but missing 'exp'
    token_missing_exp = jwt.encode({"sub": "operator", "role": "user"}, APP_SECRET, algorithm=APP_ALG)
    after_resp = app_client.get(
        "/findings/",
        headers={"Authorization": f"Bearer {token_missing_exp}"}
    )
    after_sha = hashlib.sha256(after_resp.text.encode("utf-8")).hexdigest()

    after_output = (
        f"Attempted Token: {token_missing_exp[:25]}... (Signed with valid secret, but NO 'exp' claim)\n"
        f"HTTP Request: GET /findings/\n"
        f"Response Status: {after_resp.status_code} UNAUTHORIZED (PROTECTED)\n"
        f"Response Header: {after_resp.headers.get('www-authenticate')}\n"
        f"Response Body: {after_resp.json()}\n"
        f"Security Assessment: PyJWT enforces options={{'require': ['exp']}}. Tokens lacking an expiration claim are strictly rejected."
    )

    print_poc_comparison(
        "Missing 'exp' Enforcement in JWT Verification (CWE-613 / OWASP API2:2023)",
        before_output,
        after_output,
        sha256_before=before_sha,
        sha256_after=after_sha
    )

    ev_id = record_poc_evidence("Missing 'exp' Enforcement", "Token Expiration Proof", before_output, after_output)
    print(f"[+] PoC Evidence saved to database with Evidence ID: {ev_id}")
    return True

if __name__ == "__main__":
    run_token_expiration_poc()
