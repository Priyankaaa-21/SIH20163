"""
Baseline (BEFORE) vulnerable implementations for SIH 26163 Security Audit.
Stored for deterministic, repeatable before/after proof of concept verification without git dependencies.
"""
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
import jwt
from typing import Dict, Any, Optional

SECRET_KEY = "insecure-baseline-test-secret-key"
ALGORITHM = "HS256"

baseline_app = FastAPI(title="Baseline Vulnerable App")

# In-memory baseline storage for test isolated state
baseline_users_db: Dict[str, Dict[str, Any]] = {
    "admin": {"username": "admin", "password": "admin123", "role": "admin", "failed_attempts": 0},
    "operator": {"username": "operator", "password": "operatorpassword", "role": "user", "failed_attempts": 0}
}
baseline_findings_db: list = []

class BaselineUserCreate(BaseModel):
    username: str
    password: str
    role: Optional[str] = "user"

class BaselineFindingCreate(BaseModel):
    title: str
    category: str
    severity: str
    affected_component: str
    description: str

# 1. BEFORE: Open Registration (No auth, no password minimum length)
@baseline_app.post("/users/")
def baseline_open_registration(user: BaselineUserCreate):
    # INSECURE: Open to the public, unauthenticated, allows 1-char passwords
    baseline_users_db[user.username] = {
        "username": user.username,
        "password": user.password,
        "role": user.role or "user",
        "failed_attempts": 0
    }
    return {"id": len(baseline_users_db), "username": user.username, "role": user.role}

# 2. BEFORE: Missing Token Expiry
@baseline_app.post("/token-unexpiring")
def baseline_issue_unexpiring_token(username: str = "operator"):
    # INSECURE: Issues token without 'exp' claim
    token = jwt.encode({"sub": username, "role": "user"}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}

@baseline_app.get("/protected-no-exp")
def baseline_verify_token_no_exp(token: str):
    try:
        # INSECURE: Does not require 'exp' claim; accepts unexpiring token forever
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {"status": "authorized", "user": payload.get("sub")}
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

# 3. BEFORE: Non-Admin POST allowed
@baseline_app.post("/findings/")
def baseline_create_finding_no_admin(finding: BaselineFindingCreate, user_role: str = "user"):
    # INSECURE: No role verification. Any authenticated (or standard) user can create findings
    new_finding = finding.model_dump()
    new_finding["id"] = len(baseline_findings_db) + 1
    baseline_findings_db.append(new_finding)
    return new_finding

# 4. BEFORE: Login Lockout Missing (Brute-force allowed)
@baseline_app.post("/login-no-lockout")
def baseline_login_no_lockout(username: str, password: str):
    user = baseline_users_db.get(username)
    if not user or user["password"] != password:
        # INSECURE: Infinite password guessing allowed; counter never tracks or locks
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    return {"status": "success", "username": username}
