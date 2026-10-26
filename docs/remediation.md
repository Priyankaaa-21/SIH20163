# Vulnerability Remediation Guide & Code Diffs

This document provides complete, line-by-line remediation diffs and implementation rationale for all security vulnerabilities identified and resolved in the World Monitor application.

---

## 1. Missing JWT Token Expiration Enforcement
- **Vulnerability:** JWT tokens were verified without requiring an expiration (`exp`) claim, allowing tokens without expiration to remain valid indefinitely.
- **Classification:** CWE-613 (Insufficient Session Expiration) / OWASP API2:2023 (Broken Authentication).
- **Remediation File:** `backend/main.py` (`get_current_user` function).

### Code Diff:
```diff
--- a/backend/main.py
+++ b/backend/main.py
@@ -115,3 +115,3 @@ def get_current_user(token: str = Depends(oauth2_scheme)):
     try:
-        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
+        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"require": ["exp"]})
         username: str = payload.get("sub")
```

---

## 2. Unrestricted Account Registration & Weak Password Rules
- **Vulnerability:** Unauthenticated actors could register arbitrary user accounts and assign administrative roles. In addition, single-character or trivial passwords were accepted.
- **Classification:** CWE-862 (Missing Authorization) / OWASP API5:2023 (Broken Function Level Authorization).
- **Remediation File:** `backend/main.py` (`create_user` endpoint).

### Code Diff:
```diff
--- a/backend/main.py
+++ b/backend/main.py
@@ -180,6 +180,18 @@ def create_user(
     request: Request,
     user: schemas.UserCreate,
-    db: Session = Depends(get_db)
+    db: Session = Depends(get_db),
+    current_user: dict = Depends(get_current_user)
 ):
+    # 1. Enforce admin privilege check
+    if current_user.get("role") != "admin":
+        raise HTTPException(
+            status_code=status.HTTP_403_FORBIDDEN,
+            detail="Admin privileges required to create new user accounts"
+        )
+    
+    # 2. Enforce minimum password length
+    if len(user.password) < 10:
+        raise HTTPException(
+            status_code=status.HTTP_400_BAD_REQUEST,
+            detail="Password must be at least 10 characters long"
+        )
```

---

## 3. Missing Role-Based Access Control on State-Modifying Endpoints
- **Vulnerability:** Standard users with role `"user"` were able to submit or alter security findings via `POST /findings/`.
- **Classification:** CWE-285 (Improper Authorization) / OWASP API5:2023.
- **Remediation File:** `backend/main.py` (`create_finding` endpoint).

### Code Diff:
```diff
--- a/backend/main.py
+++ b/backend/main.py
@@ -385,3 +385,7 @@ def create_finding(
     current_user: dict = Depends(get_current_user)
 ):
+    # Enforce administrative authorization
+    if current_user.get("role") != "admin":
+        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
```

---

## 4. Account Lockout & Brute-Force Rate Limiting
- **Vulnerability:** Login endpoint permitted unlimited automated password guesses without rate limiting or account lockout.
- **Classification:** CWE-307 (Improper Restriction of Excessive Authentication Attempts) / OWASP API2:2023.
- **Remediation File:** `backend/main.py` (`login` endpoint).

### Code Diff:
```diff
--- a/backend/main.py
+++ b/backend/main.py
@@ -134,8 +134,20 @@ def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db
+    # Check for active account lockout
+    if user and user.locked_until and user.locked_until > now:
+        remaining_secs = int((user.locked_until - now).total_seconds())
+        remaining_mins = max(1, remaining_secs // 60)
+        raise HTTPException(
+            status_code=status.HTTP_403_FORBIDDEN,
+            detail=f"Account is temporarily locked due to multiple failed login attempts. Try again in {remaining_mins} minutes."
+        )
+
     if not user or not is_valid:
         if user:
-            pass
+            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
+            if user.failed_login_attempts >= 5:
+                user.locked_until = now + datetime.timedelta(minutes=15)
+            db.commit()
```

---

## 5. Critical Infrastructure Geospatial Masking & Docker Isolation
- **Vulnerability:** High-precision geographical coordinates of nuclear irradiation and research facilities were exposed in datasets bundled directly into the Docker build context.
- **Classification:** CWE-200 (Exposure of Sensitive Information) / OWASP API3:2023.
- **Remediation Files:** `backend/main.py` (`read_facilities`), `backend/.dockerignore`, `.dockerignore`.

### Code Diff:
```diff
--- a/backend/.dockerignore
+++ b/backend/.dockerignore
@@ -1,3 +1,5 @@
+private/
+dataset/iaea_diif_db.json
+dataset/iaea_diif_facilities.json
```

```diff
--- a/backend/main.py
+++ b/backend/main.py
@@ -338,4 +338,10 @@ def read_facilities(current_user: dict = Depends(get_current_user)):
+    # For non-administrators: round to 0.5 degree grid with deterministic HMAC jitter
+    grid_lat = round(round(raw_lat / 0.5) * 0.5, 4)
+    grid_lon = round(round(raw_lon / 0.5) * 0.5, 4)
+    jitter_lat = deterministic_jitter(SECRET_KEY, f"{f_id}_lat", 0.02)
+    jitter_lon = deterministic_jitter(SECRET_KEY, f"{f_id}_lon", 0.02)
```
