# Retest Protocols & Verification Procedures

This document outlines the testing protocols used to verify security remediations and prevent regressions.

---

## 1. Automated PoC Retest Suite (`backend/poc/run_all.py`)

The primary verification mechanism is the unified Before/After test suite. It executes each proof against both the pre-patch baseline (`backend/baseline/`) and the remediated application endpoints (`backend/main.py`).

### How to Run:
```bash
python -m backend.poc.run_all
```
*(Or via the virtualenv: `./backend/.venv/bin/python -m backend.poc.run_all`)*

### Expected Output:
```text
================================================================================
 SIH 26163 — AUTOMATED PROOF OF CONCEPT (PoC) VERIFICATION SUITE
================================================================================
Executing all Before/After test harnesses against baseline and hardened implementations...

[*] Running PoC: Open User Registration Proof...
[+] PoC Evidence saved to database with Evidence ID: ...
[*] Running PoC: Missing Token Expiration Proof...
[+] PoC Evidence saved to database with Evidence ID: ...
[*] Running PoC: Non-Admin State Modification (POST) Proof...
[+] PoC Evidence saved to database with Evidence ID: ...
[*] Running PoC: Login Lockout / Brute-Force Protection Proof...
[+] PoC Evidence saved to database with Evidence ID: ...

================================================================================
 PROOF OF CONCEPT EXECUTION SUMMARY
================================================================================
 - Open User Registration              : [PASSED]
 - Missing Token Expiration            : [PASSED]
 - Non-Admin State Modification        : [PASSED]
 - Account Lockout Protection          : [PASSED]
================================================================================
[✓] All 4 PoC proofs executed successfully with evidence recorded in database.
```

---

## 2. Running Individual Proof of Concept Scripts

Each PoC script is completely standalone and can be executed independently:

### 2.1 Open Registration Proof
```bash
python -m backend.poc.poc_open_registration
```
- **BEFORE:** Status 200 OK — unauthenticated account creation succeeds.
- **AFTER:** Status 401 Unauthorized (without token) / 403 Forbidden (non-admin caller).

### 2.2 Token Expiry Proof
```bash
python -m backend.poc.poc_token_expiration
```
- **BEFORE:** Status 200 OK — token without `exp` accepted indefinitely.
- **AFTER:** Status 401 Unauthorized — PyJWT mandates `options={"require": ["exp"]}`.

### 2.3 Non-Admin POST Proof
```bash
python -m backend.poc.poc_non_admin_post
```
- **BEFORE:** Status 200 OK — finding injected by standard user.
- **AFTER:** Status 403 Forbidden — administrative role check enforced.

### 2.4 Login Lockout Proof
```bash
python -m backend.poc.poc_login_lockout
```
- **BEFORE:** Unlimited failed login attempts accepted with status 400.
- **AFTER:** Attempt 5 triggers 15-minute account lockout; Attempt 6 blocked with status 403.

---

## 3. Running the Complete Pytest Test Suite

Execute the 14 automated unit and integration tests:
```bash
pytest tests/ -v
```
*(Or `./backend/.venv/bin/pytest tests/ -v`)*

### Passing Criteria:
All 14 test cases must return `PASSED`:
- `test_expired_token`
- `test_non_admin_post_findings_blocked`
- `test_non_admin_post_users_blocked`
- `test_account_lockout_after_five_failed_logins`
- `test_open_registration_unauthenticated`
- `test_password_minimum_length_enforced`
- `test_successful_user_creation_by_admin`
- `test_cvss_helper_computations`
- `test_code_audit_check_detects_remediations`
- `test_config_audit_groups_findings`
- `test_data_privacy_check`
- `test_secret_scanner_check`
- `test_facilities_role_precision`
- `test_audit_log_access`

---

## 4. Running the Attack Surface Inventory Scanner

```bash
python -m backend.targets.worldmonitor_review --path .
```
- Inspects all route decorators, container definitions, and Nginx configurations.
- Persists attack surface records into `attack_surfaces` table.
- Emits discovered routes with lifecycle `DISCOVERED` and confidence `"Needs Validation"`.
