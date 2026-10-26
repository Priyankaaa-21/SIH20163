# Assessment Methodology & Verification Framework

## 1. Overview
The SIH 26163 Security Assessment of the World Monitor platform utilizes a rigorous, evidence-backed hybrid methodology combining **Abstract Syntax Tree (AST) code auditing**, **configuration & data privacy sanitization**, **read-only attack surface inventory analysis**, and **automated Before/After Proof-of-Concept (PoC) harnesses**.

---

## 2. Security Assessment Modules

### 2.1 Static Abstract Syntax Tree (AST) Code Audit (`backend/security/code_audit.py`)
Rather than relying on brittle pattern matching, the code auditor parses Python Abstract Syntax Trees to verify defensive constructs:
- **JWT Expiration Validation:** Inspects `jwt.decode` calls to verify that the options dictionary mandates `{"require": ["exp"]}`.
- **Function-Level Access Control:** Walks all AST `FunctionDef` nodes decorated with `@app.post` to guarantee that role verification checks (`current_user.get("role") == "admin"`) are present.
- **Registration Hardening:** Verifies that unauthenticated user creation routes are disabled and password length rules are strictly validated.
- **CORS Narrowing:** Audits `CORSMiddleware` configuration to ensure wildcard methods (`*`) and headers are replaced with explicit whitelists (`GET`, `POST`, `OPTIONS`).
- **Default Credential Refusal:** Inspects application startup routines to verify that the server refuses to initialize if `ADMIN_PASSWORD` is unset or equals known defaults (`admin123`).

### 2.2 Configuration & Trust Boundary Audit (`backend/security/config_audit.py`)
- Analyzes OSINT intelligence feed configurations (`dataset/news_channels.json`, `news_channels_x.json`).
- Flags Tier-1 intelligence channels lacking verified numeric `accountId` metadata, which are vulnerable to identity forking and disinformation injection.

### 2.3 Data Privacy & Geospatial Masking (`backend/security/data_privacy.py`)
- Audits critical infrastructure datasets (`iaea_diif_*.json`).
- Verifies that raw unmasked files are strictly excluded from the Docker build context (`.dockerignore`) and stored in gitignored private storage.
- Enforces role-based coordinate coarsening: non-admin callers receive coordinates rounded to a 0.5-degree grid with deterministic HMAC-seeded jitter, while authorized administrators access exact coordinates from isolated storage.

### 2.4 Credentials & Secret Scanning (`backend/security/secret_scanner.py`)
- Recursively audits dataset trees and config objects for leaked AWS access keys (`AKIA...`), bearer tokens, and suspicious key-value pairs.
- Ensures all detected tokens are masked in output (`AKIA***1234`) and injected via runtime environment variables.

### 2.5 Supply Chain & Dependency Audit (`backend/security/dependency_audit.py`)
- Automatically inspects frontend npm dependencies via `npm audit --json`.
- Evaluates lockfiles for known cross-origin middleware vulnerabilities and transitive package flaws.

---

## 3. CVSS v3.1 Dual Scoring System

Every finding in this platform is evaluated under two distinct vectors computed programmatically using the CVSS v3.1 base score algorithm:

1. **`cvss_primary` (Operational Baseline):** Reflects the realistic operational risk in a standard deployment environment where secondary controls may mitigate certain aspects.
2. **`cvss_conservative` (Worst-Case Potential):** Evaluates the worst-case scenario assuming perimeter defenses fail, Scope changes (`S:C`), or Impact elevates (`C:H/I:H/A:H`).

Both scores are calculated using the exact CVSS v3.1 formulas:
$$\text{ISS} = 1 - [(1 - \text{Impact}_{\text{Conf}}) \times (1 - \text{Impact}_{\text{Integ}}) \times (1 - \text{Impact}_{\text{Avail}})]$$
$$\text{Exploitability} = 8.22 \times \text{AV} \times \text{AC} \times \text{PR} \times \text{UI}$$

---

## 4. Vulnerability Lifecycle State Machine

Findings advance through a formal 5-stage lifecycle state machine with an append-only JSON audit trail:

```mermaid
graph LR
    DISCOVERED --> VALIDATED
    VALIDATED --> CONFIRMED
    CONFIRMED --> REMEDIATED
    REMEDIATED --> RETESTED
```

1. **`DISCOVERED`:** Initial identification via static inventory analysis (`worldmonitor_review.py`).
2. **`VALIDATED`:** Affected component, file path, and code line validated.
3. **`CONFIRMED`:** Vulnerability pattern confirmed against baseline code; CVSS vectors assigned.
4. **`REMEDIATED`:** Security patch implemented and verified via AST code inspection.
5. **`RETESTED`:** Passing automated Before/After Proof-of-Concept test harness (`backend/poc/`) with zero regressions.

---

## 5. Cryptographic Evidence Provenance

To eliminate simulated or fabricated evidence:
- **No Typed-In Evidence:** All evidence raw data is produced exclusively by running code.
- **Dynamic SHA-256 Hashing:** Every evidence record generates a cryptographic hash at execution time:
  $$\text{SHA-256} = \text{hashlib.sha256(raw\_data.encode('utf-8')).hexdigest()}$$
- **Execution Metadata:** Records exact UTC collection timestamp (`collected_at`) and execution environment context (`local-assessment`, `static-ast`, `poc-testclient`).
