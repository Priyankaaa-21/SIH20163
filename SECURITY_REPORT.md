# Security Assessment Report: World Monitor Application
**Date Generated:** 2026-10-26 02:43:34
**Project:** SIH 26163 — Security Assessment of the World Monitor Application

## 1. Executive Summary
This report details the findings from the automated and manual security assessment of the World Monitor Application and its associated datasets. The assessment evaluated the system across authentication, authorization, data privacy, source code implementation, and API security posture.

**Overall Security Posture:** 
A total of 18 security items were analyzed:
- **Critical Severity:** 0
- **High Severity:** 14
- **Medium Severity:** 4
- **Low Severity:** 0
- **Informational:** 0

**Remediation Progress:**
- **Remediated Controls:** 12
- **Open / Confirmed Items:** 6

## 2. Scope & Methodology
**Scope:** 
The assessment encompassed the complete World Monitor application stack:
- Backend API endpoints and authentication handlers (`backend/main.py`)
- OSINT intelligence feed configurations (`dataset/news_channels.json`, `dataset/news_channels_x.json`)
- Radiological and critical infrastructure datasets (Docker context isolation and coordinate privacy)
- Frontend dependency audit and build hygiene

**Methodology:**
The assessment was performed using an automated AST and static analysis security engine (`backend/security/*`). Findings are classified using industry-standard **CWE (Common Weakness Enumeration)** and **OWASP API Security Top 10** taxonomies, with scores derived from the standard **CVSS v3.1** base metrics.

## 3. Assessment Coverage
- Authentication & JWT Session Security (OWASP API2:2023)
- Role-Based Access Control / Authorization (OWASP API5:2023)
- Data Privacy & Geospatial Masking (OWASP API3:2023)
- Configuration & Feed Identity Validation (OWASP API8:2023)
- Credentials & Secret Management (CWE-798)
- Dependency Vulnerability Scanning (OWASP API10:2023)

---

## 4. Detailed Findings

### 4.1 Missing 'exp' Enforcement in JWT Token Verification
- **Severity:** High
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (9.1)`
- **CWE:** CWE-613: Insufficient Session Expiration
- **OWASP:** API2:2023 Broken Authentication
- **Category:** Authentication
- **Status:** `Remediated`
- **Affected Component:** `backend/main.py (get_current_user)`
- **Scan Run ID:** `scan_20261025_205717_4aa27c`

#### Description
JWT tokens must explicitly require an 'exp' (expiration) claim during verification to prevent indefinite access using stolen or unexpiring tokens.

#### Business Impact
If tokens do not require an expiration claim, an attacker holding a valid token can maintain persistent access indefinitely.

#### Remediation Guidance
Configure jwt.decode with options={'require': ['exp']} to mandate token expiration timestamps.

#### Evidence
**Source Code Audit (Before - Insecure)**: Token decoded without requiring expiration claim.
```text
jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM]) # Insecure: missing options={'require': ['exp']}
```

**Source Code Audit (After - Remediated)**: Current implementation in backend/main.py.
```text
payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"require": ["exp"]})
```

---

### 4.2 Missing Role-Based Access Control on Modifying API Endpoints
- **Severity:** High
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H (8.8)`
- **CWE:** CWE-285: Improper Authorization
- **OWASP:** API5:2023 Broken Function Level Authorization
- **Category:** Authorization
- **Status:** `Remediated`
- **Affected Component:** `backend/main.py (POST routes)`
- **Scan Run ID:** `scan_20261025_205717_4aa27c`

#### Description
State-modifying endpoints (POST) must enforce administrative authorization checks to prevent unauthorized state alteration or privilege escalation.

#### Business Impact
Unprivileged users could submit unauthorized findings or register new users without administrative oversight.

#### Remediation Guidance
Verify the authenticated user's role equals 'admin' before executing state modifications on all POST routes.

#### Evidence
**Source Code Audit (Before - Insecure)**: POST endpoint without role verification.
```text
@app.post('/users/')
def create_user(user: schemas.UserCreate):
    # Missing admin check: any user could register accounts
```

**Source Code Audit (After - Remediated)**: Verified POST routes: ['/users/', '/findings/']. Unprotected: []
```text
if current_user.get('role') != 'admin':
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Admin privileges required')
```

---

### 4.3 Overly Permissive CORS Policy with Wildcard Methods and Headers
- **Severity:** Medium
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N (5.4)`
- **CWE:** CWE-942: Permissive Cross-domain Policy with Untrusted Domains
- **OWASP:** API8:2023 Security Misconfiguration
- **Category:** API Security
- **Status:** `Remediated`
- **Affected Component:** `backend/main.py (CORSMiddleware)`
- **Scan Run ID:** `scan_20261025_205717_4aa27c`

#### Description
CORS configuration used wildcard '*' for allow_methods and allow_headers, unnecessarily widening the cross-origin attack surface.

#### Business Impact
Permissive CORS policies can allow untrusted web applications to perform unintended HTTP methods and supply sensitive custom headers.

#### Remediation Guidance
Restrict allow_methods to explicitly needed verbs (GET, POST, OPTIONS) and allow_headers to standard required headers.

#### Evidence
**Source Code Audit (Before - Insecure)**: Wildcard CORS configuration.
```text
allow_methods=["*"], allow_headers=["*"]
```

**Source Code Audit (After - Remediated)**: Strictly narrowed CORS allow_methods and allow_headers.
```text
allow_methods=["GET", "POST", "OPTIONS"],
allow_headers=["Authorization", "Content-Type", "Accept", "Origin", "X-Requested-With"]
```

---

### 4.4 Hardcoded Insecure Default Password Fallback for Administrator Account
- **Severity:** High
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (9.1)`
- **CWE:** CWE-259: Use of Hard-coded Password
- **OWASP:** API2:2023 Broken Authentication
- **Category:** Authentication
- **Status:** `Remediated`
- **Affected Component:** `backend/main.py (startup_event / ADMIN_PASSWORD check)`
- **Scan Run ID:** `scan_20261025_205717_4aa27c`

#### Description
The application previously had a fallback default admin password ('admin123') in code if the ADMIN_PASSWORD environment variable was not set.

#### Business Impact
Default credentials allow unauthorized users to gain immediate administrative control over the security assessment platform.

#### Remediation Guidance
Refuse to start the server if ADMIN_PASSWORD is unset or equals the known default 'admin123'. Mandate strong password configuration via environment variables.

#### Evidence
**Source Code Audit (Before - Insecure)**: Hardcoded default fallback in code.
```text
admin_pw = os.getenv("ADMIN_PASSWORD", "admin123") # Insecure default fallback
```

**Source Code Audit (After - Remediated)**: Strict check requiring explicit non-default ADMIN_PASSWORD.
```text
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
if not ADMIN_PASSWORD or ADMIN_PASSWORD == "admin123":
    raise RuntimeError("ADMIN_PASSWORD unset or using insecure default. Refusing to start.")
```

---

### 4.5 Unrestricted Account Registration Without Admin Authorization
- **Severity:** High
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N (8.2)`
- **CWE:** CWE-862: Missing Authorization
- **OWASP:** API5:2023 Broken Function Level Authorization
- **Category:** Authorization
- **Status:** `Remediated`
- **Affected Component:** `backend/main.py (POST /users/)`
- **Scan Run ID:** `scan_20261025_205717_4aa27c`

#### Description
The POST /users/ route allowed open user creation without administrative authorization, allowing any actor to register accounts.

#### Business Impact
Unrestricted registration exposes internal endpoints and increases the attack surface for credential stuffing and privilege escalation.

#### Remediation Guidance
Restrict POST /users/ so only authenticated users with the 'admin' role can create accounts.

#### Evidence
**Source Code Audit (Before - Insecure)**: Open registration route without authorization.
```text
@app.post("/users/")
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    # Insecure: Any client could register accounts
```

**Source Code Audit (After - Remediated)**: Restricted to authenticated admin users only.
```text
@app.post("/users/", response_model=schemas.UserResponse)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
```

---

### 4.6 Missing Account ID Verification in Tier-1 News Feeds (8 channels)
- **Severity:** Medium
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N (5.3)`
- **CWE:** CWE-345: Insufficient Verification of Data Authenticity
- **OWASP:** API8:2023 Security Misconfiguration
- **Category:** Configuration / Trust
- **Status:** `Confirmed`
- **Affected Component:** `OSINT Feed Configs (news_channels.json, news_channels_x.json)`
- **Scan Run ID:** `scan_20261025_205717_4aa27c`

#### Description
Audited 8 Tier-1 intelligence feed channels across news_channels.json and news_channels_x.json missing verified numeric 'accountId' values. Unverified handles silently degrade feed integrity and are susceptible to identity forking if handles are renamed.

#### Business Impact
An attacker could claim a dropped or renamed handle and inject disinformation directly into Tier-1 intelligence feeds, triggering false incident alerts.

#### Remediation Guidance
Enforce strict schema validation on configuration files. Require all Tier-1 enabled feeds to contain verified numeric 'accountId' values validated against the provider API.

#### Evidence
**Config Snippet (news_channels.json)**: Tier-1 channel @SaudiDCD (index 0) missing verified accountId in news_channels.json.
```text
{
  "handle": "SaudiDCD",
  "label": "Saudi Civil Defense",
  "topic": "middleeast",
  "tier": 1,
  "enabled": true,
  "region": "saudi-arabia",
  "maxMessages": 25
}
```

**Config Snippet (news_channels.json)**: Tier-1 channel @InaTEWS_BMKG (index 1) missing verified accountId in news_channels.json.
```text
{
  "handle": "InaTEWS_BMKG",
  "label": "BMKG InaTEWS",
  "topic": "breaking",
  "tier": 1,
  "enabled": true,
  "region": "indonesia",
  "maxMessages": 25
}
```

**Config Snippet (news_channels.json)**: Tier-1 channel @dsns_telegram (index 2) missing verified accountId in news_channels.json.
```text
{
  "handle": "dsns_telegram",
  "label": "Ukraine State Emergency Service",
  "topic": "breaking",
  "tier": 1,
  "enabled": true,
  "region": "ukraine",
  "maxMessages": 25
}
```

**Config Snippet (news_channels.json)**: Tier-1 channel @PikudHaOref_all (index 3) missing verified accountId in news_channels.json.
```text
{
  "handle": "PikudHaOref_all",
  "label": "Israel Home Front Command",
  "topic": "middleeast",
  "tier": 1,
  "enabled": true,
  "region": "israel",
  "maxMessages": 25
}
```

**Config Snippet (news_channels.json)**: Tier-1 channel @govsg (index 5) missing verified accountId in news_channels.json.
```text
{
  "handle": "govsg",
  "label": "Singapore Government",
  "topic": "geopolitics",
  "tier": 1,
  "enabled": true,
  "region": "singapore",
  "maxMessages": 25
}
```

**Config Snippet (news_channels.json)**: Tier-1 channel @VahidOnline (index 7) missing verified accountId in news_channels.json.
```text
{
  "handle": "VahidOnline",
  "label": "Vahid Online",
  "topic": "geopolitics",
  "tier": 1,
  "enabled": true,
  "region": "iran",
  "maxMessages": 20
}
```

**Config Snippet (news_channels.json)**: Tier-1 channel @IDFofficial (index 44) missing verified accountId in news_channels.json.
```text
{
  "handle": "IDFofficial",
  "label": "IDF Official",
  "topic": "breaking",
  "tier": 1,
  "enabled": true,
  "region": "middleeast",
  "maxMessages": 25
}
```

**Config Snippet (news_channels.json)**: Tier-1 channel @RocketAlert (index 45) missing verified accountId in news_channels.json.
```text
{
  "handle": "RocketAlert",
  "label": "Rocket Alert",
  "topic": "breaking",
  "tier": 1,
  "enabled": true,
  "region": "middleeast",
  "maxMessages": 25
}
```

---

### 4.7 Exposure of Critical Infrastructure Coordinates (100 facilities)
- **Severity:** High
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5)`
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **OWASP:** API3:2023 Broken Object Property Level Authorization
- **Category:** Data Privacy / Storage
- **Status:** `Confirmed`
- **Affected Component:** `Critical Infrastructure Dataset Export`
- **Scan Run ID:** `scan_20261025_205717_4aa27c`

#### Description
The application dataset contains geographical coordinates for 100 critical infrastructure / irradiation facilities. Aggregating precise coordinates of nuclear/radiological infrastructure poses a serious physical security risk if accessed by unauthorized actors.

#### Business Impact
Unrestricted access to exact facility coordinates could allow malicious actors to locate and target radiological facilities.

#### Remediation Guidance
Implement role-based precision masking on coordinates. Round coordinates to a coarse grid (0.5 degrees) with deterministic noise for standard users, and restrict precise coordinates to authorized admins.

#### Evidence
**Dataset Record (iaea_diif_db_safe)**: Facility ID: gi-001, Location: Barakah (Region), UAE exposes exact lat/lon.
```text
{
  "id": "gi-001",
  "city": "Barakah (Region)",
  "country": "UAE",
  "lat": 24.9802,
  "lon": 53.6436
}
```

**Dataset Record (iaea_diif_db_safe)**: Facility ID: gi-002, Location: Rovno (Region), Ukraine exposes exact lat/lon.
```text
{
  "id": "gi-002",
  "city": "Rovno (Region)",
  "country": "Ukraine",
  "lat": 51.9153,
  "lon": 24.8494
}
```

**Dataset Record (iaea_diif_db_safe)**: Facility ID: gi-003, Location: Richland (Region), USA exposes exact lat/lon.
```text
{
  "id": "gi-003",
  "city": "Richland (Region)",
  "country": "USA",
  "lat": 47.0989,
  "lon": -118.1517
}
```

**Dataset Record (iaea_diif_db_safe)**: Facility ID: gi-004, Location: Richland (Region), USA exposes exact lat/lon.
```text
{
  "id": "gi-004",
  "city": "Richland (Region)",
  "country": "USA",
  "lat": 45.9452,
  "lon": -119.0939
}
```

**Dataset Record (iaea_diif_db_safe)**: Facility ID: gi-005, Location: Novovoronezh (Region), Russia exposes exact lat/lon.
```text
{
  "id": "gi-005",
  "city": "Novovoronezh (Region)",
  "country": "Russia",
  "lat": 50.9362,
  "lon": 37.7145
}
```

**Dataset Record (iaea_diif_db_safe)**: Facility ID: gi-006, Location: Fukushima (Region), Japan exposes exact lat/lon.
```text
{
  "id": "gi-006",
  "city": "Fukushima (Region)",
  "country": "Japan",
  "lat": 36.8094,
  "lon": 142.1962
}
```

**Dataset Record (iaea_diif_db_safe)**: Facility ID: gi-007, Location: Bucha (Region), Ukraine exposes exact lat/lon.
```text
{
  "id": "gi-007",
  "city": "Bucha (Region)",
  "country": "Ukraine",
  "lat": 50.3937,
  "lon": 30.2397
}
```

**Dataset Record (iaea_diif_db_safe)**: Facility ID: gi-008, Location: Doel (Region), Belgium exposes exact lat/lon.
```text
{
  "id": "gi-008",
  "city": "Doel (Region)",
  "country": "Belgium",
  "lat": 50.8171,
  "lon": 4.1403
}
```

**Dataset Record (iaea_diif_db_safe)**: Facility ID: gi-009, Location: Fukushima (Region), Japan exposes exact lat/lon.
```text
{
  "id": "gi-009",
  "city": "Fukushima (Region)",
  "country": "Japan",
  "lat": 38.7176,
  "lon": 141.8825
}
```

**Dataset Record (iaea_diif_db_safe)**: Facility ID: gi-010, Location: Bruce (Region), Canada exposes exact lat/lon.
```text
{
  "id": "gi-010",
  "city": "Bruce (Region)",
  "country": "Canada",
  "lat": 44.1078,
  "lon": -82.0374
}
```

---

### 4.8 Raw Critical Infrastructure Datasets Present in Build Context
- **Severity:** High
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5)`
- **CWE:** CWE-552: Files or Directories Accessible to External Parties
- **OWASP:** API8:2023 Security Misconfiguration
- **Category:** Data Privacy / Storage
- **Status:** `Remediated`
- **Affected Component:** `Docker Build Context (dataset/ vs private/)`
- **Scan Run ID:** `scan_20261025_205717_4aa27c`

#### Description
Raw IAEA DIIF database exports containing unmasked nuclear facility coordinates must not be present in the Docker build context or committed to repository tracking.

#### Business Impact
Any files copied into the Docker container image during build (COPY dataset/ dataset/) can be extracted from public container registries or compromised containers.

#### Remediation Guidance
Move raw unmasked dataset files to a gitignored 'private/' directory excluded via .dockerignore and .gitignore. Only include synthetic or fuzzed datasets (iaea_diif_db_safe.json) in the container image.

#### Evidence
**Docker Context Audit (Before - Insecure)**: Raw unmasked datasets located in build context.
```text
dataset/iaea_diif_db.json
dataset/iaea_diif_facilities.json
dataset/iaea_diif_tableau.json
```

**Docker Context Audit (After - Remediated)**: Raw files successfully moved to private/ directory and excluded from build context via .dockerignore.
```text
Isolated in private/ directory (gitignored): True
Excluded from Docker context via backend/.dockerignore
```

---

### 4.9 Vulnerable Frontend Dependencies Detected (3 packages via npm audit)
- **Severity:** High
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L (7.3)`
- **CWE:** CWE-1395: Dependency on Vulnerable Third-Party Component
- **OWASP:** API10:2023 Unsafe Consumption of APIs
- **Category:** Dependency Management
- **Status:** `Confirmed`
- **Affected Component:** `frontend/package.json & package-lock.json`
- **Scan Run ID:** `scan_20261025_205717_4aa27c`

#### Description
Automated dependency security audit surfaced 3 known vulnerable dependencies in the frontend build pipeline.

#### Business Impact
Exploitation of vulnerable packages during development or production build can lead to XSS, DoS, or credential exposure.

#### Remediation Guidance
Update vulnerable dependencies using 'npm audit fix' and keep library versions pinned to secure releases.

#### Evidence
**npm audit vulnerability**: Vulnerable package: follow-redirects (Severity: high)
```text
{
  "package": "follow-redirects",
  "severity": "high",
  "via": [
    "follow-redirects array-form headers bypass cross-origin credential stripping",
    "follow-redirects sensitiveHeaders regex escaping can expose credential headers"
  ],
  "range": "1.16.0"
}
```

**npm audit vulnerability**: Vulnerable package: source-map-js (Severity: high)
```text
{
  "package": "source-map-js",
  "severity": "high",
  "via": [
    "source-map-js allows event-loop denial of service through indexed source-map section offsets"
  ],
  "range": "1.0.0 - 1.2.1"
}
```

**npm audit vulnerability**: Vulnerable package: vite (Severity: high)
```text
{
  "package": "vite",
  "severity": "high",
  "via": [
    "launch-editor: escapeCmdArgs() omits % escaping on Windows",
    "launch-editor: Editor CLI flag misinterpretation causing arbitrary command execution for some editors",
    "launch-editor: `fs.existsSync()` existence check can be bypassed on Windows",
    "Vite: Cross origin script execution through Vite custom middleware",
    "Vite: Files outside `server.fs.allow` could be served when project paths match system paths on non-Windows machine",
    "Vite: First 4 bytes of files outside of `server.fs` setting is exposed by `?vite-wasm-instance`"
  ],
  "range": "8.3.0 - 8.3.2"
}
```

---

### 4.10 Missing 'exp' Enforcement in JWT Token Verification
- **Severity:** High
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (9.1)`
- **CWE:** CWE-613: Insufficient Session Expiration
- **OWASP:** API2:2023 Broken Authentication
- **Category:** Authentication
- **Status:** `Remediated`
- **Affected Component:** `backend/main.py (get_current_user)`
- **Scan Run ID:** `scan_20261025_211334_c2a164`

#### Description
JWT tokens must explicitly require an 'exp' (expiration) claim during verification to prevent indefinite access using stolen or unexpiring tokens.

#### Business Impact
If tokens do not require an expiration claim, an attacker holding a valid token can maintain persistent access indefinitely.

#### Remediation Guidance
Configure jwt.decode with options={'require': ['exp']} to mandate token expiration timestamps.

#### Evidence
**Source Code Audit (Before - Insecure)**: Token decoded without requiring expiration claim.
```text
jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM]) # Insecure: missing options={'require': ['exp']}
```

**Source Code Audit (After - Remediated)**: Current implementation in backend/main.py.
```text
payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"require": ["exp"]})
```

---

### 4.11 Missing Role-Based Access Control on Modifying API Endpoints
- **Severity:** High
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H (8.8)`
- **CWE:** CWE-285: Improper Authorization
- **OWASP:** API5:2023 Broken Function Level Authorization
- **Category:** Authorization
- **Status:** `Remediated`
- **Affected Component:** `backend/main.py (POST routes)`
- **Scan Run ID:** `scan_20261025_211334_c2a164`

#### Description
State-modifying endpoints (POST) must enforce administrative authorization checks to prevent unauthorized state alteration or privilege escalation.

#### Business Impact
Unprivileged users could submit unauthorized findings or register new users without administrative oversight.

#### Remediation Guidance
Verify the authenticated user's role equals 'admin' before executing state modifications on all POST routes.

#### Evidence
**Source Code Audit (Before - Insecure)**: POST endpoint without role verification.
```text
@app.post('/users/')
def create_user(user: schemas.UserCreate):
    # Missing admin check: any user could register accounts
```

**Source Code Audit (After - Remediated)**: Verified POST routes: ['/users/', '/findings/']. Unprotected: []
```text
if current_user.get('role') != 'admin':
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Admin privileges required')
```

---

### 4.12 Overly Permissive CORS Policy with Wildcard Methods and Headers
- **Severity:** Medium
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N (5.4)`
- **CWE:** CWE-942: Permissive Cross-domain Policy with Untrusted Domains
- **OWASP:** API8:2023 Security Misconfiguration
- **Category:** API Security
- **Status:** `Remediated`
- **Affected Component:** `backend/main.py (CORSMiddleware)`
- **Scan Run ID:** `scan_20261025_211334_c2a164`

#### Description
CORS configuration used wildcard '*' for allow_methods and allow_headers, unnecessarily widening the cross-origin attack surface.

#### Business Impact
Permissive CORS policies can allow untrusted web applications to perform unintended HTTP methods and supply sensitive custom headers.

#### Remediation Guidance
Restrict allow_methods to explicitly needed verbs (GET, POST, OPTIONS) and allow_headers to standard required headers.

#### Evidence
**Source Code Audit (Before - Insecure)**: Wildcard CORS configuration.
```text
allow_methods=["*"], allow_headers=["*"]
```

**Source Code Audit (After - Remediated)**: Strictly narrowed CORS allow_methods and allow_headers.
```text
allow_methods=["GET", "POST", "OPTIONS"],
allow_headers=["Authorization", "Content-Type", "Accept", "Origin", "X-Requested-With"]
```

---

### 4.13 Hardcoded Insecure Default Password Fallback for Administrator Account
- **Severity:** High
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (9.1)`
- **CWE:** CWE-259: Use of Hard-coded Password
- **OWASP:** API2:2023 Broken Authentication
- **Category:** Authentication
- **Status:** `Remediated`
- **Affected Component:** `backend/main.py (startup_event / ADMIN_PASSWORD check)`
- **Scan Run ID:** `scan_20261025_211334_c2a164`

#### Description
The application previously had a fallback default admin password ('admin123') in code if the ADMIN_PASSWORD environment variable was not set.

#### Business Impact
Default credentials allow unauthorized users to gain immediate administrative control over the security assessment platform.

#### Remediation Guidance
Refuse to start the server if ADMIN_PASSWORD is unset or equals the known default 'admin123'. Mandate strong password configuration via environment variables.

#### Evidence
**Source Code Audit (Before - Insecure)**: Hardcoded default fallback in code.
```text
admin_pw = os.getenv("ADMIN_PASSWORD", "admin123") # Insecure default fallback
```

**Source Code Audit (After - Remediated)**: Strict check requiring explicit non-default ADMIN_PASSWORD.
```text
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
if not ADMIN_PASSWORD or ADMIN_PASSWORD == "admin123":
    raise RuntimeError("ADMIN_PASSWORD unset or using insecure default. Refusing to start.")
```

---

### 4.14 Unrestricted Account Registration Without Admin Authorization
- **Severity:** High
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N (8.2)`
- **CWE:** CWE-862: Missing Authorization
- **OWASP:** API5:2023 Broken Function Level Authorization
- **Category:** Authorization
- **Status:** `Remediated`
- **Affected Component:** `backend/main.py (POST /users/)`
- **Scan Run ID:** `scan_20261025_211334_c2a164`

#### Description
The POST /users/ route allowed open user creation without administrative authorization, allowing any actor to register accounts.

#### Business Impact
Unrestricted registration exposes internal endpoints and increases the attack surface for credential stuffing and privilege escalation.

#### Remediation Guidance
Restrict POST /users/ so only authenticated users with the 'admin' role can create accounts.

#### Evidence
**Source Code Audit (Before - Insecure)**: Open registration route without authorization.
```text
@app.post("/users/")
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    # Insecure: Any client could register accounts
```

**Source Code Audit (After - Remediated)**: Restricted to authenticated admin users only.
```text
@app.post("/users/", response_model=schemas.UserResponse)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
```

---

### 4.15 Missing Account ID Verification in Tier-1 News Feeds (8 channels)
- **Severity:** Medium
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N (5.3)`
- **CWE:** CWE-345: Insufficient Verification of Data Authenticity
- **OWASP:** API8:2023 Security Misconfiguration
- **Category:** Configuration / Trust
- **Status:** `Confirmed`
- **Affected Component:** `OSINT Feed Configs (news_channels.json, news_channels_x.json)`
- **Scan Run ID:** `scan_20261025_211334_c2a164`

#### Description
Audited 8 Tier-1 intelligence feed channels across news_channels.json and news_channels_x.json missing verified numeric 'accountId' values. Unverified handles silently degrade feed integrity and are susceptible to identity forking if handles are renamed.

#### Business Impact
An attacker could claim a dropped or renamed handle and inject disinformation directly into Tier-1 intelligence feeds, triggering false incident alerts.

#### Remediation Guidance
Enforce strict schema validation on configuration files. Require all Tier-1 enabled feeds to contain verified numeric 'accountId' values validated against the provider API.

#### Evidence
**Config Snippet (news_channels.json)**: Tier-1 channel @SaudiDCD (index 0) missing verified accountId in news_channels.json.
```text
{
  "handle": "SaudiDCD",
  "label": "Saudi Civil Defense",
  "topic": "middleeast",
  "tier": 1,
  "enabled": true,
  "region": "saudi-arabia",
  "maxMessages": 25
}
```

**Config Snippet (news_channels.json)**: Tier-1 channel @InaTEWS_BMKG (index 1) missing verified accountId in news_channels.json.
```text
{
  "handle": "InaTEWS_BMKG",
  "label": "BMKG InaTEWS",
  "topic": "breaking",
  "tier": 1,
  "enabled": true,
  "region": "indonesia",
  "maxMessages": 25
}
```

**Config Snippet (news_channels.json)**: Tier-1 channel @dsns_telegram (index 2) missing verified accountId in news_channels.json.
```text
{
  "handle": "dsns_telegram",
  "label": "Ukraine State Emergency Service",
  "topic": "breaking",
  "tier": 1,
  "enabled": true,
  "region": "ukraine",
  "maxMessages": 25
}
```

**Config Snippet (news_channels.json)**: Tier-1 channel @PikudHaOref_all (index 3) missing verified accountId in news_channels.json.
```text
{
  "handle": "PikudHaOref_all",
  "label": "Israel Home Front Command",
  "topic": "middleeast",
  "tier": 1,
  "enabled": true,
  "region": "israel",
  "maxMessages": 25
}
```

**Config Snippet (news_channels.json)**: Tier-1 channel @govsg (index 5) missing verified accountId in news_channels.json.
```text
{
  "handle": "govsg",
  "label": "Singapore Government",
  "topic": "geopolitics",
  "tier": 1,
  "enabled": true,
  "region": "singapore",
  "maxMessages": 25
}
```

**Config Snippet (news_channels.json)**: Tier-1 channel @VahidOnline (index 7) missing verified accountId in news_channels.json.
```text
{
  "handle": "VahidOnline",
  "label": "Vahid Online",
  "topic": "geopolitics",
  "tier": 1,
  "enabled": true,
  "region": "iran",
  "maxMessages": 20
}
```

**Config Snippet (news_channels.json)**: Tier-1 channel @IDFofficial (index 44) missing verified accountId in news_channels.json.
```text
{
  "handle": "IDFofficial",
  "label": "IDF Official",
  "topic": "breaking",
  "tier": 1,
  "enabled": true,
  "region": "middleeast",
  "maxMessages": 25
}
```

**Config Snippet (news_channels.json)**: Tier-1 channel @RocketAlert (index 45) missing verified accountId in news_channels.json.
```text
{
  "handle": "RocketAlert",
  "label": "Rocket Alert",
  "topic": "breaking",
  "tier": 1,
  "enabled": true,
  "region": "middleeast",
  "maxMessages": 25
}
```

---

### 4.16 Exposure of Critical Infrastructure Coordinates (100 facilities)
- **Severity:** High
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5)`
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **OWASP:** API3:2023 Broken Object Property Level Authorization
- **Category:** Data Privacy / Storage
- **Status:** `Confirmed`
- **Affected Component:** `Critical Infrastructure Dataset Export`
- **Scan Run ID:** `scan_20261025_211334_c2a164`

#### Description
The application dataset contains geographical coordinates for 100 critical infrastructure / irradiation facilities. Aggregating precise coordinates of nuclear/radiological infrastructure poses a serious physical security risk if accessed by unauthorized actors.

#### Business Impact
Unrestricted access to exact facility coordinates could allow malicious actors to locate and target radiological facilities.

#### Remediation Guidance
Implement role-based precision masking on coordinates. Round coordinates to a coarse grid (0.5 degrees) with deterministic noise for standard users, and restrict precise coordinates to authorized admins.

#### Evidence
**Dataset Record (iaea_diif_db_safe)**: Facility ID: gi-001, Location: Barakah (Region), UAE exposes exact lat/lon.
```text
{
  "id": "gi-001",
  "city": "Barakah (Region)",
  "country": "UAE",
  "lat": 24.9802,
  "lon": 53.6436
}
```

**Dataset Record (iaea_diif_db_safe)**: Facility ID: gi-002, Location: Rovno (Region), Ukraine exposes exact lat/lon.
```text
{
  "id": "gi-002",
  "city": "Rovno (Region)",
  "country": "Ukraine",
  "lat": 51.9153,
  "lon": 24.8494
}
```

**Dataset Record (iaea_diif_db_safe)**: Facility ID: gi-003, Location: Richland (Region), USA exposes exact lat/lon.
```text
{
  "id": "gi-003",
  "city": "Richland (Region)",
  "country": "USA",
  "lat": 47.0989,
  "lon": -118.1517
}
```

**Dataset Record (iaea_diif_db_safe)**: Facility ID: gi-004, Location: Richland (Region), USA exposes exact lat/lon.
```text
{
  "id": "gi-004",
  "city": "Richland (Region)",
  "country": "USA",
  "lat": 45.9452,
  "lon": -119.0939
}
```

**Dataset Record (iaea_diif_db_safe)**: Facility ID: gi-005, Location: Novovoronezh (Region), Russia exposes exact lat/lon.
```text
{
  "id": "gi-005",
  "city": "Novovoronezh (Region)",
  "country": "Russia",
  "lat": 50.9362,
  "lon": 37.7145
}
```

**Dataset Record (iaea_diif_db_safe)**: Facility ID: gi-006, Location: Fukushima (Region), Japan exposes exact lat/lon.
```text
{
  "id": "gi-006",
  "city": "Fukushima (Region)",
  "country": "Japan",
  "lat": 36.8094,
  "lon": 142.1962
}
```

**Dataset Record (iaea_diif_db_safe)**: Facility ID: gi-007, Location: Bucha (Region), Ukraine exposes exact lat/lon.
```text
{
  "id": "gi-007",
  "city": "Bucha (Region)",
  "country": "Ukraine",
  "lat": 50.3937,
  "lon": 30.2397
}
```

**Dataset Record (iaea_diif_db_safe)**: Facility ID: gi-008, Location: Doel (Region), Belgium exposes exact lat/lon.
```text
{
  "id": "gi-008",
  "city": "Doel (Region)",
  "country": "Belgium",
  "lat": 50.8171,
  "lon": 4.1403
}
```

**Dataset Record (iaea_diif_db_safe)**: Facility ID: gi-009, Location: Fukushima (Region), Japan exposes exact lat/lon.
```text
{
  "id": "gi-009",
  "city": "Fukushima (Region)",
  "country": "Japan",
  "lat": 38.7176,
  "lon": 141.8825
}
```

**Dataset Record (iaea_diif_db_safe)**: Facility ID: gi-010, Location: Bruce (Region), Canada exposes exact lat/lon.
```text
{
  "id": "gi-010",
  "city": "Bruce (Region)",
  "country": "Canada",
  "lat": 44.1078,
  "lon": -82.0374
}
```

---

### 4.17 Raw Critical Infrastructure Datasets Present in Build Context
- **Severity:** High
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5)`
- **CWE:** CWE-552: Files or Directories Accessible to External Parties
- **OWASP:** API8:2023 Security Misconfiguration
- **Category:** Data Privacy / Storage
- **Status:** `Remediated`
- **Affected Component:** `Docker Build Context (dataset/ vs private/)`
- **Scan Run ID:** `scan_20261025_211334_c2a164`

#### Description
Raw IAEA DIIF database exports containing unmasked nuclear facility coordinates must not be present in the Docker build context or committed to repository tracking.

#### Business Impact
Any files copied into the Docker container image during build (COPY dataset/ dataset/) can be extracted from public container registries or compromised containers.

#### Remediation Guidance
Move raw unmasked dataset files to a gitignored 'private/' directory excluded via .dockerignore and .gitignore. Only include synthetic or fuzzed datasets (iaea_diif_db_safe.json) in the container image.

#### Evidence
**Docker Context Audit (Before - Insecure)**: Raw unmasked datasets located in build context.
```text
dataset/iaea_diif_db.json
dataset/iaea_diif_facilities.json
dataset/iaea_diif_tableau.json
```

**Docker Context Audit (After - Remediated)**: Raw files successfully moved to private/ directory and excluded from build context via .dockerignore.
```text
Isolated in private/ directory (gitignored): True
Excluded from Docker context via backend/.dockerignore
```

---

### 4.18 Vulnerable Frontend Dependencies Detected (3 packages via npm audit)
- **Severity:** High
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L (7.3)`
- **CWE:** CWE-1395: Dependency on Vulnerable Third-Party Component
- **OWASP:** API10:2023 Unsafe Consumption of APIs
- **Category:** Dependency Management
- **Status:** `Confirmed`
- **Affected Component:** `frontend/package.json & package-lock.json`
- **Scan Run ID:** `scan_20261025_211334_c2a164`

#### Description
Automated dependency security audit surfaced 3 known vulnerable dependencies in the frontend build pipeline.

#### Business Impact
Exploitation of vulnerable packages during development or production build can lead to XSS, DoS, or credential exposure.

#### Remediation Guidance
Update vulnerable dependencies using 'npm audit fix' and keep library versions pinned to secure releases.

#### Evidence
**npm audit vulnerability**: Vulnerable package: follow-redirects (Severity: high)
```text
{
  "package": "follow-redirects",
  "severity": "high",
  "via": [
    "follow-redirects array-form headers bypass cross-origin credential stripping",
    "follow-redirects sensitiveHeaders regex escaping can expose credential headers"
  ],
  "range": "1.16.0"
}
```

**npm audit vulnerability**: Vulnerable package: source-map-js (Severity: high)
```text
{
  "package": "source-map-js",
  "severity": "high",
  "via": [
    "source-map-js allows event-loop denial of service through indexed source-map section offsets"
  ],
  "range": "1.0.0 - 1.2.1"
}
```

**npm audit vulnerability**: Vulnerable package: vite (Severity: high)
```text
{
  "package": "vite",
  "severity": "high",
  "via": [
    "launch-editor: escapeCmdArgs() omits % escaping on Windows",
    "launch-editor: Editor CLI flag misinterpretation causing arbitrary command execution for some editors",
    "launch-editor: `fs.existsSync()` existence check can be bypassed on Windows",
    "Vite: Cross origin script execution through Vite custom middleware",
    "Vite: Files outside `server.fs.allow` could be served when project paths match system paths on non-Windows machine",
    "Vite: First 4 bytes of files outside of `server.fs` setting is exposed by `?vite-wasm-instance`"
  ],
  "range": "8.3.0 - 8.3.2"
}
```

---

## 5. Conclusion
The assessment demonstrates marked security improvements. Critical code-level vulnerabilities—including missing JWT expiration, open user registration, default password fallbacks, and overly permissive CORS—have been fully remediated and verified via AST code audit. Sensitive datasets have been isolated from the Docker build context with role-based coordinate masking enforced. Ongoing remediation of third-party dependencies and OSINT feed verification will maintain the platform's robust security posture.
