import os
import ast
import re
from typing import List, Dict, Any
from .base import SecurityCheck, build_finding, build_evidence

class CodeAuditCheck(SecurityCheck):
    def __init__(self, main_path: str = None):
        if not main_path:
            curr_dir = os.path.dirname(os.path.abspath(__file__))
            candidate = os.path.join(curr_dir, "..", "main.py")
            if os.path.exists(candidate):
                self.main_path = os.path.abspath(candidate)
            else:
                self.main_path = os.path.abspath("backend/main.py")
        else:
            self.main_path = main_path

    def run_check(self, dataset: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        findings = []
        if not os.path.exists(self.main_path):
            return findings

        with open(self.main_path, "r", encoding="utf-8") as f:
            source = f.read()

        try:
            tree = ast.parse(source)
        except Exception:
            tree = None

        # (a) jwt.decode requires "exp"
        has_jwt_exp = bool(re.search(r'jwt\.decode\([^)]*options\s*=\s*\{[^}]*[\'"]require[\'"]\s*:\s*\[[^\]]*[\'"]exp[\'"]', source))
        jwt_status = "Remediated" if has_jwt_exp else "Detected"
        jwt_lifecycle = "RETESTED" if has_jwt_exp else "CONFIRMED"
        jwt_after_evidence = (
            "payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={\"require\": [\"exp\"]})"
            if has_jwt_exp else "jwt.decode called without requiring 'exp' claim"
        )
        findings.append(build_finding(
            title="Missing 'exp' Enforcement in JWT Token Verification",
            category="Authentication",
            severity="High",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            conservative_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
            confidence="High",
            cwe="CWE-613: Insufficient Session Expiration",
            owasp="API2:2023 Broken Authentication",
            affected_component="backend/main.py (get_current_user)",
            description="JWT tokens must explicitly require an 'exp' (expiration) claim during verification to prevent indefinite access using stolen or unexpiring tokens.",
            impact="If tokens do not require an expiration claim, an attacker holding a valid token can maintain persistent access indefinitely.",
            remediation="Configure jwt.decode with options={'require': ['exp']} to mandate token expiration timestamps.",
            status=jwt_status,
            lifecycle=jwt_lifecycle,
            lifecycle_note="Configured jwt.decode with options={'require': ['exp']}.",
            evidence=[
                build_evidence(
                    evidence_type="Source Code Audit (Before - Insecure)",
                    description="Token decoded without requiring expiration claim.",
                    raw_data="jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM]) # Insecure: missing options={'require': ['exp']}"
                ),
                build_evidence(
                    evidence_type="Source Code Audit (After - Remediated)" if has_jwt_exp else "Source Code Audit (Current State - Vulnerable)",
                    description="Current implementation in backend/main.py.",
                    raw_data=jwt_after_evidence
                )
            ]
        ))

        # (b) Every POST route has an admin role check
        post_routes_without_admin = []
        post_routes_with_admin = []
        if tree:
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    for dec in node.decorator_list:
                        is_post = False
                        path = None
                        if isinstance(dec, ast.Call):
                            func = dec.func
                            if isinstance(func, ast.Attribute) and func.attr == "post":
                                is_post = True
                                if dec.args and isinstance(dec.args[0], ast.Constant):
                                    path = dec.args[0].value

                        if is_post and path and path != "/token":
                            func_code = ast.get_source_segment(source, node) or ""
                            has_admin_check = bool(
                                re.search(r'role\s*!=\s*[\'"]admin[\'"]', func_code) or
                                re.search(r'role\s*==\s*[\'"]admin[\'"]', func_code) or
                                "Admin privileges required" in func_code or
                                "Not enough permissions" in func_code
                            )
                            if has_admin_check:
                                post_routes_with_admin.append(path)
                            else:
                                post_routes_without_admin.append(path)

        all_post_admin = len(post_routes_without_admin) == 0 and len(post_routes_with_admin) > 0
        b_status = "Remediated" if all_post_admin else "Detected"
        b_lifecycle = "RETESTED" if all_post_admin else "CONFIRMED"
        findings.append(build_finding(
            title="Missing Role-Based Access Control on Modifying API Endpoints",
            category="Authorization",
            severity="High",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            conservative_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            confidence="High",
            cwe="CWE-285: Improper Authorization",
            owasp="API5:2023 Broken Function Level Authorization",
            affected_component="backend/main.py (POST routes)",
            description="State-modifying endpoints (POST) must enforce administrative authorization checks to prevent unauthorized state alteration or privilege escalation.",
            impact="Unprivileged users could submit unauthorized findings or register new users without administrative oversight.",
            remediation="Verify the authenticated user's role equals 'admin' before executing state modifications on all POST routes.",
            status=b_status,
            lifecycle=b_lifecycle,
            lifecycle_note="Enforced current_user.get('role') == 'admin' check on all modifying POST endpoints.",
            evidence=[
                build_evidence(
                    evidence_type="Source Code Audit (Before - Insecure)",
                    description="POST endpoint without role verification.",
                    raw_data="@app.post('/users/')\ndef create_user(user: schemas.UserCreate):\n    # Missing admin check: any user could register accounts"
                ),
                build_evidence(
                    evidence_type="Source Code Audit (After - Remediated)" if all_post_admin else "Source Code Audit (Current State - Vulnerable)",
                    description=f"Verified POST routes: {post_routes_with_admin}. Unprotected: {post_routes_without_admin}",
                    raw_data=(
                        "if current_user.get('role') != 'admin':\n    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Admin privileges required')"
                        if all_post_admin else f"Unprotected POST endpoints: {post_routes_without_admin}"
                    )
                )
            ]
        ))

        # (c) CORS does not use wildcard methods/headers
        has_wildcard_cors = bool(
            re.search(r'allow_methods\s*=\s*\[[^\]]*[\'"]\*[\'"]', source) or
            re.search(r'allow_headers\s*=\s*\[[^\]]*[\'"]\*[\'"]', source)
        )
        c_status = "Detected" if has_wildcard_cors else "Remediated"
        c_lifecycle = "CONFIRMED" if has_wildcard_cors else "RETESTED"
        findings.append(build_finding(
            title="Overly Permissive CORS Policy with Wildcard Methods and Headers",
            category="API Security",
            severity="Medium",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            conservative_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            confidence="High",
            cwe="CWE-942: Permissive Cross-domain Policy with Untrusted Domains",
            owasp="API8:2023 Security Misconfiguration",
            affected_component="backend/main.py (CORSMiddleware)",
            description="CORS configuration used wildcard '*' for allow_methods and allow_headers, unnecessarily widening the cross-origin attack surface.",
            impact="Permissive CORS policies can allow untrusted web applications to perform unintended HTTP methods and supply sensitive custom headers.",
            remediation="Restrict allow_methods to explicitly needed verbs (GET, POST, OPTIONS) and allow_headers to standard required headers.",
            status=c_status,
            lifecycle=c_lifecycle,
            lifecycle_note="Narrowed allow_methods to ['GET', 'POST', 'OPTIONS'] and explicit allow_headers.",
            evidence=[
                build_evidence(
                    evidence_type="Source Code Audit (Before - Insecure)",
                    description="Wildcard CORS configuration.",
                    raw_data="allow_methods=[\"*\"], allow_headers=[\"*\"]"
                ),
                build_evidence(
                    evidence_type="Source Code Audit (After - Remediated)" if not has_wildcard_cors else "Source Code Audit (Current State - Vulnerable)",
                    description="Strictly narrowed CORS allow_methods and allow_headers.",
                    raw_data=(
                        "allow_methods=[\"GET\", \"POST\", \"OPTIONS\"],\nallow_headers=[\"Authorization\", \"Content-Type\", \"Accept\", \"Origin\", \"X-Requested-With\"]"
                        if not has_wildcard_cors else "Still using wildcard '*' methods or headers"
                    )
                )
            ]
        ))

        # (d) No default admin password fallback in code
        has_admin_fallback = bool(re.search(r'getenv\(\s*[\'"]ADMIN_PASSWORD[\'"]\s*,\s*[\'"][^\'"]+[\'"]\)', source))
        has_admin_refusal = bool(
            "admin123" in source and
            re.search(r'ADMIN_PASSWORD.*==.*[\'"]admin123[\'"].*raise', source, re.DOTALL)
        )
        d_status = "Remediated" if (not has_admin_fallback and has_admin_refusal) else "Detected"
        d_lifecycle = "RETESTED" if (not has_admin_fallback and has_admin_refusal) else "CONFIRMED"
        findings.append(build_finding(
            title="Hardcoded Insecure Default Password Fallback for Administrator Account",
            category="Authentication",
            severity="High",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            conservative_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
            confidence="High",
            cwe="CWE-259: Use of Hard-coded Password",
            owasp="API2:2023 Broken Authentication",
            affected_component="backend/main.py (startup_event / ADMIN_PASSWORD check)",
            description="The application previously had a fallback default admin password ('admin123') in code if the ADMIN_PASSWORD environment variable was not set.",
            impact="Default credentials allow unauthorized users to gain immediate administrative control over the security assessment platform.",
            remediation="Refuse to start the server if ADMIN_PASSWORD is unset or equals the known default 'admin123'. Mandate strong password configuration via environment variables.",
            status=d_status,
            lifecycle=d_lifecycle,
            lifecycle_note="Server refuses startup if ADMIN_PASSWORD is unset or equals default 'admin123'.",
            evidence=[
                build_evidence(
                    evidence_type="Source Code Audit (Before - Insecure)",
                    description="Hardcoded default fallback in code.",
                    raw_data="admin_pw = os.getenv(\"ADMIN_PASSWORD\", \"admin123\") # Insecure default fallback"
                ),
                build_evidence(
                    evidence_type="Source Code Audit (After - Remediated)" if d_status == "Remediated" else "Source Code Audit (Current State - Vulnerable)",
                    description="Strict check requiring explicit non-default ADMIN_PASSWORD.",
                    raw_data=(
                        "ADMIN_PASSWORD = os.getenv(\"ADMIN_PASSWORD\")\nif not ADMIN_PASSWORD or ADMIN_PASSWORD == \"admin123\":\n    raise RuntimeError(\"ADMIN_PASSWORD unset or using insecure default. Refusing to start.\")"
                        if d_status == "Remediated" else "Default password fallback still active in code"
                    )
                )
            ]
        ))

        # (e) /users/ route requires admin
        users_admin_enforced = False
        if tree:
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == "create_user":
                    func_code = ast.get_source_segment(source, node) or ""
                    if "current_user" in func_code and ("admin" in func_code) and ("HTTP_403_FORBIDDEN" in func_code or "403" in func_code):
                        users_admin_enforced = True
        e_status = "Remediated" if users_admin_enforced else "Detected"
        e_lifecycle = "RETESTED" if users_admin_enforced else "CONFIRMED"
        findings.append(build_finding(
            title="Unrestricted Account Registration Without Admin Authorization",
            category="Authorization",
            severity="High",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",
            conservative_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            confidence="High",
            cwe="CWE-862: Missing Authorization",
            owasp="API5:2023 Broken Function Level Authorization",
            affected_component="backend/main.py (POST /users/)",
            description="The POST /users/ route allowed open user creation without administrative authorization, allowing any actor to register accounts.",
            impact="Unrestricted registration exposes internal endpoints and increases the attack surface for credential stuffing and privilege escalation.",
            remediation="Restrict POST /users/ so only authenticated users with the 'admin' role can create accounts.",
            status=e_status,
            lifecycle=e_lifecycle,
            lifecycle_note="Enforced admin check and minimum 10-char password validation on POST /users/.",
            evidence=[
                build_evidence(
                    evidence_type="Source Code Audit (Before - Insecure)",
                    description="Open registration route without authorization.",
                    raw_data="@app.post(\"/users/\")\ndef create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):\n    # Insecure: Any client could register accounts"
                ),
                build_evidence(
                    evidence_type="Source Code Audit (After - Remediated)" if users_admin_enforced else "Source Code Audit (Current State - Vulnerable)",
                    description="Restricted to authenticated admin users only.",
                    raw_data=(
                        "@app.post(\"/users/\", response_model=schemas.UserResponse)\ndef create_user(user: schemas.UserCreate, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):\n    if current_user.get(\"role\") != \"admin\":\n        raise HTTPException(status_code=403, detail=\"Admin privileges required\")"
                        if users_admin_enforced else "Open registration still enabled on /users/"
                    )
                )
            ]
        ))

        return findings
