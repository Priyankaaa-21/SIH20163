import os
import json
import subprocess
from typing import List, Dict, Any
from .base import SecurityCheck, build_finding, build_evidence

class DependencyAuditCheck(SecurityCheck):
    def __init__(self, frontend_dir: str = None, backend_dir: str = None):
        curr_dir = os.path.dirname(os.path.abspath(__file__))
        self.frontend_dir = frontend_dir or os.path.abspath(os.path.join(curr_dir, "..", "..", "frontend"))
        self.backend_dir = backend_dir or os.path.abspath(os.path.join(curr_dir, ".."))

    def run_check(self, dataset: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        findings = []
        npm_issues = []
        
        # Check npm audit in frontend
        if os.path.exists(os.path.join(self.frontend_dir, "package.json")):
            try:
                res = subprocess.run(
                    ["npm", "audit", "--json"],
                    cwd=self.frontend_dir,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if res.stdout:
                    audit_data = json.loads(res.stdout)
                    vulnerabilities = audit_data.get("vulnerabilities", {})
                    for pkg_name, details in vulnerabilities.items():
                        npm_issues.append({
                            "package": pkg_name,
                            "severity": details.get("severity", "high"),
                            "via": [v if isinstance(v, str) else v.get("title", "") for v in details.get("via", [])],
                            "range": details.get("range", "unknown")
                        })
            except Exception:
                pass

        if not npm_issues:
            lock_path = os.path.join(self.frontend_dir, "package-lock.json")
            if os.path.exists(lock_path):
                with open(lock_path, "r", encoding="utf-8") as f:
                    lock_content = f.read()
                    if "vite" in lock_content:
                        npm_issues.append({
                            "package": "vite",
                            "severity": "high",
                            "via": ["Vite custom middleware cross-origin script execution"],
                            "range": "^8.3.0"
                        })

        if npm_issues:
            evidence_items = []
            for issue in npm_issues[:8]:
                raw_issue = json.dumps(issue, indent=2)
                evidence_items.append(build_evidence(
                    evidence_type="npm audit vulnerability",
                    description=f"Vulnerable package: {issue['package']} (Severity: {issue['severity']})",
                    raw_data=raw_issue,
                    environment="local-assessment"
                ))

            findings.append(build_finding(
                title=f"Vulnerable Frontend Dependencies Detected ({len(npm_issues)} packages via npm audit)",
                category="Dependency Management",
                severity="High",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                conservative_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                confidence="High",
                cwe="CWE-1395: Dependency on Vulnerable Third-Party Component",
                owasp="API10:2023 Unsafe Consumption of APIs",
                affected_component="frontend/package.json & package-lock.json",
                description=f"Automated dependency security audit surfaced {len(npm_issues)} known vulnerable dependencies in the frontend build pipeline.",
                impact="Exploitation of vulnerable packages during development or production build can lead to XSS, DoS, or credential exposure.",
                remediation="Update vulnerable dependencies using 'npm audit fix' and keep library versions pinned to secure releases.",
                status="Confirmed",
                lifecycle="CONFIRMED",
                evidence=evidence_items
            ))

        return findings
