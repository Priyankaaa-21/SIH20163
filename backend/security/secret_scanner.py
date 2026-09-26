from typing import List, Dict, Any
from .base import SecurityCheck
import re

class SecretScannerCheck(SecurityCheck):
    def run_check(self, dataset: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        
        # Regex for catching things that look like common API keys or tokens
        patterns = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Generic Bearer Token": r"Bearer\s+[a-zA-Z0-9_\-\.]{20,}"
        }
        
        def search_dict(d, path=""):
            if isinstance(d, dict):
                for k, v in d.items():
                    # Check the key and value
                    if isinstance(v, str):
                        matched = False
                        for secret_type, pattern in patterns.items():
                            if re.search(pattern, v):
                                matched = True
                                self._add_finding(findings, k, v, path, secret_type)
                                break
                        
                        if not matched and re.search(r"(?i)(api_?key|secret|password|token)", k) and len(v) > 8:
                            self._add_finding(findings, k, v, path, "Suspicious Key Name")
                            
                    elif isinstance(v, (dict, list)):
                        search_dict(v, f"{path}.{k}" if path else k)
            elif isinstance(d, list):
                for i, item in enumerate(d):
                    search_dict(item, f"{path}[{i}]")

        search_dict(dataset)
        return findings

    def _add_finding(self, findings, key, value, path, secret_type):
        masked_val = f"{value[:4]}***{value[-4:]}" if len(value) > 8 else "***"
        findings.append({
            "title": f"Hardcoded Secrets Detected: {secret_type}",
            "category": "Credentials Management",
            "severity": "Critical",
            "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N (10.0)",
            "confidence": "High",
            "affected_component": f"Dataset Field: {path}.{key}",
            "description": f"The dataset contains a hardcoded or exposed secret in the field '{key}'. Exposing tokens or passwords in datasets can lead to unauthorized access to associated third-party services.",
            "impact": "An attacker could extract this token and authenticate to downstream services (APIs, databases, AWS) as the application, resulting in data breaches or system compromise.",
            "remediation": "Remove the hardcoded secret from the dataset. Use a secure vault (like AWS Secrets Manager or HashiCorp Vault) and inject secrets at runtime using environment variables.",
            "status": "Confirmed",
            "evidence": [
                {
                    "evidence_type": "Dataset Record",
                    "description": f"Found in path: {path}.{key}",
                    "raw_data": f'"{key}": "{masked_val}"'
                }
            ]
        })
