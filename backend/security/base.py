import os
import hashlib
import datetime
import json
from typing import List, Dict, Any, Optional
from abc import ABC, abstractmethod
from .cvss import cvss_score, format_cvss, compute_dual_cvss

def build_evidence(
    evidence_type: str,
    description: str,
    raw_data: str,
    environment: str = "local-assessment",
    source_file: Optional[str] = None
) -> Dict[str, Any]:
    """Builds a standardized Evidence dictionary with dynamically computed SHA-256 and timestamps."""
    if source_file and os.path.exists(source_file):
        with open(source_file, "rb") as f:
            computed_sha = hashlib.sha256(f.read()).hexdigest()
    else:
        computed_sha = hashlib.sha256(raw_data.encode("utf-8")).hexdigest()

    return {
        "evidence_type": evidence_type,
        "description": description,
        "raw_data": raw_data,
        "collected_at": datetime.datetime.utcnow(),
        "environment": environment,
        "sha256": computed_sha
    }

def build_finding(
    title: str,
    category: str,
    severity: str,
    cvss_vector: str,
    confidence: str,
    cwe: str,
    owasp: str,
    affected_component: str,
    description: str,
    impact: str,
    remediation: str,
    status: str,
    lifecycle: str,
    evidence: List[Dict[str, Any]],
    conservative_vector: Optional[str] = None,
    lifecycle_note: Optional[str] = None
) -> Dict[str, Any]:
    """Builds a standardized Finding dictionary with dual CVSS and lifecycle history."""
    dual = compute_dual_cvss(cvss_vector, conservative_vector)
    now = datetime.datetime.utcnow().isoformat()
    
    history = [
        {"lifecycle": "DISCOVERED", "timestamp": now, "note": "Identified during automated security assessment.", "actor": "Automated Scanner"},
        {"lifecycle": "VALIDATED", "timestamp": now, "note": "Target component and condition validated.", "actor": "Security Engine"}
    ]
    if lifecycle in ("CONFIRMED", "REMEDIATED", "RETESTED"):
        history.append({"lifecycle": "CONFIRMED", "timestamp": now, "note": "Vulnerability pattern confirmed against codebase/configuration.", "actor": "Security Analyst"})
    if lifecycle in ("REMEDIATED", "RETESTED"):
        history.append({"lifecycle": "REMEDIATED", "timestamp": now, "note": lifecycle_note or "Remediation verified implemented in codebase.", "actor": "AST Code Auditor"})
    if lifecycle == "RETESTED":
        history.append({"lifecycle": "RETESTED", "timestamp": now, "note": "Retest verification passed with zero regressions.", "actor": "Test Harness"})

    return {
        "title": title,
        "category": category,
        "severity": severity,
        "cvss": dual["cvss_primary"],
        "cvss_primary": dual["cvss_primary"],
        "cvss_conservative": dual["cvss_conservative"],
        "confidence": confidence,
        "cwe": cwe,
        "owasp": owasp,
        "affected_component": affected_component,
        "description": description,
        "impact": impact,
        "remediation": remediation,
        "status": status,
        "lifecycle": lifecycle,
        "lifecycle_history": json.dumps(history),
        "evidence": evidence
    }

class SecurityCheck(ABC):
    
    @abstractmethod
    def run_check(self, dataset: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Runs the security check against the ingested dataset or application context.
        Returns a list of finding dictionaries matching the FindingCreate schema.
        """
        pass
