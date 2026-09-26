import os
import datetime
from sqlalchemy.orm import Session
from .database import SessionLocal
from . import models

def generate_markdown_report(db: Session, output_path: str):
    findings = db.query(models.Finding).all()
    
    total_findings = len(findings)
    critical_count = len([f for f in findings if f.severity == 'Critical'])
    high_count = len([f for f in findings if f.severity == 'High'])
    medium_count = len([f for f in findings if f.severity == 'Medium'])
    low_count = len([f for f in findings if f.severity == 'Low'])
    
    report_content = f"""# Security Assessment Report: World Monitor Application
**Date Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Project:** SIH 26163 — Security Assessment of the World Monitor Application

## 1. Executive Summary
This report details the findings from the automated and manual security assessment of the World Monitor Application and its associated datasets. The assessment focused on identifying vulnerabilities across authentication, authorization, data privacy, and API security.

**Overall Security Posture:** 
A total of {total_findings} findings were identified during this assessment. 
- Critical: {critical_count}
- High: {high_count}
- Medium: {medium_count}
- Low: {low_count}

## 2. Scope & Methodology
**Scope:** 
The assessment covered the provided World Monitor application resources, including the OSINT channel configurations and the IAEA DIIF critical infrastructure datasets.

**Methodology:**
The assessment was performed using a custom-built modular security assessment engine. It leverages static analysis and dataset introspection to identify misconfigurations and data exposure risks without performing destructive exploitation.

## 3. Assessment Coverage
- Authentication and Session Management
- Authorization / Access Control
- API Security
- Data Storage and Privacy

---

## 4. Detailed Findings

"""

    for idx, finding in enumerate(findings, 1):
        report_content += f"### 4.{idx} {finding.title}\n"
        report_content += f"- **Severity:** {finding.severity}\n"
        report_content += f"- **CVSS:** {finding.cvss or 'N/A'}\n"
        report_content += f"- **Category:** {finding.category}\n"
        report_content += f"- **Status:** {finding.status}\n"
        report_content += f"- **Affected Component:** `{finding.affected_component}`\n\n"
        
        report_content += f"#### Description\n{finding.description}\n\n"
        report_content += f"#### Business Impact\n{finding.impact}\n\n"
        report_content += f"#### Remediation Guidance\n{finding.remediation}\n\n"
        
        if finding.evidence:
            report_content += "#### Evidence\n"
            for ev in finding.evidence:
                report_content += f"**{ev.evidence_type}**: {ev.description}\n"
                report_content += f"```json\n{ev.raw_data}\n```\n\n"
        
        report_content += "---\n\n"

    report_content += """## 5. Conclusion
The assessment highlights areas requiring immediate remediation, particularly concerning the exposure of critical infrastructure data and simulated authentication flows. Implementing the recommended remediation steps will significantly enhance the application's security posture.
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_content)
    print(f"Report successfully generated at: {output_path}")

if __name__ == "__main__":
    db = SessionLocal()
    try:
        report_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "SECURITY_REPORT.md"))
        generate_markdown_report(db, report_path)
    finally:
        db.close()
