from typing import List, Dict, Any
from .base import SecurityCheck
import json

class DataPrivacyCheck(SecurityCheck):
    def run_check(self, dataset: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        
        # Check if the dataset contains precise coordinates of sensitive facilities
        if "iaea_diif_db" in dataset:
            iaea_data = dataset["iaea_diif_db"]
            if "facilities" in iaea_data and len(iaea_data["facilities"]) > 0:
                first_facility = iaea_data["facilities"][0]
                
                # Check for lat/lon fields indicating precise location
                if "lat" in first_facility and "lon" in first_facility:
                    evidence_json = json.dumps(first_facility, indent=2)
                    findings.append({
                        "title": "Exposure of Critical Infrastructure Coordinates",
                        "category": "Data Privacy / Storage",
                        "severity": "High",
                        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5)",
                        "confidence": "High",
                        "affected_component": "IAEA DIIF Database Export",
                        "description": "The application dataset contains exact geographical coordinates (latitude/longitude) of industrial gamma irradiator facilities. While some of this may be OSINT, aggregating precise coordinates of nuclear/radiological infrastructure poses a significant security risk if accessed by unauthorized actors.",
                        "impact": "Unrestricted access to this data could allow malicious actors to precisely locate and target radiological facilities, leading to potential physical security incidents.",
                        "remediation": "Implement strict access controls on datasets containing critical infrastructure locations. Add intentional jitter (noise) to the coordinates when rendering maps for lower-privileged users, or restrict viewing to country/city level only.",
                        "status": "Confirmed",
                        "evidence": [
                            {
                                "evidence_type": "Dataset Record",
                                "description": "Facility record exposing precise lat/lon coordinates.",
                                "raw_data": evidence_json
                            }
                        ]
                    })
        return findings
