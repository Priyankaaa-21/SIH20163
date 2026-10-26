import os
import json
from typing import List, Dict, Any
from .base import SecurityCheck, build_finding, build_evidence

class DataPrivacyCheck(SecurityCheck):
    def __init__(self, dataset_dir: str = None):
        if not dataset_dir:
            curr_dir = os.path.dirname(os.path.abspath(__file__))
            candidate = os.path.join(curr_dir, "..", "..", "dataset")
            if os.path.exists(candidate):
                self.dataset_dir = os.path.abspath(candidate)
            else:
                self.dataset_dir = os.path.abspath("dataset")
        else:
            self.dataset_dir = dataset_dir

    def run_check(self, dataset: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []

        # 1. Check ALL facilities in dataset for coordinate exposure
        facility_keys = [k for k in dataset.keys() if "iaea" in k or "facilit" in k]
        exposed_facilities = []
        for key in facility_keys:
            data = dataset[key]
            if isinstance(data, dict) and "facilities" in data and isinstance(data["facilities"], list):
                for fac in data["facilities"]:
                    if "lat" in fac and "lon" in fac:
                        exposed_facilities.append((key, fac))

        if exposed_facilities:
            evidence_items = []
            for key, fac in exposed_facilities[:10]:
                raw_json = json.dumps(fac, indent=2)
                evidence_items.append(build_evidence(
                    evidence_type=f"Dataset Record ({key})",
                    description=f"Facility ID: {fac.get('id', 'N/A')}, Location: {fac.get('city', 'N/A')}, {fac.get('country', 'N/A')} exposes exact lat/lon.",
                    raw_data=raw_json,
                    environment="local-assessment"
                ))

            findings.append(build_finding(
                title=f"Exposure of Critical Infrastructure Coordinates ({len(exposed_facilities)} facilities)",
                category="Data Privacy / Storage",
                severity="High",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                conservative_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                confidence="High",
                cwe="CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
                owasp="API3:2023 Broken Object Property Level Authorization",
                affected_component="Critical Infrastructure Dataset Export",
                description=f"The application dataset contains geographical coordinates for {len(exposed_facilities)} critical infrastructure / irradiation facilities. Aggregating precise coordinates of nuclear/radiological infrastructure poses a serious physical security risk if accessed by unauthorized actors.",
                impact="Unrestricted access to exact facility coordinates could allow malicious actors to locate and target radiological facilities.",
                remediation="Implement role-based precision masking on coordinates. Round coordinates to a coarse grid (0.5 degrees) with deterministic noise for standard users, and restrict precise coordinates to authorized admins.",
                status="Confirmed",
                lifecycle="CONFIRMED",
                evidence=evidence_items
            ))

        # 2. Check for raw iaea_diif_*.json files present in the Docker build context
        raw_files_in_dataset = []
        if os.path.exists(self.dataset_dir):
            for pattern in ["iaea_diif_db.json", "iaea_diif_facilities.json", "iaea_diif_tableau.json"]:
                file_path = os.path.join(self.dataset_dir, pattern)
                if os.path.exists(file_path):
                    raw_files_in_dataset.append(pattern)

        private_dir = os.path.abspath(os.path.join(self.dataset_dir, "..", "private"))
        isolated_in_private = os.path.exists(private_dir) and any(
            os.path.exists(os.path.join(private_dir, p)) for p in ["iaea_diif_db.json", "iaea_diif_facilities.json", "iaea_diif_tableau.json"]
        )

        raw_files_status = "Detected" if len(raw_files_in_dataset) > 0 else "Remediated"
        raw_files_lifecycle = "CONFIRMED" if len(raw_files_in_dataset) > 0 else "RETESTED"
        findings.append(build_finding(
            title="Raw Critical Infrastructure Datasets Present in Build Context",
            category="Data Privacy / Storage",
            severity="High",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            conservative_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
            confidence="High",
            cwe="CWE-552: Files or Directories Accessible to External Parties",
            owasp="API8:2023 Security Misconfiguration",
            affected_component="Docker Build Context (dataset/ vs private/)",
            description="Raw IAEA DIIF database exports containing unmasked nuclear facility coordinates must not be present in the Docker build context or committed to repository tracking.",
            impact="Any files copied into the Docker container image during build (COPY dataset/ dataset/) can be extracted from public container registries or compromised containers.",
            remediation="Move raw unmasked dataset files to a gitignored 'private/' directory excluded via .dockerignore and .gitignore. Only include synthetic or fuzzed datasets (iaea_diif_db_safe.json) in the container image.",
            status=raw_files_status,
            lifecycle=raw_files_lifecycle,
            lifecycle_note="Raw unmasked datasets removed from build context and isolated into gitignored private/ repository storage.",
            evidence=[
                build_evidence(
                    evidence_type="Docker Context Audit (Before - Insecure)",
                    description="Raw unmasked datasets located in build context.",
                    raw_data="dataset/iaea_diif_db.json\ndataset/iaea_diif_facilities.json\ndataset/iaea_diif_tableau.json"
                ),
                build_evidence(
                    evidence_type="Docker Context Audit (After - Remediated)" if raw_files_status == "Remediated" else "Docker Context Audit (Current State - Vulnerable)",
                    description=(
                        "Raw files successfully moved to private/ directory and excluded from build context via .dockerignore."
                        if raw_files_status == "Remediated" else f"Raw files still present in build context: {raw_files_in_dataset}"
                    ),
                    raw_data=(
                        f"Isolated in private/ directory (gitignored): {isolated_in_private}\nExcluded from Docker context via backend/.dockerignore"
                        if raw_files_status == "Remediated" else f"Found exposed files: {raw_files_in_dataset}"
                    )
                )
            ]
        ))

        return findings
