import json
from typing import List, Dict, Any
from .base import SecurityCheck, build_finding, build_evidence

class ConfigurationAuditCheck(SecurityCheck):
    def run_check(self, dataset: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        evidence_items = []
        
        # Audit both news_channels.json and news_channels_x.json
        target_keys = [("news_channels", "news_channels.json"), ("news_channels_x", "news_channels_x.json")]
        
        for dataset_key, filename in target_keys:
            if dataset_key in dataset:
                data = dataset[dataset_key]
                if isinstance(data, dict) and "channels" in data and "full" in data["channels"]:
                    for idx, channel in enumerate(data["channels"]["full"]):
                        # Flag Tier 1 channels that don't have an accountId verified
                        if channel.get("tier") == 1 and not channel.get("accountId"):
                            handle = channel.get("handle", "unknown")
                            raw_snippet = json.dumps(channel, indent=2)
                            evidence_items.append(build_evidence(
                                evidence_type=f"Config Snippet ({filename})",
                                description=f"Tier-1 channel @{handle} (index {idx}) missing verified accountId in {filename}.",
                                raw_data=raw_snippet,
                                environment="local-assessment"
                            ))

        if evidence_items:
            cvss_primary = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
            cvss_conservative = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"
            findings.append(build_finding(
                title=f"Missing Account ID Verification in Tier-1 News Feeds ({len(evidence_items)} channels)",
                category="Configuration / Trust",
                severity="Medium",
                cvss_vector=cvss_primary,
                conservative_vector=cvss_conservative,
                confidence="High",
                cwe="CWE-345: Insufficient Verification of Data Authenticity",
                owasp="API8:2023 Security Misconfiguration",
                affected_component="OSINT Feed Configs (news_channels.json, news_channels_x.json)",
                description=f"Audited {len(evidence_items)} Tier-1 intelligence feed channels across news_channels.json and news_channels_x.json missing verified numeric 'accountId' values. Unverified handles silently degrade feed integrity and are susceptible to identity forking if handles are renamed.",
                impact="An attacker could claim a dropped or renamed handle and inject disinformation directly into Tier-1 intelligence feeds, triggering false incident alerts.",
                remediation="Enforce strict schema validation on configuration files. Require all Tier-1 enabled feeds to contain verified numeric 'accountId' values validated against the provider API.",
                status="Confirmed",
                lifecycle="CONFIRMED",
                evidence=evidence_items
            ))

        return findings
