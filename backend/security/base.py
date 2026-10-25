from typing import List, Dict, Any
from abc import ABC, abstractmethod
from .cvss import cvss_score, format_cvss

class SecurityCheck(ABC):
    
    @abstractmethod
    def run_check(self, dataset: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Runs the security check against the ingested dataset or application context.
        Returns a list of finding dictionaries matching the FindingCreate schema.
        """
        pass
