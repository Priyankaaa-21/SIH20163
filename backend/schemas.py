from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import enum

class EvidenceBase(BaseModel):
    evidence_type: str
    description: str
    raw_data: str

class EvidenceCreate(EvidenceBase):
    pass

class Evidence(EvidenceBase):
    id: int
    finding_id: int
    
    class Config:
        orm_mode = True

class FindingBase(BaseModel):
    title: str
    category: str
    severity: str
    cvss: Optional[str] = None
    confidence: str
    affected_component: str
    description: str
    impact: str
    remediation: str
    status: str

class FindingCreate(FindingBase):
    evidence: List[EvidenceCreate] = []

class Finding(FindingBase):
    id: int
    created_at: datetime
    evidence: List[Evidence] = []
    
    class Config:
        orm_mode = True
