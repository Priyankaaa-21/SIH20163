from pydantic import BaseModel, ConfigDict
from typing import List, Optional
from datetime import datetime
from .models import SeverityEnum, FindingStatusEnum

class UserBase(BaseModel):
    username: str
    role: str = "user"

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: int
    model_config = ConfigDict(from_attributes=True)

class EvidenceBase(BaseModel):
    evidence_type: str
    description: str
    raw_data: str

class EvidenceCreate(EvidenceBase):
    pass

class Evidence(EvidenceBase):
    id: int
    finding_id: int
    model_config = ConfigDict(from_attributes=True)

class FindingBase(BaseModel):
    title: str
    category: str
    severity: SeverityEnum
    cvss: Optional[str] = None
    confidence: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    affected_component: str
    description: str
    impact: str
    remediation: str
    status: FindingStatusEnum
    scan_run_id: Optional[str] = None

class FindingCreate(FindingBase):
    evidence: List[EvidenceCreate] = []

class Finding(FindingBase):
    id: int
    created_at: datetime
    evidence: List[Evidence] = []
    model_config = ConfigDict(from_attributes=True)

class AuditLogResponse(BaseModel):
    id: int
    timestamp: datetime
    action: str
    username: Optional[str] = None
    ip_address: Optional[str] = None
    details: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)
