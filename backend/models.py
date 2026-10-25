from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Enum
from sqlalchemy.orm import relationship
import enum
import datetime
from .database import Base

class SeverityEnum(str, enum.Enum):
    critical = "Critical"
    high = "High"
    medium = "Medium"
    low = "Low"
    informational = "Informational"

class FindingStatusEnum(str, enum.Enum):
    detected = "Detected"
    potential = "Potential"
    needs_validation = "Needs Validation"
    confirmed = "Confirmed"
    remediated = "Remediated"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="user")
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_run_id = Column(String, index=True, nullable=True)
    title = Column(String, index=True)
    category = Column(String, index=True)
    severity = Column(String)  # Critical, High, Medium, Low, Informational
    cvss = Column(String)
    confidence = Column(String)
    cwe = Column(String, nullable=True)
    owasp = Column(String, nullable=True)
    affected_component = Column(String)
    description = Column(Text)
    impact = Column(Text)
    remediation = Column(Text)
    status = Column(String, default=FindingStatusEnum.detected)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    evidence = relationship("Evidence", back_populates="finding", cascade="all, delete")

class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"))
    evidence_type = Column(String)
    description = Column(Text)
    raw_data = Column(Text)
    
    finding = relationship("Finding", back_populates="evidence")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    action = Column(String, index=True)
    username = Column(String, index=True, nullable=True)
    ip_address = Column(String, nullable=True)
    details = Column(Text, nullable=True)
