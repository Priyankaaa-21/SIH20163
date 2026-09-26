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

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    category = Column(String, index=True)
    severity = Column(String)  # Critical, High, Medium, Low, Informational
    cvss = Column(String)
    confidence = Column(String)
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
    evidence_type = Column(String)  # Dataset record, API information, Config, etc.
    description = Column(Text)
    raw_data = Column(Text)
    
    finding = relationship("Finding", back_populates="evidence")
