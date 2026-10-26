import os
import sys
import uuid
import datetime

# Add parent directory to path to allow importing from backend
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.ingestion.dataset_ingestor import DatasetIngestor
from backend.security.data_privacy import DataPrivacyCheck
from backend.security.code_audit import CodeAuditCheck
from backend.security.secret_scanner import SecretScannerCheck
from backend.security.config_audit import ConfigurationAuditCheck
from backend.security.dependency_audit import DependencyAuditCheck
from backend.database import SessionLocal, engine, ensure_db_schema
from backend import models

# Ensure tables exist and schema columns are up to date
models.Base.metadata.create_all(bind=engine)
ensure_db_schema()

def main():
    print("Starting SIH 26163 Security Assessment Scan...")
    
    # 1. Ingest Dataset
    dataset_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "dataset"))
    print(f"Loading dataset from: {dataset_path}")
    ingestor = DatasetIngestor(dataset_path)
    dataset = ingestor.load_dataset()
    
    print(f"Loaded {len(dataset)} dataset files.")
    
    # 2. Run Security Checks
    checks = [
        CodeAuditCheck(),
        ConfigurationAuditCheck(),
        DataPrivacyCheck(),
        SecretScannerCheck(),
        DependencyAuditCheck()
    ]
    
    all_findings = []
    for check in checks:
        findings = check.run_check(dataset)
        all_findings.extend(findings)
        
    print(f"Generated {len(all_findings)} findings across {len(checks)} security modules.")
    
    # 3. Save to Database with persistent scan run history
    scan_run_id = f"scan_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    now = datetime.datetime.utcnow()
    
    db = SessionLocal()
    try:
        # We do NOT silently wipe existing findings; we preserve full audit history
        saved_count = 0
        for finding_data in all_findings:
            evidence_data = finding_data.pop("evidence", [])
            finding_data["scan_run_id"] = scan_run_id
            finding_data["created_at"] = now
            
            db_finding = models.Finding(**finding_data)
            db.add(db_finding)
            db.commit()
            db.refresh(db_finding)
            
            for ev in evidence_data:
                db_evidence = models.Evidence(**ev, finding_id=db_finding.id)
                db.add(db_evidence)
            db.commit()
            saved_count += 1
            
        print(f"Successfully recorded scan run '{scan_run_id}' with {saved_count} findings in the database.")
    except Exception as e:
        print(f"Error saving to database: {e}")
        db.rollback()
        raise
    finally:
        db.close()

if __name__ == "__main__":
    main()
