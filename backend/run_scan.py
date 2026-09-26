import os
import sys

# Add parent directory to path to allow importing from backend
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.ingestion.dataset_ingestor import DatasetIngestor
from backend.security.data_privacy import DataPrivacyCheck
from backend.security.simulated_auth import SimulatedAuthCheck
from backend.security.authorization import SimulatedAuthorizationCheck
from backend.security.secret_scanner import SecretScannerCheck
from backend.security.config_audit import ConfigurationAuditCheck
from backend.database import SessionLocal, engine
from backend import models

# Ensure tables exist
models.Base.metadata.create_all(bind=engine)

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
        DataPrivacyCheck(),
        SimulatedAuthCheck(),
        SimulatedAuthorizationCheck(),
        SecretScannerCheck(),
        ConfigurationAuditCheck()
    ]
    
    all_findings = []
    for check in checks:
        findings = check.run_check(dataset)
        all_findings.extend(findings)
        
    print(f"Generated {len(all_findings)} findings.")
    
    # 3. Save to Database
    db = SessionLocal()
    try:
        # Clear old findings for demo purposes
        db.query(models.Evidence).delete()
        db.query(models.Finding).delete()
        db.commit()
        
        for finding_data in all_findings:
            evidence_data = finding_data.pop("evidence", [])
            db_finding = models.Finding(**finding_data)
            db.add(db_finding)
            db.commit()
            db.refresh(db_finding)
            
            for ev in evidence_data:
                db_evidence = models.Evidence(**ev, finding_id=db_finding.id)
                db.add(db_evidence)
            db.commit()
        print("Successfully saved findings to the database.")
    except Exception as e:
        print(f"Error saving to database: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    main()
