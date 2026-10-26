from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sih_assessment.db")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def ensure_db_schema():
    """Ensures SQLite tables have all required columns without dropping data."""
    try:
        with engine.connect() as conn:
            # Check findings columns
            res = conn.exec_driver_sql("PRAGMA table_info(findings);").fetchall()
            existing_finding_cols = {row[1] for row in res}
            if existing_finding_cols:
                if "cvss_primary" not in existing_finding_cols:
                    conn.exec_driver_sql("ALTER TABLE findings ADD COLUMN cvss_primary VARCHAR;")
                if "cvss_conservative" not in existing_finding_cols:
                    conn.exec_driver_sql("ALTER TABLE findings ADD COLUMN cvss_conservative VARCHAR;")
                if "lifecycle" not in existing_finding_cols:
                    conn.exec_driver_sql("ALTER TABLE findings ADD COLUMN lifecycle VARCHAR DEFAULT 'DISCOVERED';")
                if "lifecycle_history" not in existing_finding_cols:
                    conn.exec_driver_sql("ALTER TABLE findings ADD COLUMN lifecycle_history TEXT DEFAULT '[]';")

            # Check evidence columns
            res_ev = conn.exec_driver_sql("PRAGMA table_info(evidence);").fetchall()
            existing_ev_cols = {row[1] for row in res_ev}
            if existing_ev_cols:
                if "collected_at" not in existing_ev_cols:
                    conn.exec_driver_sql("ALTER TABLE evidence ADD COLUMN collected_at DATETIME;")
                if "environment" not in existing_ev_cols:
                    conn.exec_driver_sql("ALTER TABLE evidence ADD COLUMN environment VARCHAR DEFAULT 'local-assessment';")
                if "sha256" not in existing_ev_cols:
                    conn.exec_driver_sql("ALTER TABLE evidence ADD COLUMN sha256 VARCHAR;")
            
            conn.commit()
    except Exception:
        pass

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
