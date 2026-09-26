from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List

from . import models, schemas
from .database import engine, get_db

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="SIH 26163 Security Assessment Platform", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

@app.get("/")
def read_root():
    return {"message": "Welcome to the SIH 26163 Security Assessment Platform API"}

@app.get("/findings/", response_model=List[schemas.Finding])
def read_findings(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    findings = db.query(models.Finding).offset(skip).limit(limit).all()
    return findings

@app.get("/findings/{finding_id}", response_model=schemas.Finding)
def read_finding(finding_id: int, db: Session = Depends(get_db)):
    finding = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding

@app.post("/findings/", response_model=schemas.Finding)
def create_finding(finding: schemas.FindingCreate, db: Session = Depends(get_db)):
    db_finding = models.Finding(**finding.dict(exclude={'evidence'}))
    db.add(db_finding)
    db.commit()
    db.refresh(db_finding)
    
    for ev in finding.evidence:
        db_evidence = models.Evidence(**ev.dict(), finding_id=db_finding.id)
        db.add(db_evidence)
    
    db.commit()
    db.refresh(db_finding)
    return db_finding
