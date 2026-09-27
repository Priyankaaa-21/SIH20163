from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import datetime
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List
import jwt
import os
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

from . import models, schemas
from .database import engine, get_db

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SIH 26163 Security Assessment Platform", 
    version="1.0.0",
    docs_url=None, 
    redoc_url=None, 
    openapi_url=None
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Restrict to frontend origin (Vite default)
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# Basic authentication scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Secret key to encode and decode JWT tokens loaded from environment variables
SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-if-missing")
ALGORITHM = os.getenv("ALGORITHM", "HS256")

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Require an expiration ('exp') claim to fix the simulated security finding
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"require": ["exp"]})
        username: str = payload.get("sub")
        role: str = payload.get("role", "user")
        if username is None:
            raise credentials_exception
    except jwt.InvalidTokenError:
        raise credentials_exception
        
    return {"username": username, "role": role}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # Basic mock authentication - in a real app, query the database
    if form_data.username == "admin" and form_data.password == "admin123":
        payload = {
            "sub": form_data.username,
            "role": "admin",
            # Expiration fixes the security finding
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=400, detail="Incorrect username or password")

@app.get("/")
def read_root():
    return {"message": "Welcome to the SIH 26163 Security Assessment Platform API"}

@app.get("/findings/", response_model=List[schemas.Finding])
def read_findings(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    findings = db.query(models.Finding).offset(skip).limit(limit).all()
    return findings

@app.get("/findings/{finding_id}", response_model=schemas.Finding)
def read_finding(finding_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    finding = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding

@app.post("/findings/", response_model=schemas.Finding)
def create_finding(finding: schemas.FindingCreate, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    # Basic Role-Based Access Control (RBAC) check
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")
        
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
