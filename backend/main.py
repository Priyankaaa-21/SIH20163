from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import datetime
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List
import jwt
import os
import json
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

from . import models, schemas
from .database import engine, get_db
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SIH 26163 Security Assessment Platform", 
    version="1.0.0",
    docs_url=None, 
    redoc_url=None, 
    openapi_url=None
)

@app.on_event("startup")
def startup_event():
    db = next(get_db())
    admin = db.query(models.User).filter(models.User.username == "admin").first()
    if not admin:
        hashed_pw = get_password_hash("admin123")
        admin = models.User(username="admin", hashed_password=hashed_pw, role="admin")
        db.add(admin)
        db.commit()

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
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    payload = {
        "sub": user.username,
        "role": user.role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}

@app.post("/users/", response_model=schemas.UserResponse)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)
    db_user = models.User(username=user.username, hashed_password=hashed_password, role=user.role)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.get("/")
def read_root():
    return {"message": "Welcome to the SIH 26163 Security Assessment Platform API"}

@app.get("/findings/", response_model=List[schemas.Finding])
def read_findings(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    findings = db.query(models.Finding).offset(skip).limit(limit).all()
    return findings

@app.get("/facilities/")
def read_facilities(current_user: dict = Depends(get_current_user)):
    try:
        # Use absolute path resolution relative to main.py
        current_dir = os.path.dirname(os.path.abspath(__file__))
        dataset_path = os.path.join(current_dir, "..", "dataset", "iaea_diif_db_safe.json")
        with open(dataset_path, "r") as f:
            data = json.load(f)
            return data.get("facilities", [])
    except Exception as e:
        return []

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
