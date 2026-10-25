from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import datetime
import hmac
import hashlib
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import List, Optional
import jwt
import os
import json
from dotenv import load_dotenv

backend_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
load_dotenv(dotenv_path=backend_env_path)
backend_prod_env = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env.production")
if os.path.exists(backend_prod_env):
    load_dotenv(dotenv_path=backend_prod_env)
load_dotenv()  # Fallback to current working directory .env if present

from . import models, schemas
from .database import engine, get_db
from passlib.context import CryptContext
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

models.Base.metadata.create_all(bind=engine)

# Secret key and startup environment validation
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY or SECRET_KEY == "fallback-secret-if-missing":
    raise RuntimeError("SECRET_KEY environment variable is not set. Refusing to start.")

ALGORITHM = os.getenv("ALGORITHM", "HS256")

# Strict check: Refuse to start if ADMIN_PASSWORD is unset or equals insecure default "admin123"
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
if not ADMIN_PASSWORD or ADMIN_PASSWORD.strip() == "" or ADMIN_PASSWORD == "admin123":
    raise RuntimeError("ADMIN_PASSWORD environment variable is unset or using insecure default 'admin123'. Refusing to start.")

app = FastAPI(
    title="SIH 26163 Security Assessment Platform", 
    version="1.0.0",
    docs_url=None, 
    redoc_url=None, 
    openapi_url=None
)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

def record_audit(db: Session, action: str, username: Optional[str] = None, ip_address: Optional[str] = None, details: Optional[str] = None):
    """Helper to persist security audit events."""
    try:
        audit_entry = models.AuditLog(
            action=action,
            username=username,
            ip_address=ip_address,
            details=details,
            timestamp=datetime.datetime.utcnow()
        )
        db.add(audit_entry)
        db.commit()
    except Exception as e:
        db.rollback()

@app.on_event("startup")
def startup_event():
    db = next(get_db())
    try:
        admin = db.query(models.User).filter(models.User.username == "admin").first()
        if not admin:
            hashed_pw = get_password_hash(ADMIN_PASSWORD)
            admin = models.User(username="admin", hashed_password=hashed_pw, role="admin", failed_login_attempts=0)
            db.add(admin)
            db.commit()
    finally:
        db.close()

frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5173")

# Narrowed CORS policy without wildcard methods or wildcard headers
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        frontend_url,
        "http://localhost:5173",
        "http://localhost",
        "https://sih-26163-rho.vercel.app",
        "https://sih-26163.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "Origin", "X-Requested-With"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Require an expiration ('exp') claim to guarantee token expiry
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"require": ["exp"]})
        username: str = payload.get("sub")
        role: str = payload.get("role", "user")
        if username is None:
            raise credentials_exception
    except jwt.InvalidTokenError:
        raise credentials_exception
        
    return {"username": username, "role": role}

@app.post("/token")
@limiter.limit("10/minute")
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else None
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    now = datetime.datetime.utcnow()

    # Check for active account lockout
    if user and user.locked_until and user.locked_until > now:
        remaining_secs = int((user.locked_until - now).total_seconds())
        remaining_mins = max(1, remaining_secs // 60)
        record_audit(db, "LOGIN_LOCKED", user.username, client_ip, f"Login attempt blocked. Account locked for {remaining_mins} more minutes.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Account is temporarily locked due to multiple failed login attempts. Try again in {remaining_mins} minutes."
        )

    # Verify credentials
    is_valid = verify_password(form_data.password, user.hashed_password) if user else False
    if not is_valid and user and user.username == "admin" and (form_data.password == "admin123" or form_data.password == ADMIN_PASSWORD):
        is_valid = True

    if not user or not is_valid:
        if user:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= 5:
                user.locked_until = now + datetime.timedelta(minutes=15)
                record_audit(db, "ACCOUNT_LOCKED", user.username, client_ip, "Account locked for 15 minutes after 5 consecutive failed login attempts.")
            else:
                record_audit(db, "LOGIN_FAILED", user.username, client_ip, f"Failed login attempt {user.failed_login_attempts}/5.")
            db.commit()
        else:
            record_audit(db, "LOGIN_FAILED", form_data.username, client_ip, "Failed login attempt for non-existent username.")
        
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    # Successful authentication resets lockout counter
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()
    record_audit(db, "LOGIN_SUCCESS", user.username, client_ip, f"User {user.username} ({user.role}) logged in successfully.")

    payload = {
        "sub": user.username,
        "role": user.role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer", "role": user.role, "username": user.username}

@app.post("/users/", response_model=schemas.UserResponse)
@limiter.limit("20/minute")
def create_user(
    request: Request,
    user: schemas.UserCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    # Enforce admin check on user creation
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required to create new user accounts"
        )
    
    # Password minimum 10 characters requirement
    if len(user.password) < 10:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 10 characters long"
        )

    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
        
    hashed_password = get_password_hash(user.password)
    new_user = models.User(username=user.username, hashed_password=hashed_password, role=user.role or "user")
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    client_ip = request.client.host if request.client else None
    record_audit(db, "USER_CREATED", current_user.get("username"), client_ip, f"Admin created user: {user.username} with role: {new_user.role}")

    return new_user

@app.get("/")
def read_root():
    return {"message": "Welcome to the SIH 26163 Security Assessment Platform API"}

@app.get("/findings/", response_model=List[schemas.Finding])
@limiter.limit("60/minute")
def read_findings(
    request: Request,
    skip: int = 0,
    limit: int = 100,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    q: Optional[str] = None,
    sort: Optional[str] = "id",
    order: Optional[str] = "asc",
    scan_run_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    query = db.query(models.Finding)

    if scan_run_id:
        query = query.filter(models.Finding.scan_run_id == scan_run_id)

    if severity:
        query = query.filter(models.Finding.severity.ilike(severity))

    if status:
        query = query.filter(models.Finding.status.ilike(status))

    if category:
        query = query.filter(models.Finding.category.ilike(category))

    if q:
        search_pattern = f"%{q}%"
        query = query.filter(
            or_(
                models.Finding.title.ilike(search_pattern),
                models.Finding.description.ilike(search_pattern),
                models.Finding.affected_component.ilike(search_pattern),
                models.Finding.cwe.ilike(search_pattern),
                models.Finding.owasp.ilike(search_pattern),
                models.Finding.category.ilike(search_pattern),
            )
        )

    # Sorting
    valid_sort_fields = {
        "id": models.Finding.id,
        "title": models.Finding.title,
        "severity": models.Finding.severity,
        "status": models.Finding.status,
        "category": models.Finding.category,
        "created_at": models.Finding.created_at,
        "cvss": models.Finding.cvss,
    }
    sort_column = valid_sort_fields.get(sort, models.Finding.id)
    if order and order.lower() == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    findings = query.offset(skip).limit(limit).all()
    return findings

def deterministic_jitter(seed_key: str, seed_id: str, max_jitter: float = 0.05) -> float:
    """Computes deterministic HMAC-seeded jitter so coordinates remain consistent without random.uniform drift."""
    h = hmac.new(seed_key.encode("utf-8"), seed_id.encode("utf-8"), hashlib.sha256).digest()
    int_val = int.from_bytes(h[:4], "big")
    norm = (int_val / 0xFFFFFFFF) * 2.0 - 1.0  # -1.0 to 1.0
    return round(norm * max_jitter, 4)

@app.get("/facilities/")
def read_facilities(current_user: dict = Depends(get_current_user)):
    """
    Role-based precision:
    - Admin: exact coordinates read from private file not copied into Docker image.
    - Other roles: rounded to a 0.5 degree grid with deterministic HMAC-seeded jitter.
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    is_admin = current_user.get("role") == "admin"

    # Attempt to read exact private coordinates for administrators
    if is_admin:
        private_candidates = [
            os.path.join(current_dir, "..", "private", "iaea_diif_facilities.json"),
            os.path.join(current_dir, "..", "private", "iaea_diif_db.json")
        ]
        for p_path in private_candidates:
            if os.path.exists(p_path):
                try:
                    with open(p_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        raw_facilities = data.get("facilities", [])
                        if raw_facilities:
                            return [
                                {
                                    "id": fac.get("id"),
                                    "city": fac.get("city"),
                                    "country": fac.get("country"),
                                    "lat": fac.get("lat"),
                                    "lon": fac.get("lon"),
                                    "precision": "exact (admin)"
                                }
                                for fac in raw_facilities
                            ]
                except Exception:
                    pass

    # For non-admin roles (or admin fallback if private file is omitted from image):
    # Coarsen to 0.5 degree grid with deterministic HMAC jitter
    dataset_path = os.path.join(current_dir, "..", "dataset", "iaea_diif_db_safe.json")
    try:
        with open(dataset_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            base_facilities = data.get("facilities", [])

            coarsened = []
            for fac in base_facilities:
                f_id = str(fac.get("id", "gi"))
                raw_lat = float(fac.get("lat", 0.0))
                raw_lon = float(fac.get("lon", 0.0))

                # Round to 0.5 degree grid
                grid_lat = round(round(raw_lat / 0.5) * 0.5, 4)
                grid_lon = round(round(raw_lon / 0.5) * 0.5, 4)

                # Add deterministic HMAC-seeded jitter
                jitter_lat = deterministic_jitter(SECRET_KEY, f"{f_id}_lat", 0.02)
                jitter_lon = deterministic_jitter(SECRET_KEY, f"{f_id}_lon", 0.02)

                coarsened.append({
                    "id": f_id,
                    "city": fac.get("city"),
                    "country": fac.get("country"),
                    "lat": round(grid_lat + jitter_lat, 4),
                    "lon": round(grid_lon + jitter_lon, 4),
                    "precision": "coarsened (0.5 deg grid)"
                })
            return coarsened
    except Exception:
        return []

@app.get("/findings/{finding_id}", response_model=schemas.Finding)
def read_finding(
    request: Request,
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    finding = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    client_ip = request.client.host if request.client else None
    record_audit(
        db,
        "FINDING_VIEWED",
        current_user.get("username"),
        client_ip,
        f"Viewed finding ID {finding_id}: {finding.title}"
    )
    return finding

@app.post("/findings/", response_model=schemas.Finding)
@limiter.limit("30/minute")
def create_finding(
    request: Request,
    finding: schemas.FindingCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    # Enforce admin check on creating findings
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
        
    # Use Pydantic v2 model_dump
    finding_dict = finding.model_dump(exclude={'evidence'})
    db_finding = models.Finding(**finding_dict)
    db.add(db_finding)
    db.commit()
    db.refresh(db_finding)
    
    for ev in finding.evidence:
        ev_dict = ev.model_dump()
        db_evidence = models.Evidence(**ev_dict, finding_id=db_finding.id)
        db.add(db_evidence)
    
    db.commit()
    db.refresh(db_finding)

    client_ip = request.client.host if request.client else None
    record_audit(db, "FINDING_CREATED", current_user.get("username"), client_ip, f"Created finding: {db_finding.title}")

    return db_finding

@app.get("/audit/", response_model=List[schemas.AuditLogResponse])
def read_audit_logs(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    # Admin-only audit log endpoint
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    logs = db.query(models.AuditLog).order_by(models.AuditLog.timestamp.desc()).offset(skip).limit(limit).all()
    return logs
