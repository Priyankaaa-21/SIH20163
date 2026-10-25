import os
import sys

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient

# Ensure required environment variables for test execution
os.environ["SECRET_KEY"] = "test-secret-key-for-pytest-32-chars-long"
os.environ["ALGORITHM"] = "HS256"
os.environ["ADMIN_PASSWORD"] = "StrongTestPassword2026!"
os.environ["FRONTEND_URL"] = "http://localhost:5173"

from backend.main import app, get_password_hash
from backend.database import get_db, Base
from backend import models
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Disable rate limiting during automated test suite to prevent 429 errors
app.state.limiter.enabled = False

TEST_DATABASE_URL = "sqlite:///./test_assessment.db"
test_engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

@pytest.fixture(scope="session", autouse=True)
def setup_database():
    Base.metadata.create_all(bind=test_engine)
    db = TestingSessionLocal()
    # Seed admin user
    admin = db.query(models.User).filter(models.User.username == "admin").first()
    if not admin:
        admin = models.User(
            username="admin",
            hashed_password=get_password_hash("StrongTestPassword2026!"),
            role="admin",
            failed_login_attempts=0
        )
        db.add(admin)
    # Seed standard user
    regular = db.query(models.User).filter(models.User.username == "testuser").first()
    if not regular:
        regular = models.User(
            username="testuser",
            hashed_password=get_password_hash("UserPassword123!"),
            role="user",
            failed_login_attempts=0
        )
        db.add(regular)
    db.commit()
    db.close()
    yield
    Base.metadata.drop_all(bind=test_engine)
    if os.path.exists("./test_assessment.db"):
        os.remove("./test_assessment.db")

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def admin_token(client):
    res = client.post(
        "/token",
        data={"username": "admin", "password": "StrongTestPassword2026!"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert res.status_code == 200, res.text
    return res.json()["access_token"]

@pytest.fixture
def user_token(client):
    res = client.post(
        "/token",
        data={"username": "testuser", "password": "UserPassword123!"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert res.status_code == 200, res.text
    return res.json()["access_token"]
