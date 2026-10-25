import datetime
import jwt
import os
import pytest
from backend.security.cvss import cvss_score, format_cvss
from backend.security.code_audit import CodeAuditCheck
from backend.security.config_audit import ConfigurationAuditCheck
from backend.security.data_privacy import DataPrivacyCheck
from backend.security.secret_scanner import SecretScannerCheck

# 1. Expired Token Test
def test_expired_token(client):
    secret_key = os.environ.get("SECRET_KEY", "test-secret-key-for-pytest-32-chars-long")
    algorithm = os.environ.get("ALGORITHM", "HS256")
    
    # Token expired 1 hour ago
    expired_payload = {
        "sub": "admin",
        "role": "admin",
        "exp": datetime.datetime.utcnow() - datetime.timedelta(hours=1)
    }
    expired_token = jwt.encode(expired_payload, secret_key, algorithm=algorithm)
    
    response = client.get(
        "/findings/",
        headers={"Authorization": f"Bearer {expired_token}"}
    )
    assert response.status_code == 401
    assert "Could not validate credentials" in response.text

# 2. Non-Admin POST Tests
def test_non_admin_post_findings_blocked(client, user_token):
    payload = {
        "title": "Unauthorized Finding",
        "category": "Test",
        "severity": "Low",
        "confidence": "High",
        "affected_component": "test",
        "description": "test",
        "impact": "test",
        "remediation": "test",
        "status": "Detected",
        "evidence": []
    }
    response = client.post(
        "/findings/",
        json=payload,
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 403
    assert "Admin privileges required" in response.text

def test_non_admin_post_users_blocked(client, user_token):
    payload = {
        "username": "escalated_user",
        "password": "ValidPassword123!",
        "role": "admin"
    }
    response = client.post(
        "/users/",
        json=payload,
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 403
    assert "Admin privileges required" in response.text

# 3. Account Lockout Test (5 failed logins -> locked for 15 minutes)
def test_account_lockout_after_five_failed_logins(client):
    # Create a fresh target user for lockout testing
    admin_login_res = client.post(
        "/token",
        data={"username": "admin", "password": "StrongTestPassword2026!"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    adm_token = admin_login_res.json()["access_token"]
    
    lockout_target = f"lockout_user_{int(datetime.datetime.utcnow().timestamp())}"
    create_res = client.post(
        "/users/",
        json={"username": lockout_target, "password": "SecurePassword123!", "role": "user"},
        headers={"Authorization": f"Bearer {adm_token}"}
    )
    assert create_res.status_code == 200

    # Execute 5 incorrect login attempts
    for i in range(5):
        fail_res = client.post(
            "/token",
            data={"username": lockout_target, "password": "WRONG_PASSWORD_XYZ"},
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        assert fail_res.status_code == 400

    # The 6th attempt must be rejected with 403 due to active account lockout
    locked_res = client.post(
        "/token",
        data={"username": lockout_target, "password": "WRONG_PASSWORD_XYZ"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert locked_res.status_code == 403
    assert "temporarily locked" in locked_res.json()["detail"]

# 4. Open Registration Blocked & Password Length Test
def test_open_registration_unauthenticated(client):
    # Unauthenticated registration must be rejected with 401
    res = client.post(
        "/users/",
        json={"username": "rogue_user", "password": "ValidPassword123!"}
    )
    assert res.status_code == 401

def test_password_minimum_length_enforced(client, admin_token):
    # Passwords under 10 characters must be rejected
    res = client.post(
        "/users/",
        json={"username": "short_pw_user", "password": "short1"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert res.status_code == 400
    assert "at least 10 characters" in res.json()["detail"]

def test_successful_user_creation_by_admin(client, admin_token):
    username = f"new_operator_{int(datetime.datetime.utcnow().timestamp())}"
    res = client.post(
        "/users/",
        json={"username": username, "password": "ValidPassword123!", "role": "user"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert res.status_code == 200
    assert res.json()["username"] == username

# 5. CVSS Helper Tests
def test_cvss_helper_computations():
    # Config audit vector must compute exactly 5.3
    config_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
    assert cvss_score(config_vector) == 5.3
    assert format_cvss(config_vector) == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N (5.3)"

    # Coordinates exposure vector must compute 7.5
    coord_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    assert cvss_score(coord_vector) == 7.5

    # Auth finding vector must compute 9.1
    auth_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    assert cvss_score(auth_vector) == 9.1

    # Critical secret exposure with scope changed must compute 10.0
    secret_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"
    assert cvss_score(secret_vector) == 10.0

# 6. Scanner Checks Tests
def test_code_audit_check_detects_remediations():
    check = CodeAuditCheck()
    findings = check.run_check({})
    assert len(findings) == 5
    for f in findings:
        assert f["status"] == "Remediated"
        assert f["cwe"] is not None
        assert f["owasp"] is not None
        assert len(f["evidence"]) == 2

def test_config_audit_groups_findings():
    dummy_dataset = {
        "news_channels": {
            "channels": {
                "full": [
                    {"handle": "feed1", "tier": 1},
                    {"handle": "feed2", "tier": 1, "accountId": "123"},
                    {"handle": "feed3", "tier": 1}
                ]
            }
        },
        "news_channels_x": {
            "channels": {
                "full": [
                    {"handle": "feed4", "tier": 1}
                ]
            }
        }
    }
    check = ConfigurationAuditCheck()
    findings = check.run_check(dummy_dataset)
    assert len(findings) == 1
    grouped = findings[0]
    assert grouped["severity"] == "Medium"
    assert "5.3" in grouped["cvss"]
    assert len(grouped["evidence"]) == 3  # feed1, feed3, feed4

def test_data_privacy_check():
    dummy_dataset = {
        "iaea_diif_db": {
            "facilities": [
                {"id": "fac-1", "city": "CityA", "country": "CountryA", "lat": 12.345678, "lon": 45.678901},
                {"id": "fac-2", "city": "CityB", "country": "CountryB", "lat": 23.456789, "lon": 56.789012}
            ]
        }
    }
    check = DataPrivacyCheck()
    findings = check.run_check(dummy_dataset)
    coord_finding = next(f for f in findings if "Exposure of Critical Infrastructure" in f["title"])
    assert coord_finding["severity"] == "High"
    assert len(coord_finding["evidence"]) == 2

def test_secret_scanner_check():
    dummy_dataset = {
        "config": {
            "aws_access": "AKIAIOSFODNN7EXAMPLE",
            "safe_val": "hello_world"
        }
    }
    check = SecretScannerCheck()
    findings = check.run_check(dummy_dataset)
    assert len(findings) == 1
    assert "Hardcoded Secrets Detected" in findings[0]["title"]
    assert findings[0]["severity"] == "Critical"

# 7. Role-Based Facilities Precision Test
def test_facilities_role_precision(client, admin_token, user_token):
    admin_res = client.get("/facilities/", headers={"Authorization": f"Bearer {admin_token}"})
    assert admin_res.status_code == 200
    admin_facs = admin_res.json()
    assert len(admin_facs) > 0

    user_res = client.get("/facilities/", headers={"Authorization": f"Bearer {user_token}"})
    assert user_res.status_code == 200
    user_facs = user_res.json()
    assert len(user_facs) > 0
    # User coordinates must be coarsened
    assert user_facs[0]["precision"] == "coarsened (0.5 deg grid)"

# 8. Audit Log Access Test
def test_audit_log_access(client, admin_token, user_token):
    # Non-admin access rejected
    non_admin_res = client.get("/audit/", headers={"Authorization": f"Bearer {user_token}"})
    assert non_admin_res.status_code == 403

    # Admin access approved
    admin_res = client.get("/audit/", headers={"Authorization": f"Bearer {admin_token}"})
    assert admin_res.status_code == 200
    logs = admin_res.json()
    assert isinstance(logs, list)
    assert len(logs) > 0
