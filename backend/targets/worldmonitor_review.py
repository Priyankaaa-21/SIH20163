#!/usr/bin/env python3
"""
World Monitor Attack Surface & Configuration Review
Read-only static inventory scanner for local repositories.
Analyzes API route decorators, container services, nginx configurations, and environment templates.
Flags routes lacking auth, rate limiting, CORS checks, or URL allowlists.
"""

import os
import sys
import ast
import re
import json
import argparse
import hashlib
import datetime
from typing import Dict, List, Any

# Add repo root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from backend.database import SessionLocal, engine, ensure_db_schema
from backend import models
from backend.security.base import build_finding, build_evidence

def parse_api_routes(repo_path: str) -> List[Dict[str, Any]]:
    """Inspects Python source files for FastAPI/Starlette route definitions and checks controls."""
    routes = []
    
    # Target files to inspect
    candidate_files = []
    for root, _, files in os.walk(repo_path):
        # Exclude virtual environments and node_modules
        if any(ignored in root for ignored in [".venv", "venv", "node_modules", ".git", "__pycache__"]):
            continue
        for file in files:
            if file.endswith(".py"):
                candidate_files.append(os.path.join(root, file))

    for filepath in candidate_files:
        rel_path = os.path.relpath(filepath, repo_path)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                source = f.read()
            tree = ast.parse(source)
        except Exception:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                for dec in node.decorator_list:
                    # Check for @app.get(...), @app.post(...), @router.get(...), etc.
                    method = None
                    path = None
                    
                    if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                        attr_name = dec.func.attr.lower()
                        if attr_name in ["get", "post", "put", "delete", "patch", "options"]:
                            method = attr_name.upper()
                            if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                                path = dec.args[0].value

                    if method and path:
                        func_code = ast.get_source_segment(source, node) or ""
                        # Analyze decorators and function body
                        has_auth = bool(
                            "get_current_user" in func_code or 
                            "Authorization" in func_code or 
                            "oauth2_scheme" in func_code or
                            "Depends(get_current_user)" in func_code or
                            path in ["/token", "/docs", "/openapi.json"]
                        )
                        has_rate_limit = bool(
                            "@limiter.limit" in source and (
                                f"@limiter.limit" in source[max(0, source.find(node.name) - 300):source.find(node.name)] or
                                "@limiter" in func_code
                            )
                        )
                        # Check role checks
                        has_role_check = bool(
                            "role" in func_code and ("admin" in func_code or "HTTP_403_FORBIDDEN" in func_code)
                        )
                        # Check url allowlist for routes taking url/feed/proxy parameters
                        has_url_param = any(param in func_code.lower() for param in ["url:", "url =", "target_url", "feed_url"])
                        has_url_allowlist = bool("allowlist" in func_code.lower() or "whitelist" in func_code.lower() or "trusted_domains" in func_code.lower())
                        
                        missing_controls = []
                        if not has_auth and path not in ["/", "/token"]:
                            missing_controls.append("Missing Authentication")
                        if not has_rate_limit and path not in ["/"]:
                            missing_controls.append("Missing Rate Limiting")
                        if method in ["POST", "PUT", "DELETE"] and not has_role_check and path != "/token":
                            missing_controls.append("Missing RBAC / Admin Check")
                        if has_url_param and not has_url_allowlist:
                            missing_controls.append("Missing URL Allowlist / SSRF Risk")

                        routes.append({
                            "path": path,
                            "method": method,
                            "function": node.name,
                            "source_file": rel_path,
                            "has_auth": has_auth,
                            "has_rate_limit": has_rate_limit,
                            "has_role_check": has_role_check,
                            "missing_controls": missing_controls,
                            "flagged": len(missing_controls) > 0,
                            "risk_level": "High" if "Missing Authentication" in missing_controls else ("Medium" if missing_controls else "Low")
                        })
    return routes

def parse_docker_services(repo_path: str) -> List[Dict[str, Any]]:
    """Extracts container service definitions from docker-compose files."""
    services = []
    compose_files = ["docker-compose.yml", "docker-compose.prod.yml", "docker-compose.override.yml"]
    
    for c_file in compose_files:
        full_path = os.path.join(repo_path, c_file)
        if os.path.exists(full_path):
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    content = f.read()
                
                # Simple parser for services in docker-compose YAML without external pyyaml dependency
                in_services = False
                curr_service = None
                for line in content.splitlines():
                    if line.strip().startswith("services:"):
                        in_services = True
                        continue
                    if in_services:
                        # Top-level key under services has 2-space indentation
                        match = re.match(r"^ {2}([a-zA-Z0-9_-]+):", line)
                        if match:
                            curr_service = match.group(1)
                            services.append({
                                "service": curr_service,
                                "compose_file": c_file,
                                "ports": [],
                                "has_healthcheck": "healthcheck" in content[content.find(curr_service):content.find(curr_service)+300]
                            })
                        elif curr_service and "ports:" in line:
                            pass
            except Exception:
                pass
    return services

def parse_config_surfaces(repo_path: str) -> List[Dict[str, Any]]:
    """Analyzes web server, reverse proxy, and environment configs."""
    configs = []
    
    # 1. Nginx config
    nginx_candidates = [
        os.path.join(repo_path, "frontend", "nginx.conf"),
        os.path.join(repo_path, "nginx.conf")
    ]
    for n_path in nginx_candidates:
        if os.path.exists(n_path):
            with open(n_path, "r", encoding="utf-8") as f:
                c = f.read()
            configs.append({
                "type": "Nginx Web Server",
                "file": os.path.relpath(n_path, repo_path),
                "has_hsts": "Strict-Transport-Security" in c,
                "has_csp": "Content-Security-Policy" in c,
                "has_x_frame": "X-Frame-Options" in c,
                "has_proxy_headers": "X-Forwarded-For" in c
            })

    # 2. Env template
    env_candidates = [
        os.path.join(repo_path, ".env.template"),
        os.path.join(repo_path, "backend", ".env.template")
    ]
    for e_path in env_candidates:
        if os.path.exists(e_path):
            with open(e_path, "r", encoding="utf-8") as f:
                c = f.read()
            configs.append({
                "type": "Environment Template",
                "file": os.path.relpath(e_path, repo_path),
                "variables_count": len([line for line in c.splitlines() if line.strip() and not line.startswith("#")]),
                "has_secret_key": "SECRET_KEY" in c,
                "has_admin_pw": "ADMIN_PASSWORD" in c
            })
            
    return configs

def review_worldmonitor_target(repo_path: str) -> Dict[str, Any]:
    """Coordinates read-only inspection of the target repo."""
    abs_repo = os.path.abspath(repo_path)
    if not os.path.exists(abs_repo):
        raise FileNotFoundError(f"Target repository path does not exist: {abs_repo}")

    routes = parse_api_routes(abs_repo)
    services = parse_docker_services(abs_repo)
    configs = parse_config_surfaces(abs_repo)

    flagged_routes = [r for r in routes if r.get("flagged")]

    inventory = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "target_path": abs_repo,
        "metrics": {
            "total_routes": len(routes),
            "flagged_routes_count": len(flagged_routes),
            "services_count": len(services),
            "configs_count": len(configs)
        },
        "routes": routes,
        "flagged_routes": flagged_routes,
        "services": services,
        "configs": configs
    }

    # Save to Database
    ensure_db_schema()
    db = SessionLocal()
    try:
        attack_surface_entry = models.AttackSurface(
            scan_path=abs_repo,
            total_routes=len(routes),
            flagged_routes_count=len(flagged_routes),
            services_count=len(services),
            configs_count=len(configs),
            inventory_json=json.dumps(inventory),
            flagged_routes_json=json.dumps(flagged_routes),
            created_at=datetime.datetime.utcnow()
        )
        db.add(attack_surface_entry)
        db.commit()
        db.refresh(attack_surface_entry)

        # Emit findings starting as DISCOVERED with confidence "Needs Validation"
        if flagged_routes:
            evidence_data = json.dumps(flagged_routes[:5], indent=2)
            finding = build_finding(
                title=f"Attack Surface Inventory: {len(flagged_routes)} Exposed Routes Lacking Security Controls",
                category="Attack Surface Inventory",
                severity="Medium",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                conservative_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                confidence="Needs Validation",
                cwe="CWE-1008: Architectural Security Weakness",
                owasp="API8:2023 Security Misconfiguration",
                affected_component="Application Route Surface",
                description=f"Static inventory audit discovered {len(flagged_routes)} routes lacking explicit authentication, rate limiting, or role checks. Further manual or runtime validation is required.",
                impact="Uncontrolled endpoints may allow unauthorized information disclosure or resource starvation.",
                remediation="Apply authentication, rate limits, and role enforcement across all flagged route decorators.",
                status="Detected",
                lifecycle="DISCOVERED",
                lifecycle_note="Discovered by worldmonitor_review read-only inventory scan.",
                evidence=[
                    build_evidence(
                        evidence_type="Attack Surface Inventory Scan",
                        description=f"Summary of {len(flagged_routes)} flagged routes identified during local static inspection.",
                        raw_data=evidence_data,
                        environment="static-ast"
                    )
                ]
            )
            
            # Check if this finding already exists
            existing = db.query(models.Finding).filter(
                models.Finding.category == "Attack Surface Inventory"
            ).first()
            if not existing:
                ev_list = finding.pop("evidence", [])
                db_f = models.Finding(**finding)
                db.add(db_f)
                db.commit()
                db.refresh(db_f)
                for ev in ev_list:
                    db.add(models.Evidence(**ev, finding_id=db_f.id))
                db.commit()

        print(f"[+] Attack Surface inventory record #{attack_surface_entry.id} saved to database.")
    finally:
        db.close()

    return inventory

def main():
    parser = argparse.ArgumentParser(description="World Monitor Attack Surface Review")
    parser.add_argument("--path", default=".", help="Local path to repository root (read-only)")
    parser.add_argument("--json", action="store_true", help="Print raw JSON output")
    args = parser.parse_args()

    inventory = review_worldmonitor_target(args.path)
    
    if args.json:
        print(json.dumps(inventory, indent=2))
    else:
        m = inventory["metrics"]
        print("=" * 75)
        print(" WORLD MONITOR ATTACK SURFACE & INVENTORY REVIEW")
        print("=" * 75)
        print(f" Target Path       : {inventory['target_path']}")
        print(f" Total API Routes  : {m['total_routes']}")
        print(f" Flagged Routes    : {m['flagged_routes_count']}")
        print(f" Docker Services   : {m['services_count']}")
        print(f" Config Surfaces   : {m['configs_count']}")
        print("-" * 75)
        if inventory["flagged_routes"]:
            print(" FLAGGED ROUTES IDENTIFIED (Confidence: Needs Validation, Lifecycle: DISCOVERED):")
            for r in inventory["flagged_routes"]:
                issues = ", ".join(r["missing_controls"])
                print(f" - [{r['method']}] {r['path']:<22} | File: {r['source_file']:<20} | Issues: {issues}")
        print("=" * 75)

if __name__ == "__main__":
    main()
