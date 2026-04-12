from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel
from typing import Any, List
from sqlalchemy.orm import Session

# Agents
from agents.db_guard import db_guard_agent
from agents.log_guard import log_guard_agent
from agents.watcher_guard import watcher_guard_agent
from agents.cloud_guard import cloud_guard_agent
from agents.ir_agent import incident_response_agent
from agents.honeypot_guard import honeypot_guard_agent
from agents.vuln_scanner import vuln_scanner_agent, public_web_scan
from agents.threat_intel import threat_intel_agent
from agents.reporting_agent import reporting_agent
from agents.deadman_switch import deadman_switch_agent
from agents.ueba_agent import ueba_agent
from agents.phishing_agent import phishing_agent
from agents.sandbox_agent import sandbox_agent
from agents.auth_guard import auth_guard_agent
from agents.dark_intel_agent import dark_intel_agent

# Core
from core.orchestrator import run_soc_pipeline
from core.database import (
    get_db, get_all_incidents, get_all_pipeline_runs, 
    get_incident_stats, User, Client
)
from core.auth import require_api_key
from core.auth_manager import (
    hash_password, verify_password, create_access_token, 
    get_current_user, generate_api_key
)

router = APIRouter()

# ==========================================
# AUTHENTICATION SCHEMAS
# ==========================================

class UserSignup(BaseModel):
    email: str
    password: str
    site_name: str

class UserLogin(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# ==========================================
# AUTHENTICATION ROUTES
# ==========================================

@router.post("/auth/signup", response_model=Token)
async def signup(request: UserSignup, db: Session = Depends(get_db)):
    """Creates a new GUARD account and generates the first API key."""
    # 1. Check if user exists
    existing_user = db.query(User).filter(User.email == request.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # 2. Create User
    new_user = User(
        email=request.email,
        password_hash=hash_password(request.password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # 3. Create First Client/Key
    new_client = Client(
        user_id=new_user.id,
        site_name=request.site_name,
        api_key=generate_api_key()
    )
    db.add(new_client)
    db.commit()
    
    # 4. Return Token
    access_token = create_access_token(data={"sub": new_user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/auth/login", response_model=Token)
async def login(request: UserLogin, db: Session = Depends(get_db)):
    """Authenticates a user and returns a session token."""
    user = db.query(User).filter(User.email == request.email).first()
    if not user or not verify_password(request.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/auth/me")
async def get_me(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Returns the current user's profile and their protection keys."""
    clients = db.query(Client).filter(Client.user_id == current_user.id).all()
    return {
        "email": current_user.email,
        "clients": [
            {"site_name": c.site_name, "api_key": c.api_key, "plan": c.plan_type} 
            for c in clients
        ]
    }

# ==========================================
# THREAT ANALYSIS MODELS
# ==========================================

class QueryRequest(BaseModel): query: str
class LogRequest(BaseModel): log_entry: str
class TrafficRequest(BaseModel): traffic_log: str
class CloudAuditRequest(BaseModel): cloud_audit_log: dict
class AnalysisResponse(BaseModel):
    status: str
    threat_level: str
    reason: str
    recommendation: str
    attack_type: str = "NONE"

# ==========================================
# PROTECTED SOC ENDPOINTS
# ==========================================

class PipelineRequest(BaseModel):
    threat_type: str
    payload: Any

@router.post("/run")
async def run_pipeline(request: PipelineRequest, client_id: str = Depends(require_api_key)):
    """THE MAIN ENDPOINT. Verification is handled by require_api_key dependency."""
    try:
        result = run_soc_pipeline(request.threat_type, request.payload, client_id=client_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/incidents")
async def list_incidents(limit: int = 50, client_id: str = Depends(require_api_key)):
    try:
        return {"incidents": get_all_incidents(limit=limit, client_id=client_id), "count": limit}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/stats")
async def get_stats(client_id: str = Depends(require_api_key)):
    try:
        return get_incident_stats(client_id=client_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ==========================================
# PUBLIC MARKETING ENDPOINTS
# ==========================================

class PublicScanRequest(BaseModel): url: str
class PublicScanResponse(BaseModel):
    url: str
    status: str
    score: int
    risks_found: list
    priority_fix: str
    sales_pitch: str

@router.post("/scan-site", response_model=PublicScanResponse)
async def scan_public_site(request: PublicScanRequest):
    try:
        return public_web_scan(request.url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
async def health_check():
    return {"status": "healthy", "version": "1.2.0-SENTINEL"}
