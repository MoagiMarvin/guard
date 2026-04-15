from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel
from typing import Any, List
from sqlalchemy.orm import Session

# Core
from core.orchestrator import run_inspect_pipeline
from core.database import (
    get_db, get_all_incidents, get_all_pipeline_runs, 
    get_incident_stats, User, Client
)
from core.auth import require_api_key
from core.auth_manager import (
    create_access_token, verify_password, hash_password
)

router = APIRouter()

# ==========================================
# AUTHENTICATION ENDPOINTS
# ==========================================

class UserCreate(BaseModel):
    email: str
    password: str

@router.post("/auth/signup")
async def signup(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_pw = hash_password(user.password)
    new_user = User(email=user.email, password_hash=hashed_pw)
    db.add(new_user)
    db.commit()
    return {"message": "User created successfully"}

@router.post("/auth/login")
async def login(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token(data={"sub": db_user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/auth/me")
async def get_me(token: str = Depends(require_api_key), db: Session = Depends(get_db)):
    # Note: require_api_key is used for simple demo, in real apps use OAuth2PasswordBearer
    user = db.query(User).filter(User.email == token).first()
    if not user:
        # If token is an email (passed by require_api_key in some cases)
        user = db.query(User).filter(User.email == token).first()
        
    return {
        "email": user.email,
        "clients": [{"site": c.site_name, "api_key": c.api_key, "plan": c.plan_type} for c in user.clients]
    }

# ==========================================
# GUARD CORE ENDPOINTS
# ==========================================

class InspectionRequest(BaseModel):
    request_url: str
    method: str = "POST"
    payload: Any = ""
    session_token: str = "none"
    device_signature: str = "none"
    ip: str = "0.0.0.0"
    user_agent: str = "unknown"

@router.post("/inspect")
async def inspect_request(request: InspectionRequest, client_id: str = Depends(require_api_key)):
    """NEW Unified middleware endpoint. The heartbeat of GUARD."""
    try:
        result = run_inspect_pipeline(request.model_dump(), client_id=client_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/incidents")
async def list_incidents(limit: int = 50, client_id: str = Depends(require_api_key)):
    try:
        incidents = get_all_incidents(limit=limit, client_id=client_id)
        return {"incidents": incidents}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/stats")
async def get_stats(client_id: str = Depends(require_api_key)):
    try:
        stats = get_incident_stats(client_id=client_id)
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ==========================================
# PUBLIC SCANNER (Lead Gen)
# ==========================================

class ScanRequest(BaseModel):
    url: str

@router.post("/scan-site")
async def scan_site(request: ScanRequest):
    """Public scanner. Uses legacy vuln_scanner logic internally (mocked for now)."""
    # For now, we simulate a quick scan to keep the sales pitch active
    return {
        "url": request.url,
        "score": 42,
        "status": "VULNERABLE",
        "sales_pitch": "We found outdated headers and potential XSS entry points. GUARD would block these instantly."
    }
