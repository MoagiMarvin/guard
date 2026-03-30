from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from agents.db_guard import db_guard_agent
from agents.log_guard import log_guard_agent

router = APIRouter()

class QueryRequest(BaseModel):
    query: str

class LogRequest(BaseModel):
    log_entry: str

class AnalysisResponse(BaseModel):
    status: str
    threat_level: str
    reason: str
    recommendation: str
    attack_type: str = "NONE"

@router.post("/analyze/db", response_model=AnalysisResponse)
async def analyze_db(request: QueryRequest):
    """
    Analyzes a database query for SQL injection threats.
    """
    try:
        result = db_guard_agent(request.query)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/analyze/log", response_model=AnalysisResponse)
async def analyze_log(request: LogRequest):
    """
    Analyzes a log entry for suspicious patterns.
    """
    try:
        result = log_guard_agent(request.log_entry)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
async def health_check():
    return {"status": "healthy", "agents": ["db_guard", "log_guard"]}
