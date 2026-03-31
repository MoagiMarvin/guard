from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from agents.db_guard import db_guard_agent
from agents.log_guard import log_guard_agent
from agents.watcher_guard import watcher_guard_agent
from agents.cloud_guard import cloud_guard_agent
from agents.ir_agent import incident_response_agent

router = APIRouter()

class QueryRequest(BaseModel):
    query: str

class LogRequest(BaseModel):
    log_entry: str

class TrafficRequest(BaseModel):
    traffic_log: str

class CloudAuditRequest(BaseModel):
    cloud_audit_log: dict

class AnalysisResponse(BaseModel):
    status: str
    threat_level: str
    reason: str
    recommendation: str
    attack_type: str = "NONE"

class ThreatReportRequest(BaseModel):
    threat_report: dict

class ResponseAction(BaseModel):
    mitigation_summary: str
    action_type: str
    target: str
    windows_command: str
    linux_command: str
    execution_status: str

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

@router.post("/analyze/traffic", response_model=AnalysisResponse)
async def analyze_traffic(request: TrafficRequest):
    """
    Analyzes a network traffic/NetFlow log for DDoS or port scanning.
    """
    try:
        result = watcher_guard_agent(request.traffic_log)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/analyze/cloud", response_model=AnalysisResponse)
async def analyze_cloud(request: CloudAuditRequest):
    """
    Analyzes a Cloud IAM/audit event for misconfigurations.
    """
    try:
        result = cloud_guard_agent(request.cloud_audit_log)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/respond", response_model=ResponseAction)
async def trigger_response(request: ThreatReportRequest):
    """
    Triggers the Incident Response agent to generate a mitigation strategy
    based on a threat report from another guard.
    """
    try:
        result = incident_response_agent(request.threat_report)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
async def health_check():
    return {"status": "healthy", "agents": ["db_guard", "log_guard", "watcher_guard", "cloud_guard", "ir_agent"]}
