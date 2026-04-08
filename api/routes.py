from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Any
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
from core.orchestrator import run_soc_pipeline
from core.database import get_all_incidents, get_all_pipeline_runs, get_incident_stats
from core.auth import require_api_key
router = APIRouter()


class QueryRequest(BaseModel):
    query: str

class LogRequest(BaseModel):
    log_entry: str

class TrafficRequest(BaseModel):
    traffic_log: str

class CloudAuditRequest(BaseModel):
    cloud_audit_log: dict

class HoneypotRequest(BaseModel):
    honeypot_interaction: str

class VulnScanRequest(BaseModel):
    system_config: str

class IntelRequest(BaseModel):
    indicator: str

class ReportRequest(BaseModel):
    incident_logs: list

class LockdownRequest(BaseModel):
    trigger_signal: str

class UebaRequest(BaseModel):
    user_activity_log: str

class PhishingRequest(BaseModel):
    email_content: str

class SandboxRequest(BaseModel):
    malware_code: str

class AnalysisResponse(BaseModel):
    status: str
    threat_level: str
    reason: str
    recommendation: str
    attack_type: str = "NONE"

class ThreatReportRequest(BaseModel):
    threat_report: dict

class PublicScanRequest(BaseModel):
    url: str

class PublicScanResponse(BaseModel):
    url: str
    status: str
    score: int
    risks_found: list
    priority_fix: str
    sales_pitch: str

class ResponseAction(BaseModel):
    mitigation_summary: str
    action_type: str
    target: str
    windows_command: str
    linux_command: str
    execution_status: str

class VulnScanResponse(BaseModel):
    vulnerability_found: bool
    threat_level: str
    cve_reference: str
    attack_vector: str
    remediation: str

class IntelResponse(BaseModel):
    indicator_analyzed: str
    suspected_actor: str
    confidence: str
    motive: str
    defense_intel: str

class ReportResponse(BaseModel):
    classification: str
    executive_summary: str
    timeline_reconstructed: list
    remaining_risk: str

class LockdownResponse(BaseModel):
    protocol_status: str
    simulated_encryption_progress: str
    decryption_key_storage: str
    ceo_sms_draft: str

class UebaResponse(BaseModel):
    status: str
    anomaly_score: int
    intent: str
    action_required: str

class PhishingResponse(BaseModel):
    status: str
    phishing_type: str
    malicious_url: str
    explanation: str

class SandboxResponse(BaseModel):
    status: str
    threat_level: str
    attack_family: str
    code_intent_summary: str
    c2_callbacks: str

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

@router.post("/analyze/honeypot", response_model=AnalysisResponse)
async def analyze_honeypot(request: HoneypotRequest):
    """
    Analyzes an interaction with a deceptive fake system (Honeypot).
    """
    try:
        result = honeypot_guard_agent(request.honeypot_interaction)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/analyze/vuln", response_model=VulnScanResponse)
async def analyze_vuln(request: VulnScanRequest):
    """
    Proactively scans a system configuration for known vulnerabilities (CVEs).
    """
    try:
        result = vuln_scanner_agent(request.system_config)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/analyze/intel", response_model=IntelResponse)
async def analyze_intel(request: IntelRequest):
    """
    Cross-references an IOC with known threat actors.
    """
    try:
        result = threat_intel_agent(request.indicator)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/report", response_model=ReportResponse)
async def generate_report(request: ReportRequest):
    """
    Synthesizes raw SOC logs into an executive summary.
    """
    try:
        result = reporting_agent(request.incident_logs)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/lockdown", response_model=LockdownResponse)
async def trigger_lockdown(request: LockdownRequest):
    """
    Triggers the Zero-Day Lockdown Protocol.
    """
    try:
        result = deadman_switch_agent(request.trigger_signal)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/analyze/ueba", response_model=UebaResponse)
async def analyze_ueba(request: UebaRequest):
    """
    Analyzes authenticated employee behavior to catch Insider Threats.
    """
    try:
        result = ueba_agent(request.user_activity_log)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/analyze/phishing", response_model=PhishingResponse)
async def analyze_phishing(request: PhishingRequest):
    """
    Analyzes raw email content for phishing attempts and extracts callbacks.
    """
    try:
        result = phishing_agent(request.email_content)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/analyze/sandbox", response_model=SandboxResponse)
async def analyze_sandbox(request: SandboxRequest):
    """
    Perform static code analysis on potentially malicious scripts.
    """
    try:
        result = sandbox_agent(request.malware_code)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan-site", response_model=PublicScanResponse)
async def scan_public_site(request: PublicScanRequest):
    """
    PUBLIC ENDPOINT: Performs a non-invasive vulnerability scan of a website.
    Used for marketing/lead generation. No API key needed for basic scans.
    """
    try:
        result = public_web_scan(request.url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
async def health_check():
    agents = [
        "db_guard", "log_guard", "watcher_guard", "cloud_guard", "ir_agent",
        "honeypot_guard", "vuln_scanner", "threat_intel", "reporting_agent",
        "deadman_switch", "ueba_agent", "phishing_agent", "sandbox_agent"
    ]
    return {"status": "healthy", "version": "1.0.0", "agents": agents, "total": len(agents)}


# ============================================================
# ORCHESTRATOR — Full SOC Pipeline (the main product feature)
# ============================================================

class PipelineRequest(BaseModel):
    threat_type: str  # e.g. "db", "phishing", "ueba", "sandbox", etc.
    payload: Any      # string or dict depending on threat_type


@router.post("/run")
async def run_pipeline(request: PipelineRequest, client_id: str = Depends(require_api_key)):
    """
    THE MAIN ENDPOINT. Runs the full SOC pipeline for a given threat type.

    threat_type options: db | log | traffic | cloud | honeypot | vuln | ueba | phishing | sandbox

    - Routes to correct detection agent automatically
    - If DANGEROUS: IR Agent + Threat Intel fire automatically
    - If CRITICAL: Dead Man Switch fires automatically
    - Reporting Agent always generates the executive summary
    - Everything is saved to the database with Client Identity (SaaS mode)
    """
    try:
        result = run_soc_pipeline(request.threat_type, request.payload, client_id=client_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# DATABASE ENDPOINTS — Incident History & Stats
# ============================================================

@router.get("/incidents")
async def list_incidents(limit: int = 50, client_id: str = Depends(require_api_key)):
    """Returns the most recent security incidents saved to the database (filtered by client)."""
    try:
        return {"incidents": get_all_incidents(limit=limit, client_id=client_id), "count": limit}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/pipeline-runs")
async def list_pipeline_runs(limit: int = 20, client_id: str = Depends(require_api_key)):
    """Returns the most recent full SOC pipeline runs with all agent outputs (filtered by client)."""
    try:
        return {"runs": get_all_pipeline_runs(limit=limit, client_id=client_id), "count": limit}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_stats(client_id: str = Depends(require_api_key)):
    """Returns aggregate SOC statistics for the dashboard (filtered by client)."""
    try:
        return get_incident_stats(client_id=client_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
