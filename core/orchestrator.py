"""
Guard SOC - Central Orchestrator
The brain that chains the 5 core agents into a linear middleware pipeline.
Clean Product Architecture.
"""
import logging
from datetime import datetime

from agents.injection_guard import injection_guard_agent
from agents.session_anchor import session_anchor_agent
from agents.compliance_agent import compliance_agent
from agents.deadman_switch import deadman_switch_agent
from agents.rate_limit_guard import rate_limit_guard_agent

logger = logging.getLogger(__name__)

def run_inspect_pipeline(request_data: dict, client_id: str = "Global") -> dict:
    """
    NEW LINEAR PIPELINE (Clean Product Architecture)
    Runs 5 agents in sequence for a single request. 
    Returns one definitive PASS or BLOCK decision.
    """
    started_at = datetime.utcnow().isoformat()
    logger.info("GUARD INSPECT PIPELINE STARTED — Client: %s", client_id)
    
    stages_results = []
    final_decision = "PASS"
    blocking_reason = ""
    blocking_agent = "NONE"
    
    # 1. LAYER 1: IDENTITY
    # Session Anchor Agent
    identity_res = session_anchor_agent(request_data)
    stages_results.append(identity_res)
    if identity_res["decision"] == "BLOCK":
        final_decision = "BLOCK"
        blocking_reason = identity_res["reason"]
        blocking_agent = identity_res["agent"]
    
    # 2. LAYER 2: INSPECTION
    # Injection Guard Agent (Only if not already blocked)
    if final_decision == "PASS":
        injection_res = injection_guard_agent(request_data)
        stages_results.append(injection_res)
        if injection_res["decision"] == "BLOCK":
            final_decision = "BLOCK"
            blocking_reason = injection_res["reason"]
            blocking_agent = injection_res["agent"]
            
    # Rate Limit Agent (Only if not already blocked)
    if final_decision == "PASS":
        rate_res = rate_limit_guard_agent(request_data)
        stages_results.append(rate_res)
        if rate_res["decision"] == "BLOCK":
            final_decision = "BLOCK"
            blocking_reason = rate_res["reason"]
            blocking_agent = rate_res["agent"]
            
    # 3. LAYER 3: EVIDENCE
    # Compliance Agent (Always runs, handles logging)
    compliance_res = compliance_agent(request_data, stages_results, client_id)
    
    # Dead Man Switch (Always runs, evaluates patterns)
    deadman_res = deadman_switch_agent(request_data, client_id)
    
    logger.info("PIPELINE COMPLETE — Decision: %s | Final Status: %s", final_decision, deadman_res["status"])
    
    return {
        "decision": final_decision,
        "reason": blocking_reason if final_decision == "BLOCK" else "Request passed all security layers.",
        "agent": blocking_agent,
        "confidence": 100, # Simplified
        "incident_id": compliance_res.get("audit_id"),
        "popia_logged": True,
        "deadman_status": deadman_res["status"],
        "metadata": {
            "started_at": started_at,
            "client_id": client_id,
            "flow": [r.get("agent") for r in stages_results]
        }
    }
