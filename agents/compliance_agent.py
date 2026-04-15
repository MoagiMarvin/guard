import os
import json
import logging
import hashlib
from datetime import datetime
from dotenv import load_dotenv
import google.generativeai as genai
from core.database import save_incident

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
model = genai.GenerativeModel("gemini-2.5-flash")

def compliance_agent(request_data: dict, pipeline_results: list, client_id: str) -> dict:
    """
    LAYER 3: EVIDENCE
    Logs every request into a POPIA-compliant audit trail.
    Synthesizes the pipeline results into a report if a block occurred.
    """
    decision_log = []
    final_decision = "PASS"
    blocking_agent = "NONE"
    
    for res in pipeline_results:
        decision_log.append({
            "agent": res.get("agent"),
            "decision": res.get("decision", "PASS"),
            "reason": res.get("reason", "")
        })
        if res.get("decision") == "BLOCK":
            final_decision = "BLOCK"
            blocking_agent = res.get("agent")

    # Generate internal audit hash for POPIA integrity
    payload_str = str(request_data.get("payload", ""))
    audit_hash = hashlib.sha256(f"{datetime.utcnow()}{payload_str}".encode()).hexdigest()
    
    # Save to database (Audit Trail)
    # We strip sensitive payload before long-term storage if it's a pass
    safe_payload = payload_str[:500] if final_decision == "BLOCK" else "[REDACTED FOR PRIVACY]"
    
    save_incident(
        client_id=client_id,
        agent="compliance_agent",
        status=final_decision,
        threat_level="HIGH" if final_decision == "BLOCK" else "LOW",
        payload=f"Audit Hash: {audit_hash} | Payload: {safe_payload}",
        result={
            "pipeline_summary": decision_log,
            "final_decision": final_decision,
            "blocking_agent": blocking_agent,
            "compliance_standard": "POPIA Section 19",
            "audit_hash": audit_hash,
            "requester_ip": request_data.get("ip", "0.0.0.0")
        }
    )
    
    logger.info(f"Compliance Agent: Audit log stored. Decision: {final_decision}. Hash: {audit_hash[:8]}")
    
    return {
        "popia_logged": True,
        "audit_id": audit_hash[:12],
        "compliance_status": "CERTIFIED",
        "final_decision": final_decision
    }

# Backwards compatibility wrapper for core/orchestrator.py
def compliance_agent_legacy_wrapper(incident_logs: list) -> dict:
    """Old reporting agent logic synthesis."""
    if not incident_logs:
        return {"status": "NO_INCIDENTS", "executive_summary": "All systems nominal."}
    
    prompt = f"""
    You are a CISO Reporting AI. Synthesize these technical logs into an executive report:
    {json.dumps(incident_logs, indent=2)}
    
    Respond in JSON: executive_summary (string), classification (string).
    """
    try:
        response = model.generate_content(prompt, generation_config={"response_mime_type": "application/json"})
        parsed = json.loads(response.text)
        return {
            "classification": parsed.get("classification", "ROUTINE"),
            "executive_summary": parsed.get("executive_summary", "Summary unavailable.")
        }
    except:
        return {"classification": "UNKNOWN", "executive_summary": "Failed to synthesize report."}
