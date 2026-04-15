import os
import json
import logging
from dotenv import load_dotenv
import google.generativeai as genai

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
model = genai.GenerativeModel("gemini-2.5-flash")

def cloud_guard_agent(cloud_audit_log: dict) -> dict:
    """
    Analyzes AWS/Azure Control Plane logs (e.g., CloudTrail events, IAM changes, S3 bucket policy changes).
    Accepts JSON strings or dictionaries from the API.
    """
    if not cloud_audit_log:
        return {"status": "SAFE", "reason": "Empty cloud audit log", "threat_level": "NONE"}

    # Convert dict to string for the prompt
    if isinstance(cloud_audit_log, dict):
        log_snippet = json.dumps(cloud_audit_log, indent=2)
    else:
        log_snippet = str(cloud_audit_log)

    prompt = f"""
    You are a Cloud Security Posture Management (CSPM) and IAM expert.
    
    Analyse this cloud infrastructure audit event (AWS CloudTrail, Azure Monitor, etc.) and determine if it represents a security vulnerability or exploit:
    
    Event Data:
    {log_snippet}
    
    Look for: S3 buckets made public, highly privileged IAM roles being attached, deletion of audit trails, or impossible travel logins to the cloud console.
    
    Return your response in JSON format with the following keys:
    - status: (SAFE or DANGEROUS)
    - threat_level: (LOW, MEDIUM, or CRITICAL)
    - attack_type: (e.g., IAM_ESCALATION, EXPOSED_STORAGE, TRAIL_TAMPERING, NONE)
    - reason: (one sentence explanation of the cloud risk)
    - recommendation: (what IAM or policy remediation to apply immediately)
    """
    
    try:
        response = model.generate_content(
            prompt,
            generation_config={"response_mime_type": "application/json"}
        )
        parsed = json.loads(response.text)
        
        return {
            "log": "Cloud Audit Event",
            "status": parsed.get("status", "UNKNOWN"),
            "threat_level": parsed.get("threat_level", "UNKNOWN"),
            "attack_type": parsed.get("attack_type", "NONE"),
            "reason": parsed.get("reason", ""),
            "recommendation": parsed.get("recommendation", "")
        }
    except Exception as e:
        logger.error(f"Cloud Guard AI Error: {e}")
        return {
            "log": "Cloud Audit Event",
            "status": "ERROR",
            "threat_level": "UNKNOWN",
            "reason": f"Agent failed: {str(e)}",
            "recommendation": "Check API logs."
        }
