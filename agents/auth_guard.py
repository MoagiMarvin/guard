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

def auth_guard_agent(request_data: str) -> dict:
    """
    Analyzes identity and access patterns to detect Broken Access Control (OWASP A01).
    Focuses on IDOR, JWT tampering, and Privilege Escalation.
    """
    if not request_data:
        return {"status": "SAFE", "reason": "No request data provided", "threat_level": "NONE"}

    prompt = f"""
    You are an elite Identity and Access Management (IAM) Security Auditor.
    
    Analyze the following request data, session tokens, or access patterns for signs of Broken Access Control (OWASP A01):
    
    Request Data:
    {request_data}
    
    Identify if this represents:
    - IDOR (Insecure Direct Object Reference) - e.g., accessing 'user/10' while logged in as 'user/5'.
    - JWT Tampering - e.g., 'alg: none' or invalid signatures.
    - Privilege Escalation - e.g., a regular user attempting to hit '/admin' endpoints.
    - Missing Auth - e.g., sensitive actions without tokens.
    
    Return your response strictly in JSON format with the following keys:
    - status: (SAFE or DANGEROUS)
    - threat_level: (LOW, MEDIUM, HIGH, or CRITICAL)
    - attack_type: (IDOR, JWT_TAMPER, PRIV_ESCALATION, MISSING_AUTH, or NONE)
    - reason: (One sentence explaining the identity logic flaw found)
    - recommendation: (How to fix the access control code, e.g., 'Add ownership check in DB query')
    """
    
    try:
        response = model.generate_content(
            prompt,
            generation_config={"response_mime_type": "application/json"}
        )
        parsed = json.loads(response.text)
        
        return {
            "log": "Identity & Access Audit",
            "status": parsed.get("status", "UNKNOWN"),
            "threat_level": parsed.get("threat_level", "UNKNOWN"),
            "attack_type": parsed.get("attack_type", "NONE"),
            "reason": parsed.get("reason", "Identity pattern analyzed."),
            "recommendation": parsed.get("recommendation", "Ensure robust authorization logic.")
        }
    except Exception as e:
        logger.error(f"Auth Guard AI Error: {e}")
        return {
            "log": "Auth Guard Error",
            "status": "ERROR",
            "threat_level": "UNKNOWN",
            "reason": f"Identity agent failed: {str(e)}",
            "recommendation": "Check API logs and IAM configuration."
        }
