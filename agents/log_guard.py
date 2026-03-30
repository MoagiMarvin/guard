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

def log_guard_agent(log_entry: str) -> dict:
    """
    Analyzes log entries for suspicious activity like brute force or unauthorized access.
    """
    if not log_entry:
        return {"status": "SAFE", "reason": "Empty log entry", "threat_level": "NONE"}

    prompt = f"""
    You are a cybersecurity expert specialising in log analysis and intrusion detection.
    
    Analyse this log entry and determine if it represents a security threat (e.g., brute force, unauthorized access, suspicious origin):
    
    Log Entry: {log_entry}
    
    Return your response in JSON format with the following keys:
    - status: (SAFE or DANGEROUS)
    - threat_level: (LOW, MEDIUM, or CRITICAL)
    - attack_type: (e.g., BRUTE_FORCE, UNAUTHORIZED_ACCESS, or NONE)
    - reason: (one sentence explanation)
    - recommendation: (what to do about it)
    """
    
    try:
        response = model.generate_content(
            prompt,
            generation_config={"response_mime_type": "application/json"}
        )
        parsed = json.loads(response.text)
        
        return {
            "log": log_entry,
            "status": parsed.get("status", "UNKNOWN"),
            "threat_level": parsed.get("threat_level", "UNKNOWN"),
            "attack_type": parsed.get("attack_type", "NONE"),
            "reason": parsed.get("reason", ""),
            "recommendation": parsed.get("recommendation", "")
        }
    except Exception as e:
        logger.error(f"Log Guard AI Error: {e}")
        return {
            "log": log_entry,
            "status": "ERROR",
            "threat_level": "UNKNOWN",
            "reason": f"Agent failed: {str(e)}",
            "recommendation": "Check API logs."
        }
