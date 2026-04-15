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

def ueba_agent(user_activity_log: str) -> dict:
    """
    User and Entity Behavior Analytics (UEBA).
    Analyzes authenticated employee behavior to catch Insider Threats like data exfiltration.
    """
    if not user_activity_log:
        return {"status": "SAFE", "anomaly_score": 0, "intent": "None"}

    prompt = f"""
    You are an elite Employee Insider Threat Investigator (UEBA System).
    
    A fully authenticated employee has performed the following actions today:
    {user_activity_log}
    
    Your job is to determine if this is normal business activity OR a malicious insider threat (e.g., an employee stealing data before quitting, or a compromised account).
    
    Return your response strictly in JSON format with the following keys:
    - status: (SAFE, SUSPICIOUS, or CRITICAL)
    - anomaly_score: (1 to 100, where 100 means obvious data theft)
    - intent: (What is the employee trying to do? e.g., 'Normal Operations', 'Data Exfiltration', 'Sabotage')
    - action_required: (What HR or the SOC team should do immediately, e.g., 'Lock AD Account', 'Monitor Only')
    """
    
    try:
        response = model.generate_content(
            prompt,
            generation_config={"response_mime_type": "application/json"}
        )
        parsed = json.loads(response.text)
        
        return {
            "log": "UEBA Scan",
            "status": parsed.get("status", "UNKNOWN"),
            "anomaly_score": parsed.get("anomaly_score", 0),
            "intent": parsed.get("intent", "Unknown"),
            "action_required": parsed.get("action_required", "Verify Activity manually")
        }
    except Exception as e:
        logger.error(f"UEBA AI Error: {e}")
        return {
            "log": "UEBA Scan Error",
            "status": "ERROR",
            "anomaly_score": -1,
            "intent": f"Agent failed: {str(e)}",
            "action_required": "Check API Logs"
        }
