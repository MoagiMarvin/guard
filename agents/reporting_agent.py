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

def reporting_agent(incident_logs: list) -> dict:
    """
    Acts as the Executive Reporting desk. Takes an array of raw system alerts and mitigation logs
    and converts them into a boardroom-ready CISO briefing.
    """
    if not incident_logs:
        return {"status": "NO_INCIDENTS", "report": "No incidents to report.", "executive_summary": "All systems nominal."}

    logs_string = json.dumps(incident_logs, indent=2)

    prompt = f"""
    You are the Chief Information Security Officer (CISO) Reporting AI.
    
    A severe cyber incident just concluded, handled by our automated SOC agents.
    Here is the raw data dump of what happened (The Detection logs, the IR mitigation, the Intels):
    
    RAW INCIDENT LOGS:
    {logs_string}
    
    Your job is to synthesize these technical logs into a clear, professional, executive-level "Post-Incident Report".
    
    Return your response strictly in JSON format with the following keys:
    - classification: (e.g., SEV-1, SEV-2, ROUTINE_BLOCK)
    - executive_summary: (A 2-3 sentence paragraph explaining to the CEO what happened, who did it, and how we stopped it)
    - timeline_reconstructed: (An array of strings creating a timeline of key events, like ['10:42 Watcher flagged DDoS', '10:42 IR blocked IP IP', etc.])
    - remaining_risk: (Any outstanding vulnerabilities or ongoing monitoring required)
    """
    
    try:
        response = model.generate_content(
            prompt,
            generation_config={"response_mime_type": "application/json"}
        )
        parsed = json.loads(response.text)
        
        return {
            "log": "Executive Reporting Completed",
            "classification": parsed.get("classification", "UNKNOWN"),
            "executive_summary": parsed.get("executive_summary", "Summary unavailable."),
            "timeline_reconstructed": parsed.get("timeline_reconstructed", []),
            "remaining_risk": parsed.get("remaining_risk", "Unknown.")
        }
    except Exception as e:
        logger.error(f"Reporting AI Error: {e}")
        return {
            "log": "Reporting Error",
            "classification": "ERROR",
            "executive_summary": f"Failed to generate report: {str(e)}",
            "timeline_reconstructed": [],
            "remaining_risk": "High."
        }
