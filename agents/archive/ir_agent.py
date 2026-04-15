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

def incident_response_agent(threat_report: dict) -> dict:
    """
    Acts as the 'Muscle'. Takes a threat report (from DB, Log, or Watcher Guard)
    and determines the exact mitigation strategy and commands to execute.
    """
    if not threat_report or threat_report.get("status") != "DANGEROUS":
        return {"action": "NONE", "message": "No active threat detected. Standing by."}

    # Convert the dictionary output from another agent back to a string for the prompt
    report_string = json.dumps(threat_report, indent=2)

    prompt = f"""
    You are an automated Cybersecurity Incident Response (IR) Orchestrator.
    
    You have just received an active threat report from a detection agent:
    
    THREAT REPORT:
    {report_string}
    
    Your job is to determine the exact steps to mitigate this threat automatically.
    
    Return your response in JSON format strictly with the following keys:
    - action_type: (e.g., BLOCK_IP, DISABLE_USER, QUARANTINE_DB, REVOKE_IAM)
    - target: (The specific IP, Username, or Resource extracted from the report that needs to be neutralized)
    - windows_command: (The exact PowerShell or netsh command to execute the mitigation on a Windows Server)
    - linux_command: (The exact bash or iptables command to execute the mitigation on a Linux Server)
    - mitigation_summary: (A one-sentence summary of the action you are taking)
    """
    
    try:
        response = model.generate_content(
            prompt,
            generation_config={"response_mime_type": "application/json"}
        )
        parsed = json.loads(response.text)
        
        # In a real enterprise system, we would use Python's subprocess module here 
        # to actually run `parsed.get("windows_command")` directly on the host OS.
        # For safety in this environment, we are returning the command for execution simulation.
        
        logger.warning(f"IR Agent mapped target {parsed.get('target')} for {parsed.get('action_type')}")
        
        return {
            "mitigation_summary": parsed.get("mitigation_summary", "Executing emergency lockdown."),
            "action_type": parsed.get("action_type", "UNKNOWN"),
            "target": parsed.get("target", "UNKNOWN"),
            "windows_command": parsed.get("windows_command", "echo 'Manual intervention required'"),
            "linux_command": parsed.get("linux_command", "echo 'Manual intervention required'"),
            "execution_status": "SIMULATED_SUCCESS" # Represents the command was staged
        }
    except Exception as e:
        logger.error(f"IR Agent Error: {e}")
        return {
            "mitigation_summary": "Failed to determine mitigation strategy.",
            "action_type": "ERROR",
            "execution_status": "FAILED"
        }
