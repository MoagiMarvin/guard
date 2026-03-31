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

def watcher_guard_agent(traffic_log: str) -> dict:
    """
    Analyzes raw network traffic, NetFlow, or firewall logs for malicious behavior.
    """
    if not traffic_log:
        return {"status": "SAFE", "reason": "Empty traffic log", "threat_level": "NONE"}

    # --- Fast Pre-check ---
    suspicious_patterns = ["Nmap", "masscan", "flood", "SYN_SENT", "malformed"]
    if any(pattern.lower() in traffic_log.lower() for pattern in suspicious_patterns):
        logger.info(f"Watcher Pre-check flagged suspicious network activity: {traffic_log}")

    prompt = f"""
    You are a cybersecurity expert specializing in Network Traffic Analysis and Intrusion Detection Systems (IDS).
    
    Analyse this network/firewall log and determine if it represents a security threat (e.g., DDoS, port scanning, data exfiltration, abnormal beaconing):
    
    Traffic Log: {traffic_log}
    
    Return your response in JSON format with the following keys:
    - status: (SAFE or DANGEROUS)
    - threat_level: (LOW, MEDIUM, or CRITICAL)
    - attack_type: (e.g., PORT_SCAN, DDOS, EXFILTRATION, NONE)
    - reason: (one sentence explanation of the network anomaly)
    - recommendation: (what firewall or routing action to take)
    """
    
    try:
        response = model.generate_content(
            prompt,
            generation_config={"response_mime_type": "application/json"}
        )
        parsed = json.loads(response.text)
        
        return {
            "log": traffic_log,
            "status": parsed.get("status", "UNKNOWN"),
            "threat_level": parsed.get("threat_level", "UNKNOWN"),
            "attack_type": parsed.get("attack_type", "NONE"),
            "reason": parsed.get("reason", ""),
            "recommendation": parsed.get("recommendation", "")
        }
    except Exception as e:
        logger.error(f"Watcher Guard AI Error: {e}")
        return {
            "log": traffic_log,
            "status": "ERROR",
            "threat_level": "UNKNOWN",
            "reason": f"Agent failed: {str(e)}",
            "recommendation": "Check API logs."
        }
