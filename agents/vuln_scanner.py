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

def vuln_scanner_agent(system_config: str) -> dict:
    """
    Proactively scans a system configuration, library list, or server snapshot
    for known vulnerabilities (CVEs) and zero-day risks.
    """
    if not system_config:
        return {"status": "SAFE", "reason": "No configuration provided", "threat_level": "NONE"}

    prompt = f"""
    You are an elite Offensive Security Engineer and Software Vulnerability Analyst.
    
    You have intercepted a system snapshot, configuration file, or list of software running on an internal server.
    
    Snapshot Data:
    {system_config}
    
    Your job is to identify if this setup is vulnerable to a cyber attack based on outdated software, weak configurations, or known CVEs (like Log4j, outdated Apache versions, insecure cipher suites).
    
    Return your response strictly in JSON format with the following keys:
    - vulnerability_found: (True or False)
    - threat_level: (LOW, MEDIUM, HIGH, or CRITICAL based on exploitability)
    - cve_reference: (The suspected CVE or weakness name, e.g., 'CVE-2021-44228' or 'Default Credentials')
    - attack_vector: (How a hacker would break into this, e.g., 'Remote Code Execution', 'Privilege Escalation')
    - remediation: (Exact steps the IT team must take to patch this weakness before we get attacked)
    """
    
    try:
        response = model.generate_content(
            prompt,
            generation_config={"response_mime_type": "application/json"}
        )
        parsed = json.loads(response.text)
        
        return {
            "log": "Vulnerability Scan",
            "vulnerability_found": parsed.get("vulnerability_found", False),
            "threat_level": parsed.get("threat_level", "SAFE"),
            "cve_reference": parsed.get("cve_reference", "None"),
            "attack_vector": parsed.get("attack_vector", "None"),
            "remediation": parsed.get("remediation", "System secure.")
        }
    except Exception as e:
        logger.error(f"Vuln Scanner AI Error: {e}")
        return {
            "log": "Vulnerability Scan Error",
            "vulnerability_found": "ERROR",
            "threat_level": "UNKNOWN",
            "reason": f"Agent failed: {str(e)}",
            "remediation": "Check API logs."
        }
