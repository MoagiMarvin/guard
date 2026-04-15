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

def sandbox_agent(malware_code: str) -> dict:
    """
    Static Code Analysis Sandbox.
    Reads raw, potentially obfuscated scripts (PowerShell, Bash, Python)
    and explains the attack vector without detonating the payload.
    """
    if not malware_code:
        return {"status": "SAFE", "threat_level": "None", "code_intent": "None"}

    prompt = f"""
    You are an elite Reverse Engineer and Malware Analyst working in a secure Sandbox.
    
    A SOC Endpoint agent caught an unknown, highly suspicious script trying to execute in memory. Here is the raw code:
    {malware_code}
    
    Your job is to act as a Static Code Analyzer. Read the code, de-obfuscate it mentally, and explain to a junior SOC analyst exactly what this code is programmed to do. Does it drop ransomware? Steal credentials? Open a reverse shell?
    
    Return your response strictly in JSON format with the following keys:
    - status: (MALICIOUS or SAFE)
    - threat_level: (LOW, MEDIUM, HIGH, CRITICAL)
    - attack_family: (e.g., 'Ransomware', 'Reverse Shell', 'Wiper', 'Benign Admin Script')
    - code_intent_summary: (A 2-sentence explanation of what the code actually does when executed)
    - c2_callbacks: (If the script contains an IP or URL it calls home to, list it here so we can block it. Otherwise 'None')
    """
    
    try:
        response = model.generate_content(
            prompt,
            generation_config={"response_mime_type": "application/json"}
        )
        parsed = json.loads(response.text)
        
        return {
            "log": "Sandbox Static Analysis",
            "status": parsed.get("status", "UNKNOWN"),
            "threat_level": parsed.get("threat_level", "UNKNOWN"),
            "attack_family": parsed.get("attack_family", "Unknown"),
            "code_intent_summary": parsed.get("code_intent_summary", "Failed to parse script intent."),
            "c2_callbacks": parsed.get("c2_callbacks", "None")
        }
    except Exception as e:
        logger.error(f"Sandbox AI Error: {e}")
        return {
            "log": "Sandbox Scan Error",
            "status": "ERROR",
            "threat_level": "None",
            "attack_family": "None",
            "code_intent_summary": f"Agent failed: {str(e)}",
            "c2_callbacks": "None"
        }
