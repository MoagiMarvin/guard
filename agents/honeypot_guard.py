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

def honeypot_guard_agent(honeypot_interaction: str) -> dict:
    """
    Analyzes an interaction with a deceptive fake system (Honeypot).
    Extracts the attacker's Tactics, Techniques, and Procedures (TTPs).
    """
    if not honeypot_interaction:
        return {"status": "SAFE", "reason": "No interaction logged", "threat_level": "NONE"}

    prompt = f"""
    You are an elite Cyber Threat Intelligence (CTI) expert specializing in Deception Technology and Honeypots.
    
    An attacker has just interacted with one of our Honeypot systems (a fake database, fake SSH server, or fake web admin panel).
    
    Here is the log of their interaction:
    {honeypot_interaction}
    
    Your job is to profile the attacker. Determine what they were trying to do, their skill level, and recommend how to block them across the real network.
    
    Return your response strictly in JSON format with the following keys:
    - status: (Must be DANGEROUS, because any interaction with a honeypot is inherently malicious)
    - threat_level: (LOW, MEDIUM, or CRITICAL based on the sophistication of the payload)
    - attacker_profile: (A one-sentence description of the attacker's assumed intent or skill level)
    - attack_type: (e.g., RECONNAISSANCE, EXPLOITATION, BRUTE_FORCE)
    - recommendation: (What should we do with this IP address on the main network?)
    """
    
    try:
        response = model.generate_content(
            prompt,
            generation_config={"response_mime_type": "application/json"}
        )
        parsed = json.loads(response.text)
        
        return {
            "log": "Honeypot Triggered",
            "status": parsed.get("status", "DANGEROUS"),
            "threat_level": parsed.get("threat_level", "UNKNOWN"),
            "attack_type": parsed.get("attack_type", "UNKNOWN"),
            "attacker_profile": parsed.get("attacker_profile", "Unknown"),
            "recommendation": parsed.get("recommendation", "Block IP globally.")
        }
    except Exception as e:
        logger.error(f"Honeypot Guard AI Error: {e}")
        return {
            "log": "Honeypot Error",
            "status": "ERROR",
            "threat_level": "UNKNOWN",
            "reason": f"Agent failed: {str(e)}",
            "recommendation": "Check API logs."
        }
