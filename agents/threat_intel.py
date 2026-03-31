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

def threat_intel_agent(indicator: str) -> dict:
    """
    Acts as the Cyber Threat Intelligence (CTI) desk. Takes an indicator of compromise (IoC)
    like an IP, file hash, or behavioral log, and maps it to known threat actors (APTs).
    """
    if not indicator:
        return {"status": "UNKNOWN", "threat_actor": "None", "confidence": "LOW"}

    prompt = f"""
    You are an elite Cyber Threat Intelligence (CTI) operations desk.
    
    Analyze the following Indicator of Compromise (IoC) or attack behavior:
    {indicator}
    
    Your job is to cross-reference this behavior with known global threat actors, APTs, or ransomware gangs (e.g., Lazarus Group, LockBit, Cozy Bear, Anonymous, automated botnets).
    
    Return your response strictly in JSON format with the following keys:
    - indicator_analyzed: (the IP or behavior you analyzed)
    - suspected_actor: (The name of the suspected hacking group or 'Generic Automated Botnet')
    - confidence: (LOW, MEDIUM, HIGH, or EXPERT)
    - motive: (What does this group usually want? e.g., Financial Extortion, Espionage, Disruptive)
    - defense_intel: (A single sentence on the best strategic defense against this specific actor's usual TTPs)
    """
    
    try:
        response = model.generate_content(
            prompt,
            generation_config={"response_mime_type": "application/json"}
        )
        parsed = json.loads(response.text)
        
        return {
            "log": "Threat Intel Report",
            "indicator_analyzed": parsed.get("indicator_analyzed", "UNKNOWN"),
            "suspected_actor": parsed.get("suspected_actor", "Unknown Actor"),
            "confidence": parsed.get("confidence", "LOW"),
            "motive": parsed.get("motive", "Unknown Motive"),
            "defense_intel": parsed.get("defense_intel", "Increase monitoring.")
        }
    except Exception as e:
        logger.error(f"Threat Intel AI Error: {e}")
        return {
            "log": "Threat Intel Error",
            "suspected_actor": "ERROR",
            "confidence": "UNKNOWN",
            "reason": f"Agent failed: {str(e)}"
        }
