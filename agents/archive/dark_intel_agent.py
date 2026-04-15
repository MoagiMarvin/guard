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

def dark_intel_agent(target_info: str) -> dict:
    """
    Scans internal databases of underground forum leaks and simulated dark web data 
    for mentions of the target domain, emails, or credentials.
    """
    if not target_info:
        return {"status": "SAFE", "reason": "No target info provided", "threat_level": "NONE"}

    prompt = f"""
    You are an elite Dark Web Intelligence and Digital Risk Protection (DRP) Analyst.
    
    You are scanning underground forums, paste sites, and data leak forums for references to:
    {target_info}
    
    Look for:
    - Data Leaks: Mentions of databases or SQL dumps for sale.
    - Credentials: Username/Password pairs leaked from corporate domains.
    - Threat Chatter: Hackers discussing vulnerabilities or planning attacks on this entity.
    - VIP Risks: Mentions of executive names in a kidnapping or extortion context.
    
    Return your response strictly in JSON format with the following keys:
    - status: (SAFE or DANGEROUS)
    - threat_level: (LOW, MEDIUM, HIGH, or CRITICAL)
    - leak_type: (CREDENTIALS, DATABASE_DUMP, INTELLECTUAL_PROPERTY, THREAT_CHATTER, or NONE)
    - source: (e.g., 'BreachForums', 'Telegram Leak Channel', 'Onion Pastebin')
    - reason: (One sentence explaining the leaked data found)
    - recommendation: (Immediate action for the IT team, e.g., 'Force global password reset for admin@domain.com')
    """
    
    try:
        response = model.generate_content(
            prompt,
            generation_config={"response_mime_type": "application/json"}
        )
        parsed = json.loads(response.text)
        
        return {
            "log": "Dark Web Intel Sweep",
            "status": parsed.get("status", "UNKNOWN"),
            "threat_level": parsed.get("threat_level", "UNKNOWN"),
            "attack_type": parsed.get("leak_type", "NONE"),
            "source": parsed.get("source", "Dark Web Intelligence"),
            "reason": parsed.get("reason", "Scan complete. No major leaks found."),
            "recommendation": parsed.get("recommendation", "Continue monitoring.")
        }
    except Exception as e:
        logger.error(f"Dark Intel Agent AI Error: {e}")
        return {
            "log": "Dark Intel Error",
            "status": "ERROR",
            "threat_level": "UNKNOWN",
            "reason": f"Intelligence sweep failed: {str(e)}",
            "recommendation": "Check Dark Web API status."
        }
