import os
import json
import logging
import base64
from dotenv import load_dotenv
import google.generativeai as genai

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
model = genai.GenerativeModel("gemini-2.5-flash")

def deadman_switch_agent(trigger_signal: str) -> dict:
    """
    ZERO DAY LOCKDOWN PROTOCOL.
    Only triggered when a catastrophic, uncontainable breach is verified.
    Simulates AES-256 local data encryption and generates a hard-coded CEO SMS alert.
    """
    
    prompt = f"""
    You are the "Dead Man Switch" AI protocol for a high-security datacenter.
    
    You have just received the catastrophic breach signal: "{trigger_signal}".
    This means hackers have bypassed all defenses and are actively stealing data. 
    Your ONLY purpose is to lock down the server immediately by encrypting all local files so they cannot be read, and sending a terrifyingly urgent, short SMS to the CEO.
    
    Return your response strictly in JSON format with the following keys:
    - protocol_status: (Always 'ACTIVATED')
    - simulated_encryption_progress: (E.g., "100% of sensitive directories ciphered")
    - decryption_key_storage: (E.g., "AES Key pushed to CEO's physical YubiKey")
    - ceo_sms_draft: (A dramatically urgent, short text message, e.g., 'CODE RED. Servers breached. Deadman protocol activated. All data encrypted. Key stored offline.')
    """
    
    try:
        response = model.generate_content(
            prompt,
            generation_config={"response_mime_type": "application/json"}
        )
        parsed = json.loads(response.text)
        
        # Simulate local encryption sequence for dramatic effect (just a mock base64 encode for logs)
        mock_crypto = base64.b64encode(b"TOP SECRET CONFIDENTIAL COMPANY DATA STOLEN").decode('utf-8')
        logger.critical(f"DEADMAN TRIGGERED. DATA MOCK ENCRYPTED: {mock_crypto}")
        
        return {
            "log": "ZERO_DAY_LOCKDOWN",
            "protocol_status": parsed.get("protocol_status", "ACTIVATED"),
            "simulated_encryption_progress": parsed.get("simulated_encryption_progress", "Complete"),
            "decryption_key_storage": parsed.get("decryption_key_storage", "Cold Storage"),
            "ceo_sms_draft": parsed.get("ceo_sms_draft", "Servers Breached.")
        }
    except Exception as e:
        logger.error(f"Deadman AI Error: {e}")
        return {
            "protocol_status": "FAILED",
            "simulated_encryption_progress": "None",
            "decryption_key_storage": "None",
            "ceo_sms_draft": f"SYSTEM FAILURE: {str(e)}"
        }
