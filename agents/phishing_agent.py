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

def phishing_agent(email_content: str) -> dict:
    """
    Email Security Agent. Analyzes the text and URLs of suspicious corporate emails
    reported by employees to determine if they are malicious phishing attempts.
    """
    if not email_content:
        return {"status": "SAFE", "phishing_type": "None", "malicious_url": "None"}

    prompt = f"""
    You are an elite Email Security Analyst for a Fortune 500 company.
    
    An employee just clicked the "Report Suspicious Email" button. Here is the raw text content and any links/attachments they received:
    {email_content}
    
    Your job is to determine definitively if this is a Phishing attack, a Business Email Compromise (BEC) scam, Spam, or a legitimate email.
    
    Return your response strictly in JSON format with the following keys:
    - status: (SAFE, SUSPICIOUS, or CRITICAL_PHISHING)
    - phishing_type: (e.g., 'Credential Harvesting', 'Spear Phishing', 'Spam', 'Legitimate')
    - malicious_url: (If the email contains a fake login link, extract it perfectly here so we can block it. Otherwise 'None')
    - explanation: (A single sentence explaining why you categorized it this way)
    """
    
    try:
        response = model.generate_content(
            prompt,
            generation_config={"response_mime_type": "application/json"}
        )
        parsed = json.loads(response.text)
        
        return {
            "log": "Phishing Analysis",
            "status": parsed.get("status", "UNKNOWN"),
            "phishing_type": parsed.get("phishing_type", "Unknown"),
            "malicious_url": parsed.get("malicious_url", "None"),
            "explanation": parsed.get("explanation", "Failed to parse context.")
        }
    except Exception as e:
        logger.error(f"Phishing AI Error: {e}")
        return {
            "log": "Phishing Scan Error",
            "status": "ERROR",
            "phishing_type": "None",
            "malicious_url": "None",
            "explanation": f"Agent failed: {str(e)}"
        }
