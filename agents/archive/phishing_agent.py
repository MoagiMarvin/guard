import os
import json
import logging
import re
import requests
from dotenv import load_dotenv
import google.generativeai as genai

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
model = genai.GenerativeModel("gemini-2.5-flash")

def _fetch_url_metadata(url: str) -> str:
    """Helper: Visits the URL and returns title, snippet, and form detection."""
    try:
        res = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
        content = res.text[:3000] # Get first 3KB
        
        # Title Detection
        title_match = re.search('<title>(.*?)</title>', content, re.IGNORECASE)
        title = title_match.group(1).strip() if title_match else "No Title"
        
        # Form & Password Detection (The "Harvesting" check)
        has_form = "<form" in content.lower()
        has_password = 'type="password"' in content.lower() or "type='password'" in content.lower()
        
        intel = f"Website Title: {title}\n"
        intel += f"Form Detected: {'YES' if has_form else 'NO'}\n"
        intel += f"Password Field found: {'YES' if has_password else 'NO'}\n"
        intel += f"Site Content Snippet: {content[:1000]}"
        return intel
    except Exception as e:
        return f"Connection Failed: {str(e)}"

def phishing_agent(email_content: str) -> dict:
    """
    Email Security Agent. Analyzes the text and URLs of suspicious corporate emails
    reported by employees to determine if they are malicious phishing attempts.
    """
    if not email_content:
        return {"status": "SAFE", "phishing_type": "None", "malicious_url": "None"}
    
    # URL Extraction
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    urlsFound = re.findall(url_pattern, email_content)
    site_intel = ""
    if urlsFound:
        primary_url = urlsFound[0]
        site_intel = f"\n--- LIVE WEB CRAWL DATA FOR {primary_url} ---\n" + _fetch_url_metadata(primary_url)

    prompt = f"""
    An employee/user just reported a suspicious content. It could be an Email, an SMS link, or a direct Website URL. 
    Here is the raw input:
    {email_content}
    
    {site_intel}
    
    Your job is to determine if this is a Social Engineering (S.E.) attack. 
    - Does the SITE CLAIM to be a brand (e.g. Amazon) but is hosted on a random domain?
    - Is there a PASSWORD FORM on a non-official website? (CREDENTIAL HARVESTING)
    - Is the EMAIL TEXT using extreme emotional pressure (URGENCY, FEAR)?
    
    Return your response strictly in JSON format with the following keys:
    - status: (SAFE, SUSPICIOUS, or CRITICAL_PHISHING)
    - phishing_type: (e.g., 'Credential Harvesting', 'Brand Impersonation', 'Sentiment Manipulation', 'Safe')
    - malicious_url: (The suspicious link found. If none, 'None')
    - explanation: (A single sentence explaining the risk, specifically mentioning if a fake form was found)
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
            "status": "ERROR",
            "phishing_type": "None",
            "malicious_url": "None",
            "explanation": f"The Sentinel engine hit an error while analyzing the content: {str(e)}"
        }
