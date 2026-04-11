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
    """Helper: Visits the URL and returns the title and a snippet for AI analysis."""
    try:
        res = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
        content = res.text[:2000] # Get first 2KB
        title_match = re.search('<title>(.*?)</title>', content, re.IGNORECASE)
        title = title_match.group(1) if title_match else "No Title"
        return f"Website Title: {title}\nSite Content Snippet: {content[:1000]}"
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
    You are an elite Email Security Analyst for a Fortune 500 company.
    
    An employee just reported an email. Here is the raw content:
    {email_content}
    
    {site_intel}
    
    Your job is to determine if this is a Phishing attack. 
    Compare the EMAIL CLAIM (e.g. 'I am from Microsoft') against the WEBSITE DATA (e.g. site is hosted on a random domain and asks for passwords). 
    Identify "Look-alike" domains or "Brand Impersonation".
    
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
            "status": "ERROR",
            "phishing_type": "None",
            "malicious_url": "None",
            "explanation": f"The Sentinel engine hit an error while analyzing the content: {str(e)}"
        }
