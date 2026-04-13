import os
from dotenv import load_dotenv
import google.generativeai as genai
import json
import logging
from core.database import get_cached_ai, set_cached_ai

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
model = genai.GenerativeModel("gemini-2.5-flash") # Using 2.5-flash as requested and verified available

def db_guard_agent(query: str) -> dict:
    if not query:
        return {"status": "SAFE", "reason": "Empty query", "threat_level": "NONE"}

    # --- Quota Guard: Caching Layer ---
    cached = get_cached_ai("db_guard", query)
    if cached:
        logger.info(f"Quota Guard: Using cached response for query.")
        return cached

    # --- Pre-check layer (Fast & Free) ---
    suspicious_patterns = ["' OR", "UNION SELECT", "DROP TABLE", "--", ";", "OR 1=1"]
    if any(pattern.lower() in query.lower() for pattern in suspicious_patterns):
        logger.info(f"Pre-check flagged suspicious pattern in query: {query}")
        # We still send to AI for a detailed analysis if suspicious, 
        # but we could also return early if cost is a concern.

    
    prompt = f"""
    You are a cybersecurity expert specialising in SQL injection detection.
    
    Analyse this database query and determine if it is a SQL injection attack:
    
    Query: {query}
    
    Return your response in JSON format with the following keys:
    - status: (SAFE or DANGEROUS)
    - threat_level: (LOW, MEDIUM, or CRITICAL)
    - reason: (one sentence explanation)
    - recommendation: (what to do about it)
    """
    
    try:
        response = model.generate_content(
            prompt,
            generation_config={"response_mime_type": "application/json"}
        )
        parsed = json.loads(response.text)
        
        result = {
            "query": query,
            "status": parsed.get("status", "UNKNOWN"),
            "threat_level": parsed.get("threat_level", "UNKNOWN"),
            "reason": parsed.get("reason", ""),
            "recommendation": parsed.get("recommendation", "")
        }

        # Save to cache
        set_cached_ai("db_guard", query, result)
        return result
    except Exception as e:
        logger.error(f"AI Agent Error: {e}")
        return {
            "query": query,
            "status": "ERROR",
            "threat_level": "UNKNOWN",
            "reason": f"Agent failed to process: {str(e)}",
            "recommendation": "Check API logs and key configuration."
        }