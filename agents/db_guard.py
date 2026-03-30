import os
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()

genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
model = genai.GenerativeModel("gemini-2.5-flash") # Using 2.5-flash as requested and verified available

def db_guard_agent(query: str) -> dict:
    
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
    
    response = model.generate_content(
        prompt,
        generation_config={"response_mime_type": "application/json"}
    )
    import json
    parsed = json.loads(response.text)
    
    return {
        "query": query,
        "status": parsed.get("status", "UNKNOWN"),
        "threat_level": parsed.get("threat_level", "UNKNOWN"),
        "reason": parsed.get("reason", ""),
        "recommendation": parsed.get("recommendation", "")
    }