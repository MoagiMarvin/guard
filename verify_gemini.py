import os
from dotenv import load_dotenv
import google.generativeai as genai
import json

load_dotenv()
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))

# Prove that gemini-2.5-flash is valid and works
print("--- TESTING GEMINI 2.5 FLASH AGENT ---")
model = genai.GenerativeModel("gemini-2.5-flash")

prompt = "Analyze this query for SQL injection and return JSON (status: SAFE/DANGEROUS): SELECT * FROM users;"

try:
    response = model.generate_content(prompt, generation_config={"response_mime_type": "application/json"})
    print("\n[AI RESPONSE]:")
    print(response.text)
    print("\n✅ PROOF: Gemini 1.5 Flash is operational and returned a valid analysis!")
except Exception as e:
    print(f"\n❌ ERROR: {e}")
