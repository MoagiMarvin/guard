import requests
import json
import time

BASE_URL = "http://127.0.0.1:8000/api"
HEADERS = {"X-API-Key": "guard-admin-demo"}

def test_inspect(payload, url="/index.html", sig="none"):
    data = {
        "request_url": url,
        "method": "POST",
        "payload": payload,
        "session_token": "test-session-123",
        "device_signature": sig,
        "ip": "1.2.3.4"
    }
    response = requests.post(f"{BASE_URL}/inspect", headers=HEADERS, json=data)
    print(f"\n--- Testing Endpoint: {url} | Payload: {payload[:30]}... ---")
    print(f"Status Code: {response.status_code}")
    print(json.dumps(response.json(), indent=2))
    return response.json()

if __name__ == "__main__":
    print("STARTING GUARD RESTRUCTURE VERIFICATION...")
    
    # 1. Clean Request
    test_inspect("Hello world", "/public")
    
    # 2. SQL Injection Block
    test_inspect("admin' OR 1=1 --", "/login")
    
    # 3. XSS Block
    test_inspect("<script>alert('pwned')</script>", "/contact")
    
    # 4. Session Anchor Block (Sensitive endpoint, no signature)
    test_inspect("Valid payload", "/admin")
    
    # 5. Session Anchor Pass (Sensitive endpoint, valid mock signature)
    test_inspect("Valid payload", "/admin", sig="VALID_SIGNATURE_MOCK")
    
    # 6. Rate Limit Block
    print("\n--- Testing Rate Limit (10 requests to /auth) ---")
    for i in range(12):
        res = test_inspect("attempt", "/auth")
        if res.get("decision") == "BLOCK" and res.get("agent") == "rate_limit_guard":
            print(f"RATE LIMIT TRIGGERED AT ATTEMPT {i+1}")
            break
