import requests
import json
import time

BASE_URL = "http://localhost:8000/api"

def test_db_guard():
    print("--- Testing DB Guard Agent ---")
    query = "SELECT * FROM users WHERE username = 'admin' OR 1=1; --"
    try:
        response = requests.post(f"{BASE_URL}/analyze/db", json={"query": query})
        print(f"Status Code: {response.status_code}")
        print(json.dumps(response.json(), indent=4))
    except Exception as e:
        print(f"Error: {e}")

def test_log_guard():
    print("\n--- Testing Log Guard Agent ---")
    log_entry = "2023-10-27 10:15:22 - Multiple failed login attempts for user 'admin' from IP 192.168.1.100"
    try:
        response = requests.post(f"{BASE_URL}/analyze/log", json={"log_entry": log_entry})
        print(f"Status Code: {response.status_code}")
        print(json.dumps(response.json(), indent=4))
    except Exception as e:
        print(f"Error: {e}")

def test_watcher_guard():
    print("\n--- Testing Watcher Agent (Network Guard) ---")
    traffic_log = "09:42:15.123 192.168.1.5 -> 10.0.0.1 TCP 443 SYN_SENT (Repeated 5000 times in 2 seconds)"
    try:
        response = requests.post(f"{BASE_URL}/analyze/traffic", json={"traffic_log": traffic_log})
        print(f"Status Code: {response.status_code}")
        print(json.dumps(response.json(), indent=4))
    except Exception as e:
        print(f"Error: {e}")

def test_cloud_guard():
    print("\n--- Testing Cloud Guard Agent ---")
    cloud_audit_log = {
        "eventSource": "s3.amazonaws.com",
        "eventName": "PutBucketAcl",
        "userIdentity": {"type": "Root", "principalId": "123456789012"},
        "requestParameters": {
            "bucketName": "company-confidential-data",
            "AccessControlPolicy": "PublicReadWrite"
        }
    }
    try:
        response = requests.post(f"{BASE_URL}/analyze/cloud", json={"cloud_audit_log": cloud_audit_log})
        print(f"Status Code: {response.status_code}")
        print(json.dumps(response.json(), indent=4))
    except Exception as e:
        print(f"Error: {e}")

def test_active_defense_pipeline():
    print("\n--- Testing Active Defense Pipeline (Watcher -> IR Agent) ---")
    traffic_log = "09:42:15.123 192.168.1.5 -> 10.0.0.1 TCP 443 SYN_SENT (Repeated 5000 times in 2 seconds)"
    
    print("[1] Watcher Agent scanning traffic...")
    try:
        watcher_response = requests.post(f"{BASE_URL}/analyze/traffic", json={"traffic_log": traffic_log}).json()
        print(f"    Threat Detected: {watcher_response.get('attack_type')} from log.")
        
        if watcher_response.get("status") == "DANGEROUS":
            print("[2] Threat is CRITICAL. Pushing report to Incident Response Agent...")
            ir_response = requests.post(f"{BASE_URL}/respond", json={"threat_report": watcher_response}).json()
            
            print(f"    [IR AGENT ACTION]: {ir_response.get('mitigation_summary')}")
            print(f"    [TARGET]: {ir_response.get('target')}")
            print(f"    [WINDOWS COMMAND]: {ir_response.get('windows_command')}")
            print(f"    [LINUX COMMAND]: {ir_response.get('linux_command')}")
            print(f"    [STATUS]: {ir_response.get('execution_status')}")
            
    except Exception as e:
        print(f"Error Pipeline: {e}")

if __name__ == "__main__":
    print("Ensure you have the server running in another terminal (python main.py)\n")
    test_db_guard()
    test_log_guard()
    test_watcher_guard()
    test_cloud_guard()
    test_active_defense_pipeline()
