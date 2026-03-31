import requests
import json

BASE_URL = "http://localhost:8000/api"

watcher_response = {
  "log": "09:42:15.123 192.168.1.5 -> 10.0.0.1 TCP 443 SYN_SENT",
  "status": "DANGEROUS",
  "threat_level": "CRITICAL",
  "attack_type": "DDOS",
  "reason": "Repeated SYN packets.",
  "recommendation": "Block the source IP (192.168.1.5)"
}

try:
    ir_response = requests.post(f"{BASE_URL}/respond", json={"threat_report": watcher_response})
    print(ir_response.status_code)
    print(json.dumps(ir_response.json(), indent=4))
except Exception as e:
    print(f"Error: {e}")
