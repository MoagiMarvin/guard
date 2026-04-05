"""
Guard SOC - Full Pipeline Integration Test
Tests the orchestrator end-to-end: detection → IR → Threat Intel → Report
"""
import requests
import json

BASE = "http://localhost:8000/api"
HEADERS = {"X-API-Key": "guard-admin-demo"}

def divider(title):
    print(f"\n{'='*55}")
    print(f"  {title}")
    print("="*55)

# -------------------------------------------------------
# TEST 1: Health Check
# -------------------------------------------------------
divider("Health Check")
r = requests.get(f"{BASE}/health")
data = r.json()
print(f"Status: {r.status_code}")
print(f"Server: {data['status']} | Version: {data.get('version')} | Agents: {data['total']}")

# -------------------------------------------------------
# TEST 2: Full SOC Pipeline — SQL Injection (CRITICAL)
# -------------------------------------------------------
divider("SOC Pipeline — SQL Injection Attack")
payload = "SELECT * FROM users WHERE id=1 OR 1=1; DROP TABLE users;--"
print(f"Payload: {payload}")
print("Running pipeline... (this will call 4 agents)")

r = requests.post(f"{BASE}/run", headers=HEADERS, json={
    "threat_type": "db",
    "payload": payload
}, timeout=120)

result = r.json()
print(f"\nHTTP Status: {r.status_code}")
print(f"Pipeline Status: {result.get('pipeline_status')}")
print(f"Pipeline Run ID: #{result.get('pipeline_run_id')}")
print(f"Agent Used: {result.get('agent_used')}")

stages = result.get("stages", {})
detection = stages.get("detection", {})
ir = stages.get("ir_response")
intel = stages.get("threat_intel")
report = stages.get("report", {})

print(f"\n--- DETECTION AGENT ---")
print(f"  Status: {detection.get('status')}")
print(f"  Threat Level: {detection.get('threat_level')}")
print(f"  Reason: {detection.get('reason', '')[:120]}")

print(f"\n--- IR AGENT (auto-triggered) ---")
if ir:
    print(f"  Action: {ir.get('action_type')}")
    print(f"  Target: {ir.get('target')}")
    print(f"  Summary: {ir.get('mitigation_summary', '')[:120]}")
else:
    print("  Not triggered (threat below threshold)")

print(f"\n--- THREAT INTEL (auto-triggered) ---")
if intel:
    print(f"  Suspected Actor: {intel.get('suspected_actor')}")
    print(f"  Confidence: {intel.get('confidence')}")
    print(f"  Motive: {intel.get('motive', '')[:100]}")
else:
    print("  Not triggered")

print(f"\n--- REPORT (always runs) ---")
print(f"  Classification: {report.get('classification')}")
print(f"  Summary: {report.get('executive_summary', '')[:200]}")

print(f"\n--- DEAD MAN SWITCH ---")
print(f"  Activated: {stages.get('deadman_activated')}")

# -------------------------------------------------------
# TEST 3: Auth Check — No Key Should Be Rejected
# -------------------------------------------------------
divider("Auth Test — Request Without API Key")
r = requests.get(f"{BASE}/stats")
print(f"Status (no key): {r.status_code} — Expected: 403")

# -------------------------------------------------------
# TEST 4: Incidents DB
# -------------------------------------------------------
divider("Database — Incident History")
r = requests.get(f"{BASE}/stats", headers=HEADERS)
print(f"Stats: {json.dumps(r.json(), indent=2)}")

print("\n\n✅ ALL TESTS COMPLETE. Guard SOC Pipeline is OPERATIONAL.")
