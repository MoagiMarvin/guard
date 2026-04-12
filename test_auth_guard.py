import os
import json
from agents.auth_guard import auth_guard_agent
from core.orchestrator import run_soc_pipeline

def test_auth_guard_logic():
    print("\n--- Testing AuthGuard Agent Logic ---")
    
    # Test Case 1: Potential IDOR
    idor_data = "User logged in as id=5, but requesting resource /api/user/v1/profile/10"
    res1 = auth_guard_agent(idor_data)
    print(f"IDOR Test Result: {res1.get('status')} | {res1.get('attack_type')} | {res1.get('reason')}")
    
    # Test Case 2: JWT Tamper
    jwt_data = "Authorization: Bearer header.payload.signature | Decoded header: {'alg': 'none'}"
    res2 = auth_guard_agent(jwt_data)
    print(f"JWT Test Result: {res2.get('status')} | {res2.get('attack_type')} | {res2.get('reason')}")
    
    # Test Case 3: Safe Request
    safe_data = "User id=5 requesting their own profile /api/user/v1/profile/5"
    res3 = auth_guard_agent(safe_data)
    print(f"Safe Test Result: {res3.get('status')} | {res3.get('attack_type')} | {res3.get('reason')}")

def test_soc_pipeline_auth():
    print("\n--- Testing Full SOC Pipeline (Auth) ---")
    payload = "CRITICAL: Attempt to bypass admin login at /api/admin/system/shutdown with Guest Token"
    
    # Run the pipeline (this saves to DB and chains IR/Intel)
    pipeline_res = run_soc_pipeline(threat_type="auth", payload=payload, client_id="TEST_IDENTITY")
    
    print(f"Pipeline Status: {pipeline_res.get('pipeline_status')}")
    print(f"Agent Used: {pipeline_res.get('agent_used')}")
    print(f"Report: {pipeline_res.get('stages').get('report').get('executive_summary')[:100]}...")

if __name__ == "__main__":
    test_auth_guard_logic()
    test_soc_pipeline_auth()
