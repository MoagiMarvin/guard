import os
import json
from agents.dark_intel_agent import dark_intel_agent
from core.orchestrator import run_soc_pipeline

def test_dark_intel_logic():
    print("\n--- Testing DarkIntel Agent Logic ---")
    
    # Test Case 1: Database Leak
    target_info = "moagimarvin.com"
    res1 = dark_intel_agent(target_info)
    print(f"Leak Test Result: {res1.get('status')} | {res1.get('attack_type')} | {res1.get('reason')}")
    
    # Test Case 2: Credential Leak
    target_info = "admin@moagimarvin.com"
    res2 = dark_intel_agent(target_info)
    print(f"Cred Test Result: {res2.get('status')} | {res2.get('attack_type')} | {res2.get('reason')}")

def test_soc_pipeline_dark_intel():
    print("\n--- Testing Full SOC Pipeline (DarkIntel) ---")
    payload = "URGENT: Database dump of moagimarvin_users table with 50,000 rows found on BreachForums."
    
    # Run the pipeline
    pipeline_res = run_soc_pipeline(threat_type="dark_intel", payload=payload, client_id="TEST_IDENTITY")
    
    print(f"Pipeline Status: {pipeline_res.get('pipeline_status')}")
    print(f"Agent Used: {pipeline_res.get('agent_used')}")
    print(f"Report: {pipeline_res.get('stages').get('report').get('executive_summary')[:100]}...")

if __name__ == "__main__":
    test_dark_intel_logic()
    test_soc_pipeline_dark_intel()
