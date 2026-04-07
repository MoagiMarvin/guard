import requests
import json

BASE_URL = "http://localhost:8000/api"
HEADERS = {"X-API-Key": "guard-admin-demo", "Content-Type": "application/json"}

def test_full_orchestra():
    print("\n" + "="*60)
    print("  RUNNING CURRENT SOC ORCHESTRA TEST")
    print("="*60)
    
    # Simulating a SQL Injection attack
    payload = "SELECT * FROM users WHERE id=1 OR 1=1; -- DROP TABLE users;"
    
    print(f"Targeting: DB Guard")
    print(f"Payload: {payload}")
    print("-" * 60)
    
    try:
        response = requests.post(
            f"{BASE_URL}/run", 
            json={"threat_type": "db", "payload": payload},
            headers=HEADERS
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"Pipeline Run ID: #{result.get('pipeline_run_id')}")
            print(f"Final SOC Status: {result.get('pipeline_status')}")
            print("\nAgents Participated:")
            for stage, data in result.get('stages', {}).items():
                if data:
                    print(f" - [✓] {stage.upper()}")
            
            print("\nExecutive Summary:")
            print(result.get('stages', {}).get('report', {}).get('executive_summary', 'No summary generated.'))
        else:
            print(f"Error: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"Connection Failed: {e}")
    print("="*60 + "\n")

if __name__ == "__main__":
    test_full_orchestra()
