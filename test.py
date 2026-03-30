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

if __name__ == "__main__":
    print("Ensure you have the server running in another terminal (python main.py)\n")
    test_db_guard()
    test_log_guard()
