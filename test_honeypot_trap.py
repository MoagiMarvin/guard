from core.orchestrator import run_soc_pipeline
import json

def test_honeypot_trap():
    """
    Demonstrates the 'Trap' in action:
    1. Attacker touches the Honeypot.
    2. Guard catches them immediately.
    3. IR Agent (The Muscle) fires to block them.
    """
    print("\n" + "="*50)
    print("      GUARD SOC: HONEYPOT TRAP DEMONSTRATION")
    print("="*50)

    # 1. THE TRAP: A hacker tries to enter a fake SSH server
    hacker_activity = "SSH Login Attempt from 103.45.12.99: user='root', pass='123456'"
    print(f"\n[STEP 1] Hacker touches the Honeypot:\n         '{hacker_activity}'")

    # 2. THE SOC PIPELINE: The Trap is Sprung
    print("\n[STEP 2] Guard SOC Pipeline Processing...")
    result = run_soc_pipeline("honeypot", hacker_activity)

    # 3. THE VERDICT
    detection = result['stages']['detection']
    print(f"\n[VERDICT] Status: {detection['status']} | Threat Level: {detection['threat_level']}")
    print(f"          Profile: {detection['attacker_profile']}")

    # 4. THE MUSCLE: Automatic Incident Response
    ir = result['stages']['ir_response']
    if ir:
        print(f"\n[🛡️ PROTECTION ENGAGED] {ir['action_type']} on target {ir['target']}")
        print(f"          Action Summary: {ir['mitigation_summary']}")
        print(f"          Command: {ir['windows_command']}")
    else:
        print("\n[!] No IR response triggered (Check logic).")

    print("\n" + "="*50)

if __name__ == "__main__":
    test_honeypot_trap()
