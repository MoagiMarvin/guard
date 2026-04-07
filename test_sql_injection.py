from core.orchestrator import run_soc_pipeline
import json

def test_sql_injection_defense():
    """
    Simulates a SQL Injection attack and shows the 5-agent chain in action.
    """
    print("\n" + "="*60)
    print("      GUARD SOC: SQL INJECTION MULTI-AGENT DEFENSE")
    print("="*60)

    # THE ATTACK: A bypass login attempt via SQL Injection
    sql_payload = "SELECT * FROM users WHERE id = 1 OR 1=1; DROP TABLE users;--"
    print(f"\n[ATTACK] Hacker Payload:\n         '{sql_payload}'")

    print("\n[PIPELINE] Orchestrating Defense Agents...")
    result = run_soc_pipeline("db", sql_payload)

    stages = result['stages']

    # 1. DB GUARD (The Lookout)
    print(f"\n[1] DB GUARD (Detection):")
    print(f"    Verdict: {stages['detection']['status']} | Level: {stages['detection']['threat_level']}")
    print(f"    Reason:  {stages['detection']['reason']}")

    # 2. IR AGENT (The Muscle)
    ir = stages['ir_response']
    if ir:
        print(f"\n[2] IR AGENT (Protection):")
        print(f"    Action:  {ir['action_type']} on {ir['target']}")
        print(f"    Summary: {ir['mitigation_summary']}")
        print(f"    Command: {ir['windows_command']}")

    # 3. THREAT INTEL (The Detective)
    intel = stages['threat_intel']
    if intel:
        print(f"\n[3] THREAT INTEL (Intelligence):")
        print(f"    Actor:      {intel['suspected_actor']}")
        print(f"    Confidence: {intel['confidence']}")
        print(f"    Motive:     {intel['motive']}")

    # 4. REPORTING (The CISO)
    report = stages['report']
    print(f"\n[4] REPORTING (Executive):")
    print(f"    Classification: {report['classification']}")
    print(f"    Summary:        {report['executive_summary']}")

    # 5. DEAD MAN SWITCH (The Last Resort)
    if stages['deadman_activated']:
        print(f"\n[5] DEAD MAN SWITCH (Emergency):")
        print(f"    STATUS: ACTIVATED — ZERO DAY LOCKDOWN IN PROGRESS!")

    print("\n" + "="*60)

if __name__ == "__main__":
    test_sql_injection_defense()
