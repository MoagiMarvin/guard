try:
    print("Testing imports from agents.db_guard...")
    from agents.db_guard import db_guard_agent, injection_guard_agent
    print("Testing imports from agents.auth_guard...")
    from agents.auth_guard import auth_guard_agent, session_anchor_agent
    print("Testing imports from agents.reporting_agent...")
    from agents.reporting_agent import reporting_agent, compliance_agent
    print("Testing imports from agents.rate_limit_guard...")
    from agents.rate_limit_guard import rate_limit_guard_agent
    print("Testing imports from agents.deadman_switch...")
    from agents.deadman_switch import deadman_switch_agent
    print("Testing imports from core.orchestrator...")
    from core.orchestrator import run_soc_pipeline, run_inspect_pipeline
    print("Testing imports from api.routes...")
    from api.routes import router
    print("All imports successful!")
except Exception as e:
    import traceback
    traceback.print_exc()
