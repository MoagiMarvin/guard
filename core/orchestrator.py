"""
Guard SOC - Central Orchestrator
The brain that chains all 13 agents into a real SOC pipeline.
No CrewAI. No frameworks. Pure Python.

Pipeline flow:
  1. Detection Agent (routes based on threat_type)
  2. If DANGEROUS/CRITICAL → IR Agent fires automatically
  3. If DANGEROUS/CRITICAL → Threat Intel fires automatically  
  4. Reporting Agent always synthesises everything
  5. If CRITICAL → Dead Man Switch fires automatically
  All results saved to database.
"""
import logging
from datetime import datetime

from agents.db_guard import db_guard_agent
from agents.log_guard import log_guard_agent
from agents.watcher_guard import watcher_guard_agent
from agents.cloud_guard import cloud_guard_agent
from agents.honeypot_guard import honeypot_guard_agent
from agents.vuln_scanner import vuln_scanner_agent
from agents.ueba_agent import ueba_agent
from agents.phishing_agent import phishing_agent
from agents.sandbox_agent import sandbox_agent
from agents.ir_agent import incident_response_agent
from agents.threat_intel import threat_intel_agent
from agents.reporting_agent import reporting_agent
from agents.deadman_switch import deadman_switch_agent
from core.database import save_incident, save_pipeline_run

logger = logging.getLogger(__name__)

# -------------------------------------------------------------------
# Agent Registry
# Maps a simple threat_type string → the correct detection function
# -------------------------------------------------------------------
DETECTION_AGENTS = {
    "db":        {"fn": db_guard_agent,       "arg": "query",               "label": "DB Guard"},
    "log":       {"fn": log_guard_agent,      "arg": "log_entry",           "label": "Log Guard"},
    "traffic":   {"fn": watcher_guard_agent,  "arg": "traffic_log",         "label": "Watcher Guard"},
    "cloud":     {"fn": cloud_guard_agent,    "arg": "cloud_audit_log",     "label": "Cloud Guard"},
    "honeypot":  {"fn": honeypot_guard_agent, "arg": "honeypot_interaction","label": "Honeypot Guard"},
    "vuln":      {"fn": vuln_scanner_agent,   "arg": "system_config",       "label": "Vuln Scanner"},
    "ueba":      {"fn": ueba_agent,           "arg": "user_activity_log",   "label": "UEBA Agent"},
    "phishing":  {"fn": phishing_agent,       "arg": "email_content",       "label": "Phishing Agent"},
    "sandbox":   {"fn": sandbox_agent,        "arg": "malware_code",        "label": "Sandbox Agent"},
}

def _is_dangerous(result: dict) -> bool:
    """Checks if a detection agent returned a threat that needs a response."""
    status = result.get("status", "").upper()
    level = result.get("threat_level", "").upper()
    anomaly = result.get("anomaly_score", 0)
    # UEBA uses SUSPICIOUS/CRITICAL status, others use DANGEROUS
    return status in ("DANGEROUS", "CRITICAL", "SUSPICIOUS") or level in ("HIGH", "CRITICAL") or anomaly >= 70

def _is_critical(result: dict) -> bool:
    """Checks if a threat is severe enough to trigger the Dead Man Switch."""
    level = result.get("threat_level", "").upper()
    anomaly = result.get("anomaly_score", 0)
    status = result.get("status", "").upper()
    return level == "CRITICAL" or anomaly >= 90 or status == "CRITICAL"

def _extract_reason(result: dict) -> str:
    """Pulls the best available description string from a detection result."""
    return (
        result.get("reason") or
        result.get("intent") or
        result.get("code_intent_summary") or
        result.get("explanation") or
        str(result)
    )[:500]


def run_soc_pipeline(threat_type: str, payload, client_id: str = "Global") -> dict:
    """
    Main entry point. Runs the full SOC pipeline for a given threat type and payload.

    Args:
        threat_type: One of the keys in DETECTION_AGENTS (e.g. 'db', 'phishing')
        payload: The raw data to analyse (string or dict depending on agent)
        client_id: The identity of the client (UL, TestSite, etc.)

    Returns:
        A dict containing the full pipeline result with all agent outputs.
    """
    started_at = datetime.utcnow().isoformat()
    logger.info("=" * 60)
    logger.info("GUARD SOC PIPELINE STARTED — Type: %s | Time: %s", threat_type, started_at)

    # ----------------------------------------------------------------
    # STEP 1 — Route to the correct Detection Agent
    # ----------------------------------------------------------------
    agent_config = DETECTION_AGENTS.get(threat_type)
    if not agent_config:
        return {
            "error": f"Unknown threat_type '{threat_type}'. Valid types: {list(DETECTION_AGENTS.keys())}",
            "pipeline_status": "FAILED"
        }

    agent_fn    = agent_config["fn"]
    agent_label = agent_config["label"]

    logger.info("STEP 1 — Routing to %s...", agent_label)
    detection_result = agent_fn(payload)
    detection_status = detection_result.get("status", "UNKNOWN")
    detection_level  = detection_result.get("threat_level", detection_result.get("status", "UNKNOWN"))

    # Save detection result immediately with client attribution
    save_incident(
        client_id=client_id,
        agent=agent_label,
        status=detection_status,
        threat_level=detection_level,
        payload=payload if isinstance(payload, str) else str(payload),
        result=detection_result
    )
    logger.info("STEP 1 COMPLETE — Status: %s | Level: %s", detection_status, detection_level)

    # ----------------------------------------------------------------
    # STEP 2 & 3 — If dangerous, chain IR Agent + Threat Intel
    # ----------------------------------------------------------------
    ir_result     = None
    intel_result  = None
    deadman_fired = False

    if _is_dangerous(detection_result):
        logger.warning("THREAT DETECTED. Engaging IR Agent and Threat Intel automatically...")

        # IR Agent takes the detection result and decides how to respond
        logger.info("STEP 2 — IR Agent engaging...")
        # IR Agent expects status == DANGEROUS, normalise if needed
        ir_input = {**detection_result, "status": "DANGEROUS"}
        ir_result = incident_response_agent(ir_input)
        logger.info("STEP 2 COMPLETE — IR Action: %s | Target: %s", ir_result.get("action_type"), ir_result.get("target"))

        # Threat Intel cross-references the attack indicator
        logger.info("STEP 3 — Threat Intel cross-referencing...")
        intel_result = threat_intel_agent(_extract_reason(detection_result))
        logger.info("STEP 3 COMPLETE — Suspected actor: %s | Confidence: %s", intel_result.get("suspected_actor"), intel_result.get("confidence"))

        # ----------------------------------------------------------------
        # STEP 4 — Dead Man Switch (only on critical)
        # ----------------------------------------------------------------
        if _is_critical(detection_result):
            logger.critical("CRITICAL THREAT — DEAD MAN SWITCH ENGAGING...")
            deadman_result = deadman_switch_agent(
                f"CONFIRMED BREACH via {agent_label}: {_extract_reason(detection_result)}"
            )
            deadman_fired = True
            logger.critical("DEAD MAN SWITCH ACTIVATED — Protocol: %s", deadman_result.get("protocol_status"))
    else:
        logger.info("Threat level below response threshold. Standing by.")

    # ----------------------------------------------------------------
    # STEP 5 — Reporting Agent always runs, synthesises everything
    # ----------------------------------------------------------------
    logger.info("STEP 5 — Reporting Agent generating executive summary...")
    all_logs = [l for l in [detection_result, ir_result, intel_result] if l is not None]
    report_result = reporting_agent(all_logs)
    logger.info("STEP 5 COMPLETE — Classification: %s", report_result.get("classification"))

    # ----------------------------------------------------------------
    # Save the full pipeline run to database with client attribution
    # ----------------------------------------------------------------
    run_id = save_pipeline_run(
        client_id=client_id,
        threat_type=threat_type,
        payload=payload if isinstance(payload, str) else str(payload),
        detection=detection_result,
        ir_response=ir_result,
        threat_intel=intel_result,
        report=report_result,
        deadman_fired=deadman_fired,
        final_status="CRITICAL" if deadman_fired else ("DANGEROUS" if _is_dangerous(detection_result) else "SAFE")
    )

    logger.info("PIPELINE COMPLETE — Run ID: #%d | Deadman Fired: %s", run_id, deadman_fired)
    logger.info("=" * 60)

    # ----------------------------------------------------------------
    # Return the full pipeline result
    # ----------------------------------------------------------------
    return {
        "pipeline_run_id": run_id,
        "started_at": started_at,
        "threat_type": threat_type,
        "agent_used": agent_label,
        "pipeline_status": "CRITICAL" if deadman_fired else ("DANGEROUS" if _is_dangerous(detection_result) else "SAFE"),
        "stages": {
            "detection": detection_result,
            "ir_response": ir_result,
            "threat_intel": intel_result,
            "report": report_result,
            "deadman_activated": deadman_fired
        }
    }
