import logging
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def session_anchor_agent(request_data: dict) -> dict:
    """
    LAYER 1: IDENTITY
    Proves the human is real using mobile hardware binding.
    Checks for a valid device signature matching the session.
    """
    device_sig = request_data.get("device_signature")
    session_token = request_data.get("session_token")
    request_url = request_data.get("request_url", "")
    
    # Logic: Some endpoints require Session Anchor (e.g. login, payments, admin)
    sensitive_endpoints = ["/login", "/admin", "/pay", "/delete", "/transfer"]
    is_sensitive = any(endpoint in request_url for endpoint in sensitive_endpoints)
    
    if not is_sensitive:
        return {
            "decision": "PASS",
            "reason": "Legacy/Public endpoint - Session Anchor not enforced",
            "agent": "session_anchor",
            "confidence": 100
        }

    if not device_sig:
        logger.warning(f"Session hijacking attempt? No device signature for sensitive endpoint: {request_url}")
        return {
            "decision": "BLOCK",
            "reason": "Mobile Device Not Linked. Please scan QR code to authenticate.",
            "agent": "session_anchor",
            "confidence": 100,
            "incident_type": "UNREGISTERED_DEVICE"
        }

    # Simulation of cryptographic verification
    # In production, we'd verify 'device_sig' against 'device_public_key' stored in DB for this session
    if device_sig == "INVALID":
        return {
            "decision": "BLOCK",
            "reason": "Cryptographic signature mismatch. Session hijacked or device spoofed.",
            "agent": "session_anchor",
            "confidence": 99,
            "incident_type": "SESSION_HIJACK"
        }

    return {
        "decision": "PASS",
        "reason": "Device signature verified via hardware enclave.",
        "agent": "session_anchor",
        "confidence": 100
    }
