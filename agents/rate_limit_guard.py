import time
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# In-memory storage for rate limiting (reset on server restart)
# In production, use Redis for persistence and distributed scalability
# Structure: { ip: { "requests": [timestamp, ...], "failed_logins": [timestamp, ...] } }
rate_limit_data = {}

def rate_limit_guard_agent(request_data: dict) -> dict:
    """
    LAYER 2: INSPECTION (Rate Limiting)
    Prevents DDoS and Brute Force attacks.
    """
    ip = request_data.get("ip", "0.0.0.0")
    request_url = request_data.get("request_url", "")
    now = time.time()
    
    if ip not in rate_limit_data:
        rate_limit_data[ip] = {"requests": [], "failed_logins": []}
    
    # 1. Cleaning up old timestamps (sliding window: 60 seconds)
    rate_limit_data[ip]["requests"] = [t for t in rate_limit_data[ip]["requests"] if now - t < 60]
    rate_limit_data[ip]["failed_logins"] = [t for t in rate_limit_data[ip]["failed_logins"] if now - t < 300] # 5 mins for brute force
    
    # 2. General Rate Limiting (DDoS mitigation)
    # Threshold: 100 requests per minute per IP
    rate_limit_data[ip]["requests"].append(now)
    if len(rate_limit_data[ip]["requests"]) > 100:
        logger.warning(f"Rate Limit: IP {ip} exceeded 100 requests/min. BLOCKING.")
        return {
            "decision": "BLOCK",
            "reason": "Extreme traffic volume detected from your IP. Cooling down for 60s.",
            "agent": "rate_limit_guard",
            "confidence": 100,
            "threat_type": "DDOS"
        }

    # 3. Brute Force Protection (on /login or /auth endpoints)
    if "/login" in request_url or "/auth" in request_url:
        # Note: We track ATTEMPTS. In a real system, you'd increment 'failed_logins' 
        # only if the app signals a failure, but for middleware-only check, 
        # we can limit total auth attempts.
        rate_limit_data[ip]["failed_logins"].append(now)
        if len(rate_limit_data[ip]["failed_logins"]) > 10:
            logger.warning(f"Rate Limit: IP {ip} exceeded 10 login attempts in 5 mins. BLOCKING.")
            return {
                "decision": "BLOCK",
                "reason": "Too many login attempts. Access temporarily restricted to prevent brute force.",
                "agent": "rate_limit_guard",
                "confidence": 100,
                "threat_type": "BRUTE_FORCE"
            }

    return {
        "decision": "PASS",
        "reason": "Request volume within normal operating limits.",
        "agent": "rate_limit_guard",
        "confidence": 100
    }
