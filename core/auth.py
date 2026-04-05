"""
Guard SOC - API Key Authentication
Secures all endpoints so only authorised clients (e.g. UL IT team) can access the SOC.
Add X-API-Key header to all requests with the key from your .env file.
"""
import os
import logging
from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


def get_valid_keys() -> set:
    """
    Loads valid API keys from environment. 
    Supports multiple keys separated by commas (e.g. for different clients).
    GUARD_API_KEYS=key-for-ul,key-for-admin,key-for-demo
    """
    raw = os.getenv("GUARD_API_KEYS", os.getenv("GUARD_API_KEY", ""))
    if not raw:
        logger.warning("No GUARD_API_KEYS set in .env — auth is effectively disabled!")
        return set()
    return {k.strip() for k in raw.split(",") if k.strip()}


async def require_api_key(api_key: str = Security(API_KEY_HEADER)) -> str:
    """
    FastAPI dependency. Attach to any route to protect it.
    Usage:  async def my_route(..., _: str = Depends(require_api_key)):
    """
    valid_keys = get_valid_keys()

    # If no keys are configured, allow all (dev mode)
    if not valid_keys:
        logger.warning("Auth bypassed — no API keys configured (dev mode)")
        return "dev-mode"

    if not api_key or api_key not in valid_keys:
        logger.warning("Rejected request — invalid or missing API key")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API key. Include X-API-Key header."
        )

    return api_key
