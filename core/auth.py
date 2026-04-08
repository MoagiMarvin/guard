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


def get_key_map() -> dict:
    """
    Loads API keys and maps them to Client Identites from environment.
    Supports 'key:client' pairs separated by commas.
    Example: GUARD_API_KEYS=key1:UL-University,key2:TestSite-1
    """
    raw = os.getenv("GUARD_API_KEYS", "") # No fallback to single key for SaaS mode
    if not raw:
        logger.warning("No GUARD_API_KEYS set in environment!")
        return {}
    
    mapping = {}
    for entry in raw.split(","):
        if ":" in entry:
            key, client = entry.split(":", 1)
            mapping[key.strip()] = client.strip()
        else:
            # Legacy support: if no colon, name it 'Global'
            mapping[entry.strip()] = "Global"
    return mapping


async def require_api_key(api_key: str = Security(API_KEY_HEADER)) -> str:
    """
    FastAPI dependency. Returns the Client Identity (e.g. 'UL-University').
    """
    key_map = get_key_map()

    # If no keys are configured, allow all as 'Admin' (dev mode)
    if not key_map:
        logger.warning("Auth bypassed — no API keys configured (dev mode)")
        return "Admin"

    if not api_key or api_key not in key_map:
        logger.warning("Rejected request — invalid or missing API key")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API key. Include X-API-Key header."
        )

    return key_map[api_key]
