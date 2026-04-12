"""
GUARD - API Key Authentication
Secures the /run endpoint so only registered clients can send data.
Now checks the Supabase/Postgres database for valid keys.
"""
import logging
from fastapi import Security, HTTPException, status, Depends
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session
from core.database import get_db, Client

logger = logging.getLogger(__name__)

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

async def require_api_key(api_key: str = Security(API_KEY_HEADER), db: Session = Depends(get_db)) -> str:
    """
    FastAPI dependency. Verifies the X-API-Key against the database.
    Returns the Client ID (usually the key itself or the site name).
    """
    if not api_key:
        logger.warning("Rejected request — missing API key")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing API key. Include X-API-Key header."
        )

    # Check database for this key
    client = db.query(Client).filter(Client.api_key == api_key).first()
    
    if not client:
        # Fallback for admin demo mode (optional, remove in production)
        if api_key == "guard-admin-demo":
            return "Admin"
            
        logger.warning(f"Rejected request — invalid API key: {api_key[:8]}...")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key."
        )

    return client.api_key # Or return client.site_name if preferred
