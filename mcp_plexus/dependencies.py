# mcp_plexus/dependencies.py
import logging
from fastapi import HTTPException, status, Header
from typing import Optional, Annotated

from .settings import settings

logger = logging.getLogger(__name__)

async def get_admin_api_key(
    x_admin_api_key: Annotated[
        Optional[str], 
        Header(description="The API Key for accessing admin routes.")
    ] = None
) -> str:
    """
    Validates admin API key authentication for protected admin endpoints.
    
    Returns the validated API key if authentication succeeds.
    Raises HTTPException with appropriate status codes for various failure scenarios.
    """
    # Ensure server has admin API key configured before processing requests
    if not settings.admin_api_key:
        logger.critical("ADMIN_API_KEY is not configured on the server. Admin endpoints are effectively disabled.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin API service is not configured properly (API Key missing on server).",
        )
    
    # Check if client provided the required authentication header
    if not x_admin_api_key:
        logger.warning("Admin API: Missing X-Admin-API-Key header.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated: X-Admin-API-Key header missing.",
            headers={"WWW-Authenticate": 'Basic realm="Admin Area"'}, 
        )

    # Validate the provided API key against server configuration
    if x_admin_api_key != settings.admin_api_key:
        logger.warning("Admin API: Invalid X-Admin-API-Key provided.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Forbidden: Invalid API Key.",
            headers={"WWW-Authenticate": 'Basic realm="Admin Area"'},
        )
    
    return x_admin_api_key