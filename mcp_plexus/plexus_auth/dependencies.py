# mcp_plexus/plexus_auth/dependencies.py
import logging
import secrets
from typing import Optional, Dict, Any, Annotated
from fastapi import Request as FastAPIRequest, HTTPException, status, Header, Depends

from mcp_plexus.plexus_auth.sqlite_user_auth_token_store import get_sqlite_plexus_user_auth_token_store 
from mcp_plexus.plexus_auth.token_manager import DefaultPlexusUserTokenManager, PlexusUserTokenManagerProtocol
from ..settings import settings
from mcp_plexus.plexus_auth.storage_interfaces import AbstractPlexusUserAuthTokenStore

logger = logging.getLogger(__name__)


async def get_plexus_user_auth_token_store_dependency() -> AbstractPlexusUserAuthTokenStore:
    """Dependency provider for the Plexus user authentication token store."""
    return await get_sqlite_plexus_user_auth_token_store()


async def verify_host_app_secret(
    x_host_app_secret: Annotated[Optional[str], Header(alias="X-Host-App-Secret")] = None
) -> str:
    """
    Validates the host application secret from the X-Host-App-Secret header.
    
    This ensures that only authorized host applications can register with the Plexus system.
    Uses constant-time comparison to prevent timing attacks.
    """
    if not settings.host_app_registration_secret:
        logger.error("CRITICAL: HOST_APP_REGISTRATION_SECRET is not configured on the server. Cannot verify host app.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, 
            detail="Host application registration is not configured correctly (server-side)."
        )

    if not x_host_app_secret:
        logger.warning("Host App Auth: X-Host-App-Secret header missing.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authorized: X-Host-App-Secret header missing.",
            headers={"WWW-Authenticate": 'Basic realm="Plexus Host App Registration"'}
        )

    # Use secrets.compare_digest for constant-time comparison to prevent timing attacks
    if not secrets.compare_digest(x_host_app_secret, settings.host_app_registration_secret):
        logger.warning("Host App Auth: Invalid X-Host-App-Secret provided.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Invalid X-Host-App-Secret.",
            headers={"WWW-Authenticate": 'Basic realm="Plexus Host App Registration"'}
        )
    
    logger.info("Host App Auth: X-Host-App-Secret verified successfully.")
    return x_host_app_secret


def get_plexus_user_token_manager_dependency() -> PlexusUserTokenManagerProtocol:
    """Dependency provider for the Plexus user token manager."""
    return DefaultPlexusUserTokenManager()


async def get_current_plexus_user(
    request: FastAPIRequest,
    token_store: Annotated[AbstractPlexusUserAuthTokenStore, Depends(get_plexus_user_auth_token_store_dependency)],
    token_manager: Annotated[PlexusUserTokenManagerProtocol, Depends(get_plexus_user_token_manager_dependency)],
    authorization: Annotated[Optional[str], Header()] = None 
) -> Dict[str, Any]:
    """
    Authenticates and validates a Plexus user based on their Bearer token.
    
    Extracts entity_id from the request path and validates that the provided token
    belongs to that specific entity. Returns user information if authentication succeeds.
    """
    entity_id_from_path = request.path_params.get("entity_id")
    if not entity_id_from_path:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Entity ID missing in path.")

    token: Optional[str] = None
    auth_method_used: Optional[str] = None

    # Extract Bearer token from Authorization header
    if authorization:
        scheme, _, credentials = authorization.partition(" ")
        if scheme.lower() == "bearer":
            token = credentials
            auth_method_used = "Header (Bearer)"
    
    if not token:
        logger.warning(f"Plexus User Auth: No token provided for E:{entity_id_from_path} via Bearer header.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated: Missing or invalid Plexus User Auth Token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Hash the token and verify it exists and matches the entity
    token_hash = token_manager.hash_token(token)
    token_data = await token_store.get_token_data_by_hash(token_hash)

    if not token_data or token_data.entity_id != entity_id_from_path:
        logger.warning(f"Plexus User Auth: Invalid or mismatched token for E:{entity_id_from_path}. Auth method: {auth_method_used}.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired Plexus User Auth Token for this entity.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Update token last used timestamp for tracking purposes
    await token_store.update_token_last_used(token_hash)
    logger.info(f"Plexus User Auth: Successful for E:{entity_id_from_path}, User:{token_data.persistent_user_id} via {auth_method_used}.")
    
    return {"entity_id": token_data.entity_id, "persistent_user_id": token_data.persistent_user_id}