import logging
from fastapi import APIRouter, Depends, HTTPException, Path, Request
from typing import Annotated
from datetime import datetime, timezone

from .models import UserRegistrationRequest, PlexusUserAuthTokenResponse, PlexusUserAuthTokenData
from .errors import InvalidHostAppIdentifierError, PlexusUserAuthTokenGenerationError
from .token_manager import DefaultPlexusUserTokenManager, PlexusUserTokenManagerProtocol
from .storage_interfaces import AbstractPlexusUserAuthTokenStore
from .dependencies import verify_host_app_secret
from .sqlite_user_auth_token_store import get_sqlite_plexus_user_auth_token_store
from ..settings import settings

logger = logging.getLogger(__name__)
plexus_auth_router = APIRouter()


async def get_plexus_user_auth_token_store_dependency() -> AbstractPlexusUserAuthTokenStore:
    """
    Returns the configured token store implementation.
    Currently uses SQLite but can be extended to support multiple backends.
    """
    return await get_sqlite_plexus_user_auth_token_store()


def get_plexus_user_token_manager_dependency() -> PlexusUserTokenManagerProtocol:
    """Returns the default token manager for generating and hashing tokens."""
    return DefaultPlexusUserTokenManager()


@plexus_auth_router.post(
    "/register-user",
    response_model=PlexusUserAuthTokenResponse,
    summary="Register a host application user and get a Plexus User Auth Token",
    tags=["Plexus User Authentication"]
)
async def register_user_and_get_token(
    request_data: UserRegistrationRequest,
    entity_id: Annotated[str, Path(description="The tenant identifier for this registration.")],
    token_store: Annotated[
        AbstractPlexusUserAuthTokenStore,
        Depends(get_plexus_user_auth_token_store_dependency)
    ],
    token_manager: Annotated[
        PlexusUserTokenManagerProtocol,
        Depends(get_plexus_user_token_manager_dependency)
    ],
    _: Annotated[str, Depends(verify_host_app_secret)]
):
    """
    Registers a user from a host application and generates a Plexus authentication token.
    
    If the user already exists, generates a new token and updates the existing record.
    The host application secret is verified via dependency injection before this handler executes.
    """
    logger.info(
        f"Attempting user registration for entity '{entity_id}', "
        f"host_app_user_id: '{request_data.user_id_from_host_app}'."
    )

    # Additional safety check for registration secret configuration
    if not settings.host_app_registration_secret:
        logger.warning(
            "HOST_APP_REGISTRATION_SECRET is not set, yet request proceeded. "
            "This indicates a potential logic flaw if header was checked."
        )

    persistent_user_id = request_data.user_id_from_host_app
    
    # Check if user already exists in the system
    existing_token_data = await token_store.get_token_data_by_user_id(entity_id, persistent_user_id)
    
    if existing_token_data:
        logger.info(
            f"User '{persistent_user_id}' in entity '{entity_id}' already exists. "
            f"Generating a new token and updating record."
        )

    try:
        # Generate new token and its hash for secure storage
        plexus_user_auth_token, token_hash = token_manager.generate_token_and_hash()
        
        # Create token data record with current timestamp
        new_token_data = PlexusUserAuthTokenData(
            entity_id=entity_id,
            persistent_user_id=persistent_user_id,
            token_hash=token_hash,
            created_at=datetime.now(timezone.utc).isoformat(),
            last_used_at=datetime.now(timezone.utc).isoformat()
        )
        
        # Save or update the token data in storage
        await token_store.save_token_data(new_token_data)
        
        logger.info(
            f"Successfully processed Plexus User Auth Token for user '{persistent_user_id}' "
            f"in entity '{entity_id}'."
        )
        
        return PlexusUserAuthTokenResponse(
            plexus_user_auth_token=plexus_user_auth_token,
            persistent_user_id=persistent_user_id
        )
        
    except Exception as e:
        logger.error(
            f"Error during token generation/storage for user '{persistent_user_id}': {e}",
            exc_info=True
        )
        raise PlexusUserAuthTokenGenerationError(
            detail=f"Could not process user token: {str(e)}"
        )