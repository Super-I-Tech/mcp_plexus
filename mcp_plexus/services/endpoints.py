# mcp_plexus/services/endpoints.py
import logging
from fastapi import APIRouter, Depends, HTTPException, Path, status
from typing import Annotated, Dict, Any

from .models import UserApiKeySubmissionRequest
from .service import UserExternalApiKeyService
from ..oauth.storage_interfaces import AbstractUserExternalApiKeyStore 
from .sqlite_user_external_api_key_store import get_sqlite_user_external_api_key_store 
from ..plexus_auth.dependencies import get_current_plexus_user 

logger = logging.getLogger(__name__)

user_services_router = APIRouter(
    prefix="/{entity_id}/plexus-services", 
    tags=["User Services - API Keys"],
)


async def get_user_external_api_key_service(
    api_key_store: Annotated[
        AbstractUserExternalApiKeyStore, 
        Depends(get_sqlite_user_external_api_key_store)
    ]
) -> UserExternalApiKeyService:
    """
    Factory function to create a UserExternalApiKeyService instance with proper dependency injection.
    """
    return UserExternalApiKeyService(api_key_store=api_key_store)


@user_services_router.post(
    "/api-keys",
    response_model=Dict[str, str], 
    status_code=status.HTTP_200_OK, 
    summary="Submit or update an external API key for a specific provider."
)
async def submit_or_update_user_api_key(
    request_data: UserApiKeySubmissionRequest,
    entity_id: Annotated[
        str, 
        Path(description="The Entity ID for which this API key is being submitted.")
    ],
    current_plexus_user: Annotated[Dict[str, Any], Depends(get_current_plexus_user)], 
    service: Annotated[UserExternalApiKeyService, Depends(get_user_external_api_key_service)]
):
    """
    Endpoint to store or update an external API key for a user within a specific entity.
    The API key is encrypted before storage for security purposes.
    """
    persistent_user_id = current_plexus_user.get("persistent_user_id")
    if not persistent_user_id:
        # Additional validation layer to ensure user identity is properly established
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="User identity not established."
        )

    logger.info(
        f"User '{persistent_user_id}' in entity '{entity_id}' "
        f"submitting API key for provider '{request_data.provider_name}'."
    )
    
    stored_key_data = await service.save_or_update_api_key(
        entity_id=entity_id,
        persistent_user_id=persistent_user_id,
        submission_request=request_data
    )

    # Check if the storage operation was successful
    if not stored_key_data:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save API key. Encryption might have failed or an internal error occurred."
        )
    
    return {
        "message": f"API key for provider '{request_data.provider_name}' was successfully saved/updated."
    }