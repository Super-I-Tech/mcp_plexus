# mcp_plexus/oauth_providers_admin/endpoints.py
import logging
from fastapi import APIRouter, Depends, HTTPException, Path, status
from typing import List, Annotated

from ..oauth.models import OAuthProviderSettings
from .service import ExternalOAuthProviderService
from ..oauth.storage import get_external_oauth_provider_config_store
from ..oauth.storage_interfaces import AbstractExternalOAuthProviderConfigStore
from ..dependencies import get_admin_api_key

logger = logging.getLogger(__name__)

# Admin router for managing external OAuth provider configurations per entity
# Requires admin API key authentication for all endpoints
external_oauth_providers_admin_router = APIRouter(
    prefix="/{entity_id}/admin/external-oauth-providers",
    tags=["Admin - External OAuth Providers (per Entity)"],
    dependencies=[Depends(get_admin_api_key)]
)


async def get_ext_oauth_provider_service(
    store: Annotated[
        AbstractExternalOAuthProviderConfigStore, 
        Depends(get_external_oauth_provider_config_store)
    ]
) -> ExternalOAuthProviderService:
    """Factory function to create ExternalOAuthProviderService with injected storage."""
    return ExternalOAuthProviderService(store)


@external_oauth_providers_admin_router.post(
    "/", 
    response_model=OAuthProviderSettings, 
    status_code=status.HTTP_201_CREATED,
    summary="Register a new External OAuth Provider configuration for an Entity"
)
async def create_external_oauth_provider(
    entity_id: Annotated[str, Path(description="The Entity ID for which to register the provider.")],
    provider_config_create: OAuthProviderSettings,
    service: Annotated[ExternalOAuthProviderService, Depends(get_ext_oauth_provider_service)]
):
    """
    Creates a new OAuth provider configuration for the specified entity.
    Returns 409 if provider already exists, 500 for unexpected errors.
    """
    logger.info(
        f"API: Create ext OAuth provider '{provider_config_create.provider_name}' "
        f"for entity '{entity_id}'."
    )
    try:
        created_config = await service.create_provider_config(entity_id, provider_config_create)
        return created_config
    except ValueError as e:
        logger.warning(
            f"API: Ext OAuth provider creation failed for E:'{entity_id}', "
            f"P:'{provider_config_create.provider_name}': {e}"
        )
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except Exception as e:
        logger.error(f"API: Unexpected error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Could not create external OAuth provider configuration."
        )


@external_oauth_providers_admin_router.get(
    "/{provider_name}", 
    response_model=OAuthProviderSettings,
    summary="Get a specific External OAuth Provider configuration for an Entity"
)
async def get_external_oauth_provider(
    entity_id: Annotated[str, Path(description="The Entity ID.")],
    provider_name: Annotated[
        str, 
        Path(description="The name of the external OAuth provider (e.g., 'github').")
    ],
    service: Annotated[ExternalOAuthProviderService, Depends(get_ext_oauth_provider_service)]
):
    """Retrieves a specific OAuth provider configuration by entity and provider name."""
    config = await service.get_provider_config(entity_id, provider_name)
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail=f"External OAuth provider '{provider_name}' not found for entity '{entity_id}'."
        )
    return config


@external_oauth_providers_admin_router.get(
    "/", 
    response_model=List[OAuthProviderSettings],
    summary="List all External OAuth Provider configurations for an Entity"
)
@external_oauth_providers_admin_router.get(
    "", 
    response_model=List[OAuthProviderSettings],
    include_in_schema=False  # Handle trailing slash variant without duplicating in docs
)
async def list_external_oauth_providers(
    entity_id: Annotated[str, Path(description="The Entity ID.")],
    service: Annotated[ExternalOAuthProviderService, Depends(get_ext_oauth_provider_service)]
):
    """Returns all OAuth provider configurations for the specified entity."""
    return await service.list_provider_configs(entity_id)


@external_oauth_providers_admin_router.put(
    "/{provider_name}", 
    response_model=OAuthProviderSettings,
    summary="Update an External OAuth Provider configuration for an Entity"
)
async def update_external_oauth_provider(
    entity_id: Annotated[str, Path(description="The Entity ID.")],
    provider_name: Annotated[str, Path(description="The name of the provider to update.")],
    provider_config_update: OAuthProviderSettings,
    service: Annotated[ExternalOAuthProviderService, Depends(get_ext_oauth_provider_service)]
):
    """
    Updates an existing OAuth provider configuration.
    Requires all fields to be present in the request body.
    """
    logger.info(f"API: Update ext OAuth provider '{provider_name}' for entity '{entity_id}'.")
    try:
        updated_config = await service.update_provider_config(
            entity_id, 
            provider_name, 
            provider_config_update
        )
        if not updated_config:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail=f"External OAuth provider '{provider_name}' not found for entity '{entity_id}'."
            )
        return updated_config
    except ValueError as e:
        # Handle service-level validation errors (e.g., provider name mismatch)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(
            f"API: Unexpected error updating ext OAuth provider '{provider_name}' "
            f"for E:'{entity_id}': {e}", 
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Could not update external OAuth provider configuration."
        )


@external_oauth_providers_admin_router.delete(
    "/{provider_name}", 
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an External OAuth Provider configuration for an Entity"
)
async def delete_external_oauth_provider(
    entity_id: Annotated[str, Path(description="The Entity ID.")],
    provider_name: Annotated[str, Path(description="The name of the provider to delete.")],
    service: Annotated[ExternalOAuthProviderService, Depends(get_ext_oauth_provider_service)]
):
    """Removes an OAuth provider configuration for the specified entity."""
    deleted = await service.delete_provider_config(entity_id, provider_name)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail=f"External OAuth provider '{provider_name}' not found for entity '{entity_id}' "
                   f"or could not be deleted."
        )
    return None