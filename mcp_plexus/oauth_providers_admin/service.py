# mcp_plexus/oauth_providers_admin/service.py
import logging
from typing import Optional, List

from ..oauth.models import OAuthProviderSettings
from ..oauth.storage_interfaces import AbstractExternalOAuthProviderConfigStore


logger = logging.getLogger(__name__)


class ExternalOAuthProviderService:
    """Service layer for managing external OAuth provider configurations."""
    
    def __init__(self, store: AbstractExternalOAuthProviderConfigStore):
        self.store = store
        logger.debug(f"ExternalOAuthProviderService initialized with store: {type(store)}")

    async def create_provider_config(
        self, 
        entity_id: str, 
        config_create: OAuthProviderSettings
    ) -> OAuthProviderSettings:
        """
        Creates a new OAuth provider configuration for an entity.
        
        Raises ValueError if provider already exists for the entity.
        """
        logger.info(
            f"Service: Creating provider config '{config_create.provider_name}' "
            f"for entity '{entity_id}'."
        )
        
        # Check if provider already exists to prevent duplicates
        existing = await self.store.load_provider_config(entity_id, config_create.provider_name)
        if existing:
            logger.warning(
                f"Service: Provider '{config_create.provider_name}' already exists "
                f"for entity '{entity_id}'. Raising error."
            )
            raise ValueError(
                f"Provider '{config_create.provider_name}' already configured "
                f"for entity '{entity_id}'. Use update instead."
            )
        
        await self.store.save_provider_config(entity_id, config_create)
        
        # Verify the configuration was saved successfully
        created_config = await self.store.load_provider_config(entity_id, config_create.provider_name)
        if not created_config:
            logger.error(
                f"Service: CRITICAL - Failed to load provider config "
                f"'{config_create.provider_name}' for entity '{entity_id}' "
                f"immediately after save."
            )
            raise RuntimeError(
                f"Failed to retrieve provider config '{config_create.provider_name}' "
                f"after creation."
            )
        return created_config

    async def get_provider_config(
        self, 
        entity_id: str, 
        provider_name: str
    ) -> Optional[OAuthProviderSettings]:
        """Retrieves a specific OAuth provider configuration for an entity."""
        logger.info(f"Service: Getting provider config '{provider_name}' for entity '{entity_id}'.")
        return await self.store.load_provider_config(entity_id, provider_name)

    async def list_provider_configs(self, entity_id: str) -> List[OAuthProviderSettings]:
        """Retrieves all OAuth provider configurations for an entity."""
        logger.info(f"Service: Listing all provider configs for entity '{entity_id}'.")
        return await self.store.load_all_provider_configs_for_entity(entity_id)

    async def update_provider_config(
        self, 
        entity_id: str, 
        provider_name: str, 
        config_update: OAuthProviderSettings
    ) -> Optional[OAuthProviderSettings]:
        """
        Updates an existing OAuth provider configuration.
        
        Returns None if the provider doesn't exist.
        Raises ValueError if provider names don't match.
        """
        logger.info(f"Service: Updating provider config '{provider_name}' for entity '{entity_id}'.")
        
        # Ensure provider name consistency between path and payload
        if config_update.provider_name != provider_name:
            logger.warning(
                f"Service: Provider name in path ('{provider_name}') and body "
                f"('{config_update.provider_name}') must match for update."
            )
            raise ValueError("Provider name in path and body must match for update.")
        
        # Verify the provider exists before attempting update
        existing_config = await self.store.load_provider_config(entity_id, provider_name)
        if not existing_config:
            logger.warning(
                f"Service: Provider '{provider_name}' not found for entity '{entity_id}'. "
                f"Cannot update."
            )
            return None

        # Perform upsert operation
        await self.store.save_provider_config(entity_id, config_update)
        
        # Verify the update was successful
        updated_config = await self.store.load_provider_config(entity_id, provider_name)
        if not updated_config:
            logger.error(
                f"Service: CRITICAL - Failed to load provider config '{provider_name}' "
                f"for entity '{entity_id}' immediately after update."
            )
            raise RuntimeError(
                f"Failed to retrieve provider config '{provider_name}' after update."
            )
        return updated_config

    async def delete_provider_config(self, entity_id: str, provider_name: str) -> bool:
        """
        Deletes an OAuth provider configuration.
        
        Returns True if deletion was successful, False if provider didn't exist.
        """
        logger.info(f"Service: Deleting provider config '{provider_name}' for entity '{entity_id}'.")
        
        # Check if provider exists before deletion
        existing = await self.store.load_provider_config(entity_id, provider_name)
        if not existing:
            logger.warning(
                f"Service: Provider '{provider_name}' not found for entity '{entity_id}'. "
                f"Cannot delete."
            )
            return False
        
        await self.store.delete_provider_config(entity_id, provider_name)
        
        # Verify deletion was successful
        if await self.store.load_provider_config(entity_id, provider_name) is None:
            return True
        else:
            logger.error(
                f"Service: Failed to confirm deletion of provider '{provider_name}' "
                f"for entity '{entity_id}'."
            )
            return False