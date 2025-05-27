from __future__ import annotations
import logging
from typing import Optional
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..oauth.storage_interfaces import AbstractUserExternalApiKeyStore
from datetime import datetime, timezone

from .models import StoredUserExternalApiKey, UserApiKeySubmissionRequest
from ..utils.security import FernetEncryptor
from ..settings import settings

logger = logging.getLogger(__name__)


class UserExternalApiKeyService:
    """Service for managing encrypted external API keys for users."""
    
    def __init__(self, api_key_store: "AbstractUserExternalApiKeyStore"):
        self.store = api_key_store
        # Initialize encryptor to handle all encryption/decryption operations
        self._encryptor = FernetEncryptor(settings.plexus_encryption_key)
        
        if not self._encryptor.key_valid:
            logger.critical(
                "UserExternalApiKeyService: PLEXUS_ENCRYPTION_KEY is invalid or not set. "
                "API key storage will be insecure or fail."
            )

    async def save_or_update_api_key(
        self, 
        entity_id: str, 
        persistent_user_id: str, 
        submission_request: UserApiKeySubmissionRequest
    ) -> Optional[StoredUserExternalApiKey]:
        """
        Encrypts and saves/updates an API key for a user.
        
        Preserves original registration time for existing keys while updating the timestamp.
        Returns the stored model with encrypted value for confirmation purposes.
        """
        if not self._encryptor.key_valid or not self._encryptor.fernet_instance:
            logger.error("Cannot save API key: Encryption service is not properly configured.")
            return None

        # Encrypt the API key before storage
        raw_key_value = submission_request.api_key_value.get_secret_value()
        encrypted_value = self._encryptor.encrypt(raw_key_value)

        if not encrypted_value:
            logger.error(
                f"Failed to encrypt API key for E:{entity_id}, U:{persistent_user_id}, "
                f"P:{submission_request.provider_name}."
            )
            return None

        now = datetime.now(timezone.utc)
        
        # Check if this is an update or new registration
        existing_key_data = await self.store.load_api_key_data(
            entity_id, persistent_user_id, submission_request.provider_name
        )

        if existing_key_data:
            # Preserve original registration time for updates
            key_data_to_save = StoredUserExternalApiKey(
                entity_id=entity_id,
                persistent_user_id=persistent_user_id,
                provider_name=submission_request.provider_name,
                encrypted_api_key_value=encrypted_value,
                registered_at=existing_key_data.registered_at,
                last_updated_at=now 
            )
        else:
            # New registration
            key_data_to_save = StoredUserExternalApiKey(
                entity_id=entity_id,
                persistent_user_id=persistent_user_id,
                provider_name=submission_request.provider_name,
                encrypted_api_key_value=encrypted_value,
                registered_at=now,
                last_updated_at=now
            )
        
        await self.store.save_api_key(key_data_to_save)
        logger.info(
            f"API key for E:{entity_id}, U:{persistent_user_id}, "
            f"P:{submission_request.provider_name} saved/updated."
        )
        
        return key_data_to_save

    async def get_decrypted_api_key(
        self, entity_id: str, persistent_user_id: str, provider_name: str
    ) -> Optional[str]:
        """
        Retrieves and decrypts an API key for the specified user and provider.
        
        Returns the plain text API key or None if not found or decryption fails.
        """
        if not self._encryptor.key_valid or not self._encryptor.fernet_instance:
            logger.error("Cannot get API key: Encryption service is not properly configured.")
            return None
            
        stored_data = await self.store.load_api_key_data(entity_id, persistent_user_id, provider_name)
        
        if stored_data and stored_data.encrypted_api_key_value:
            decrypted_key = self._encryptor.decrypt(stored_data.encrypted_api_key_value)
            if decrypted_key:
                return decrypted_key
            else:
                logger.error(
                    f"Failed to decrypt API key for E:{entity_id}, U:{persistent_user_id}, "
                    f"P:{provider_name}."
                )
                return None
        
        return None

    async def delete_api_key(
        self, entity_id: str, persistent_user_id: str, provider_name: str
    ) -> bool:
        """Deletes an API key for the specified user and provider."""
        return await self.store.delete_api_key(entity_id, persistent_user_id, provider_name)