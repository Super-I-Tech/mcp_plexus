# mcp_plexus/oauth/storage_interfaces.py
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..services.models import StoredUserExternalApiKey

from .models import (
    AuthCodeData,
    AccessTokenData,
    RefreshTokenData,
    OAuthProviderSettings,
    OAuthClient
)

logger = logging.getLogger(__name__)


class AbstractAuthCodeStore(ABC):
    """Abstract base class for storing and managing OAuth authorization codes."""
    
    @abstractmethod
    async def save_auth_code(self, auth_code_data: AuthCodeData) -> None:
        """Store an authorization code with its associated data."""
        pass
    
    @abstractmethod
    async def load_auth_code(self, code: str) -> Optional[AuthCodeData]:
        """Retrieve authorization code data by code value."""
        pass
    
    @abstractmethod
    async def delete_auth_code(self, code: str) -> None:
        """Remove an authorization code from storage."""
        pass
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the storage backend."""
        pass
    
    @abstractmethod
    async def teardown(self) -> None:
        """Clean up storage resources."""
        pass


class AbstractUserExternalTokenStore(ABC):
    """Abstract base class for storing OAuth tokens obtained from external providers."""
    
    @abstractmethod
    async def save_user_external_token(
        self, 
        entity_id: str, 
        user_id: str, 
        provider_name: str, 
        token_data: Dict[str, Any]
    ) -> None:
        """Store external OAuth token data for a user."""
        pass
    
    @abstractmethod
    async def load_user_external_token(
        self, 
        entity_id: str, 
        user_id: str, 
        provider_name: str
    ) -> Optional[Dict[str, Any]]:
        """Retrieve external OAuth token data for a user."""
        pass
    
    @abstractmethod
    async def delete_user_external_token(
        self, 
        entity_id: str, 
        user_id: str, 
        provider_name: str
    ) -> None:
        """Remove external OAuth token data for a user."""
        pass
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the storage backend."""
        pass
    
    @abstractmethod
    async def teardown(self) -> None:
        """Clean up storage resources."""
        pass


class AbstractOAuthTokenStore(ABC):
    """Abstract base class for storing internal OAuth server tokens (access and refresh)."""
    
    @abstractmethod
    async def save_access_token(self, access_token_data: AccessTokenData) -> None:
        """Store an access token with its metadata."""
        pass
    
    @abstractmethod
    async def load_access_token(self, access_token: str) -> Optional[AccessTokenData]:
        """Retrieve access token data by token value."""
        pass
    
    @abstractmethod
    async def delete_access_token(self, access_token: str) -> None:
        """Remove an access token from storage."""
        pass
    
    @abstractmethod
    async def save_refresh_token(self, refresh_token_data: RefreshTokenData) -> None:
        """Store a refresh token with its metadata."""
        pass
    
    @abstractmethod
    async def load_refresh_token(self, refresh_token: str) -> Optional[RefreshTokenData]:
        """Retrieve refresh token data by token value."""
        pass
    
    @abstractmethod
    async def delete_refresh_token(self, refresh_token: str) -> None:
        """Remove a refresh token from storage."""
        pass
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the storage backend."""
        pass
    
    @abstractmethod
    async def teardown(self) -> None:
        """Clean up storage resources."""
        pass


class AbstractExternalOAuthProviderConfigStore(ABC):
    """Abstract base class for storing external OAuth provider configurations."""
    
    @abstractmethod
    async def save_provider_config(
        self, 
        entity_id: str, 
        provider_config: OAuthProviderSettings
    ) -> None:
        """Store OAuth provider configuration for an entity."""
        pass
    
    @abstractmethod
    async def load_provider_config(
        self, 
        entity_id: str, 
        provider_name: str
    ) -> Optional[OAuthProviderSettings]:
        """Retrieve OAuth provider configuration for an entity."""
        pass
    
    @abstractmethod
    async def delete_provider_config(
        self, 
        entity_id: str, 
        provider_name: str
    ) -> None:
        """Remove OAuth provider configuration for an entity."""
        pass
    
    @abstractmethod
    async def load_all_provider_configs_for_entity(
        self, 
        entity_id: str
    ) -> list[OAuthProviderSettings]:
        """Retrieve all OAuth provider configurations for an entity."""
        pass
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the storage backend."""
        pass
    
    @abstractmethod
    async def teardown(self) -> None:
        """Clean up storage resources."""
        pass


class AbstractUserExternalApiKeyStore(ABC):
    """Abstract base class for storing external API keys for users."""
    
    @abstractmethod
    async def save_api_key(self, api_key_data: "StoredUserExternalApiKey") -> None:
        """Store external API key data for a user."""
        pass
    
    @abstractmethod
    async def load_api_key_data(
        self, 
        entity_id: str, 
        persistent_user_id: str, 
        provider_name: str
    ) -> Optional["StoredUserExternalApiKey"]:
        """Retrieve external API key data for a user."""
        pass
    
    @abstractmethod
    async def delete_api_key(
        self, 
        entity_id: str, 
        persistent_user_id: str, 
        provider_name: str
    ) -> bool:
        """Remove external API key data for a user. Returns True if deleted."""
        pass
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the storage backend."""
        pass
    
    @abstractmethod
    async def teardown(self) -> None:
        """Clean up storage resources."""
        pass


class AbstractOAuthClientStore(ABC):
    """Abstract base class for storing internal OAuth server client registrations."""
    
    @abstractmethod
    async def save_client(self, client: OAuthClient) -> None:
        """Store OAuth client registration data."""
        pass
    
    @abstractmethod
    async def load_client(self, client_id: str) -> Optional[OAuthClient]:
        """Retrieve OAuth client by client ID."""
        pass
    
    @abstractmethod
    async def delete_client(self, client_id: str) -> None:
        """Remove OAuth client registration."""
        pass
    
    @abstractmethod
    async def list_clients_for_entity(self, entity_id: str) -> List[OAuthClient]:
        """Retrieve all OAuth clients associated with an entity."""
        pass
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the storage backend."""
        pass
    
    @abstractmethod
    async def teardown(self) -> None:
        """Clean up storage resources."""
        pass