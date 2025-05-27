# mcp_plexus/plexus_auth/storage_interfaces.py
from abc import ABC, abstractmethod
from typing import Optional
from .models import PlexusUserAuthTokenData


class AbstractPlexusUserAuthTokenStore(ABC):
    """
    Abstract base class defining the interface for user authentication token storage.
    
    This interface provides methods for managing authentication tokens including
    creation, retrieval, updates, and deletion. Implementations should handle
    the underlying storage mechanism (database, cache, etc.).
    """

    @abstractmethod
    async def save_token_data(self, token_data: PlexusUserAuthTokenData) -> None:
        """Store authentication token data in the underlying storage system."""
        pass

    @abstractmethod
    async def get_token_data_by_hash(self, token_hash: str) -> Optional[PlexusUserAuthTokenData]:
        """Retrieve token data using the token hash as identifier."""
        pass
    
    @abstractmethod
    async def get_token_data_by_user_id(self, entity_id: str, persistent_user_id: str) -> Optional[PlexusUserAuthTokenData]:
        """Retrieve token data using entity and user identifiers."""
        pass

    @abstractmethod
    async def delete_token_data_by_hash(self, token_hash: str) -> None:
        """Remove token data from storage using the token hash."""
        pass

    @abstractmethod
    async def delete_token_data_by_user_id(self, entity_id: str, persistent_user_id: str) -> None:
        """Remove token data from storage using entity and user identifiers."""
        pass
        
    @abstractmethod
    async def update_token_last_used(self, token_hash: str) -> None:
        """Update the last used timestamp for token activity tracking."""
        pass

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the storage system and prepare for operations."""
        pass

    @abstractmethod
    async def teardown(self) -> None:
        """Clean up resources and gracefully shutdown the storage system."""
        pass