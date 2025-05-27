# mcp_plexus/plexus_auth/token_manager.py
import secrets
import hashlib
from abc import ABC, abstractmethod
from typing import Tuple

from ..settings import settings


class PlexusUserTokenManagerProtocol(ABC):
    """Protocol defining the interface for user token management operations."""
    
    @abstractmethod
    def generate_token_and_hash(self) -> Tuple[str, str]:
        """Generate a new token and return both the raw token and its hash."""
        pass

    @abstractmethod
    def hash_token(self, token: str) -> str:
        """Create a secure hash of the provided token."""
        pass


class DefaultPlexusUserTokenManager(PlexusUserTokenManagerProtocol):
    """Default implementation of token management using secure random generation and SHA-256 hashing."""
    
    def generate_token_and_hash(self) -> Tuple[str, str]:
        """
        Generate a cryptographically secure token and its corresponding hash.
        
        Returns:
            Tuple containing the raw token (for client use) and its hash (for storage).
        """
        token = secrets.token_urlsafe(settings.plexus_user_auth_token_bytes_length)
        token_hash = self.hash_token(token)
        return token, token_hash

    def hash_token(self, token: str) -> str:
        """
        Create SHA-256 hash of token for secure storage.
        
        Raw tokens should never be stored; only their hashes are persisted
        to prevent exposure in case of data breaches.
        """
        return hashlib.sha256(token.encode('utf-8')).hexdigest()