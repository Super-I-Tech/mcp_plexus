# mcp_plexus/plexus_auth/__init__.py
"""
Plexus authentication module initialization.

This module provides a comprehensive authentication system for the Plexus platform,
including user registration, token management, storage interfaces, and API endpoints.
"""

# Core data models for authentication requests and responses
from .models import (
    UserRegistrationRequest,
    PlexusUserAuthTokenResponse,
    PlexusUserAuthTokenData
)

# Authentication-specific error classes for proper exception handling
from .errors import (
    UserAuthError,
    InvalidHostAppIdentifierError,
    PlexusUserAuthTokenGenerationError,
    PlexusUserAuthTokenValidationError
)

# Token management protocols and implementations
from .token_manager import (
    PlexusUserTokenManagerProtocol,
    DefaultPlexusUserTokenManager
)

# Storage abstraction layer for auth token persistence
from .storage_interfaces import AbstractPlexusUserAuthTokenStore

# SQLite-specific implementation of the auth token store
from .sqlite_user_auth_token_store import (
    SQLitePlexusUserAuthTokenStore,
    get_sqlite_plexus_user_auth_token_store
)

# FastAPI router containing authentication endpoints
from .endpoints import plexus_auth_router

# Explicit public API definition for the authentication module
__all__ = [
    # Data models
    "UserRegistrationRequest",
    "PlexusUserAuthTokenResponse",
    "PlexusUserAuthTokenData",
    
    # Exception classes
    "UserAuthError",
    "InvalidHostAppIdentifierError",
    "PlexusUserAuthTokenGenerationError",
    "PlexusUserAuthTokenValidationError",
    
    # Token management
    "PlexusUserTokenManagerProtocol",
    "DefaultPlexusUserTokenManager",
    
    # Storage interfaces
    "AbstractPlexusUserAuthTokenStore",
    "SQLitePlexusUserAuthTokenStore",
    "get_sqlite_plexus_user_auth_token_store",
    
    # API endpoints
    "plexus_auth_router"
]