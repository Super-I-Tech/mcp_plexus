# mcp_plexus/oauth/__init__.py
# OAuth 2.1 Provider Package for MCP Plexus

# Core OAuth models and data structures
from .models import (
    TokenResponse, 
    AuthCodeData, 
    AuthRequest, 
    TokenRequest, 
    OAuthClient, 
    OAuthProviderSettings, 
    WellKnownOAuthMetadata 
)

# OAuth error types and exception handling
from .errors import (
    OAuthError, 
    InvalidRequestError, 
    InvalidClientError, 
    InvalidGrantError, 
    UnauthorizedClientError,  
    UnsupportedGrantTypeError, 
    InvalidScopeError, 
    ServerError, 
    TemporarilyUnavailableError,
    PlexusExternalAuthRequiredError, 
    InvalidTokenError, 
    InsufficientScopeError
)

# PKCE (Proof Key for Code Exchange) utilities for enhanced security
from .pkce import generate_pkce_code_verifier, generate_pkce_code_challenge

# Main OAuth provider implementation
from .provider import PlexusOAuthProvider

# FastAPI router endpoints for OAuth flows
from .endpoints import oauth_router

# Authentication decorators
from .decorators import requires_auth 

# Abstract storage interfaces for dependency injection and flexibility
from .storage_interfaces import (
    AbstractOAuthTokenStore,
    AbstractAuthCodeStore,
    AbstractExternalOAuthProviderConfigStore,
    AbstractOAuthClientStore,
    AbstractUserExternalTokenStore
)

# Redis-based storage implementations
from .storage import ( 
    RedisOAuthTokenStore,
    RedisAuthCodeStore,
    RedisExternalOAuthProviderConfigStore,
    get_oauth_token_store, 
    get_auth_code_store,
    get_external_oauth_provider_config_store,
    get_internal_oauth_client_store
)

# SQLite-based storage implementations for local/embedded usage
from .sqlite_oauth_internal_token_store import (
    SQLiteOAuthTokenStore, 
    get_sqlite_oauth_internal_token_store
)
from .sqlite_auth_code_store import (
    SQLiteAuthCodeStore, 
    get_sqlite_auth_code_store
)
from .sqlite_external_oauth_provider_config_store import (
    SQLiteExternalOAuthProviderConfigStore, 
    get_sqlite_external_oauth_provider_config_store
)
from .sqlite_oauth_internal_client_store import (
    SQLiteOAuthClientStore, 
    get_sqlite_internal_oauth_client_store
)

# User-specific external token storage (Redis implementation)
from .user_token_store import (
    RedisUserExternalTokenStore,
    get_user_external_token_store,
)

# User-specific external token storage (SQLite implementation)
from .sqlite_user_external_token_store import (
    SQLiteUserExternalTokenStore, 
    get_sqlite_user_external_token_store
)

# Public API - explicitly define what should be imported when using "from oauth import *"
__all__ = [
    # Core models and data structures
    "TokenResponse", 
    "AuthCodeData", 
    "AuthRequest", 
    "TokenRequest", 
    "OAuthClient",
    "OAuthProviderSettings", 
    "WellKnownOAuthMetadata",
    
    # Error handling
    "OAuthError", 
    "InvalidRequestError", 
    "InvalidClientError", 
    "InvalidGrantError", 
    "UnauthorizedClientError", 
    "UnsupportedGrantTypeError", 
    "InvalidScopeError", 
    "InsufficientScopeError", 
    "PlexusExternalAuthRequiredError",
    
    # Security utilities
    "generate_pkce_code_verifier", 
    "generate_pkce_code_challenge",
    
    # Core provider
    "PlexusOAuthProvider",
    
    # Authentication
    "requires_auth",
    
    # API endpoints
    "oauth_router",
    
    # Storage interfaces and implementations for internal OAuth tokens and codes
    "AbstractOAuthTokenStore", 
    "RedisOAuthTokenStore", 
    "SQLiteOAuthTokenStore",
    "AbstractAuthCodeStore", 
    "RedisAuthCodeStore", 
    "SQLiteAuthCodeStore",
    "get_oauth_token_store", 
    "get_auth_code_store", 
    "get_sqlite_oauth_internal_token_store", 
    "get_sqlite_auth_code_store",
    
    # Storage for OAuth client configurations
    "AbstractOAuthClientStore", 
    "SQLiteOAuthClientStore",
    "get_internal_oauth_client_store", 
    "get_sqlite_internal_oauth_client_store",
    
    # Storage for external OAuth provider configurations
    "AbstractExternalOAuthProviderConfigStore", 
    "RedisExternalOAuthProviderConfigStore", 
    "SQLiteExternalOAuthProviderConfigStore",
    "get_external_oauth_provider_config_store", 
    "get_sqlite_external_oauth_provider_config_store",
    
    # Storage for user-specific external OAuth tokens
    "AbstractUserExternalTokenStore", 
    "RedisUserExternalTokenStore", 
    "SQLiteUserExternalTokenStore",
    "get_user_external_token_store", 
    "get_sqlite_user_external_token_store",
]