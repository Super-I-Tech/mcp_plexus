# mcp_plexus/oauth/models.py
from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import secrets


def default_state_generator() -> str:
    """Generate a cryptographically secure random state parameter for OAuth requests."""
    return secrets.token_urlsafe(32)


class AuthRequest(BaseModel):
    """OAuth authorization request parameters as per RFC 6749."""
    response_type: str = Field(description="Must be 'code'.")
    client_id: str = Field(description="The client identifier.")
    redirect_uri: HttpUrl = Field(description="The URI to redirect the user agent back to.")
    scope: Optional[str] = Field(
        default=None, 
        description="Space-separated list of requested scopes."
    )
    state: str = Field(
        default_factory=default_state_generator,
        description="An opaque value used to maintain state between the request and callback."
    )
    code_challenge: Optional[str] = Field(
        default=None, 
        description="PKCE code challenge."
    )
    code_challenge_method: Optional[str] = Field(
        default=None, 
        description="PKCE code challenge method (e.g., 'S256')."
    )


class TokenRequest(BaseModel):
    """OAuth token request parameters for authorization code or refresh token grants."""
    grant_type: str = Field(
        description="Type of grant, e.g., 'authorization_code' or 'refresh_token'."
    )
    code: Optional[str] = Field(
        default=None, 
        description="The authorization code received from the authorization server."
    )
    redirect_uri: Optional[HttpUrl] = Field(
        default=None, 
        description="Required if included in the authorization request."
    )
    client_id: Optional[str] = Field(
        default=None, 
        description="The client identifier (optional for public clients)."
    )
    code_verifier: Optional[str] = Field(
        default=None, 
        description="PKCE code verifier."
    )
    refresh_token: Optional[str] = Field(
        default=None, 
        description="The refresh token."
    )


class TokenResponse(BaseModel):
    """OAuth token response structure as per RFC 6749."""
    access_token: str
    token_type: str = "Bearer"
    expires_in: Optional[int] = None
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    id_token: Optional[str] = None  # For OpenID Connect


class AuthCodeData(BaseModel):
    """Internal representation of authorization code data for storage and validation."""
    code: str = Field(description="The authorization code.")
    client_id: str
    redirect_uri: HttpUrl
    requested_scopes: Optional[List[str]] = None
    user_id: str  # Identifier for the authenticated user within MCP Plexus
    entity_id: str  # MCP Plexus tenant ID
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = None
    expires_at: datetime
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AccessTokenData(BaseModel):
    """Internal representation of access token data for validation and scope checking."""
    access_token: str
    client_id: str
    user_id: str
    entity_id: str
    issued_scopes: Optional[List[str]] = None
    expires_at: datetime
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RefreshTokenData(BaseModel):
    """Internal representation of refresh token data for token renewal."""
    refresh_token: str
    client_id: str
    user_id: str
    entity_id: str
    issued_scopes: Optional[List[str]] = None  # Scopes originally granted
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class OAuthClient(BaseModel):
    """Represents a registered OAuth client application."""
    client_id: str
    client_secret_hash: Optional[str] = None  # For confidential clients
    client_name: str
    redirect_uris: List[HttpUrl]
    allowed_scopes: List[str] = Field(default_factory=list)
    allowed_grant_types: List[str] = Field(default=["authorization_code", "refresh_token"])
    is_trusted_internal: bool = Field(
        default=False,
        description="If True, consent may be auto-approved for this client for specific internal flows."
    )


class OAuthProviderSettings(BaseModel):
    """
    Configuration for an external (third-party) OAuth provider that MCP Plexus tools might use.
    This is distinct from MCP Plexus's own embedded OAuth server settings.
    """
    provider_name: str = Field(
        description="Unique name for this provider (e.g., 'google', 'github')."
    )
    client_id: str = Field(
        description="Client ID obtained from the third-party provider."
    )
    client_secret: str = Field(
        description="Client Secret obtained from the third-party provider."
    )
    authorization_url: HttpUrl = Field(
        description="The third-party provider's authorization endpoint."
    )
    token_url: HttpUrl = Field(
        description="The third-party provider's token endpoint."
    )
    userinfo_url: Optional[HttpUrl] = Field(
        default=None,
        description="The third-party provider's userinfo endpoint (optional)."
    )
    default_scopes: List[str] = Field(
        description="Default scopes to request if not specified by the tool."
    )


class WellKnownOAuthMetadata(BaseModel):
    """OAuth 2.0 server metadata as defined in RFC 8414 for discovery endpoint."""
    issuer: HttpUrl
    authorization_endpoint: HttpUrl
    token_endpoint: HttpUrl
    scopes_supported: Optional[List[str]] = None
    response_types_supported: List[str] = ["code"]
    grant_types_supported: List[str] = ["authorization_code", "refresh_token"]
    token_endpoint_auth_methods_supported: Optional[List[str]] = None
    code_challenge_methods_supported: List[str] = ["S256", "plain"]