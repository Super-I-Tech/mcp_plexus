# mcp_plexus/oauth/errors.py
from fastapi import HTTPException, status
from typing import Optional


class OAuthError(HTTPException):
    """Base class for OAuth 2.1 errors that properly formats error responses."""
    
    def __init__(
        self, 
        status_code: int, 
        error: str, 
        error_description: str | None = None, 
        error_uri: str | None = None
    ):
        self.error = error
        self.error_description = error_description
        self.error_uri = error_uri
        
        # Standard OAuth Bearer token authentication header
        headers = {"WWW-Authenticate": "Bearer"}
        
        # Build error detail dictionary according to OAuth specification
        detail = {"error": error}
        if error_description:
            detail["error_description"] = error_description
        if error_uri:
            detail["error_uri"] = error_uri
            
        super().__init__(status_code=status_code, detail=detail, headers=headers)


class InvalidRequestError(OAuthError):
    """
    The request is missing a required parameter, includes an
    unsupported parameter value (other than grant type),
    repeats a parameter, includes multiple credentials,
    utilizes more than one mechanism for authenticating the
    client, or is otherwise malformed.
    (RFC 6749 - Section 5.2)
    """
    
    def __init__(self, error_description: str | None = None, error_uri: str | None = None):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            error="invalid_request",
            error_description=error_description,
            error_uri=error_uri
        )


class InvalidClientError(OAuthError):
    """
    Client authentication failed (e.g., unknown client, no
    client authentication included, or unsupported
    authentication method). The authorization server MAY
    return an HTTP 401 (Unauthorized) status code to indicate
    which HTTP authentication schemes are supported.
    (RFC 6749 - Section 5.2)
    """
    
    def __init__(
        self, 
        error_description: str | None = "Client authentication failed.", 
        error_uri: str | None = None
    ):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            error="invalid_client",
            error_description=error_description,
            error_uri=error_uri
        )


class InvalidGrantError(OAuthError):
    """
    The provided authorization grant (e.g., authorization
    code, resource owner credentials) or refresh token is
    invalid, expired, revoked, does not match the redirection
    URI used in the authorization request, or was issued to
    another client.
    (RFC 6749 - Section 5.2)
    """
    
    def __init__(
        self, 
        error_description: str | None = "Invalid authorization grant or refresh token.", 
        error_uri: str | None = None
    ):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            error="invalid_grant",
            error_description=error_description,
            error_uri=error_uri
        )


class UnauthorizedClientError(OAuthError):
    """
    The authenticated client is not authorized to use this
    authorization grant type.
    (RFC 6749 - Section 5.2)
    """
    
    def __init__(self, error_description: str | None = None, error_uri: str | None = None):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            error="unauthorized_client",
            error_description=error_description,
            error_uri=error_uri
        )


class UnsupportedGrantTypeError(OAuthError):
    """
    The authorization grant type is not supported by the
    authorization server.
    (RFC 6749 - Section 5.2)
    """
    
    def __init__(self, error_description: str | None = None, error_uri: str | None = None):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            error="unsupported_grant_type",
            error_description=error_description,
            error_uri=error_uri
        )


class InvalidScopeError(OAuthError):
    """
    The requested scope is invalid, unknown, malformed, or
    exceeds the scope granted by the resource owner.
    (RFC 6749 - Section 5.2)
    """
    
    def __init__(self, error_description: str | None = None, error_uri: str | None = None):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            error="invalid_scope",
            error_description=error_description,
            error_uri=error_uri
        )


class InvalidTokenError(OAuthError):
    """
    The access token provided is expired, revoked, malformed, or
    invalid for other reasons. The resource SHOULD respond with
    the HTTP 401 (Unauthorized) status code.
    (RFC 6750 - Section 3.1)
    """
    
    def __init__(
        self, 
        error_description: str | None = "The access token is invalid.", 
        realm: str | None = None
    ):
        # Construct WWW-Authenticate header according to RFC 6750
        realm_value = realm if realm else "mcp_plexus"
        headers = {"WWW-Authenticate": f'Bearer realm="{realm_value}", error="invalid_token"'}
        
        if error_description:
            headers["WWW-Authenticate"] += f', error_description="{error_description}"'
        
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            error="invalid_token",
            error_description=error_description
        )


class InsufficientScopeError(OAuthError):
    """
    The request requires higher privileges than provided by the
    access token. The resource server SHOULD respond with the HTTP
    403 (Forbidden) status code and MAY include the "scope"
    attribute with the scope necessary to access the resource.
    (RFC 6750 - Section 3.1)
    """
    
    def __init__(
        self, 
        required_scope: str | None = None, 
        error_description: str | None = "The request requires higher privileges than provided by the access token.", 
        realm: str | None = None
    ):
        realm_value = realm if realm else "mcp_plexus"
        headers = {"WWW-Authenticate": f'Bearer realm="{realm_value}", error="insufficient_scope"'}
        
        if required_scope:
            headers["WWW-Authenticate"] += f', scope="{required_scope}"'
        if error_description:
            headers["WWW-Authenticate"] += f', error_description="{error_description}"'

        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            error="insufficient_scope",
            error_description=error_description
        )


class PlexusExternalAuthRequiredError(Exception):
    """
    Special error to signal that an external OAuth flow is required.
    Contains necessary information for the client to initiate the OAuth flow.
    """
    
    def __init__(
        self, 
        authorization_url: str, 
        provider_name: str, 
        detail_message: str = "External OAuth authentication required."
    ):
        self.authorization_url = authorization_url
        self.provider_name = provider_name
        self.detail_message = detail_message
        
        # Store structured detail for easier programmatic access
        self.detail = {
            "error": "external_auth_required",
            "message": detail_message,
            "provider_name": provider_name,
            "authorization_url": authorization_url,
        }
        
        super().__init__(detail_message)


class ServerError(OAuthError):
    """
    The authorization server encountered an unexpected
    condition that prevented it from fulfilling the request.
    (RFC 6749 - Section 4.1.2.1 / 4.2.2.1)
    """
    
    def __init__(
        self, 
        error_description: str | None = "The authorization server encountered an internal error.", 
        error_uri: str | None = None
    ):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error="server_error",
            error_description=error_description,
            error_uri=error_uri
        )


class PlexusApiKeyRequiredError(Exception):
    """
    Special error to signal that an API key is required from the user.
    Contains necessary information for the client to prompt the user for the key.
    """
    
    def __init__(
        self, 
        provider_name: str, 
        key_name_display: str, 
        instructions: Optional[str] = None, 
        detail_message: str = "External API Key required."
    ):
        self.provider_name = provider_name
        self.key_name_display = key_name_display
        self.instructions = instructions
        self.detail_message = detail_message
        
        # Store structured detail for easier programmatic access when converting to ToolError
        self.detail = {
            "error": "plexus_api_key_required",
            "message": detail_message,
            "provider_name": provider_name,
            "key_name_display": key_name_display,
            "instructions": instructions,
        }
        
        super().__init__(detail_message)


class TemporarilyUnavailableError(OAuthError):
    """
    The authorization server is currently unable to handle the request due to a 
    temporary overloading or maintenance of the server.
    (RFC 6749 - Section 5.2)
    """
    
    def __init__(
        self, 
        error_description: str | None = "The authorization server is temporarily unavailable.", 
        error_uri: str | None = None
    ):
        super().__init__(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            error="temporarily_unavailable",
            error_description=error_description,
            error_uri=error_uri
        )