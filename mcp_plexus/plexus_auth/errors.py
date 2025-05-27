# mcp_plexus/plexus_auth/errors.py
from fastapi import HTTPException, status


class UserAuthError(HTTPException):
    """Base exception class for user authentication errors in the Plexus system.
    
    Inherits from FastAPI's HTTPException to provide consistent error handling
    across the authentication module.
    """
    
    def __init__(self, status_code: int, detail: str):
        super().__init__(status_code=status_code, detail=detail)


class InvalidHostAppIdentifierError(UserAuthError):
    """Raised when a host application provides invalid or missing credentials.
    
    This error occurs during the initial authentication phase when the host
    application identifier or secret cannot be validated.
    """
    
    def __init__(self, detail: str = "Invalid or missing host application identifier or secret."):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


class PlexusUserAuthTokenGenerationError(UserAuthError):
    """Raised when the system fails to generate or process a Plexus User Auth Token.
    
    This indicates an internal server error during token creation, typically
    due to system failures rather than user input errors.
    """
    
    def __init__(self, detail: str = "Failed to generate or process Plexus User Auth Token."):
        super().__init__(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=detail)


class PlexusUserAuthTokenValidationError(UserAuthError):
    """Raised when a provided Plexus User Auth Token is invalid or expired.
    
    This error occurs during token validation and indicates the client
    needs to re-authenticate to obtain a new valid token.
    """
    
    def __init__(self, detail: str = "Invalid or expired Plexus User Auth Token."):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)