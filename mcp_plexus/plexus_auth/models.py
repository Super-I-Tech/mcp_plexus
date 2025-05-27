# mcp_plexus/plexus_auth/models.py
from pydantic import BaseModel, Field
from typing import Optional


class UserRegistrationRequest(BaseModel):
    """Request model for user registration containing host application user identifier."""
    user_id_from_host_app: str = Field(
        description="A unique and stable user identifier provided by the host application."
    )
    # host_app_secret is expected as an X-Host-App-Secret header


class PlexusUserAuthTokenResponse(BaseModel):
    """Response model containing generated authentication token and user information."""
    plexus_user_auth_token: str = Field(
        description="The generated Plexus User Auth Token for the user."
    )
    persistent_user_id: str = Field(
        description="The persistent user ID associated with the token within MCP Plexus."
    )
    message: str = "User token processed successfully."


class PlexusUserAuthTokenData(BaseModel):
    """Internal model for storing user authentication token data in the system."""
    entity_id: str
    persistent_user_id: str
    token_hash: str  # Store hash of the token for security
    created_at: str  # ISO format datetime string
    last_used_at: Optional[str] = None  # ISO format datetime string for tracking usage