# mcp_plexus/sessions/session_data.py
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
from datetime import datetime, timezone


class SessionData(BaseModel):
    """
    Represents the data stored for an MCP Plexus session.
    
    This model encapsulates all session-related information including
    identifiers, timestamps, internal data, and authentication tokens.
    """

    mcp_session_id: str = Field(
        description="The unique MCP session identifier provided by the client or server."
    )
    entity_id: str = Field(
        description="The tenant identifier for this session."
    )
    
    # Enables user tracking across multiple sessions for better continuity
    persistent_user_id: Optional[str] = Field(
        default=None, 
        description="A stable identifier for the user across sessions."
    )

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Storage for core MCP state and Plexus-specific session metadata
    plexus_internal_data: Dict[str, Any] = Field(default_factory=dict)

    # OAuth token storage organized by provider for easy lookup and management
    # Tokens are session-scoped and may be refreshed from persistent storage
    oauth_tokens: Dict[str, Dict[str, Any]] = Field(default_factory=dict)

    # Reserved for future user authentication features within Plexus
    user_identity: Optional[Dict[str, Any]] = None

    class Config:
        # Enables automatic validation when field values are modified
        validate_assignment = True

    def touch(self) -> None:
        """
        Updates the updated_at timestamp to current UTC time.
        
        Used to track when session data was last modified without
        requiring explicit timestamp management in calling code.
        """
        self.updated_at = datetime.now(timezone.utc)