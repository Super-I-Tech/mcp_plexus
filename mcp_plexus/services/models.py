# mcp_plexus/services/models.py
from pydantic import BaseModel, Field, SecretStr
from typing import Optional
from datetime import datetime, timezone


class UserApiKeySubmissionRequest(BaseModel):
    """Request model for user API key submission to external services."""
    
    provider_name: str = Field(
        description="Identifier for the external service (e.g., 'openai', 'google_maps')."
    )
    api_key_value: SecretStr = Field(
        description="The API key value provided by the user."
    )


class StoredUserExternalApiKey(BaseModel):
    """Model representing a user's encrypted API key stored in the system."""
    
    entity_id: str
    persistent_user_id: str
    provider_name: str
    encrypted_api_key_value: str  # The Fernet-encrypted API key
    registered_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    last_updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    class Config:
        # Enable compatibility with ORM objects like SQLAlchemy
        orm_mode = True
        from_attributes = True  # Pydantic V2 compatibility