# mcp_plexus/tenants/models.py
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime


class TenantBase(BaseModel):
    """Base model containing common tenant fields shared across operations."""
    tenant_name: str
    status: str = Field(
        default="active", 
        description="Tenant status (e.g., active, inactive)"
    )
    settings_json: Optional[Dict[str, Any]] = Field(
        default_factory=dict, 
        description="JSON blob for tenant-specific settings"
    )


class TenantCreate(TenantBase):
    """Model for tenant creation requests, includes entity_id as required field."""
    entity_id: str = Field(
        description="Unique identifier for the tenant (URL slug, etc.)"
    )


class TenantUpdate(BaseModel):
    """Model for partial tenant updates - all fields are optional."""
    tenant_name: Optional[str] = None
    status: Optional[str] = None
    settings_json: Optional[Dict[str, Any]] = None


class TenantInDBBase(TenantBase):
    """Base model for tenant records stored in database, includes system fields."""
    entity_id: str
    created_at: datetime

    class Config:
        from_attributes = True


class Tenant(TenantInDBBase):
    """Model for tenant data in API responses."""
    pass


class TenantInDB(TenantInDBBase):
    """Model for tenant data as stored in database."""
    pass