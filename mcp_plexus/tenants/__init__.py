# mcp_plexus/tenants/__init__.py
"""
Tenant management module initialization.

This module provides a complete tenant management system including data models,
storage abstractions, concrete implementations, business logic, and API endpoints.
"""

from .models import Tenant, TenantCreate, TenantUpdate, TenantInDB
from .storage_interfaces import AbstractTenantStore
from .sqlite_tenant_store import SQLiteTenantStore, get_sqlite_tenant_store
from .service import TenantService
from .endpoints import tenants_admin_router

# Export all public components for external use
__all__ = [
    # Data models for tenant operations
    "Tenant", 
    "TenantCreate", 
    "TenantUpdate", 
    "TenantInDB",
    # Storage layer abstractions and implementations
    "AbstractTenantStore", 
    "SQLiteTenantStore", 
    "get_sqlite_tenant_store",
    # Business logic service
    "TenantService",
    # API endpoints
    "tenants_admin_router"
]