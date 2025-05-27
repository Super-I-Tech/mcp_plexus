# mcp_plexus/oauth_providers_admin/__init__.py

"""
OAuth providers administration module.

This module provides the service layer and API endpoints for managing
external OAuth providers in the admin interface.
"""

from .service import ExternalOAuthProviderService
from .endpoints import external_oauth_providers_admin_router

# Export public interface for the OAuth providers admin module
__all__ = [
    "ExternalOAuthProviderService",
    "external_oauth_providers_admin_router"
]