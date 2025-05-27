# mcp_plexus/core/global_registry.py
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .server import MCPPlexusServer

# Global singleton instance for the MCPPlexusServer
# This will be populated by tenant_mcp_app.py after the FastMCP instance is ready
PLEXUS_SERVER_INSTANCE: Optional['MCPPlexusServer'] = None