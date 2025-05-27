# mcp_plexus/core/__init__.py

"""
Core module initialization for MCP Plexus.

This module exposes the main server class and global registry instance
for the MCP (Model Context Protocol) Plexus system.
"""

from .server import MCPPlexusServer
from .global_registry import PLEXUS_SERVER_INSTANCE

# Export public API components
__all__ = ["MCPPlexusServer", "PLEXUS_SERVER_INSTANCE"]