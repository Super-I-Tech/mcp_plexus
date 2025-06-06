# mcp_plexus/mcp_handlers/tenant_mcp_app.py
from fastmcp import FastMCP
from fastmcp import Context as FastMCPBaseContext 
from fastmcp.resources import TextResource
from pathlib import Path
from typing import Dict, Any, Callable, Literal, Optional, List
import logging 
import json 
from fastmcp.exceptions import ToolError

from ..settings import settings
from ..plexus_context import PlexusContext 
from ..tool_loader import load_tools_from_directory

# Configure logger for tenant MCP application
logger = logging.getLogger(__name__)
if not logger.hasHandlers(): 
    logging.basicConfig(
        level=logging.DEBUG, 
        format='%(asctime)s TENANT_MCP_APP - [%(levelname)s] - %(message)s'
    )
    logger.setLevel(logging.DEBUG)


def _plexus_context_factory(server_instance: FastMCP) -> PlexusContext:
    """
    Factory function to create PlexusContext instances for FastMCP server.
    
    This factory is used by FastMCP to create context objects that provide
    access to request-specific data and tenant information.
    """
    logger.info(f"Creating PlexusContext for server: {server_instance.name if server_instance else 'None'}")
    instance = PlexusContext(server_instance)
    
    # Log request context information for debugging purposes
    try:
        rc_from_instance = instance.request_context 
        if (rc_from_instance and 
            hasattr(rc_from_instance, 'starlette_request') and 
            rc_from_instance.starlette_request): 
            sr = rc_from_instance.starlette_request 
            scope_state = sr.scope.get('state', 'Not Set')
            logger.info(f"PlexusContext created with request scope state: {scope_state}")
    except Exception as e:
        logger.error(f"Error during PlexusContext debug logging: {e}")
    
    return instance


def _get_example_resource_content_str() -> str:
    """
    Generates example resource content for demonstration purposes.
    
    This provides a sample JSON structure showing how resources
    can be dynamically created and accessed within the MCP system.
    """
    logger.info("Generating example resource content")
    return json.dumps({
        "resource_for_entity": "dynamic_text_resource (entity_id N/A in this global helper)",
        "resource_mcp_session_id": "dynamic_text_resource (session_id N/A in this global helper)",
        "content": "This is a sample resource (via add_resource and TextResource).",
    })


def _create_fastmcp_instance() -> FastMCP:
    """
    Creates and configures the main FastMCP server instance.
    
    This function initializes the core MCP server with appropriate settings,
    context factory, and example resources for tenant applications.
    """
    log_level_to_use = settings.plexus_fastmcp_log_level
    logger.info(f"Creating FastMCP instance with log level: {log_level_to_use}")
    
    # Initialize FastMCP server with tenant-specific configuration
    plexus_mcp = FastMCP(
        name="MCP_Plexus_Shared_App_Server_Instance",
        instructions="MCP Plexus Tenant Application. Entity ID dynamically available in tool context.",
        log_level=log_level_to_use,
        context_factory=_plexus_context_factory,
        mask_error_details=not settings.debug_mode,
        model_config={"arbitrary_types_allowed": True}
    )
    
    logger.info(f"FastMCP instance created with ID: {id(plexus_mcp)}")
    
    # Add example resource to demonstrate resource management capabilities
    example_text_resource = TextResource(
        uri="data://example_resource", 
        name="ExamplePlexusResourceViaAdd",
        description="Demonstrates how a TextResource is added.",
        mime_type="application/json", 
        text=_get_example_resource_content_str()
    )
    plexus_mcp.add_resource(example_text_resource)
    logger.info("Added example resource to FastMCP instance")
    
    return plexus_mcp


# Create the shared FastMCP server instance that will be used across the application
shared_fastmcp_server_instance: FastMCP = _create_fastmcp_instance()
logger.info(f"Created shared FastMCP server instance, ID: {id(shared_fastmcp_server_instance)}")

# Initialize the global Plexus server facade if not already created
from ..core.server import MCPPlexusServer
import mcp_plexus.core.global_registry

if mcp_plexus.core.global_registry.PLEXUS_SERVER_INSTANCE is None:
    _plexus_server_facade = MCPPlexusServer(server_settings=None) 
    mcp_plexus.core.global_registry.PLEXUS_SERVER_INSTANCE = _plexus_server_facade
    logger.info(f"Global PLEXUS_SERVER_INSTANCE populated.")
else:
    logger.warning("Global PLEXUS_SERVER_INSTANCE was already populated.")

# Load all available tools from the tool modules directory
TOOL_MODULES_DIR = Path(__file__).resolve().parent.parent / "tool_modules"
logger.info(f"Loading tools from directory: {TOOL_MODULES_DIR}")
load_tools_from_directory(TOOL_MODULES_DIR)
logger.info(f"Tool loading from '{TOOL_MODULES_DIR}' completed")

# Log registered tools for verification
if (shared_fastmcp_server_instance and 
    hasattr(shared_fastmcp_server_instance, '_tool_manager')):
    tool_manager = shared_fastmcp_server_instance._tool_manager
    if tool_manager and hasattr(tool_manager, 'get_tools'):
        tool_names = list(tool_manager.get_tools().keys())
        logger.info(f"Tools registered on shared instance: {tool_names}")