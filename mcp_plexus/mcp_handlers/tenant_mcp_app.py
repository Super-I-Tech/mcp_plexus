# mcp_plexus/mcp_handlers/tenant_mcp_app.py
from fastmcp import FastMCP
from fastmcp import Context as FastMCPBaseContext 
from fastmcp.resources import TextResource
from pydantic import Field  
import httpx 

from ..settings import settings
from ..plexus_context import PlexusContext 
from ..oauth.decorators import requires_auth 
from pathlib import Path
from ..tool_loader import load_tools_from_directory
from typing import Dict, Any, Callable, Literal, Optional, List
import logging 
import json 
from fastmcp.exceptions import ToolError


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
    This context provides tenant-specific information and request handling.
    """
    logger.info(f"Creating PlexusContext for server: {server_instance.name if server_instance else 'None'}")
    instance = PlexusContext(server_instance)
    
    # Log request context information for debugging
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
    Returns JSON string containing sample resource data.
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
    Sets up logging, context factory, and adds example resources.
    """
    log_level_to_use = settings.plexus_fastmcp_log_level
    logger.info(f"Creating FastMCP instance with log level: {log_level_to_use}")
    
    # Allow arbitrary types in Pydantic models for tool flexibility
    tool_pydantic_model_config = {"arbitrary_types_allowed": True}
    
    plexus_mcp = FastMCP(
        name="MCP_Plexus_Shared_App_Server_Instance",
        instructions="MCP Plexus Tenant Application. Entity ID dynamically available in tool context.",
        log_level=log_level_to_use,
        context_factory=_plexus_context_factory,
        tool_model_config=tool_pydantic_model_config 
    )
    
    logger.info(f"FastMCP instance created with ID: {id(plexus_mcp)}")

    # Add example resource to demonstrate resource functionality
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


# Create the shared FastMCP server instance that all tools will be registered on
shared_fastmcp_server_instance: FastMCP = _create_fastmcp_instance()
logger.info(f"Created shared FastMCP server instance, ID: {id(shared_fastmcp_server_instance)}")

# Initialize the global PLEXUS_SERVER_INSTANCE facade
from ..core.server import MCPPlexusServer
import mcp_plexus.core.global_registry

if mcp_plexus.core.global_registry.PLEXUS_SERVER_INSTANCE is None:
    # Create the MCPPlexusServer facade that wraps the shared FastMCP instance
    _plexus_server_facade = MCPPlexusServer(server_settings=None) 
    logger.info(f"Created MCPPlexusServer facade instance, ID: {id(_plexus_server_facade)}")
    
    if hasattr(_plexus_server_facade, '_fastmcp_instance'):
        logger.info(f"Facade's internal FastMCP instance ID: {id(_plexus_server_facade._fastmcp_instance)}")
    
    # Register the facade globally so tool modules can access it
    mcp_plexus.core.global_registry.PLEXUS_SERVER_INSTANCE = _plexus_server_facade
    logger.info(f"Global PLEXUS_SERVER_INSTANCE populated with facade ID: {id(mcp_plexus.core.global_registry.PLEXUS_SERVER_INSTANCE)}")
else:
    logger.warning("Global PLEXUS_SERVER_INSTANCE was already populated - unexpected during initial app load")

# Dynamically load all tools from the tool_modules directory
TOOL_MODULES_DIR = Path(__file__).resolve().parent.parent / "tool_modules"
logger.info(f"Loading tools from directory: {TOOL_MODULES_DIR}")
load_tools_from_directory(TOOL_MODULES_DIR)
logger.info(f"Tool loading from '{TOOL_MODULES_DIR}' completed")

# Verify tools were properly registered on the FastMCP instance
if (shared_fastmcp_server_instance and 
    hasattr(shared_fastmcp_server_instance, '_tool_manager')):
    tool_manager = shared_fastmcp_server_instance._tool_manager
    if tool_manager and hasattr(tool_manager, 'get_tools'):
        registered_tools = tool_manager.get_tools()
        tool_names = list(registered_tools.keys())
        logger.info(f"Tools registered on shared instance (ID: {id(shared_fastmcp_server_instance)}): {tool_names}")
        
        if not registered_tools:
            logger.warning("No tools found registered on shared FastMCP instance's tool manager")
    else:
        logger.warning("Tool manager or get_tools method not found on shared FastMCP instance")
else:
    logger.warning("Shared FastMCP instance or its tool manager not found")

logger.info("Module-level execution complete for tenant_mcp_app.py")