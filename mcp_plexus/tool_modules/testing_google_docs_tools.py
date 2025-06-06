# mcp_plexus/tool_modules/example_api_key_tools.py
import logging
from typing import Dict, Any, Optional
from fastmcp import Context as FastMCPBaseContext
from ..core.global_registry import PLEXUS_SERVER_INSTANCE
from ..services.decorators import requires_api_key
from ..plexus_context import PlexusContext

logger = logging.getLogger(__name__)

# Ensure the global server instance is properly initialized before proceeding
if PLEXUS_SERVER_INSTANCE is None:
    raise RuntimeError("PLEXUS_SERVER_INSTANCE not initialized.")

# Provider name used for API key identification and validation
TEST_API_KEY_PROVIDER_NAME = "my_test_service_alpha"

@PLEXUS_SERVER_INSTANCE.tool(
    name="use_alpha_service_key_tool",
    description=f"A tool that requires an API key for '{TEST_API_KEY_PROVIDER_NAME}' and returns it.",
    tool_sets=["api_key_examples"]
)
@requires_api_key(
    provider_name=TEST_API_KEY_PROVIDER_NAME,
    key_name_display="My Alpha Test Service Key",
    instructions=f"Please provide your API key for the '{TEST_API_KEY_PROVIDER_NAME}' service."
)
async def use_alpha_service_key_tool(
    ctx: FastMCPBaseContext,
    some_other_param: Optional[str] = "default_value",
    *, 
    my_test_service_alpha_api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Example tool demonstrating API key usage with the requires_api_key decorator.
    
    The decorator automatically injects the API key parameter and validates its presence
    before the function executes. This serves as a reference implementation for other
    tools that need secure API key handling.
    """
    plexus_ctx = PlexusContext(ctx.fastmcp)
    logger.info(
        f"Tool '{use_alpha_service_key_tool.name}' called by entity '{plexus_ctx.entity_id}'."
    )
    
    # Validate that the decorator properly injected the API key
    if not my_test_service_alpha_api_key:
        raise ValueError("API Key was not injected correctly by the decorator.")

    # Return demonstration data showing successful API key retrieval
    return {
        "message": f"Successfully accessed tool using API key for '{TEST_API_KEY_PROVIDER_NAME}'.",
        "provider_name_used": TEST_API_KEY_PROVIDER_NAME,
        "retrieved_api_key_fragment": my_test_service_alpha_api_key[:10] + "...",
        "received_other_param": some_other_param
    }