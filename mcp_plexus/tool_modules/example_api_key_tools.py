# mcp_plexus/tool_modules/example_api_key_tools.py
import logging
from typing import Dict, Any, Optional
from fastmcp import Context as FastMCPBaseContext
from ..core.global_registry import PLEXUS_SERVER_INSTANCE
from ..services.decorators import requires_api_key

logger = logging.getLogger(__name__)

# Ensure the global server instance is initialized before registering tools
if PLEXUS_SERVER_INSTANCE is None:
    raise RuntimeError(
        "PLEXUS_SERVER_INSTANCE not initialized in mcp_plexus.core.global_registry. "
        "Ensure tenant_mcp_app.py populates it before tool modules are loaded."
    )

# Test API provider configuration
TEST_API_KEY_PROVIDER_NAME = "my_test_service_alpha"


@PLEXUS_SERVER_INSTANCE.tool(
    name="use_alpha_service_key_tool",
    description=f"A tool that requires an API key for '{TEST_API_KEY_PROVIDER_NAME}' and returns it.",
    tool_sets=["api_key_examples"]
)
@requires_api_key(
    provider_name=TEST_API_KEY_PROVIDER_NAME,
    key_name_display="My Alpha Test Service Key",
    instructions=f"Please provide your API key for the '{TEST_API_KEY_PROVIDER_NAME}' service via the API key submission endpoint."
)
async def use_alpha_service_key_tool(
    ctx: FastMCPBaseContext,
    # API key injected by decorator based on provider name
    my_test_service_alpha_api_key: Optional[str] = None,
    some_other_param: Optional[str] = "default_value"
) -> Dict[str, Any]:
    """
    Example tool demonstrating API key usage with the requires_api_key decorator.
    
    Returns verification information about the received API key for testing purposes.
    """
    logger.info(
        f"Tool 'use_alpha_service_key_tool' called. "
        f"Received API key for '{TEST_API_KEY_PROVIDER_NAME}': "
        f"{my_test_service_alpha_api_key[:5]}... (masked for log). "
        f"Other param: {some_other_param}"
    )
    
    return {
        "message": f"Successfully accessed tool using API key for '{TEST_API_KEY_PROVIDER_NAME}'.",
        "retrieved_api_key_fragment": my_test_service_alpha_api_key[:10] + "...",
        "received_other_param": some_other_param,
        "provider_name_used": TEST_API_KEY_PROVIDER_NAME
    }


logger.info(
    f"Example API key tool ('{use_alpha_service_key_tool.__name__}') "
    f"registered for provider '{TEST_API_KEY_PROVIDER_NAME}'."
)