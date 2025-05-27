# mcp_plexus/tool_modules/example_basic_tools.py
import logging
from typing import Dict, Any, Optional, Literal
import httpx
import json

from fastmcp import Context as FastMCPBaseContext
from fastmcp.exceptions import ToolError

from ..core.global_registry import PLEXUS_SERVER_INSTANCE 
from ..plexus_context import PlexusContext
from ..oauth.errors import PlexusExternalAuthRequiredError

logger = logging.getLogger(__name__)

# Ensure the PLEXUS_SERVER_INSTANCE is available before tool registration
if PLEXUS_SERVER_INSTANCE is None:
    raise RuntimeError(
        "PLEXUS_SERVER_INSTANCE not initialized in mcp_plexus.core.global_registry. "
        "Ensure tenant_mcp_app.py populates it before tool modules are loaded."
    )

# GitHub OAuth configuration for external API access
TOOL_PROVIDER_NAME_GITHUB = "github"
TOOL_SCOPES_GITHUB = ["read:user", "repo"]


@PLEXUS_SERVER_INSTANCE.tool(
    name="get_admin_info",
    description="Retrieves administrative information, restricted to specific tenants and in admin tool set.",
    tool_sets=["administration", "reporting"],
    allowed_tenant_ids=["test_tenant_001", "admin_tenant"]
)
async def get_admin_info(ctx: FastMCPBaseContext) -> Dict[str, Any]:
    """Administrative tool restricted to specific tenants for security purposes."""
    plexus_ctx = PlexusContext(ctx.fastmcp)
    entity_id = plexus_ctx.entity_id
    session_id = plexus_ctx.mcp_session_id
    
    logger.info(f"Tool 'get_admin_info' called for E:{entity_id}, S:{session_id}")
    
    return {
        "message": "Administrative information retrieved.",
        "entity_id": entity_id,
        "admin_data_for": entity_id,
        "tool_set_tags_applied": ["tool_set:administration", "tool_set:reporting"],
        "tenant_scoping_applied_to": ["test_tenant_001", "admin_tenant"]
    }


@PLEXUS_SERVER_INSTANCE.tool()
async def get_entity_info(ctx: FastMCPBaseContext) -> Dict[str, Any]:
    """Retrieves entity and session information from the Plexus context."""
    plexus_ctx: Optional[PlexusContext] = None
    final_entity_id = None
    final_mcp_session_id = None
    final_plexus_session_info = "PlexusSessionData N/A."
    tool_message = "Error: Could not obtain data via manually created PlexusContext."
    error_details_log = []
    
    try:
        if not isinstance(ctx, FastMCPBaseContext) or not hasattr(ctx, 'fastmcp') or not ctx.fastmcp:
            error_details_log.append("Injected ctx is not FastMCPBaseContext or lacks .fastmcp server instance.")
            logger.error(f"Context validation failed: {error_details_log[-1]}. Type: {type(ctx)}")
        else:
            # Create PlexusContext from the FastMCP base context
            plexus_ctx = PlexusContext(ctx.fastmcp)
            final_entity_id = plexus_ctx.entity_id
            final_mcp_session_id = plexus_ctx.mcp_session_id
            
            # Retrieve session data asynchronously
            session_data = await plexus_ctx.plexus_session_data
            if session_data:
                final_plexus_session_info = (
                    f"Session: created_at={session_data.created_at}, "
                    f"updated_at={session_data.updated_at}, "
                    f"persistent_user_id={session_data.persistent_user_id}"
                )
                logger.info(f"Session data retrieved for EntityID: {final_entity_id}, "
                           f"SessionID: {final_mcp_session_id}")
            else:
                logger.warning(f"Session data unavailable for EntityID: {final_entity_id}, "
                              f"SessionID: {final_mcp_session_id}")
                final_plexus_session_info = (
                    f"PlexusSessionData is None. EntityID ({final_entity_id}), "
                    f"SessionID ({final_mcp_session_id})"
                )
            
            if final_entity_id is not None: 
                tool_message = "SUCCESS: PlexusContext created and session data retrieved."
            else:
                tool_message = ("PlexusContext created, but entity_id is None. "
                               "Check entity configuration.")
                logger.warning(tool_message)
                
    except Exception as e:
        error_summary = f"Exception in get_entity_info: {str(e)}"
        error_details_log.append(error_summary)
        logger.error(error_summary, exc_info=True)
    
    return {
        "message": tool_message,
        "error_log_summary": error_details_log if error_details_log else "No errors.",
        "injected_base_context_type": str(type(ctx)) if ctx else None,
        "plexus_context_type": str(type(plexus_ctx)) if plexus_ctx else None,
        "final_entity_id": final_entity_id,
        "final_mcp_session_id": final_mcp_session_id,
        "final_plexus_session_info": final_plexus_session_info
    }


@PLEXUS_SERVER_INSTANCE.tool()
async def manage_plexus_session_tool(
    ctx: FastMCPBaseContext, 
    action: Literal["get", "set", "delete"],
    key: str,
    value: Optional[Any] = None
) -> Dict[str, Any]:
    """Manages session data with get, set, and delete operations."""
    plexus_ctx = PlexusContext(ctx.fastmcp)
    response_payload: Dict[str, Any] = {
        "action": action, 
        "key": key, 
        "success": False,
        "message": "PlexusContext could not be initialized or session data unavailable.",
        "retrieved_value": None, 
        "value_set": None, 
        "key_deleted": False
    }
    
    try:
        session_data = await plexus_ctx.plexus_session_data
        if not session_data:
            response_payload["message"] = "Plexus session data is not available."
            logger.warning(response_payload["message"])
            return response_payload
        
        if action == "set":
            if value is None:
                response_payload["message"] = "'value' parameter is required for 'set' action."
                return response_payload
            await plexus_ctx.set_session_value(key, value)
            response_payload.update({
                "success": True, 
                "message": f"Value set for key '{key}' in session.", 
                "value_set": value
            })
            
        elif action == "get":
            retrieved = await plexus_ctx.get_session_value(key)
            response_payload.update({
                "success": True, 
                "retrieved_value": retrieved, 
                "message": f"Value for key '{key}' retrieved: {retrieved}"
            })
            
        elif action == "delete":
            if session_data.plexus_internal_data is not None:
                if key in session_data.plexus_internal_data:
                    session_data.plexus_internal_data.pop(key, None)
                    session_data.touch()
                    response_payload.update({
                        "success": True, 
                        "key_deleted": True, 
                        "message": f"Key '{key}' deleted from session."
                    })
                else:
                    response_payload.update({
                        "success": True, 
                        "message": f"Key '{key}' not found in session, nothing to delete."
                    })
            else: 
                response_payload["message"] = "plexus_internal_data is None in the session data."
        else:
            response_payload["message"] = f"Unknown action '{action}'."
            
    except Exception as e:
        response_payload["message"] = f"Exception in tool: {str(e)}"
        logger.error(response_payload["message"], exc_info=True)
    
    return response_payload


@PLEXUS_SERVER_INSTANCE.tool(name="fetch_secure_external_data")
async def fetch_secure_external_data_tool(
    ctx: FastMCPBaseContext,
    item_id: str
) -> Dict[str, Any]:
    """Fetches external data using authenticated GitHub client."""
    tool_name = "fetch_secure_external_data_tool"
    logger.info(f"Tool '{tool_name}' called with item_id: {item_id}")
    
    # Validate context structure
    if not isinstance(ctx, FastMCPBaseContext) or not hasattr(ctx, 'fastmcp') or not ctx.fastmcp:
        logger.error(f"Tool '{tool_name}': Invalid context structure")
        raise ToolError(json.dumps({
            "error": "internal_context_error", 
            "message": "Base context setup issue."
        }))
    
    plexus_ctx = PlexusContext(ctx.fastmcp)

    try:
        # Obtain authenticated client for GitHub API access
        authenticated_client: Optional[httpx.AsyncClient] = await plexus_ctx.get_authenticated_external_client(
            provider_name=TOOL_PROVIDER_NAME_GITHUB, 
            required_scopes=TOOL_SCOPES_GITHUB      
        )
        
        if not isinstance(authenticated_client, httpx.AsyncClient):
            logger.error(f"Tool '{tool_name}': Invalid authenticated client type")
            raise ToolError(json.dumps({
                "error": "internal_auth_client_error", 
                "message": "Auth client not available or invalid type."
            }))

        logger.info(f"Tool '{tool_name}' obtained authenticated client for '{TOOL_PROVIDER_NAME_GITHUB}'")
        
        # Placeholder for actual external API calls
        return {
            "status": "success_placeholder", 
            "item_id": item_id, 
            "message": "Authenticated client obtained and tool logic executed (placeholder)."
        }

    except PlexusExternalAuthRequiredError as auth_err:
        logger.warning(f"Tool '{tool_name}': Authentication required for provider '{auth_err.provider_name}'")
        raise ToolError(json.dumps(auth_err.detail))
    except ToolError: 
        raise
    except Exception as e:
        logger.error(f"Tool '{tool_name}': Unexpected error: {e}", exc_info=True)
        raise ToolError(json.dumps({
            "error": "tool_execution_failed", 
            "message": f"An unexpected error occurred in {tool_name}."
        }))


logger.info("Example basic tools registered successfully.")