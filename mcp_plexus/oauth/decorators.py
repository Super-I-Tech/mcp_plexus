# File: mcp_plexus/oauth/decorators.py
import functools
import logging 
from typing import Callable, Any, Optional, List, TypeVar, TYPE_CHECKING 
import httpx 

from fastmcp import Context as FastMCPBaseContext
from .errors import PlexusExternalAuthRequiredError

# Use TYPE_CHECKING to avoid circular imports at runtime
if TYPE_CHECKING:
    from ..plexus_context import PlexusContext

logger = logging.getLogger(__name__)

F = TypeVar('F', bound=Callable[..., Any])

def requires_auth(provider_name: str, scopes: Optional[List[str]] = None) -> Callable[[F], F]:
    """
    Decorator that ensures an OAuth provider is authenticated before executing a tool.
    
    Extracts the FastMCP context from function arguments, creates a PlexusContext,
    and injects an authenticated HTTP client for the specified provider.
    
    Args:
        provider_name: Name of the OAuth provider (e.g., 'google', 'github')
        scopes: Optional list of OAuth scopes required for the provider
        
    Raises:
        ToolError: When authentication is required but not available
        RuntimeError: When context setup fails or client is invalid
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Import inside function to prevent circular dependency
            from ..plexus_context import PlexusContext 
            
            # Locate FastMCP context from function arguments
            base_ctx_arg: Optional[FastMCPBaseContext] = None
            ctx_from_kwargs = kwargs.get('ctx')
            if isinstance(ctx_from_kwargs, FastMCPBaseContext):
                base_ctx_arg = ctx_from_kwargs
            else: 
                for arg_val in args:
                    if isinstance(arg_val, FastMCPBaseContext):
                        base_ctx_arg = arg_val
                        break
            
            if not base_ctx_arg:
                raise RuntimeError(
                    f"FastMCPBaseContext not found for @requires_auth in tool '{func.__name__}'."
                )

            # Create PlexusContext from base context
            try:
                if not hasattr(base_ctx_arg, 'fastmcp') or base_ctx_arg.fastmcp is None:
                     raise RuntimeError(
                         f"PlexusContext setup failed due to missing server instance on base context for {func.__name__}."
                     )
                
                plexus_ctx = PlexusContext(base_ctx_arg.fastmcp)
            except Exception as e_plexus_ctx_init:
                logger.error(
                    f"Failed to create PlexusContext for tool '{func.__name__}': {e_plexus_ctx_init}", 
                    exc_info=True
                )
                raise RuntimeError(f"PlexusContext setup failed in @requires_auth for {func.__name__}.")

            # Obtain authenticated client and inject into function
            try:
                auth_client = await plexus_ctx.get_authenticated_external_client(
                    provider_name=provider_name,
                    required_scopes=scopes
                )
                
                if not isinstance(auth_client, httpx.AsyncClient):
                    raise RuntimeError(f"Internal error: OAuth client for '{provider_name}' is not valid.")

                kwargs['authenticated_client'] = auth_client
                return await func(*args, **kwargs)

            except PlexusExternalAuthRequiredError as auth_err:
                # Convert internal auth error to MCP ToolError for client consumption
                from fastmcp.exceptions import ToolError 
                import json 
                error_payload_for_mcp = auth_err.detail 
                error_json_string = json.dumps(error_payload_for_mcp)
                raise ToolError(error_json_string)
            except RuntimeError as rt_err: 
                logger.error(f"RuntimeError in auth processing for '{func.__name__}': {rt_err}", exc_info=True) 
                raise rt_err 
            except Exception as e: 
                logger.error(f"Unexpected error in @requires_auth for '{func.__name__}': {e}", exc_info=True)
                raise 
        return wrapper # type: ignore
    return decorator