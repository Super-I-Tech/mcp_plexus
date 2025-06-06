# mcp_plexus/services/decorators.py
from __future__ import annotations
import functools
import logging
from typing import Callable, Any, Optional, TypeVar, TYPE_CHECKING
import json

from fastmcp import Context as FastMCPBaseContext
from ..oauth.errors import PlexusApiKeyRequiredError

if TYPE_CHECKING:
    from ..plexus_context import PlexusContext

logger = logging.getLogger(__name__)
F = TypeVar('F', bound=Callable[..., Any])


def requires_api_key(
    provider_name: str, 
    key_name_display: str, 
    instructions: Optional[str] = None
) -> Callable[[F], F]:
    """
    Decorator that ensures an API key is available for a specific provider before executing a tool.
    
    This decorator validates API key availability and injects it into the function's kwargs.
    It also attaches metadata to exclude the injected API key parameter from FastMCP's
    tool schema generation.
    
    Args:
        provider_name: The name of the API provider (e.g., 'openai', 'anthropic')
        key_name_display: Human-readable name for the API key (e.g., 'OpenAI API Key')
        instructions: Optional custom instructions for obtaining the API key
        
    Returns:
        A decorator function that wraps the original tool function
    """
    
    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Import here to avoid circular dependencies
            from ..plexus_context import PlexusContext 
            from fastmcp.exceptions import ToolError

            # Extract FastMCPBaseContext from function arguments
            base_ctx_arg: Optional[FastMCPBaseContext] = None
            
            # Check kwargs first for context
            ctx_from_kwargs = kwargs.get('ctx')
            if isinstance(ctx_from_kwargs, FastMCPBaseContext):
                base_ctx_arg = ctx_from_kwargs
            else:
                # Fall back to checking positional arguments
                for arg_val in args:
                    if isinstance(arg_val, FastMCPBaseContext):
                        base_ctx_arg = arg_val
                        break

            if not base_ctx_arg:
                raise ToolError(json.dumps({
                    "error": "internal_context_error", 
                    "message": f"Base context ('ctx') not found for tool '{func.__name__}'."
                }))

            if not hasattr(base_ctx_arg, 'fastmcp'):
                raise ToolError(json.dumps({
                    "error": "internal_context_error", 
                    "message": f"Base context for tool '{func.__name__}' is missing server instance."
                }))

            # Create PlexusContext for API key management
            try:
                plexus_ctx = PlexusContext(base_ctx_arg.fastmcp)
            except Exception as e:
                raise ToolError(json.dumps({
                    "error": "plexus_context_creation_failed",
                    "message": f"Failed to instantiate PlexusContext for '{func.__name__}'. Details: {str(e)}"
                }))

            # Retrieve API key for the specified provider
            try:
                api_key_value = await plexus_ctx.get_api_key(provider_name)
            except Exception as e:
                logger.error(
                    f"Exception occurred during API key retrieval for '{provider_name}' in '{func.__name__}': {e}", 
                    exc_info=True
                )
                raise

            # Validate API key availability and provide helpful error if missing
            if not api_key_value:
                error_detail = PlexusApiKeyRequiredError(
                    provider_name=provider_name,
                    key_name_display=key_name_display,
                    instructions=instructions or f"Please provide your API key for {key_name_display} via the API key submission endpoint.",
                    detail_message=f"API key for {provider_name} ('{key_name_display}') is required."
                ).detail

                error_json_string = json.dumps(error_detail)
                raise ToolError(error_json_string)

            # Inject API key into function kwargs with standardized naming
            kwarg_name = f"{provider_name.lower().replace('-', '_')}_api_key"
            kwargs[kwarg_name] = api_key_value

            return await func(*args, **kwargs)
        
        # Attach metadata to exclude injected API key from schema generation
        kwarg_name_to_exclude = f"{provider_name.lower().replace('-', '_')}_api_key"
        if not hasattr(wrapper, '_plexus_exclude_args'):
            setattr(wrapper, '_plexus_exclude_args', [])
            
        getattr(wrapper, '_plexus_exclude_args').append(kwarg_name_to_exclude)
            
        return wrapper # type: ignore
    return decorator