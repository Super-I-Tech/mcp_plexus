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
    
    The decorator extracts the FastMCP context from the tool's arguments, creates a PlexusContext,
    retrieves the API key for the specified provider, and injects it into the tool's kwargs.
    If the API key is not found, raises a ToolError with structured error information.
    
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
            
            # Check kwargs first for 'ctx' parameter
            ctx_from_kwargs = kwargs.get('ctx')
            if isinstance(ctx_from_kwargs, FastMCPBaseContext):
                base_ctx_arg = ctx_from_kwargs
            else:
                # Fallback to searching positional arguments
                for arg_val in args:
                    if isinstance(arg_val, FastMCPBaseContext):
                        base_ctx_arg = arg_val
                        break

            if not base_ctx_arg:
                raise ToolError(json.dumps({
                    "error": "internal_context_error", 
                    "message": f"Base context ('ctx') not found for tool '{func.__name__}'."
                }))

            # Ensure context has required fastmcp server instance
            if not hasattr(base_ctx_arg, 'fastmcp'):
                raise ToolError(json.dumps({
                    "error": "internal_context_error", 
                    "message": f"Base context for tool '{func.__name__}' is missing server instance."
                }))

            # Create PlexusContext instance for API key management
            try:
                plexus_ctx = PlexusContext(base_ctx_arg.fastmcp)
            except Exception as e:
                raise ToolError(json.dumps({
                    "error": "plexus_context_creation_failed",
                    "message": f"Failed to instantiate PlexusContext for '{func.__name__}'. Details: {str(e)}"
                }))

            # Retrieve the API key for the specified provider
            try:
                api_key_value = await plexus_ctx.get_api_key(provider_name)
            except Exception as e:
                logger.error(
                    f"Exception occurred during API key retrieval for '{provider_name}' in '{func.__name__}': {e}", 
                    exc_info=True
                )
                raise

            # Raise structured error if API key is missing
            if not api_key_value:
                error_detail = PlexusApiKeyRequiredError(
                    provider_name=provider_name,
                    key_name_display=key_name_display,
                    instructions=instructions or f"Please provide your API key for {key_name_display} via the API key submission endpoint.",
                    detail_message=f"API key for {provider_name} ('{key_name_display}') is required."
                ).detail

                error_json_string = json.dumps(error_detail)
                raise ToolError(error_json_string)

            # Inject API key into kwargs with sanitized parameter name
            # Convert provider name to valid Python identifier format
            sanitized_provider_name = provider_name.lower().replace('-', '_').replace(' ', '_')
            kwarg_name = f"{sanitized_provider_name}_api_key"
            kwargs[kwarg_name] = api_key_value

            # Execute original function with injected API key
            return await func(*args, **kwargs)
            
        return wrapper
    return decorator