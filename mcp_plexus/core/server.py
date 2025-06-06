# mcp_plexus/core/server.py
import inspect
from functools import partial
from typing import TYPE_CHECKING, TypeVar, Callable, Any, Dict, Set, Optional, Union, List, overload
import logging

from fastmcp import FastMCP
from mcp.types import Tool as MCPTool
from fastmcp.tools import Tool, FunctionTool
from fastmcp.resources import Resource, ResourceTemplate
from fastmcp.prompts import Prompt

if TYPE_CHECKING:
    from ..oauth.models import OAuthProviderSettings
    from ..oauth.storage_interfaces import AbstractExternalOAuthProviderConfigStore

logger = logging.getLogger(__name__)

# Global cache for external OAuth config store to avoid repeated imports
_ext_oauth_config_store_cache: Optional['AbstractExternalOAuthProviderConfigStore'] = None

def _get_external_oauth_config_store_instance() -> Optional['AbstractExternalOAuthProviderConfigStore']:
    """
    Lazy-load and cache the external OAuth provider config store instance.
    Returns None if the store is not available or import fails.
    """
    global _ext_oauth_config_store_cache
    if _ext_oauth_config_store_cache is None:
        try:
            from mcp_plexus.main import external_oauth_provider_config_store_instance
            _ext_oauth_config_store_cache = external_oauth_provider_config_store_instance
            logger.debug("MCPPlexusServer: Successfully imported external_oauth_provider_config_store_instance")
        except (ImportError, AttributeError):
            logger.error("MCPPlexusServer: Failed to import or find external_oauth_provider_config_store_instance.", exc_info=True)
            return None
    return _ext_oauth_config_store_cache

F = TypeVar('F', bound=Callable[..., Any])

class MCPPlexusServer:
    """
    Main server class that wraps FastMCP functionality with additional features
    like tenant-based tool scoping and OAuth provider management.
    """
    
    def __init__(self, server_settings: Optional[Any] = None):
        """
        Initialize the MCPPlexusServer with a shared FastMCP instance.
        
        Args:
            server_settings: Optional server configuration settings
        """
        from ..mcp_handlers.tenant_mcp_app import shared_fastmcp_server_instance
        self._fastmcp_instance: FastMCP = shared_fastmcp_server_instance
        self.plexus_settings = server_settings
        
        # Track which tools are restricted to specific tenants
        self._tool_tenant_scoping: Dict[str, List[str]] = {}
        # Track which tools belong to which tool sets
        self._tool_set_assignments: Dict[str, List[str]] = {}
        
        logger.info(f"MCPPlexusServer initialized using shared FastMCP instance: {getattr(self._fastmcp_instance, 'name', 'None')}")

    def get_fastmcp_instance(self, entity_id: Optional[str] = None) -> FastMCP:
        """
        Get the FastMCP instance, with fallback recovery if instance is None.
        
        Args:
            entity_id: Optional entity identifier (currently unused but kept for API compatibility)
            
        Returns:
            The FastMCP instance
            
        Raises:
            RuntimeError: If FastMCP instance cannot be obtained
        """
        if not self._fastmcp_instance:
            logger.error("CRITICAL: MCPPlexusServer._fastmcp_instance is None!")
            from ..mcp_handlers.tenant_mcp_app import shared_fastmcp_server_instance
            self._fastmcp_instance = shared_fastmcp_server_instance
            if not self._fastmcp_instance:
                 raise RuntimeError("MCPPlexusServer._fastmcp_instance is None and could not be re-fetched.")
        return self._fastmcp_instance

    @overload
    def tool(self, func: F) -> F: ...
    
    @overload
    def tool(self, *, name: Optional[str]=None, description: Optional[str]=None, 
             tags: Optional[Set[str]]=None, annotations: Optional[Dict[str, Any]]=None, 
             tool_sets: Optional[List[str]]=None, allowed_tenant_ids: Optional[List[str]]=None, 
             exclude_args: Optional[List[str]]=None) -> Callable[[F], F]: ...
    
    def tool(self, func: Optional[F]=None, *, name: Optional[str]=None, 
             description: Optional[str]=None, tags: Optional[Set[str]]=None, 
             annotations: Optional[Dict[str, Any]]=None, tool_sets: Optional[List[str]]=None, 
             allowed_tenant_ids: Optional[List[str]]=None, 
             exclude_args: Optional[List[str]]=None) -> Union[Callable[[F], F], F]:
        """
        Decorator to register a function as an MCP tool with tenant scoping and tool set support.
        
        Args:
            func: The function to register as a tool
            name: Optional custom name for the tool
            description: Optional description of the tool
            tags: Optional set of tags for the tool
            annotations: Optional annotations for the tool
            tool_sets: Optional list of tool sets this tool belongs to
            allowed_tenant_ids: Optional list of tenant IDs that can access this tool
            exclude_args: Optional list of function arguments to exclude from the tool schema
            
        Returns:
            The decorated function or decorator
        """
        def decorator(fn: F) -> FunctionTool:
            effective_name = name or getattr(fn, '__name__', 'unknown_tool')
            logger.info(f"MCPPlexusServer.tool registering '{effective_name}'. ToolSets: {tool_sets}, Tenants: {allowed_tenant_ids}")
            
            # Build final tags including tool set tags
            final_tags = set(tags) if tags else set()
            if tool_sets:
                for ts_name in tool_sets:
                    final_tags.add(f"tool_set:{ts_name.strip().replace(' ', '_')}")
            
            # Combine exclude_args from decorator parameter and function attribute
            final_exclude_args = list(exclude_args) if exclude_args else []
            decorator_excluded = getattr(fn, '_plexus_exclude_args', [])
            final_exclude_args.extend(decorator_excluded)
            
            # Set up tenant scoping for this tool
            if allowed_tenant_ids is not None:
                self._tool_tenant_scoping[effective_name] = [tid.strip() for tid in allowed_tenant_ids if tid.strip()]
            elif effective_name not in self._tool_tenant_scoping:
                self._tool_tenant_scoping[effective_name] = []
            
            # Track tool set assignments
            if tool_sets:
                self._tool_set_assignments[effective_name] = [ts.strip() for ts in tool_sets if ts.strip()]
            
            # Create and register the tool with FastMCP
            tool_obj = Tool.from_function(
                fn=fn, 
                name=name, 
                description=description, 
                tags=final_tags, 
                annotations=annotations, 
                exclude_args=final_exclude_args if final_exclude_args else None
            )
            self.get_fastmcp_instance().add_tool(tool_obj)
            logger.info(f"MCPPlexusServer.tool: Registered tool '{tool_obj.name}' with FastMCP. Excluded args: {final_exclude_args}")
            return tool_obj

        if callable(func):
            return decorator(func)
        else:
            return decorator

    def resource(self, uri: str, *, name: Optional[str]=None, description: Optional[str]=None, 
                 mime_type: Optional[str]=None, tags: Optional[Set[str]]=None) -> Callable[[F], Union[Resource, ResourceTemplate]]:
        """
        Decorator to register a function as an MCP resource.
        
        Args:
            uri: The URI pattern for the resource
            name: Optional custom name for the resource
            description: Optional description of the resource
            mime_type: Optional MIME type for the resource
            tags: Optional set of tags for the resource
            
        Returns:
            The decorator function
        """
        def decorator(fn: F) -> Union[Resource, ResourceTemplate]:
            logger.info(f"MCPPlexusServer.resource registering URI: {uri}")
            return self.get_fastmcp_instance().resource(
                uri=uri, 
                name=name, 
                description=description, 
                mime_type=mime_type, 
                tags=tags
            )(fn)
        return decorator

    @overload
    def prompt(self, func: F) -> F: ...
    
    @overload
    def prompt(self, *, name: Optional[str]=None, description: Optional[str]=None, 
               tags: Optional[Set[str]]=None) -> Callable[[F], F]: ...
    
    def prompt(self, func: Optional[F]=None, *, name: Optional[str]=None, 
               description: Optional[str]=None, tags: Optional[Set[str]]=None) -> Union[Callable[[F], F], F]:
        """
        Decorator to register a function as an MCP prompt.
        
        Args:
            func: The function to register as a prompt
            name: Optional custom name for the prompt
            description: Optional description of the prompt
            tags: Optional set of tags for the prompt
            
        Returns:
            The decorated function or decorator
        """
        def decorator(fn: F) -> Prompt:
            prompt_obj = Prompt.from_function(fn=fn, name=name, description=description, tags=tags)
            self.get_fastmcp_instance().add_prompt(prompt_obj)
            logger.info(f"MCPPlexusServer.prompt: Registered prompt '{prompt_obj.name}' with FastMCP")
            return prompt_obj
            
        if callable(func):
            return decorator(func)
        else:
            return decorator

    async def get_mcp_tools_list_for_tenant(self, entity_id: str, tool_set_filter: Optional[str]=None, 
                                           mcp_session_id: Optional[str]=None) -> List[MCPTool]:
        """
        Get the list of MCP tools available to a specific tenant, with optional tool set filtering.
        
        Args:
            entity_id: The tenant/entity ID requesting tools
            tool_set_filter: Optional tool set name to filter by
            mcp_session_id: Optional MCP session ID (currently unused)
            
        Returns:
            List of MCP tools visible to the tenant
        """
        if not self._fastmcp_instance or not hasattr(self._fastmcp_instance, 'get_tools'):
            logger.error("MCPPlexusServer.get_mcp_tools_list_for_tenant: Invalid FastMCP instance")
            return []
            
        source_tools_dict = await self._fastmcp_instance.get_tools()
        logger.debug(f"get_mcp_tools_list_for_tenant (E:{entity_id}, SetFilter:{tool_set_filter}): Found {len(source_tools_dict)} raw tools from FastMCP")
        
        visible_tools: List[MCPTool] = []
        for tool_name, fmcp_tool_obj in source_tools_dict.items():
            # Check tenant access permissions
            is_globally_visible = not self._tool_tenant_scoping.get(tool_name, [])
            if not is_globally_visible and entity_id not in self._tool_tenant_scoping.get(tool_name, []):
                continue
                
            # Apply tool set filter if specified
            if tool_set_filter:
                expected_tag = f"tool_set:{tool_set_filter.strip().replace(' ', '_')}"
                if expected_tag not in (fmcp_tool_obj.tags or set()):
                    continue
                    
            mcp_tool = fmcp_tool_obj.to_mcp_tool(name=tool_name)
            visible_tools.append(mcp_tool)
            
        logger.info(f"get_mcp_tools_list_for_tenant (E:{entity_id}, SetFilter:{tool_set_filter}): Returning {len(visible_tools)} tools")
        return visible_tools

    async def can_tenant_call_tool(self, entity_id: str, tool_name: str) -> bool:
        """
        Check if a tenant has permission to call a specific tool.
        
        Args:
            entity_id: The tenant/entity ID
            tool_name: The name of the tool to check
            
        Returns:
            True if the tenant can call the tool, False otherwise
        """
        # Check if tool exists
        if (not self._fastmcp_instance or 
            not hasattr(self._fastmcp_instance, '_tool_manager') or 
            not self._fastmcp_instance._tool_manager.has_tool(tool_name)):
            logger.warning(f"can_tenant_call_tool: Tool '{tool_name}' not registered. Denying call for E:{entity_id}")
            return False
            
        # Check tenant permissions
        allowed_tenants_for_tool = self._tool_tenant_scoping.get(tool_name)
        if allowed_tenants_for_tool is None or not allowed_tenants_for_tool:
            # Tool is globally accessible
            return True
            
        return entity_id in allowed_tenants_for_tool

    async def register_external_oauth_provider(self, entity_id: str, provider_settings: 'OAuthProviderSettings') -> None:
        """
        Register an external OAuth provider configuration for a tenant.
        
        Args:
            entity_id: The tenant/entity ID
            provider_settings: The OAuth provider configuration
            
        Raises:
            RuntimeError: If the OAuth config store is unavailable
        """
        store = _get_external_oauth_config_store_instance()
        if not store:
            raise RuntimeError("External OAuth Provider Config Store unavailable")
            
        await store.save_provider_config(entity_id=entity_id, provider_config=provider_settings)
        logger.info(f"Registered provider '{provider_settings.provider_name}' for E:'{entity_id}'")

    async def get_external_oauth_provider(self, entity_id: str, provider_name: str) -> Optional['OAuthProviderSettings']:
        """
        Retrieve an external OAuth provider configuration for a tenant.
        
        Args:
            entity_id: The tenant/entity ID
            provider_name: The name of the OAuth provider
            
        Returns:
            The OAuth provider settings if found, None otherwise
        """
        store = _get_external_oauth_config_store_instance()
        if not store:
            return None
            
        return await store.load_provider_config(entity_id=entity_id, provider_name=provider_name)

    async def delete_external_oauth_provider(self, entity_id: str, provider_name: str) -> None:
        """
        Delete an external OAuth provider configuration for a tenant.
        
        Args:
            entity_id: The tenant/entity ID
            provider_name: The name of the OAuth provider to delete
            
        Raises:
            RuntimeError: If the OAuth config store is unavailable
        """
        store = _get_external_oauth_config_store_instance()
        if not store:
            raise RuntimeError("External OAuth Provider Config Store unavailable")
            
        await store.delete_provider_config(entity_id=entity_id, provider_name=provider_name)
        logger.info(f"Deleted provider '{provider_name}' for E:'{entity_id}'")

    async def get_all_external_oauth_providers_for_entity(self, entity_id: str) -> List['OAuthProviderSettings']:
        """
        Get all external OAuth provider configurations for a tenant.
        
        Args:
            entity_id: The tenant/entity ID
            
        Returns:
            List of OAuth provider settings for the tenant
        """
        store = _get_external_oauth_config_store_instance()
        if not store:
            return []
            
        return await store.load_all_provider_configs_for_entity(entity_id=entity_id)

    def add_resource(self, resource_obj: Resource, key: Optional[str] = None) -> None:
        """
        Add a resource object directly to the FastMCP instance.
        
        Args:
            resource_obj: The resource object to add
            key: Optional key for the resource
            
        Raises:
            RuntimeError: If FastMCP instance is not available
        """
        logger.info(f"MCPPlexusServer.add_resource: URI: {resource_obj.uri}, Key: {key}")
        if not self._fastmcp_instance:
            raise RuntimeError("FastMCP instance not available for add_resource")
            
        self._fastmcp_instance.add_resource(resource_obj, key=key)