# mcp_plexus/core/server.py
from typing import TYPE_CHECKING, TypeVar, Callable, Any, Dict, Set, Optional, Union, List, overload
import logging
from fastmcp import FastMCP
from fastmcp.resources import Resource
from mcp.types import Tool as MCPTool

if TYPE_CHECKING:
    from ..oauth.models import OAuthProviderSettings
    from ..oauth.storage_interfaces import AbstractExternalOAuthProviderConfigStore

logger = logging.getLogger(__name__)

# Global cache for external OAuth config store to avoid repeated imports
_ext_oauth_config_store_cache: Optional['AbstractExternalOAuthProviderConfigStore'] = None

def _get_external_oauth_config_store_instance() -> Optional['AbstractExternalOAuthProviderConfigStore']:
    """
    Lazy loader for the external OAuth provider config store instance.
    Uses caching to avoid repeated imports and handles import failures gracefully.
    """
    global _ext_oauth_config_store_cache
    if _ext_oauth_config_store_cache is None:
        try:
            from mcp_plexus.main import external_oauth_provider_config_store_instance
            _ext_oauth_config_store_cache = external_oauth_provider_config_store_instance
            logger.debug(f"MCPPlexusServer: Successfully imported external_oauth_provider_config_store_instance")
        except ImportError:
            logger.error("MCPPlexusServer: Failed to import external_oauth_provider_config_store_instance. Store unavailable.")
            return None
        except AttributeError:
            logger.error("MCPPlexusServer: external_oauth_provider_config_store_instance not found in main or is None. Store unavailable.")
            return None
            
    if _ext_oauth_config_store_cache is None:
        logger.warning("MCPPlexusServer: External OAuth Provider Config Store is None after import attempt.")
    return _ext_oauth_config_store_cache


F = TypeVar('F', bound=Callable[..., Any])

class MCPPlexusServer:
    """
    A facade layer over FastMCP that provides tenant-scoped tool management,
    tool set organization, and external OAuth provider configuration.
    """
    
    def __init__(self, server_settings: Optional[Any] = None): 
        # Delayed import to avoid circular dependencies
        from ..mcp_handlers.tenant_mcp_app import shared_fastmcp_server_instance
        
        self._fastmcp_instance: FastMCP = shared_fastmcp_server_instance
        self.plexus_settings = server_settings 
        
        # Track which tenants can access which tools (empty list means global access)
        self._tool_tenant_scoping: Dict[str, List[str]] = {} 
        # Track which tools belong to which tool sets
        self._tool_set_assignments: Dict[str, List[str]] = {} 

        logger.info(f"MCPPlexusServer initialized using shared FastMCP instance: {self._fastmcp_instance.name if self._fastmcp_instance else 'None'}")

    def get_fastmcp_instance(self, entity_id: Optional[str] = None) -> FastMCP:
        """
        Returns the underlying FastMCP instance, with fallback re-fetching if None.
        """
        if entity_id: 
            logger.debug(f"Requested FastMCP instance for entity_id: {entity_id}")
            
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
    def tool(self, *, 
             name: Optional[str] = None, 
             description: Optional[str] = None, 
             tags: Optional[Set[str]] = None, 
             annotations: Optional[Dict[str, Any]] = None,
             tool_sets: Optional[List[str]] = None, 
             allowed_tenant_ids: Optional[List[str]] = None
            ) -> Callable[[F], F]: ...
            
    def tool(self, func: Optional[F] = None, *, 
             name: Optional[str] = None, 
             description: Optional[str] = None, 
             tags: Optional[Set[str]] = None, 
             annotations: Optional[Dict[str, Any]] = None,
             tool_sets: Optional[List[str]] = None,      
             allowed_tenant_ids: Optional[List[str]] = None 
            ) -> Union[Callable[[F], F], F]:
        """
        Register a tool with tenant scoping and tool set assignment capabilities.
        
        Args:
            tool_sets: List of tool set names this tool belongs to
            allowed_tenant_ids: List of tenant IDs that can access this tool (None/empty = global)
        """
        
        # Determine tool name for internal tracking
        effective_name_for_tracking = name
        if callable(func) and not effective_name_for_tracking:
            effective_name_for_tracking = func.__name__
        
        logger.info(f"MCPPlexusServer.tool invoked. Func: {func.__name__ if callable(func) else 'Factory'}, "
                   f"Name: {name}, ToolSets: {tool_sets}, Tenants: {allowed_tenant_ids}")

        # Convert tool sets to tags for FastMCP compatibility
        final_tags = set(tags) if tags else set()
        if tool_sets:
            for ts_name in tool_sets:
                final_tags.add(f"tool_set:{ts_name.strip().replace(' ', '_')}") 
        
        # Store tenant scoping information
        if effective_name_for_tracking:
            if allowed_tenant_ids is not None: 
                self._tool_tenant_scoping[effective_name_for_tracking] = [
                    tid.strip() for tid in allowed_tenant_ids if tid.strip()
                ]
                logger.info(f"Tool '{effective_name_for_tracking}' scoped to tenants: "
                           f"{self._tool_tenant_scoping[effective_name_for_tracking]}")
            elif effective_name_for_tracking not in self._tool_tenant_scoping:
                # Default to global access if not already configured
                self._tool_tenant_scoping[effective_name_for_tracking] = [] 
                logger.info(f"Tool '{effective_name_for_tracking}' defaulted to global access.")

            # Store tool set assignments
            if tool_sets:
                 self._tool_set_assignments[effective_name_for_tracking] = [
                     ts.strip() for ts in tool_sets if ts.strip()
                 ]
                 logger.info(f"Tool '{effective_name_for_tracking}' assigned to tool_sets: "
                            f"{self._tool_set_assignments[effective_name_for_tracking]}")
        
        # Prepare arguments for FastMCP
        decorator_kwargs_for_fastmcp = {
            "description": description,
            "tags": final_tags if final_tags else None, 
            "annotations": annotations
        }
        if name:
            decorator_kwargs_for_fastmcp["name"] = name

        if not self._fastmcp_instance:
            logger.error("MCPPlexusServer.tool: _fastmcp_instance is None")
            raise RuntimeError("FastMCP instance not available in MCPPlexusServer.tool")

        # Handle direct function registration
        if callable(func):
            self._fastmcp_instance.add_tool(fn=func, **decorator_kwargs_for_fastmcp) 
            logger.info(f"MCPPlexusServer.tool: Registered function '{func.__name__}' with FastMCP")
            return func
        else:
            # Return decorator for factory pattern
            def wrapper(fn_wrapped: F) -> F:
                nonlocal effective_name_for_tracking
                if not effective_name_for_tracking:
                    effective_name_for_tracking = fn_wrapped.__name__
                    logger.info(f"MCPPlexusServer.tool (wrapper): Using function name '{effective_name_for_tracking}'")
                
                # Apply scoping rules for wrapped function if not already set
                if effective_name_for_tracking:
                    if allowed_tenant_ids is not None and effective_name_for_tracking not in self._tool_tenant_scoping:
                         self._tool_tenant_scoping[effective_name_for_tracking] = [
                             tid.strip() for tid in allowed_tenant_ids if tid.strip()
                         ]
                         logger.info(f"Tool '{effective_name_for_tracking}' (wrapper) scoped to: "
                                    f"{self._tool_tenant_scoping[effective_name_for_tracking]}")
                    elif effective_name_for_tracking not in self._tool_tenant_scoping:
                         self._tool_tenant_scoping[effective_name_for_tracking] = []
                         logger.info(f"Tool '{effective_name_for_tracking}' (wrapper) defaulted to global access.")

                    if tool_sets and effective_name_for_tracking not in self._tool_set_assignments:
                        self._tool_set_assignments[effective_name_for_tracking] = [
                            ts.strip() for ts in tool_sets if ts.strip()
                        ]
                        logger.info(f"Tool '{effective_name_for_tracking}' (wrapper) assigned to tool_sets: "
                                   f"{self._tool_set_assignments[effective_name_for_tracking]}")
                
                final_decorator_kwargs = decorator_kwargs_for_fastmcp.copy()
                if name:
                    final_decorator_kwargs['name'] = name

                self._fastmcp_instance.tool(**final_decorator_kwargs)(fn_wrapped)
                logger.info(f"MCPPlexusServer.tool (wrapper): Registered wrapped function '{fn_wrapped.__name__}'")
                return fn_wrapped
            return wrapper

    async def get_mcp_tools_list_for_tenant(
        self, 
        entity_id: str, 
        tool_set_filter: Optional[str] = None,
        mcp_session_id: Optional[str] = None 
    ) -> List[MCPTool]:
        """
        Get filtered list of tools available to a specific tenant.
        
        Args:
            entity_id: Tenant identifier
            tool_set_filter: Optional tool set name to filter by
            mcp_session_id: Optional session identifier for logging
            
        Returns:
            List of MCP tools the tenant can access
        """
        if not self._fastmcp_instance or not hasattr(self._fastmcp_instance, 'get_tools'):
            logger.error("MCPPlexusServer.get_mcp_tools_list_for_tenant: Invalid FastMCP instance")
            return []
            
        source_tools_dict = await self._fastmcp_instance.get_tools()
        
        logger.debug(f"get_mcp_tools_list_for_tenant (E:{entity_id}, SetFilter:{tool_set_filter}): "
                    f"Found {len(source_tools_dict)} raw tools from FastMCP")

        visible_tools: List[MCPTool] = []
        for tool_name, fmcp_tool_obj in source_tools_dict.items():
            # Check tenant access permissions
            is_globally_visible = not self._tool_tenant_scoping.get(tool_name, []) 
            
            if not is_globally_visible and entity_id not in self._tool_tenant_scoping.get(tool_name, []):
                logger.debug(f"Tool '{tool_name}' access denied for E:{entity_id}. "
                           f"Scoped to: {self._tool_tenant_scoping.get(tool_name)}")
                continue

            # Apply tool set filter if specified
            if tool_set_filter:
                expected_tag = f"tool_set:{tool_set_filter.strip().replace(' ', '_')}"
                if expected_tag not in (fmcp_tool_obj.tags or set()):
                    continue 
            
            mcp_tool = fmcp_tool_obj.to_mcp_tool(name=tool_name) 
            visible_tools.append(mcp_tool)
            logger.debug(f"Tool '{tool_name}' ADDED for E:{entity_id}")

        logger.info(f"get_mcp_tools_list_for_tenant (E:{entity_id}, SetFilter:{tool_set_filter}): "
                   f"Returning {len(visible_tools)} tools")
        return visible_tools

    async def can_tenant_call_tool(self, entity_id: str, tool_name: str) -> bool:
        """
        Check if a tenant has permission to call a specific tool.
        
        Args:
            entity_id: Tenant identifier
            tool_name: Name of the tool to check
            
        Returns:
            True if tenant can call the tool, False otherwise
        """
        # Verify tool exists in FastMCP registry
        if (not self._fastmcp_instance or 
            not hasattr(self._fastmcp_instance, '_tool_manager') or 
            not self._fastmcp_instance._tool_manager.has_tool(tool_name)):
            logger.warning(f"can_tenant_call_tool: Tool '{tool_name}' not registered. "
                          f"Denying call for E:{entity_id}")
            return False

        # Check tenant scoping
        allowed_tenants_for_tool = self._tool_tenant_scoping.get(tool_name)
        if allowed_tenants_for_tool is None or not allowed_tenants_for_tool: 
            logger.debug(f"Tool '{tool_name}' is globally accessible. Access allowed for E:{entity_id}")
            return True
            
        can_access = entity_id in allowed_tenants_for_tool
        logger.debug(f"Tool '{tool_name}' scoped to {allowed_tenants_for_tool}. "
                    f"Access for E:{entity_id}: {can_access}")
        return can_access
    
    async def register_external_oauth_provider(self, entity_id: str, provider_settings: 'OAuthProviderSettings') -> None:
        """Register an external OAuth provider for a tenant."""
        store = _get_external_oauth_config_store_instance()
        if not store: 
            raise RuntimeError("External OAuth Provider Config Store unavailable")
        await store.save_provider_config(entity_id=entity_id, provider_config=provider_settings)
        logger.info(f"Registered provider '{provider_settings.provider_name}' for E:'{entity_id}'")

    async def get_external_oauth_provider(self, entity_id: str, provider_name: str) -> Optional['OAuthProviderSettings']:
        """Retrieve an external OAuth provider configuration for a tenant."""
        store = _get_external_oauth_config_store_instance()
        if not store: 
            return None
        return await store.load_provider_config(entity_id=entity_id, provider_name=provider_name)

    async def delete_external_oauth_provider(self, entity_id: str, provider_name: str) -> None:
        """Delete an external OAuth provider configuration for a tenant."""
        store = _get_external_oauth_config_store_instance()
        if not store: 
            raise RuntimeError("External OAuth Provider Config Store unavailable")
        await store.delete_provider_config(entity_id=entity_id, provider_name=provider_name)
        logger.info(f"Deleted provider '{provider_name}' for E:'{entity_id}'")

    async def get_all_external_oauth_providers_for_entity(self, entity_id: str) -> List['OAuthProviderSettings']:
        """Get all external OAuth provider configurations for a tenant."""
        store = _get_external_oauth_config_store_instance()
        if not store: 
            return []
        return await store.load_all_provider_configs_for_entity(entity_id=entity_id)

    @overload
    def resource(self, uri: str, *, name: Optional[str] = None, description: Optional[str] = None, 
                mime_type: Optional[str] = None, tags: Optional[Set[str]] = None) -> Callable[[F], F]: ...
                
    def resource(self, uri: str, *, name: Optional[str] = None, description: Optional[str] = None, 
                mime_type: Optional[str] = None, tags: Optional[Set[str]] = None) -> Callable[[F], F]:
        """Register a resource with the underlying FastMCP instance."""
        logger.info(f"MCPPlexusServer.resource factory: URI: {uri}")
        if not self._fastmcp_instance: 
            raise RuntimeError("FastMCP instance not available for resource registration")
        return self._fastmcp_instance.resource(uri=uri, name=name, description=description, 
                                             mime_type=mime_type, tags=tags)

    @overload
    def prompt(self, func: F) -> F: ...
    
    @overload
    def prompt(self, *, name: Optional[str] = None, description: Optional[str] = None, 
              tags: Optional[Set[str]] = None) -> Callable[[F], F]: ...
              
    def prompt(self, func: Optional[F] = None, *, name: Optional[str] = None, 
              description: Optional[str] = None, tags: Optional[Set[str]] = None) -> Union[Callable[[F], F], F]:
        """Register a prompt with the underlying FastMCP instance."""
        logger.info(f"MCPPlexusServer.prompt: Func: {func.__name__ if callable(func) else 'Factory'}, Name: {name}")
        if not self._fastmcp_instance: 
            raise RuntimeError("FastMCP instance not available for prompt registration")
            
        kwargs_pass = {k: v for k, v in {"name": name, "description": description, "tags": tags}.items() if v is not None}
        if callable(func): 
            return self._fastmcp_instance.prompt(func, **kwargs_pass)
        else: 
            return self._fastmcp_instance.prompt(**kwargs_pass)

    def add_resource(self, resource_obj: Resource, key: Optional[str] = None) -> None:
        """Add a resource object to the underlying FastMCP instance."""
        logger.info(f"MCPPlexusServer.add_resource: URI: {resource_obj.uri}, Key: {key}")
        if not self._fastmcp_instance: 
            raise RuntimeError("FastMCP instance not available for add_resource")
        self._fastmcp_instance.add_resource(resource_obj, key=key)