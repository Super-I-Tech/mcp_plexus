# mcp_plexus/main.py
from fastapi import FastAPI, HTTPException
from starlette.routing import Route, Router as StarletteRouter
from starlette.endpoints import HTTPEndpoint
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse, JSONResponse
from starlette.types import Receive, Scope, Send
from contextlib import asynccontextmanager
import logging
import os
import json 
from typing import Optional, Any, Union, Dict, List 
from uuid import uuid4
from dotenv import load_dotenv
load_dotenv()

from .settings import settings
from .core.global_registry import PLEXUS_SERVER_INSTANCE as PLEXUS_INSTANCE_ON_IMPORT 
from .mcp_handlers.tenant_mcp_app import shared_fastmcp_server_instance 
from .oauth.endpoints import oauth_router as plexus_internal_oauth_router 
from .plexus_auth.endpoints import plexus_auth_router 
from .tenants.endpoints import tenants_admin_router
from .services.endpoints import user_services_router 
from .oauth_providers_admin.endpoints import external_oauth_providers_admin_router
from .tenants.storage_interfaces import AbstractTenantStore 
from .tenants.sqlite_tenant_store import get_sqlite_tenant_store 

from .storage.sqlite_base import init_sqlite_db, close_sqlite_db_connection, get_sqlite_db_connection
from .sessions import (
    RedisPlexusSessionStore, PlexusSessionManager, SessionData, 
)
from .oauth.storage import (
    get_oauth_token_store as get_internal_oauth_token_store, 
    get_auth_code_store as get_internal_auth_code_store,    
    get_external_oauth_provider_config_store,
    get_internal_oauth_client_store 
)
from .oauth.storage_interfaces import ( 
    AbstractOAuthTokenStore, AbstractAuthCodeStore, 
    AbstractExternalOAuthProviderConfigStore, AbstractUserExternalTokenStore,
    AbstractOAuthClientStore 
)
from .oauth.user_token_store import get_user_external_token_store 
from .plexus_auth.storage_interfaces import AbstractPlexusUserAuthTokenStore
from .plexus_auth.sqlite_user_auth_token_store import get_sqlite_plexus_user_auth_token_store
from .plexus_auth.token_manager import DefaultPlexusUserTokenManager, PlexusUserTokenManagerProtocol

# Conditional imports for MCP functionality - these may not be available in all environments
StreamableHTTPSessionManager = None
set_http_request_cm = None 
try:
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    logging.info("Imported StreamableHTTPSessionManager.")
    try:  
        from fastmcp.server.http import set_http_request as fastmcp_set_http_request_cm
        set_http_request_cm = fastmcp_set_http_request_cm
        logging.info("Imported set_http_request from fastmcp.server.http.")
    except ImportError: 
        from fastmcp.server.dependencies import set_http_request as fastmcp_dep_set_http_request_cm
        set_http_request_cm = fastmcp_dep_set_http_request_cm
        logging.info("Imported set_http_request from fastmcp.server.dependencies.")
except ImportError as e:
    logging.error(f"Failed to import StreamableHTTPSessionManager: {e}.", exc_info=True)

# Configure logging based on debug mode setting
if not logging.getLogger().hasHandlers():
    logging.basicConfig(
        level="DEBUG" if settings.debug_mode else "INFO", 
        format='%(asctime)s - %(name)s [%(levelname)s] - %(message)s'
    )

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG if settings.debug_mode else logging.INFO)

# Global instances for dependency injection - initialized during application startup
plexus_session_manager_instance: Optional[PlexusSessionManager] = None
plexus_fastmcp_http_session_manager: Optional[StreamableHTTPSessionManager] = None # type: ignore
plexus_user_auth_token_store_instance: Optional[AbstractPlexusUserAuthTokenStore] = None
plexus_user_token_manager_instance: Optional[PlexusUserTokenManagerProtocol] = None
internal_oauth_token_store_instance: Optional[AbstractOAuthTokenStore] = None
internal_auth_code_store_instance: Optional[AbstractAuthCodeStore] = None
external_oauth_provider_config_store_instance: Optional[AbstractExternalOAuthProviderConfigStore] = None
user_external_token_store_instance: Optional[AbstractUserExternalTokenStore] = None
internal_oauth_client_store_instance: Optional[AbstractOAuthClientStore] = None 
plexus_tenant_store_instance: Optional[AbstractTenantStore] = None

# Initialize FastMCP HTTP session manager if MCP components are available
if StreamableHTTPSessionManager:
    actual_mcp_server_app_for_manager = None
    if hasattr(shared_fastmcp_server_instance, "_mcp_server") and shared_fastmcp_server_instance._mcp_server:
        actual_mcp_server_app_for_manager = shared_fastmcp_server_instance._mcp_server
    elif hasattr(shared_fastmcp_server_instance, "app") and hasattr(shared_fastmcp_server_instance.app, "create_initialization_options"): 
        actual_mcp_server_app_for_manager = shared_fastmcp_server_instance.app
    
    if actual_mcp_server_app_for_manager:
        plexus_fastmcp_http_session_manager = StreamableHTTPSessionManager(app=actual_mcp_server_app_for_manager)
        logger.info("FastMCP StreamableHTTPSessionManager instance created.")
    else:
        logger.error("Could not find underlying MCPServer app in shared_fastmcp_server_instance. Manager not created.")
else:
    logger.error("StreamableHTTPSessionManager not imported, MCP handling will fail.")

@asynccontextmanager
async def plexns_app_lifespan(app_instance: FastAPI):
    """
    Application lifespan manager that handles initialization and cleanup of all storage backends,
    session managers, and MCP components. This ensures proper resource management throughout
    the application lifecycle.
    """
    global plexus_session_manager_instance, plexus_fastmcp_http_session_manager
    global internal_oauth_token_store_instance, internal_auth_code_store_instance
    global external_oauth_provider_config_store_instance, user_external_token_store_instance
    global plexus_user_auth_token_store_instance, plexus_user_token_manager_instance
    global internal_oauth_client_store_instance 
    global plexus_tenant_store_instance 

    logger.info("Application startup initiated.")
    initialized_stores = []
    
    try:
        # Initialize primary storage backend based on configuration
        if settings.storage_backend == "sqlite":
            await get_sqlite_db_connection() 
            logger.info("SQLite backend selected and connection initialized.")
            initialized_stores.append("sqlite_db_connection")
        elif settings.storage_backend == "redis":
            logger.info("Redis backend selected. Stores will manage their connections.")
        else:
            raise ValueError(f"Unsupported storage_backend: {settings.storage_backend}")
    except Exception as e:
        logger.error(f"Error during storage backend initialization: {e}", exc_info=True)
        raise

    # Initialize session manager - MCP sessions currently require Redis for persistence
    if settings.storage_backend == "redis": 
        redis_session_store = RedisPlexusSessionStore()
        await redis_session_store.initialize()
        plexus_session_manager_instance = PlexusSessionManager(store=redis_session_store)
        initialized_stores.append(redis_session_store) 
        logger.info("PlexusSessionManager (Redis-backed) initialized.")
    elif settings.storage_backend == "sqlite":
        # SQLite session store not yet implemented, falling back to Redis for MCP compatibility
        logger.warning("SQLite backend selected but sessions currently require Redis. Using RedisPlexusSessionStore.")
        redis_session_store = RedisPlexusSessionStore() 
        await redis_session_store.initialize()
        plexus_session_manager_instance = PlexusSessionManager(store=redis_session_store)
        initialized_stores.append(redis_session_store) 
        logger.info("PlexusSessionManager (Redis-backed fallback) initialized.")
    else: 
        raise ValueError(f"Unsupported storage_backend for session manager: {settings.storage_backend}")

    # Initialize authentication components for user token management
    plexus_user_auth_token_store_instance = await get_sqlite_plexus_user_auth_token_store()
    plexus_user_token_manager_instance = DefaultPlexusUserTokenManager()
    initialized_stores.append(plexus_user_auth_token_store_instance)
    logger.info("Plexus User Authentication components initialized.")
    
    # Initialize OAuth data stores for internal and external OAuth flows
    internal_oauth_token_store_instance = await get_internal_oauth_token_store()
    internal_auth_code_store_instance = await get_internal_auth_code_store()
    external_oauth_provider_config_store_instance = await get_external_oauth_provider_config_store()
    user_external_token_store_instance = await get_user_external_token_store()
    internal_oauth_client_store_instance = await get_internal_oauth_client_store() 
    initialized_stores.extend([
        internal_oauth_token_store_instance, internal_auth_code_store_instance,
        external_oauth_provider_config_store_instance, user_external_token_store_instance,
        internal_oauth_client_store_instance 
    ])
    logger.info("All OAuth data stores initialized.")
    
    # Initialize tenant store for multi-tenant support
    plexus_tenant_store_instance = await get_sqlite_tenant_store() 
    if plexus_tenant_store_instance: 
        await plexus_tenant_store_instance.initialize() 
        initialized_stores.append(plexus_tenant_store_instance)
        logger.info("Plexus Tenant Store initialized.")
    else:
        logger.error("plexus_tenant_store_instance is None. Tenant validation will fail.")

    # Create default OAuth client for testing and development
    from .oauth.models import OAuthClient 
    if internal_oauth_client_store_instance:
        test_client_id = "plexus-test-client"
        default_plexus_test_client = OAuthClient(
            client_id=test_client_id,
            client_name="MCP Plexus Test Client (SQLite)",
            redirect_uris=["http://localhost:8080/callback", "http://127.0.0.1:8080/callback"],
            allowed_scopes=["openid", "profile", "email", "mcp_tool:get_entity_info", "mcp_tool:manage_plexus_session_tool"],
            allowed_grant_types=["authorization_code", "refresh_token"],
            is_trusted_internal=True 
        )
        await internal_oauth_client_store_instance.save_client(default_plexus_test_client)
        logger.info(f"Default OAuth client '{test_client_id}' configured.")
    
    # Run FastMCP HTTP manager if available - this manages MCP protocol sessions
    if plexus_fastmcp_http_session_manager and hasattr(plexus_fastmcp_http_session_manager, "run"):        
        try:
            async with plexus_fastmcp_http_session_manager.run(): 
                logger.info("FastMCP HTTP manager running.")
                yield
        except Exception as e_fmcp_run: 
            logger.error(f"FastMCP manager error: {e_fmcp_run}", exc_info=True)
            raise
    else: 
        logger.warning("FastMCP manager not runnable. Proceeding without it.")
        yield 
    
    # Cleanup phase - ensure all resources are properly released
    logger.info("Application shutdown initiated.")
    for store_instance in reversed(initialized_stores):
        try:
            if store_instance == "sqlite_db_connection":
                await close_sqlite_db_connection()
            elif hasattr(store_instance, 'teardown'):
                await store_instance.teardown()
        except Exception as e_td:
            logger.error(f"Teardown error: {e_td}", exc_info=True)
    logger.info("All components torn down.")

class ResponseHandled(StarletteResponse):
    """
    A response class indicating that the response has been handled elsewhere
    and no further processing is needed. Used to signal that the MCP endpoint
    has already sent the response through its own mechanisms.
    """
    def __init__(self):
        super().__init__(content=b"", media_type="text/plain")
    
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        return

class PlexusMCPEndpoint(HTTPEndpoint):
    """
    HTTP endpoint that handles MCP (Model Context Protocol) requests with authentication
    and session management. Supports both header-based and URL-based token authentication
    for secure multi-tenant MCP operations.
    """
    
    async def _extract_and_validate_plexus_token(self, request: StarletteRequest, entity_id: str) -> Optional[str]:
        """Extract and validate Bearer token from Authorization header."""
        auth_header = request.headers.get("Authorization")
        if auth_header:
            parts = auth_header.split()
            if len(parts) == 2 and parts[0].lower() == "bearer":
                token = parts[1]
                if token and len(token) > 20: 
                    logger.info(f"Found Bearer token for entity {entity_id}.")
                    return token 
            logger.warning(f"Malformed Authorization header for entity {entity_id}.")
        return None

    async def _get_persistent_user_id_from_token(self, entity_id: str, token: str) -> Optional[str]:
        """Validate authentication token and return associated persistent user ID."""
        token_store = await get_sqlite_plexus_user_auth_token_store()
        token_manager = DefaultPlexusUserTokenManager()
        
        token_hash = token_manager.hash_token(token)
        token_data = await token_store.get_token_data_by_hash(token_hash)

        if token_data and token_data.entity_id == entity_id:
            await token_store.update_token_last_used(token_hash)
            logger.info(f"Valid token for entity {entity_id}, user: {token_data.persistent_user_id}")
            return token_data.persistent_user_id
        logger.warning(f"Invalid or mismatched token for entity {entity_id}.")
        return None

    async def _dispatch_mcp_request(self, scope: Scope, receive: Receive, send: Send) -> None:
        """
        Main request dispatcher that handles authentication, session management,
        and routing to the appropriate MCP handler. This method orchestrates the
        entire MCP request lifecycle including tenant validation, authentication,
        session management, and response handling.
        """
        from .core.global_registry import PLEXUS_SERVER_INSTANCE
        
        entity_id_from_path = scope["path_params"]["entity_id"]
        token_from_url_path = scope["path_params"].get("plexus_token_value")

        dispatch_logger = logging.getLogger(f"{__name__}._dispatch_mcp_request")
        dispatch_logger.setLevel(logging.DEBUG if settings.debug_mode else logging.INFO)

        # Variables to track request state and special handling requirements
        handle_tools_list_manually: bool = False
        tools_list_filter_param: Optional[str] = None
        tools_list_json_rpc_id: Union[str, int, None] = None
        response_started: bool = False 
        authoritative_mcp_session_id: Optional[str] = None 
        session_data_for_this_dispatch: Optional[SessionData] = None
        request_handling_exception: Optional[Exception] = None
         
        # Validate tenant exists and is active before processing any MCP requests
        if plexus_tenant_store_instance:
            tenant = await plexus_tenant_store_instance.get_tenant_by_entity_id(entity_id_from_path)
            if not tenant:
                error_response = JSONResponse(
                    status_code=404, 
                    content={"error": "tenant_not_found", "message": f"Tenant '{entity_id_from_path}' does not exist."}
                )
                await error_response(scope, receive, send)
                return
            elif tenant.status != 'active':
                error_response = JSONResponse(
                    status_code=403, 
                    content={"error": "tenant_not_active", "message": f"Tenant '{entity_id_from_path}' is not active."}
                )
                await error_response(scope, receive, send)
                return
        else:
            error_response = JSONResponse(
                status_code=503, 
                content={"error": "tenant_validation_unavailable", "message": "Cannot validate tenant."}
            )
            await error_response(scope, receive, send)
            return

        # Extract MCP session ID from headers for session continuity
        original_mcp_session_id_from_header: Optional[str] = None
        for k, v_bytes in scope.get("headers", []):
            if k.lower() == b"mcp-session-id":
                original_mcp_session_id_from_header = v_bytes.decode("utf-8", errors="ignore")
                break

        if not plexus_session_manager_instance:
            await JSONResponse({"error":"Session manager unavailable"}, status_code=503)(scope,receive,send)
            return

        # Prepare scope for MCP processing with entity context
        scope_for_mcp = scope.copy()
        current_scope_state: Dict[str, Any] = scope_for_mcp.get("state", {}) 
        if not isinstance(current_scope_state, dict):
            current_scope_state = {} 
        scope_for_mcp["state"] = current_scope_state
        scope_for_mcp["state"]["entity_id"] = entity_id_from_path
        
        # Authentication processing - support both header and URL token methods
        derived_persistent_user_id: Optional[str] = None

        starlette_request_for_header_check = StarletteRequest(scope)
        plexus_user_auth_token_from_header = await self._extract_and_validate_plexus_token(
            starlette_request_for_header_check, entity_id_from_path
        )

        # Ensure only one authentication method is used to prevent confusion
        if plexus_user_auth_token_from_header:
            if token_from_url_path:
                await JSONResponse(
                    {"error":"invalid_request", "error_description":"Multiple auth methods."}, 
                    status_code=400
                )(scope,receive,send)
                return
            derived_persistent_user_id = await self._get_persistent_user_id_from_token(
                entity_id_from_path, plexus_user_auth_token_from_header
            )
        elif token_from_url_path:
            derived_persistent_user_id = await self._get_persistent_user_id_from_token(
                entity_id_from_path, token_from_url_path
            )
        
        # Peek at request body for method detection and authorization checks
        is_currently_initialize_req = False
        first_chunk_message_storage = {'message': None}

        if scope['method'] == 'POST':
            first_chunk_message_storage['message'] = await receive()
            current_chunk_to_process = first_chunk_message_storage['message']
            temp_body_for_check = b""
            json_body_for_method_check: Optional[Dict[str, Any]] = None 
            
            if current_chunk_to_process and current_chunk_to_process['type'] == 'http.request':
                body_chunk_content = current_chunk_to_process.get('body', b'')
                more_body_flag = current_chunk_to_process.get('more_body', False)
                temp_body_for_check += body_chunk_content
                
                # Parse JSON body to determine MCP method and handle special cases
                if not more_body_flag or len(temp_body_for_check) > 20: 
                    try:
                        json_body_for_method_check = json.loads(temp_body_for_check.decode('utf-8'))
                        if not isinstance(json_body_for_method_check, dict):
                            json_body_for_method_check = None 
                        
                        if json_body_for_method_check:
                            method = json_body_for_method_check.get("method")
                            
                            if method == "initialize":
                                is_currently_initialize_req = True
                            elif method == "tools/list":
                                # Handle tools/list manually for tenant-specific filtering
                                handle_tools_list_manually = True
                                tools_list_json_rpc_id = json_body_for_method_check.get("id")
                                if isinstance(json_body_for_method_check.get("params"), dict):
                                    tools_list_filter_param = json_body_for_method_check["params"].get("tool_set_filter")
                            elif method == "tools/call":
                                # Validate tool authorization before allowing execution
                                tool_name_to_call = json_body_for_method_check.get("params", {}).get("name")
                                if tool_name_to_call:
                                    current_plexus_server_for_check = PLEXUS_SERVER_INSTANCE
                                    if not current_plexus_server_for_check or not hasattr(current_plexus_server_for_check, 'can_tenant_call_tool'):
                                        await JSONResponse(
                                            {"error":"server_configuration_error", "detail": "Tool auth check failed."}, 
                                            status_code=500
                                        )(scope, receive, send)
                                        return
                                    
                                    if not await current_plexus_server_for_check.can_tenant_call_tool(entity_id_from_path, tool_name_to_call):
                                        resp_payload = {
                                            "jsonrpc": "2.0", 
                                            "id": json_body_for_method_check.get("id"), 
                                            "error": {"code": -32003, "message": f"Tool '{tool_name_to_call}' not authorized."}
                                        }
                                        await JSONResponse(resp_payload, status_code=403)(scope, receive, send)
                                        return 
                    except Exception:
                        pass
            
            async def receive_instrumented() -> Dict[str, Any]:
                """Return cached first message or get next message from stream."""
                if first_chunk_message_storage['message']:
                    msg, first_chunk_message_storage['message'] = first_chunk_message_storage['message'], None
                    return msg
                return await receive()
        else:
            async def receive_instrumented() -> Dict[str, Any]:
                return await receive()

        # Enforce authentication requirements for all MCP operations
        if not derived_persistent_user_id:
            json_body_for_final_auth_check: Optional[Dict[str, Any]] = None
            try: 
                json_body_for_final_auth_check = json.loads(temp_body_for_check.decode('utf-8'))
            except: 
                pass 
            
            is_init_final_check = bool(
                json_body_for_final_auth_check and 
                isinstance(json_body_for_final_auth_check, dict) and 
                json_body_for_final_auth_check.get("method") == "initialize"
            )
            msg = "Auth token missing for initialize." if is_init_final_check else "Auth token missing."
            err_code = -32001 if is_init_final_check else -32000
            err_id = (json_body_for_final_auth_check.get("id") 
                     if json_body_for_final_auth_check and isinstance(json_body_for_final_auth_check, dict) 
                     else None)
            
            if is_init_final_check:
                err_payload = {"jsonrpc": "2.0", "id": err_id, "error": {"code": err_code, "message": msg}}
            else:
                err_payload = {"error":"authentication_required", "error_description":msg}
            
            await JSONResponse(err_payload, status_code=401)(scope,receive,send)
            return

        async def send_wrapper(message: Dict[Any, Any]):
            """
            Wrapper for send that manages session state and MCP session IDs.
            This ensures proper session tracking and persistence across MCP interactions.
            """
            nonlocal response_started, session_data_for_this_dispatch, authoritative_mcp_session_id
            send_wrapper_logger = logging.getLogger(__name__ + ".send_wrapper")
            send_wrapper_logger.setLevel(logging.DEBUG if settings.debug_mode else logging.INFO)
            
            if message["type"] == "http.response.start":
                if response_started:
                    return                 
                response_started = True
                
                # Extract MCP session ID from response headers
                hdrs_out_bytes = message.get('headers',[])
                hdrs_out_dict = {k.lower().decode('latin-1'): v.decode('latin-1') for k,v in hdrs_out_bytes}
                authoritative_mcp_session_id_from_fmcp = hdrs_out_dict.get("mcp-session-id")
                
                if not authoritative_mcp_session_id_from_fmcp:
                    # Fallback to original session ID or generate new one
                    authoritative_mcp_session_id_from_fmcp = (
                        original_mcp_session_id_from_header or 
                        f"error_fmcp_sid_missing_{uuid4().hex[:6]}"
                    )
                authoritative_mcp_session_id = authoritative_mcp_session_id_from_fmcp

                # Retrieve or create session data for this MCP session
                if plexus_session_manager_instance:
                    session_data_for_this_dispatch, _ = await plexus_session_manager_instance.get_session(
                        entity_id_from_path, authoritative_mcp_session_id
                    )
                    
                    # Align session with authenticated user
                    if derived_persistent_user_id and session_data_for_this_dispatch.persistent_user_id != derived_persistent_user_id:
                        session_data_for_this_dispatch.persistent_user_id = derived_persistent_user_id
                    
                    # Update session timestamp for initialize requests
                    if is_currently_initialize_req:
                        session_data_for_this_dispatch.touch()
                
                # Store session data in scope for access by other components
                if session_data_for_this_dispatch: 
                    current_scope_state["plexus_session_data"] = session_data_for_this_dispatch 
                    current_scope_state["mcp_session_id"] = session_data_for_this_dispatch.mcp_session_id
                
                # Ensure MCP session ID is properly set in response headers
                final_hdrs = [(k, v) for k, v in hdrs_out_bytes if k.lower() != b'mcp-session-id']
                if authoritative_mcp_session_id:
                    final_hdrs.append((b'mcp-session-id', authoritative_mcp_session_id.encode('utf-8')))
                message['headers'] = final_hdrs
            
            try:
                await send(message) 
            except Exception as e_send_exc:
                send_wrapper_logger.error(f"Exception during send: {e_send_exc}", exc_info=True)
                raise 
        
        # Main request processing logic
        try:
            if handle_tools_list_manually:
                # Handle tools/list requests with tenant-specific filtering
                from .core.global_registry import PLEXUS_SERVER_INSTANCE as current_plexus_server
                
                if not current_plexus_server or not hasattr(current_plexus_server, 'get_mcp_tools_list_for_tenant'):
                    await JSONResponse({"jsonrpc": "2.0", "id": tools_list_json_rpc_id, "error": {"code": -32002, "message": "Server config error."}}, status_code=500)(scope,receive,send)
                    return

                scoped_tools = await current_plexus_server.get_mcp_tools_list_for_tenant(
                    entity_id=entity_id_from_path, 
                    tool_set_filter=tools_list_filter_param, 
                    mcp_session_id=authoritative_mcp_session_id
                )
                
                # Prepare response headers with session ID
                hdrs_out = []
                if authoritative_mcp_session_id:
                    hdrs_out.append((b'mcp-session-id', authoritative_mcp_session_id.encode('utf-8')))
                else: 
                    temp_sid_tl = original_mcp_session_id_from_header or uuid4().hex 
                    hdrs_out.append((b'mcp-session-id', temp_sid_tl.encode('utf-8')))
                    authoritative_mcp_session_id = temp_sid_tl
                
                await send_wrapper({"type": "http.response.start", "status": 200, "headers": hdrs_out + [(b"content-type", b"application/json")]})
                
                tools_list_resp = {"jsonrpc": "2.0", "id": tools_list_json_rpc_id, "result": {"tools": [t.model_dump(exclude_none=True) for t in scoped_tools]}}
                await send_wrapper({"type": "http.response.body", "body": json.dumps(tools_list_resp).encode("utf-8"), "more_body": False})
            else:
                # All other requests are handled by FastMCP
                if not plexus_fastmcp_http_session_manager or not set_http_request_cm:
                    await JSONResponse({"error":"MCP handler unavailable"}, status_code=503)(scope, receive, send)
                    return
                
                if derived_persistent_user_id:
                    scope_for_mcp["state"]["derived_persistent_user_id"] = derived_persistent_user_id
                
                # Use FastMCP's request context manager for proper request handling
                with set_http_request_cm(StarletteRequest(scope_for_mcp, receive_instrumented)):  
                     await plexus_fastmcp_http_session_manager.handle_request(
                         scope_for_mcp, receive_instrumented, send_wrapper
                     )
        except Exception as e:
            request_handling_exception = e
            logger.error(f"Exception during MCP request processing: {e}", exc_info=True)
            if not response_started:
                error_response = JSONResponse(
                    status_code=500,
                    content={"error": "internal_server_error", "message": "An error occurred while processing the request."}
                )
                await error_response(scope, receive, send)
        finally:
            # Ensure session data is persisted after request processing
            if plexus_session_manager_instance and session_data_for_this_dispatch and authoritative_mcp_session_id:
                # Ensure the MCP session ID on the data object matches the final one
                if session_data_for_this_dispatch.mcp_session_id != authoritative_mcp_session_id:
                    session_data_for_this_dispatch.mcp_session_id = authoritative_mcp_session_id
                
                try:
                    await plexus_session_manager_instance.save_session(session_data_for_this_dispatch)
                except Exception as e:
                    logger.error(f"Exception during session save in finally block: {e}", exc_info=True)

    async def get(self, req: StarletteRequest) -> ResponseHandled:
        await self._dispatch_mcp_request(self.scope, self.receive, self.send)
        return ResponseHandled()
    
    async def post(self, req: StarletteRequest) -> ResponseHandled:
        await self._dispatch_mcp_request(self.scope, self.receive, self.send)
        return ResponseHandled()
    
    async def delete(self, req: StarletteRequest) -> ResponseHandled:
        await self._dispatch_mcp_request(self.scope, self.receive, self.send)
        return ResponseHandled()

# MCP routing configuration - supports both token-based and header-based authentication
mcp_starlette_router = StarletteRouter(routes=[
    Route("/{entity_id:str}/mcp/token_auth/{plexus_token_value:str}", PlexusMCPEndpoint),
    Route("/{entity_id:str}/mcp/token_auth/{plexus_token_value:str}/{mcp_path:path}", PlexusMCPEndpoint),
    Route("/{entity_id:str}/mcp", PlexusMCPEndpoint),
    Route("/{entity_id:str}/mcp/{mcp_path:path}", PlexusMCPEndpoint),
])

# FastAPI application setup with lifespan management
app = FastAPI(
    title=settings.app_name, 
    debug=settings.debug_mode, 
    version="0.2.1", 
    lifespan=plexns_app_lifespan
) 

@app.on_event("startup")
async def fastapi_startup():
    logger.info(f"{settings.app_name} FastAPI startup.")

@app.on_event("shutdown")
async def fastapi_shutdown():
    logger.info(f"{settings.app_name} FastAPI shutdown.")

@app.get("/")
async def root_api():
    return {"message": f"Welcome to {settings.app_name}!"}

@app.get("/health")
async def health_api():
    """Health check endpoint that validates storage backend connectivity and service status."""
    store_statuses: Dict[str, str] = {}
    all_healthy = True
    
    # Check SQLite database connectivity
    if settings.storage_backend == "sqlite":
        try:
            conn = await get_sqlite_db_connection()
            conn.execute("SELECT 1") 
            store_statuses["sqlite_main_db"] = "healthy"
        except Exception as e:
            store_statuses["sqlite_main_db"] = f"unhealthy: {e}"
            all_healthy = False
    
    # Check Redis session store connectivity
    if plexus_session_manager_instance and isinstance(plexus_session_manager_instance.store, RedisPlexusSessionStore):
        try:
            redis_client = await plexus_session_manager_instance.store._get_client() 
            await redis_client.ping()
            store_statuses["session_store_redis"] = "healthy"
        except Exception as e:
            store_statuses["session_store_redis"] = f"unhealthy: {e}"
            all_healthy = False
            
    return {
        "status": "healthy" if all_healthy else "degraded", 
        "storage_backend": settings.storage_backend, 
        "details": store_statuses
    }

# Mount all routers with appropriate prefixes and tags
app.include_router(plexus_auth_router, prefix="/{entity_id}/plexus-auth", tags=["Plexus User Authentication"])
app.include_router(plexus_internal_oauth_router, prefix="/{entity_id}/oauth", tags=["Plexus Internal OAuth 2.1"])
app.include_router(tenants_admin_router) 
app.include_router(external_oauth_providers_admin_router) 
app.include_router(user_services_router) 
app.mount(path="/", app=mcp_starlette_router)

logger.info(f"{settings.app_name} initialized. Storage: {settings.storage_backend}. Routers mounted.")