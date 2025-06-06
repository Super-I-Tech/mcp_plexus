# mcp_plexus/oauth/endpoints.py
from fastapi import APIRouter, Depends, Request, Response, Form, HTTPException, Path, Query
from fastapi.responses import RedirectResponse, HTMLResponse
from typing import Annotated, Optional, Dict, Any, List, Union, TYPE_CHECKING
import logging
import httpx 
import json
from urllib.parse import urlencode, parse_qs
import secrets
from datetime import datetime, timezone, timedelta
from pydantic import ValidationError as PydanticValidationError

from ..sessions import SessionData 

from .provider import PlexusOAuthProvider
from .models import AuthRequest, TokenRequest, TokenResponse, WellKnownOAuthMetadata, OAuthProviderSettings
from .errors import OAuthError, InvalidRequestError, InvalidClientError, ServerError, InvalidGrantError
from .storage import (
    get_oauth_token_store,
    get_auth_code_store,
    get_external_oauth_provider_config_store,
    get_internal_oauth_client_store 
)
from .storage_interfaces import (
    AbstractExternalOAuthProviderConfigStore, 
    AbstractUserExternalTokenStore,
    AbstractOAuthClientStore 
)
from .user_token_store import get_user_external_token_store 

if TYPE_CHECKING:
    from .storage_interfaces import AbstractUserExternalTokenStore
    from ..sessions import PlexusSessionManager 
    from .storage_interfaces import AbstractUserExternalTokenStore 

logger = logging.getLogger(__name__)
oauth_router = APIRouter()

# --- Dependency Functions ---

async def get_entity_id(request: Request) -> str:
    """Extract entity_id from path parameters with error handling."""
    entity_id = request.path_params.get("entity_id")
    if not entity_id:
        logger.error("CRITICAL: entity_id not found for get_entity_id dependency.")
        raise HTTPException(status_code=500, detail="Server configuration error: entity_id missing.")
    return entity_id

async def get_plexus_session_manager_dependency() -> 'PlexusSessionManager':
    """Get the global PlexusSessionManager instance."""
    from mcp_plexus.main import plexus_session_manager_instance 
    if plexus_session_manager_instance is None:
        logger.error("CRITICAL: PlexusSessionManager not initialized globally in main.py.")
        raise HTTPException(status_code=503, detail="Session manager service unavailable.")
    return plexus_session_manager_instance

async def get_httpx_async_client() -> httpx.AsyncClient:
    """Create a configured HTTP client for external API calls."""
    return httpx.AsyncClient(timeout=30.0)

async def get_oauth_provider() -> PlexusOAuthProvider:
    """Create a configured OAuth provider with necessary stores."""
    token_store = await get_oauth_token_store() 
    auth_code_store = await get_auth_code_store() 
    client_store = await get_internal_oauth_client_store() 
    return PlexusOAuthProvider(
        token_store=token_store, 
        auth_code_store=auth_code_store,
        client_store=client_store 
    )

async def get_current_user_for_auth(request: Request) -> Dict[str, str]:
    """
    Authenticate the current user for OAuth authorization.
    Returns user info including entity_id and user_id from session data.
    """
    from mcp_plexus.main import plexus_session_manager_instance 

    entity_id_from_path = request.path_params.get("entity_id")
    if not entity_id_from_path:
        logger.error("CRITICAL: entity_id not found in path for get_current_user_for_auth.")
        raise HTTPException(status_code=500, detail="Server configuration error: entity_id missing.")

    if not plexus_session_manager_instance:
        logger.error("CRITICAL: PlexusSessionManager not available in get_current_user_for_auth.")
        raise HTTPException(status_code=503, detail="Session manager service unavailable.")

    # Try to get MCP session ID from request scope first, then from headers
    mcp_session_id_from_scope = request.scope.get("state", {}).get("mcp_session_id")
    
    mcp_session_id_from_header: Optional[str] = None
    for k, v_bytes in request.scope.get("headers", []):
        if k.lower() == b"mcp-session-id":
            mcp_session_id_from_header = v_bytes.decode("utf-8", errors="ignore")
            break
    
    current_mcp_session_id = mcp_session_id_from_scope or mcp_session_id_from_header

    if not current_mcp_session_id:
        logger.warning(f"OAuth Authorize Endpoint: No Mcp-Session-Id found for entity '{entity_id_from_path}'. Cannot identify user.")
        raise HTTPException(status_code=400, detail="MCP session ID is required for internal OAuth authorization.")

    session_data: Optional[SessionData] = None
    try:
        # Check if session data is already in request scope to avoid redundant lookups
        session_data_from_scope_obj = request.scope.get("state", {}).get("plexus_session_data")

        if (isinstance(session_data_from_scope_obj, SessionData) and 
            hasattr(session_data_from_scope_obj, 'mcp_session_id') and 
            session_data_from_scope_obj.mcp_session_id == current_mcp_session_id):
            session_data = session_data_from_scope_obj
        else:
            # Fetch session data from session manager
            session_data, is_new = await plexus_session_manager_instance.get_session(
                entity_id_from_path, 
                current_mcp_session_id
            )

    except Exception as e:
        logger.error(
            f"OAuth Authorize Endpoint: Error loading session for E:'{entity_id_from_path}', "
            f"McpSessID:'{current_mcp_session_id}': {e}", 
            exc_info=True
        )
        raise HTTPException(status_code=503, detail="Error accessing session information.")

    if not session_data: 
        logger.error(
            f"OAuth Authorize Endpoint: SessionData object is STILL None after get_session for "
            f"E:'{entity_id_from_path}', McpSessID:'{current_mcp_session_id}'. THIS IS UNEXPECTED."
        )
        raise HTTPException(status_code=500, detail="Internal error: Session data unavailable.")

    # Require an authenticated user (not guest) for OAuth authorization
    if session_data.persistent_user_id:
        logger.info(
            f"OAuth Authorize Endpoint: Authenticated Plexus user '{session_data.persistent_user_id}' "
            f"via session for E:'{entity_id_from_path}'. ALLOWING."
        )
        return {"entity_id": entity_id_from_path, "user_id": session_data.persistent_user_id}
    else:
        logger.warning(
            f"OAuth Authorize Endpoint: No persistent_user_id in session for E:'{entity_id_from_path}', "
            f"McpSessID:'{session_data.mcp_session_id}'. DENYING internal OAuth (403)."
        )
        raise HTTPException(
            status_code=403, 
            detail="Internal OAuth requires an authenticated Plexus user. Guest access not permitted for this authorization flow."
        )

# --- Internal Helper for Authorization Logic ---

async def _process_authorization_request(
    request_obj: Request,
    auth_provider: PlexusOAuthProvider,
    current_user: Dict[str, str],
    response_type_param: Optional[str], 
    client_id_param: Optional[str],     
    redirect_uri_param: Optional[str],  
    scope_param: Optional[str],         
    state_param: Optional[str],         
    code_challenge_param: Optional[str],
    code_challenge_method_param: Optional[str] 
) -> Union[RedirectResponse, HTMLResponse]:
    """
    Process OAuth authorization request for both GET and POST methods.
    Handles validation, client trust verification, and auto-approval for trusted clients.
    """
    logger.info(
        f"Processing authorization for entity '{current_user['entity_id']}'. "
        f"Client: '{client_id_param}', Method: {request_obj.method}"
    )

    # Build parameters dictionary for validation
    auth_params_dict_for_model = {
        "response_type": response_type_param, 
        "client_id": client_id_param, 
        "redirect_uri": redirect_uri_param, 
        "scope": scope_param, 
        "state": state_param,
        "code_challenge": code_challenge_param, 
        "code_challenge_method": code_challenge_method_param,
    }
    auth_params_dict_for_model = {k: v for k, v in auth_params_dict_for_model.items() if v is not None}

    # Validate authorization request parameters
    auth_request_model: Optional[AuthRequest] = None
    try:
        auth_request_model = AuthRequest(**auth_params_dict_for_model)
    except PydanticValidationError as pydantic_exc:
        logger.warning(f"Invalid AuthRequest construction: {pydantic_exc.errors()}")
        error_desc_str = "; ".join([
            f"{e['loc'][0] if e['loc'] else 'param'}: {e['msg']}" 
            for e in pydantic_exc.errors()
        ])
        return HTMLResponse(
            f"<h1>Invalid Request</h1><p>Invalid authorization request parameters: {error_desc_str}</p>", 
            status_code=400
        )

    try:
        # Validate authorization parameters and get client info
        client, granted_scopes = await auth_provider.validate_authorization_parameters(
            auth_request=auth_request_model, 
            entity_id=current_user['entity_id']
        )
        
        # Auto-approve trusted internal clients, require explicit consent for others
        if client.is_trusted_internal:
            logger.info(
                f"Client '{client.client_id}' is trusted internal. "
                f"Auto-approving consent for scopes: {granted_scopes}."
            )
            
            redirect_target_uri_str, _ = await auth_provider.generate_auth_code_and_build_redirect(
                auth_request_model=auth_request_model,
                client=client,
                user_id=current_user["user_id"],
                entity_id=current_user["entity_id"],
                granted_scopes=granted_scopes
            )
            logger.info(f"Auto-approved. Redirecting to: {redirect_target_uri_str}")
            return RedirectResponse(url=str(redirect_target_uri_str), status_code=302)
        else:
            logger.warning(
                f"Client '{client.client_id}' is not a trusted internal client. "
                f"Denying authorization as user-facing consent is not implemented in this flow."
            )
            error_redirect = auth_provider._build_error_redirect_uri(
                str(auth_request_model.redirect_uri), 
                error="unauthorized_client", 
                error_description="This client requires explicit user consent which is not supported in this automated flow.", 
                state=auth_request_model.state
            )
            return RedirectResponse(url=str(error_redirect), status_code=302)

    except OAuthError as e: 
        logger.error(
            f"OAuthError during _process_authorization_request for client '{client_id_param}': "
            f"{e.detail if hasattr(e, 'detail') else str(e)}"
        )
        if auth_request_model and auth_request_model.redirect_uri:
            final_error_redirect = auth_provider._build_error_redirect_uri(
                str(auth_request_model.redirect_uri), 
                error=e.error, 
                error_description=e.error_description, 
                state=auth_request_model.state
            )
            return RedirectResponse(url=str(final_error_redirect), status_code=302)
        return HTMLResponse(
            f"<h1>Authorization Error</h1><p>{e.error_description or e.error}</p>", 
            status_code=e.status_code
        )
    except Exception as e_unhandled:
        logger.error(
            f"Unexpected error in _process_authorization_request for client '{client_id_param}': {e_unhandled}", 
            exc_info=True
        )
        return HTMLResponse(
            "<h1>Server Error</h1><p>An unexpected error occurred during authorization.</p>", 
            status_code=500
        )

@oauth_router.get("/authorize", name="oauth_authorize_get", response_class=RedirectResponse)
async def authorize_get(
    request: Request, 
    current_user: Annotated[Dict[str, str], Depends(get_current_user_for_auth)],
    oauth_provider: Annotated[PlexusOAuthProvider, Depends(get_oauth_provider)],
    response_type: Annotated[Optional[str], Query()] = None, 
    client_id: Annotated[Optional[str], Query()] = None,
    redirect_uri: Annotated[Optional[str], Query()] = None,
    scope: Annotated[Optional[str], Query()] = None,
    state: Annotated[Optional[str], Query()] = None,
    code_challenge: Annotated[Optional[str], Query()] = None,
    code_challenge_method: Annotated[Optional[str], Query()] = None
):
    """OAuth authorization endpoint for GET requests."""
    return await _process_authorization_request(
        request_obj=request, 
        auth_provider=oauth_provider,
        current_user=current_user,
        response_type_param=response_type,
        client_id_param=client_id,
        redirect_uri_param=redirect_uri,
        scope_param=scope,
        state_param=state,
        code_challenge_param=code_challenge,
        code_challenge_method_param=code_challenge_method
    )

@oauth_router.post("/authorize", name="oauth_authorize_post", response_class=RedirectResponse)
async def authorize_post(
    request: Request, 
    current_user: Annotated[Dict[str, str], Depends(get_current_user_for_auth)],
    oauth_provider: Annotated[PlexusOAuthProvider, Depends(get_oauth_provider)],
    response_type: Annotated[Optional[str], Form()] = None, 
    client_id: Annotated[Optional[str], Form()] = None,
    redirect_uri: Annotated[Optional[str], Form()] = None,
    scope: Annotated[Optional[str], Form()] = None,
    state: Annotated[Optional[str], Form()] = None,
    code_challenge: Annotated[Optional[str], Form()] = None,
    code_challenge_method: Annotated[Optional[str], Form()] = None
):
    """OAuth authorization endpoint for POST requests (form submissions)."""
    return await _process_authorization_request(
        request_obj=request,
        auth_provider=oauth_provider,
        current_user=current_user,
        response_type_param=response_type,
        client_id_param=client_id,
        redirect_uri_param=redirect_uri,
        scope_param=scope,
        state_param=state,
        code_challenge_param=code_challenge,
        code_challenge_method_param=code_challenge_method
    )

@oauth_router.post("/token", response_model=TokenResponse, name="oauth_token")
async def token(
    request: Request, 
    grant_type: Annotated[str, Form(...)], 
    entity_id_dep: Annotated[str, Depends(get_entity_id)], 
    oauth_provider: Annotated[PlexusOAuthProvider, Depends(get_oauth_provider)],
    code: Annotated[Optional[str], Form()] = None,
    redirect_uri: Annotated[Optional[str], Form()] = None,  
    client_id: Annotated[Optional[str], Form()] = None, 
    code_verifier: Annotated[Optional[str], Form()] = None,
    refresh_token: Annotated[Optional[str], Form()] = None,
):
    """OAuth token endpoint for exchanging authorization codes and refreshing tokens."""
    logger.info(
        f"Token endpoint called for entity '{entity_id_dep}'. "
        f"Grant type: '{grant_type}' Client ID: {client_id}"
    )
    
    # Validate token request parameters
    try:
        token_request_model = TokenRequest(
            grant_type=grant_type, 
            code=code, 
            redirect_uri=redirect_uri, 
            client_id=client_id,
            code_verifier=code_verifier, 
            refresh_token=refresh_token
        )
    except PydanticValidationError as e:
        logger.warning(f"Token request parameter validation failed: {e.errors()}")
        error_details = [
            f"Field '{str(err.get('loc', ['N/A'])[-1])}': {err.get('msg', 'Invalid')}" 
            for err in e.errors()
        ]
        raise InvalidRequestError(
            error_description=f"Invalid token request parameters: {'; '.join(error_details)}"
        )
    
    try:
        token_response_model = await oauth_provider.handle_token_request(
            token_request=token_request_model, 
            entity_id=entity_id_dep
        )
        return token_response_model 
    except OAuthError as e:  
        logger.error(f"Token endpoint OAuthError: {e.error} - {e.error_description}", exc_info=False)
        raise e 
    except Exception as e:
        logger.error(f"Unexpected error during /token: {e}", exc_info=True)
        raise ServerError(error_description="An unexpected error occurred while processing the token request.")

@oauth_router.get(
    "/.well-known/oauth-authorization-server",
    response_model=WellKnownOAuthMetadata, 
    name="oauth_metadata"
)
async def get_oauth_metadata(
    request: Request, 
    entity_id_dep: Annotated[str, Depends(get_entity_id)],
):
    """OAuth discovery endpoint providing server metadata."""
    base_url = str(request.base_url).rstrip('/') 
    
    try:
        issuer_url = f"{base_url}/{entity_id_dep}/oauth" 
        auth_endpoint_path = request.app.url_path_for("oauth_authorize_get", entity_id=entity_id_dep) 
        token_endpoint_path = request.app.url_path_for("oauth_token", entity_id=entity_id_dep)
    except Exception as e_url_path:
        logger.error(f"Error generating URL paths for .well-known metadata: {e_url_path}", exc_info=True)
        raise ServerError(error_description="Could not generate .well-known metadata URLs.")

    return WellKnownOAuthMetadata(
        issuer=issuer_url,
        authorization_endpoint=f"{base_url}{auth_endpoint_path}",
        token_endpoint=f"{base_url}{token_endpoint_path}",
        scopes_supported=["openid", "profile", "email", "mcp_tool:example_tool"], 
        response_types_supported=["code"], 
        grant_types_supported=["authorization_code", "refresh_token"],
        code_challenge_methods_supported=["S256"], 
        token_endpoint_auth_methods_supported=["none"] 
    )

@oauth_router.get("/external_callback/{provider_name}", name="oauth_external_callback", response_class=HTMLResponse)
async def external_oauth_callback(
    request: Request, 
    entity_id: Annotated[str, Path(...)], 
    provider_name: Annotated[str, Path(...)], 
    code: Annotated[str, Query(...)], 
    state: Annotated[str, Query(...)], 
    session_manager: Annotated['PlexusSessionManager', Depends(get_plexus_session_manager_dependency)],
    ext_oauth_config_store: Annotated[AbstractExternalOAuthProviderConfigStore, Depends(get_external_oauth_provider_config_store)],
    user_token_store: Annotated[AbstractUserExternalTokenStore, Depends(get_user_external_token_store)], 
    http_client: Annotated[httpx.AsyncClient, Depends(get_httpx_async_client)],
    error: Annotated[Optional[str], Query()] = None, 
    error_description: Annotated[Optional[str], Query()] = None 
):
    """
    Handle OAuth callback from external providers (GitHub, Google, etc.).
    Exchanges authorization code for access token and stores it in user session.
    """
    logger.info(
        f"External OAuth callback received for entity '{entity_id}', provider '{provider_name}'. "
        f"Code: {'SET' if code else 'NOT_SET'}, State: '{state}'"
    )
    
    # Handle OAuth errors from external provider
    if error:
        logger.error(f"Error from external provider '{provider_name}': {error} - {error_description}")
        return HTMLResponse(
            f"<h1>OAuth Error</h1><p>Provider: {provider_name}</p><p>Error: {error}</p><p>{error_description or ''}</p>", 
            status_code=400
        )

    # Parse composite state parameter (CSRF token + MCP session ID)
    try:
        csrf_token_from_provider, mcp_session_id_from_state = state.split('--', 1)
    except ValueError:
        logger.error(f"Invalid composite state received from provider '{provider_name}': '{state}'")
        return HTMLResponse("<h1>Error</h1><p>Invalid state parameter from provider.</p>", status_code=400)

    session_data: Optional[SessionData] = None
    try:
        # Retrieve session data using MCP session ID from state
        session_data, _ = await session_manager.get_session(entity_id, mcp_session_id_from_state)
        
        if not session_data:
            logger.error(
                f"No active MCP Plexus session found for mcp_session_id '{mcp_session_id_from_state}' "
                f"(from state) in entity '{entity_id}'. This is UNEXPECTED."
            )
            return HTMLResponse(
                "<h1>Error</h1><p>Your session could not be found or has expired. "
                "Please try initiating the OAuth flow again.</p>", 
                status_code=400
            )
        
        # Verify CSRF token to prevent cross-site request forgery
        stored_csrf_key = f"ext_oauth_csrf_{provider_name}_{entity_id}"
        stored_verifier_key = f"ext_oauth_pkce_verifier_{provider_name}_{entity_id}"

        if session_data.plexus_internal_data is None:
            logger.error(f"plexus_internal_data is None in session for CSRF check. McpSessID: {mcp_session_id_from_state}")
            return HTMLResponse("<h1>Error</h1><p>Session integrity issue. Please try again.</p>", status_code=500)

        stored_csrf_token = session_data.plexus_internal_data.get(stored_csrf_key)
        stored_pkce_verifier = session_data.plexus_internal_data.get(stored_verifier_key)

        if not stored_csrf_token or stored_csrf_token != csrf_token_from_provider:
            logger.error(
                f"CSRF token mismatch for provider '{provider_name}'. "
                f"Expected '{stored_csrf_token}', got '{csrf_token_from_provider}'. "
                f"Internal data: {session_data.plexus_internal_data}"
            )
            return HTMLResponse(
                "<h1>Error</h1><p>Invalid request (CSRF token mismatch). Please try again.</p>", 
                status_code=400
            )
        
        if not stored_pkce_verifier:
            logger.error(
                f"PKCE verifier not found in session for provider '{provider_name}'. "
                f"Internal data: {session_data.plexus_internal_data}"
            )
            return HTMLResponse(
                "<h1>Error</h1><p>Internal error processing your request (PKCE verifier missing). "
                "Please try again.</p>", 
                status_code=500
            )

        # Load provider configuration
        provider_settings = await ext_oauth_config_store.load_provider_config(entity_id, provider_name)
        if not provider_settings:
            logger.error(f"Configuration for external OAuth provider '{provider_name}' not found for entity '{entity_id}'.")
            return HTMLResponse(
                f"<h1>Error</h1><p>Internal server error: Provider '{provider_name}' not configured.</p>", 
                status_code=500
            )
        
        # Exchange authorization code for access token
        current_redirect_uri = str(request.url_for('oauth_external_callback', entity_id=entity_id, provider_name=provider_name)).rstrip('/')
        
        token_request_data = {
            "grant_type": "authorization_code", 
            "code": code, 
            "redirect_uri": current_redirect_uri, 
            "client_id": provider_settings.client_id, 
            "client_secret": provider_settings.client_secret, 
            "code_verifier": stored_pkce_verifier,
        }
        
        token_exchange_response = await http_client.post(
            str(provider_settings.token_url), 
            data=token_request_data, 
            headers={"Accept": "application/json"}
        )
        token_exchange_response.raise_for_status() 
        
        # Parse token response (supports both JSON and form-encoded responses)
        token_data_raw_text = token_exchange_response.text
        parsed_token_data: Dict[str, Any] = {}
        response_content_type = token_exchange_response.headers.get("content-type", "").lower()

        if "application/x-www-form-urlencoded" in response_content_type:
            parsed_qs_result = parse_qs(token_data_raw_text)
            for key_qs, value_list_qs in parsed_qs_result.items():
                if value_list_qs and len(value_list_qs) == 1: 
                    parsed_token_data[key_qs] = value_list_qs[0]
                elif value_list_qs: 
                    parsed_token_data[key_qs] = value_list_qs 
        elif "application/json" in response_content_type: 
            try: 
                parsed_token_data = token_exchange_response.json()
            except json.JSONDecodeError as jde: 
                logger.error(f"Failed to parse JSON from token response. Error: {jde}. Raw: {token_data_raw_text!r}")
                return HTMLResponse(
                    f"<h1>Error</h1><p>Failed to parse token response from {provider_name}.</p>", 
                    status_code=500
                )
        else: 
            # Fallback: try to parse as form-encoded
            try: 
                parsed_qs_result = parse_qs(token_data_raw_text)
                for k, v in parsed_qs_result.items(): 
                    parsed_token_data[k] = v[0] if len(v) == 1 else v
                if "access_token" not in parsed_token_data: 
                    raise ValueError("Fallback failed")
            except: 
                return HTMLResponse(
                    f"<h1>Error</h1><p>Unexpected response format from {provider_name}.</p>", 
                    status_code=500
                )

        # Extract token information
        access_token = parsed_token_data.get("access_token")
        refresh_token = parsed_token_data.get("refresh_token")
        expires_in_value = parsed_token_data.get("expires_in") # Get the value
        granted_scopes_str = parsed_token_data.get("scope") 

        expires_at_dt = None
        if expires_in_value is not None:
            try:
                # Try to convert to int, this handles both string and int cases gracefully.
                # If it's already an int, int() is a no-op. If it's a string "3600", it's converted.
                expires_in_seconds = int(expires_in_value) 
                expires_at_dt = datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds)
            except ValueError:
                logger.warning(f"Could not convert expires_in_value '{expires_in_value}' to an integer.")
                expires_at_dt = None # Or handle error appropriately
        granted_scopes_list = list(set(
            s.strip() for s in (granted_scopes_str or "").replace(',', ' ').split() if s.strip()
        ))

        if not access_token: 
            return HTMLResponse(
                f"<h1>Error</h1><p>Failed to retrieve access token from {provider_name}.</p>", 
                status_code=500
            )

        # Store token information in session and persistent storage
        user_token_bundle = {
            "access_token": access_token, 
            "refresh_token": refresh_token,
            "expires_at": expires_at_dt.isoformat() if expires_at_dt else None,
            "scopes": granted_scopes_list, 
            "obtained_at": datetime.now(timezone.utc).isoformat()
        }
        
        if session_data.oauth_tokens is None: 
            session_data.oauth_tokens = {} 
        session_data.oauth_tokens[provider_name] = user_token_bundle.copy()
        
        # Persist tokens for authenticated users
        if session_data.persistent_user_id:
            await user_token_store.save_user_external_token(
                entity_id, 
                session_data.persistent_user_id, 
                provider_name, 
                user_token_bundle
            )
        
        # Clean up temporary OAuth state data
        if session_data.plexus_internal_data:
            session_data.plexus_internal_data.pop(stored_csrf_key, None)
            session_data.plexus_internal_data.pop(stored_verifier_key, None)
        
        session_data.touch()
        await session_manager.save_session(session_data)
        
        return HTMLResponse(
            f"<h1>Authentication Successful!</h1><p>You have successfully authenticated with {provider_name}. "
            f"You can now close this window and return to your application.</p>"
        )

    except httpx.HTTPStatusError as e_http:
        logger.error(
            f"HTTP error during token exchange: {e_http.response.status_code} - {e_http.response.text!r}", 
            exc_info=True
        )
        return HTMLResponse(
            f"<h1>Error</h1><p>Failed to communicate with {provider_name}. Details: {e_http.response.text}</p>", 
            status_code=502
        ) 
    except Exception as e:
        logger.error(f"Unexpected error in external_oauth_callback: {e}", exc_info=True)
        return HTMLResponse("<h1>Error</h1><p>An unexpected error occurred.</p>", status_code=500)