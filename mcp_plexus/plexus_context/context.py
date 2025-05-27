# mcp_plexus/plexus_context/context.py
import logging
from typing import Optional, Any, List, Dict, TYPE_CHECKING
import httpx
import secrets
import json
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from fastmcp import FastMCP 
from fastmcp import Context as FastMCPContext
from ..sessions import SessionData
from fastmcp.server.dependencies import get_http_request 
from ..settings import settings
from ..utils.security import FernetEncryptor

# Imports for OAuth functionality
from ..oauth.errors import PlexusExternalAuthRequiredError 
from ..oauth.pkce import generate_pkce_code_verifier, generate_pkce_code_challenge
from ..services.sqlite_user_external_api_key_store import get_sqlite_user_external_api_key_store

if TYPE_CHECKING:
    from ..oauth.models import OAuthProviderSettings
    from ..oauth.storage_interfaces import AbstractUserExternalTokenStore 
    from ..sessions import PlexusSessionManager

logger = logging.getLogger(__name__)


class PlexusContext(FastMCPContext):
    """
    Extended context class that provides session management and OAuth integration
    for the Plexus MCP server. Handles entity identification, persistent user IDs,
    session data caching, and external API authentication.
    """
    _plexus_session_data_cache: Optional['SessionData'] = None 

    def __init__(self, fastmcp_server_instance: FastMCP): 
        super().__init__(fastmcp_server_instance) 
        logger.debug(f"PlexusContext INSTANCE {id(self)}: Initialized.")

    @property
    def entity_id(self) -> Optional[str]:
        """
        Retrieves the entity ID from request scope state or cached session data.
        Entity ID identifies the specific Plexus deployment/tenant.
        """
        logger.debug(f"PlexusContext PID({id(self)}): Accessing entity_id property.")
        
        # Try to get entity_id from request scope first
        try:
            current_starlette_request = get_http_request()
            if current_starlette_request:
                scope_state = current_starlette_request.scope.get("state", {})
                if isinstance(scope_state, dict):
                    eid_from_scope_val = scope_state.get("entity_id")
                    if isinstance(eid_from_scope_val, str) and eid_from_scope_val:
                        logger.debug(f"PlexusContext PID({id(self)}): entity_id found in request scope: '{eid_from_scope_val}'")
                        return eid_from_scope_val
        except RuntimeError as e_rt:
            logger.warning(f"PlexusContext PID({id(self)}): RuntimeError accessing request scope: {e_rt}")
        except Exception as e_scope_eid:
            logger.warning(f"PlexusContext PID({id(self)}): Exception accessing request scope for entity_id: {e_scope_eid}", exc_info=False)

        # Fallback to cached session data
        if (self._plexus_session_data_cache and 
            isinstance(getattr(self._plexus_session_data_cache, 'entity_id', None), str)):
            cached_eid = self._plexus_session_data_cache.entity_id
            if cached_eid: 
                logger.debug(f"PlexusContext PID({id(self)}): entity_id found in cache: '{cached_eid}'")
                return cached_eid

        logger.debug(f"PlexusContext PID({id(self)}): Could not determine entity ID. Returning None.")
        return None

    @property
    def persistent_user_id(self) -> Optional[str]:
        """
        Retrieves the persistent user ID that remains constant across sessions.
        Used for linking user data across different MCP sessions.
        """
        logger.debug(f"PlexusContext PID({id(self)}): Accessing persistent_user_id property.")
        
        # Try to get from request scope first
        try:
            current_starlette_request = get_http_request()
            if current_starlette_request:
                state_obj = current_starlette_request.scope.get("state", {})
                if isinstance(state_obj, dict):
                    pid_from_scope = state_obj.get('derived_persistent_user_id')
                    if pid_from_scope:
                        logger.debug(f"PlexusContext.persistent_user_id: Using derived persistent user ID from scope: {pid_from_scope}")
                        return pid_from_scope
        except RuntimeError:
            logger.debug("PlexusContext.persistent_user_id: Not in HTTP request context, cannot check scope state.")
        except Exception as e_scope_pid:
            logger.warning(f"PlexusContext.persistent_user_id: Error accessing request scope: {e_scope_pid}", exc_info=False)

        # Fallback to cached session data
        if (self._plexus_session_data_cache and 
            hasattr(self._plexus_session_data_cache, 'persistent_user_id') and 
            self._plexus_session_data_cache.persistent_user_id):
            logger.debug(f"PlexusContext.persistent_user_id: Using cached persistent user ID: {self._plexus_session_data_cache.persistent_user_id}")
            return self._plexus_session_data_cache.persistent_user_id
        
        logger.debug("PlexusContext.persistent_user_id: Not found in scope or cache.")
        return None

    @property
    def mcp_session_id(self) -> Optional[str]:
        """
        Retrieves the MCP session ID from request scope or cached session data.
        This ID identifies the current MCP communication session.
        """
        logger.debug(f"PlexusContext SID({id(self)}): Accessing mcp_session_id property.")
        
        # Try to get from request scope first
        try:
            current_starlette_request = get_http_request()
            if current_starlette_request:
                scope_state = current_starlette_request.scope.get("state", {})
                if isinstance(scope_state, dict):
                    sid_from_scope_val = scope_state.get("mcp_session_id")
                    if isinstance(sid_from_scope_val, str) and sid_from_scope_val:
                        logger.debug(f"PlexusContext SID({id(self)}): mcp_session_id found in request scope: '{sid_from_scope_val}'")
                        return sid_from_scope_val
        except RuntimeError as e_rt:
            logger.warning(f"PlexusContext SID({id(self)}): RuntimeError accessing request scope: {e_rt}")
        except Exception as e_scope_sid:
            logger.warning(f"PlexusContext SID({id(self)}): Exception accessing request scope: {e_scope_sid}", exc_info=False)

        # Fallback to cached session data
        if (self._plexus_session_data_cache and 
            isinstance(getattr(self._plexus_session_data_cache, 'mcp_session_id', None), str)):
            cached_sid = self._plexus_session_data_cache.mcp_session_id
            if cached_sid:  
                logger.debug(f"PlexusContext SID({id(self)}): mcp_session_id found in cache: '{cached_sid}'")
                return cached_sid

        logger.debug(f"PlexusContext SID({id(self)}): Could not determine session ID. Returning None.")
        return None

    async def _ensure_session_data_loaded(self) -> 'SessionData':
        """
        Ensures session data is loaded from the session manager and cached.
        Always fetches fresh data from the manager to ensure consistency.
        """
        from mcp_plexus.main import plexus_session_manager_instance 

        current_mcp_sid = self.mcp_session_id 
        current_entity_id = self.entity_id
        
        # Get persistent user ID from scope if available
        pid_from_scope_for_ensure: Optional[str] = None
        try:
            current_starlette_request_for_ensure = get_http_request()
            if (current_starlette_request_for_ensure and 
                isinstance(current_starlette_request_for_ensure.scope.get("state"), dict)):
                pid_from_scope_for_ensure = current_starlette_request_for_ensure.scope["state"].get('derived_persistent_user_id')
        except Exception: 
            pass

        if not current_entity_id:
            logger.error(f"CONTEXT (_ensure_session_data_loaded): entity_id is missing. Cannot load session.")
            raise RuntimeError("Cannot load session data: entity_id is missing in context.")
        
        if not plexus_session_manager_instance:
            logger.error(f"CONTEXT (_ensure_session_data_loaded): PlexusSessionManager not available.")
            raise RuntimeError("PlexusSessionManager not available for loading session data.")

        logger.debug(f"CONTEXT (_ensure_session_data_loaded): Fetching session from manager for Entity: '{current_entity_id}', McpSessID: '{current_mcp_sid}'")
        
        session_data_obj, _ = await plexus_session_manager_instance.get_session(
            current_entity_id, 
            current_mcp_sid 
        )
        
        # Align persistent user ID if it differs from scope
        if (pid_from_scope_for_ensure and 
            session_data_obj.persistent_user_id != pid_from_scope_for_ensure):
            logger.info(f"CONTEXT: Aligning session PID to scope-derived PID: {pid_from_scope_for_ensure}")
            session_data_obj.persistent_user_id = pid_from_scope_for_ensure
            session_data_obj.touch() 
            
        self._plexus_session_data_cache = session_data_obj

        logger.info(f"CONTEXT: Session data loaded - McpSessID: {getattr(self._plexus_session_data_cache, 'mcp_session_id', 'N/A')}")
        return self._plexus_session_data_cache

    @property
    async def plexus_session_data(self) -> 'SessionData':
        """Property to access the current session data, loading it if necessary."""
        return await self._ensure_session_data_loaded()

    async def get_external_oauth_provider_settings(self, provider_name: str) -> Optional['OAuthProviderSettings']:
        """
        Retrieves OAuth provider configuration for the given provider and current entity.
        """
        from mcp_plexus.main import external_oauth_provider_config_store_instance 
        current_entity_id = self.entity_id 
        if not current_entity_id or not external_oauth_provider_config_store_instance: 
            return None
        return await external_oauth_provider_config_store_instance.load_provider_config(
            entity_id=current_entity_id, 
            provider_name=provider_name
        )

    async def _attempt_token_refresh(
        self, 
        entity_id: str, 
        persistent_user_id: Optional[str], 
        provider_name: str,
        provider_settings: 'OAuthProviderSettings', 
        token_info: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Attempts to refresh an expired OAuth token using the refresh token.
        Returns the new token data if successful, None otherwise.
        """
        from mcp_plexus.main import user_external_token_store_instance, plexus_session_manager_instance
        
        logger.info(f"CONTEXT: Attempting token refresh for entity {entity_id}, provider {provider_name}")
        refresh_token = token_info.get("refresh_token")
        if not refresh_token or not isinstance(refresh_token, str):
            logger.warning(f"CONTEXT: No refresh token for provider {provider_name}. Cannot refresh.")
            return None

        async with httpx.AsyncClient(timeout=20.0) as http_client:
            try:
                refresh_payload = {
                    "grant_type": "refresh_token", 
                    "refresh_token": refresh_token,
                    "client_id": provider_settings.client_id, 
                    "client_secret": provider_settings.client_secret,
                }
                response = await http_client.post(str(provider_settings.token_url), data=refresh_payload)
                response.raise_for_status()
                new_token_data_raw = response.json()
                logger.info(f"CONTEXT: Token refresh successful for provider {provider_name}")

                # Parse the new token data
                access_token = new_token_data_raw.get("access_token")
                new_rt = new_token_data_raw.get("refresh_token", refresh_token)
                exp_in_str = new_token_data_raw.get("expires_in")
                scopes_str = new_token_data_raw.get("scope", " ".join(token_info.get("scopes",[])))
                
                # Calculate expiration time
                exp_at_dt = None
                if exp_in_str and exp_in_str.isdigit():
                    exp_at_dt = datetime.now(timezone.utc) + timedelta(seconds=int(exp_in_str))
                
                # Parse scopes
                parsed_scopes = list(set(s.strip() for s in scopes_str.replace(',', ' ').split(' ') if s.strip()))

                updated_bundle = {
                    "access_token": access_token, 
                    "refresh_token": new_rt,
                    "expires_at": exp_at_dt.isoformat() if exp_at_dt else None,
                    "scopes": parsed_scopes, 
                    "obtained_at": datetime.now(timezone.utc).isoformat()
                }
                
                # Update session data
                session_data = await self.plexus_session_data 
                if session_data.oauth_tokens is None: 
                    session_data.oauth_tokens = {} 
                session_data.oauth_tokens[provider_name] = updated_bundle.copy()
                session_data.touch()
                
                if plexus_session_manager_instance: 
                    await plexus_session_manager_instance.save_session(session_data)
                
                # Update persistent store if available
                if persistent_user_id and user_external_token_store_instance:
                    await user_external_token_store_instance.save_user_external_token(
                        entity_id, persistent_user_id, provider_name, updated_bundle
                    )
                return updated_bundle
            except Exception as e:
                logger.error(f"CONTEXT: Token refresh failed for provider {provider_name}: {e}", exc_info=True)
                return None

    async def get_api_key(self, provider_name: str) -> Optional[str]:
        """
        Retrieves and decrypts a stored API key for the given provider.
        Returns None if no key is found or decryption fails.
        """
        current_entity_id = self.entity_id
        current_persistent_user_id = self.persistent_user_id
        
        logger.info(f"API_KEY: Retrieving for entity {current_entity_id}, user {current_persistent_user_id}, provider {provider_name}")

        if not current_entity_id or not current_persistent_user_id:
            logger.warning(f"API_KEY: Missing entity_id or persistent_user_id for provider {provider_name}")
            return None

        # Get the API key store and encryptor
        api_key_store = await get_sqlite_user_external_api_key_store()
        encryptor = FernetEncryptor(settings.plexus_encryption_key)

        if not encryptor.key_valid:
            logger.error(f"API_KEY: Encryption key not valid. Cannot decrypt API key for provider {provider_name}")
            return None

        # Load and decrypt the API key
        stored_data = await api_key_store.load_api_key_data(current_entity_id, current_persistent_user_id, provider_name)
        
        if stored_data and stored_data.encrypted_api_key_value:
            logger.info(f"API_KEY: Found encrypted key for provider {provider_name}, attempting decryption")
            decrypted_key = encryptor.decrypt(stored_data.encrypted_api_key_value)
            if decrypted_key:
                logger.info(f"API_KEY: Successfully decrypted key for provider {provider_name}")
                return decrypted_key
            else:
                logger.error(f"API_KEY: Failed to decrypt key for provider {provider_name}")
                return None
        else:
            logger.info(f"API_KEY: No stored key found for provider {provider_name}")
        return None
        
    async def get_authenticated_external_client(
        self, 
        provider_name: str, 
        required_scopes: Optional[List[str]] = None
    ) -> httpx.AsyncClient:
        """
        Returns an authenticated HTTP client for the specified OAuth provider.
        Handles token validation, refresh, and initiates OAuth flow if needed.
        
        Raises PlexusExternalAuthRequiredError if OAuth authorization is needed.
        """
        from mcp_plexus.main import user_external_token_store_instance, plexus_session_manager_instance 
        
        current_entity_id_for_fetch = self.entity_id
        current_mcp_sid_for_fetch = self.mcp_session_id 

        if not current_entity_id_for_fetch:
            raise RuntimeError("Context error: entity_id missing, cannot fetch session for auth client.")
        
        if not plexus_session_manager_instance:
            raise RuntimeError("PlexusSessionManager not available for fetching session data.")

        # Always fetch fresh session data to ensure consistency
        logger.info(f"CONTEXT.get_auth_client: Fetching latest session data for entity {current_entity_id_for_fetch}")
        
        session_data_from_manager, _ = await plexus_session_manager_instance.get_session(
            current_entity_id_for_fetch, 
            current_mcp_sid_for_fetch 
        )
        
        self._plexus_session_data_cache = session_data_from_manager

        current_entity_id = session_data_from_manager.entity_id 
        current_mcp_session_id = session_data_from_manager.mcp_session_id 
        current_persistent_user_id = session_data_from_manager.persistent_user_id

        if not current_entity_id:
            raise RuntimeError("Context error: entity_id missing in fetched session data.")
        
        provider_settings = await self.get_external_oauth_provider_settings(provider_name)
        if not provider_settings:
            raise RuntimeError(f"Configuration for OAuth provider '{provider_name}' not found.")

        starlette_request = get_http_request()
        if not starlette_request:
            raise RuntimeError("Starlette request unavailable.")

        # Try to find existing token
        token_info: Optional[Dict[str, Any]] = None
        token_source: Optional[str] = None
        
        # Check persistent store first
        if current_persistent_user_id and user_external_token_store_instance:
            logger.info(f"CONTEXT: Checking persistent store for token - user {current_persistent_user_id}, provider {provider_name}")
            token_info = await user_external_token_store_instance.load_user_external_token(
                entity_id=current_entity_id, 
                user_id=current_persistent_user_id, 
                provider_name=provider_name
            )
            if token_info: 
                token_source = "persistent_user_store"
                logger.info(f"CONTEXT: Token found in persistent store for provider {provider_name}")
        
        # Check session data if not found in persistent store
        if not token_info: 
            if session_data_from_manager.oauth_tokens is None: 
                session_data_from_manager.oauth_tokens = {}  
            token_info = session_data_from_manager.oauth_tokens.get(provider_name) 
            if token_info: 
                token_source = "session_data" 
                logger.info(f"CONTEXT: Token found in session data for provider {provider_name}")

        # Validate and use existing token if available
        if token_info and isinstance(token_info.get("access_token"), str):
            access_token_value = token_info["access_token"] 
            logger.info(f"CONTEXT: Validating existing token for provider {provider_name}")
            
            # Check token expiration
            expires_at_str = token_info.get("expires_at")
            scopes_any = token_info.get("scopes", [])
            
            # Parse granted scopes
            granted_scopes_from_token = []
            if isinstance(scopes_any, list):
                granted_scopes_from_token = [str(s).strip() for s in scopes_any if str(s).strip()]
            elif isinstance(scopes_any, str):
                granted_scopes_from_token = [s.strip() for s in scopes_any.replace(',', ' ').split(' ') if s.strip()]
            scopes_set = set(granted_scopes_from_token)

            # Check if token is expired
            is_expired = True 
            if expires_at_str:
                try: 
                    expires_dt = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
                    is_expired = expires_dt <= datetime.now(timezone.utc) - timedelta(seconds=10) 
                    logger.info(f"CONTEXT: Token expiry check - expires at {expires_dt}, is_expired: {is_expired}")
                except Exception as e_exp_parse:
                    logger.warning(f"CONTEXT: Error parsing expires_at '{expires_at_str}': {e_exp_parse}")
                    is_expired = True 
            elif provider_name == "github" and access_token_value.startswith("gho_"): 
                # GitHub Personal Access Tokens don't typically expire
                logger.info(f"CONTEXT: Assuming GitHub PAT-like token is non-expiring")
                is_expired = False 
            else:
                logger.info(f"CONTEXT: No expiry info for provider {provider_name}, assuming expired")

            # Check if token has required scopes
            req_scopes_set = set(s.strip() for s in (required_scopes or []) if s.strip())
            scopes_ok = req_scopes_set.issubset(scopes_set)
            logger.info(f"CONTEXT: Scope check - required: {req_scopes_set}, granted: {scopes_set}, ok: {scopes_ok}")

            # Use token if valid and has required scopes
            if not is_expired and scopes_ok:
                # Sync token from persistent store to session if needed
                if (token_source == "persistent_user_store" and 
                    (session_data_from_manager.oauth_tokens is None or 
                     session_data_from_manager.oauth_tokens.get(provider_name) != token_info)):
                    logger.info(f"CONTEXT: Syncing token from persistent store to session for provider {provider_name}")
                    if session_data_from_manager.oauth_tokens is None:
                        session_data_from_manager.oauth_tokens = {}
                    session_data_from_manager.oauth_tokens[provider_name] = token_info.copy()
                    session_data_from_manager.touch() 
                    if plexus_session_manager_instance:
                        await plexus_session_manager_instance.save_session(session_data_from_manager) 
                        
                logger.info(f"CONTEXT: Using valid token for provider {provider_name}")
                return httpx.AsyncClient(headers={"Authorization": f"Bearer {access_token_value}"})
            
            # Try to refresh expired token
            if is_expired and scopes_ok and token_info.get("refresh_token"):
                logger.info(f"CONTEXT: Token expired for provider {provider_name}, attempting refresh")
                refreshed_token_bundle = await self._attempt_token_refresh(
                    current_entity_id, 
                    current_persistent_user_id, 
                    provider_name, 
                    provider_settings, 
                    token_info
                )
                if refreshed_token_bundle and refreshed_token_bundle.get("access_token"):
                    logger.info(f"CONTEXT: Token refresh successful for provider {provider_name}")
                    return httpx.AsyncClient(headers={"Authorization": f"Bearer {refreshed_token_bundle['access_token']}"})
                else:
                    logger.warning(f"CONTEXT: Token refresh failed for provider {provider_name}")
        
        # Initiate OAuth flow if no valid token is available
        logger.info(f"CONTEXT: Initiating OAuth flow for provider {provider_name}")
        pkce_v = generate_pkce_code_verifier()
        pkce_c = generate_pkce_code_challenge(pkce_v)

        current_mcp_session_id_for_state = current_mcp_session_id
        if not current_mcp_session_id_for_state:
            raise RuntimeError("Cannot initiate OAuth flow: MCP Session ID is missing in context.")

        # Generate CSRF token and state parameter
        csrf = secrets.token_urlsafe(16)
        state_param = f"{csrf}--{current_mcp_session_id_for_state}"
        csrf_key = f"ext_oauth_csrf_{provider_name}_{current_entity_id}"
        pkce_key = f"ext_oauth_pkce_verifier_{provider_name}_{current_entity_id}"
        
        # Store CSRF and PKCE verifier in session
        if session_data_from_manager.plexus_internal_data is None:
            session_data_from_manager.plexus_internal_data = {}
        session_data_from_manager.plexus_internal_data.update({
            csrf_key: csrf, 
            pkce_key: pkce_v
        })
        session_data_from_manager.touch()

        if plexus_session_manager_instance: 
            await plexus_session_manager_instance.save_session(session_data_from_manager)
            
            # Mark auth error as handled in request scope
            request_scope_state = starlette_request.scope.get("state")
            if isinstance(request_scope_state, dict):
                request_scope_state["plexus_auth_error_handled"] = True 
        
        # Build OAuth authorization URL
        base_url_for_cb = str(starlette_request.base_url).rstrip('/')
        cb_uri = f"{base_url_for_cb}/{current_entity_id}/oauth/external_callback/{provider_name}"
        
        auth_scopes_str = " ".join(list(set(required_scopes or provider_settings.default_scopes or [])))
        params = {
            "response_type": "code", 
            "client_id": provider_settings.client_id, 
            "redirect_uri": cb_uri, 
            "scope": auth_scopes_str, 
            "state": state_param, 
            "code_challenge": pkce_c, 
            "code_challenge_method": "S256"
        }
        auth_url = f"{provider_settings.authorization_url}?{urlencode(params)}"
        
        logger.info(f"CONTEXT: Raising auth required error for provider {provider_name}")
        raise PlexusExternalAuthRequiredError(authorization_url=auth_url, provider_name=provider_name)
    
    async def get_session_value(self, key: str, default: Optional[Any] = None) -> Optional[Any]:
        """Retrieves a value from the session's internal data store."""
        sd = await self.plexus_session_data
        return sd.plexus_internal_data.get(key, default) if sd.plexus_internal_data else default

    async def set_session_value(self, key: str, value: Any) -> None:
        """Sets a value in the session's internal data store and saves the session."""
        sd = await self.plexus_session_data
        if sd.plexus_internal_data is None:
            sd.plexus_internal_data = {}
        sd.plexus_internal_data[key] = value
        sd.touch()
        
        from mcp_plexus.main import plexus_session_manager_instance 
        if plexus_session_manager_instance:
            await plexus_session_manager_instance.save_session(sd)
            logger.info(f"CONTEXT: Session saved after setting key '{key}' for session {sd.mcp_session_id}")
        else:
            logger.error(f"CONTEXT: PlexusSessionManager not available for saving session after setting key '{key}'")