# mcp_plexus/oauth/provider.py
import logging
import secrets
from typing import Optional, Tuple, Dict, Any, List
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlsplit, urlunsplit

from .models import (
    AuthRequest, TokenRequest, TokenResponse, AuthCodeData, 
    AccessTokenData, RefreshTokenData, OAuthClient
)
from .errors import (
    InvalidRequestError, InvalidClientError, InvalidGrantError, 
    UnsupportedGrantTypeError, ServerError, InvalidScopeError
)
from .pkce import generate_pkce_code_challenge, validate_pkce_code_verifier_format
from .storage_interfaces import (
    AbstractOAuthTokenStore, AbstractAuthCodeStore, AbstractOAuthClientStore
)

logger = logging.getLogger(__name__)

# OAuth token and code lifetime configuration
AUTH_CODE_LIFETIME_SECONDS = 600  # 10 minutes
ACCESS_TOKEN_LIFETIME_SECONDS = 3600  # 1 hour
REFRESH_TOKEN_LIFETIME_SECONDS = 3600 * 24 * 30  # 30 days
ISSUE_REFRESH_TOKENS = True


class PlexusOAuthProvider:
    """
    Core logic for the MCP Plexus embedded OAuth 2.1 Authorization Server.
    Handles authorization requests, token issuance, and token validation.
    """

    def __init__(self, 
                 token_store: AbstractOAuthTokenStore, 
                 auth_code_store: AbstractAuthCodeStore,
                 client_store: AbstractOAuthClientStore):
        self.token_store = token_store
        self.auth_code_store = auth_code_store
        self.client_store = client_store
        logger.info("PlexusOAuthProvider initialized with token, auth_code, and client stores.")

    async def _validate_client(self, client_id: str, redirect_uri_str: Optional[str] = None) -> OAuthClient:
        """
        Validates the client_id and optionally checks if the redirect_uri
        is registered for the client.
        
        Args:
            client_id: The OAuth client identifier
            redirect_uri_str: Optional redirect URI to validate against client's registered URIs
            
        Returns:
            OAuthClient: The validated client object
            
        Raises:
            InvalidClientError: If client_id is unknown
            InvalidRequestError: If redirect_uri is not registered for the client
        """
        logger.debug(f"Validating client_id: {client_id}, redirect_uri_str: {redirect_uri_str}")
        
        client = await self.client_store.load_client(client_id)
        if not client:
            logger.warning(f"Unknown client_id: {client_id}")
            raise InvalidClientError(f"Unknown client_id: {client_id}")

        if redirect_uri_str:
            # Validate redirect URI format and check against registered URIs
            validated_redirect_uri_str = str(AuthRequest.model_validate({
                "response_type": "code", 
                "client_id": client_id, 
                "redirect_uri": redirect_uri_str
            }).redirect_uri)
            
            is_valid_redirect = any(
                str(registered_uri_model) == validated_redirect_uri_str 
                for registered_uri_model in client.redirect_uris
            )
            
            if not is_valid_redirect:
                logger.warning(
                    f"Redirect URI '{redirect_uri_str}' not registered for client '{client_id}'. "
                    f"Registered: {[str(uri) for uri in client.redirect_uris]}"
                )
                raise InvalidRequestError("Invalid redirect_uri for the client.")

        return client

    async def _validate_scopes(self, requested_scopes_str: Optional[str], client: OAuthClient) -> List[str]:
        """
        Validates requested scopes against client's allowed scopes.
        
        Args:
            requested_scopes_str: Space-separated string of requested scopes
            client: The OAuth client to validate scopes against
            
        Returns:
            List[str]: List of granted scopes (subset of requested that are allowed)
            
        Raises:
            InvalidScopeError: If no requested scopes are permitted for the client
        """
        if not requested_scopes_str:
            return []
        
        # Remove duplicates and split into individual scopes
        requested_scopes = list(set(requested_scopes_str.split()))
        granted_scopes = [
            scope for scope in requested_scopes 
            if scope in client.allowed_scopes
        ]
        
        # Log any rejected scopes
        rejected_scopes = set(requested_scopes) - set(granted_scopes)
        for scope in rejected_scopes:
            logger.warning(
                f"Scope '{scope}' requested by client '{client.client_id}' "
                f"is not in its allowed_scopes: {client.allowed_scopes}."
            )
        
        if not granted_scopes and requested_scopes:
            logger.warning(
                f"Client '{client.client_id}' requested scopes '{requested_scopes_str}', "
                f"but none are in its allowed_scopes."
            )
            raise InvalidScopeError("None of the requested scopes are permitted for this client.")
        
        logger.debug(
            f"Requested scopes: {requested_scopes}, Granted scopes: {granted_scopes} "
            f"for client '{client.client_id}'."
        )
        return granted_scopes

    async def validate_authorization_parameters(
        self, 
        auth_request: AuthRequest, 
        entity_id: str
    ) -> Tuple[OAuthClient, List[str]]:
        """
        Validates the authorization request parameters including client, redirect URI, 
        scopes, and PKCE requirements.
        
        Args:
            auth_request: The authorization request to validate
            entity_id: Entity context for the request
            
        Returns:
            Tuple[OAuthClient, List[str]]: Validated client and granted scopes
            
        Raises:
            InvalidRequestError: For invalid request parameters or missing PKCE
            InvalidClientError: For unknown clients
            InvalidScopeError: For invalid scope requests
        """
        logger.info(
            f"Validating authorization parameters for client '{auth_request.client_id}' "
            f"in entity '{entity_id}'."
        )

        # OAuth 2.1 requires authorization code flow
        if auth_request.response_type != "code":
            logger.warning(f"Unsupported response_type: {auth_request.response_type}")
            raise InvalidRequestError(error_description="Response type must be 'code'.")

        client = await self._validate_client(auth_request.client_id, str(auth_request.redirect_uri))

        # OAuth 2.1 mandates PKCE for all clients
        if not auth_request.code_challenge or not auth_request.code_challenge_method:
            logger.warning("PKCE code_challenge or code_challenge_method missing.")
            raise InvalidRequestError(
                error_description="PKCE code_challenge and code_challenge_method are required."
            )
            
        if auth_request.code_challenge_method != "S256":
            logger.warning(
                f"Unsupported PKCE method: {auth_request.code_challenge_method}. "
                f"Only S256 is supported."
            )
            raise InvalidRequestError(
                error_description="PKCE code_challenge_method 'S256' is required."
            )

        granted_scopes = await self._validate_scopes(auth_request.scope, client)
        
        logger.info(
            f"Authorization parameters validated for client '{client.client_id}'. "
            f"Granted scopes: {granted_scopes}"
        )
        return client, granted_scopes

    async def generate_auth_code_and_build_redirect(
        self, 
        auth_request_model: AuthRequest, 
        client: OAuthClient,
        user_id: str, 
        entity_id: str, 
        granted_scopes: List[str]
    ) -> Tuple[str, Optional[str]]:
        """
        Generates an authorization code, stores it, and builds the redirect URI.
        
        Args:
            auth_request_model: Validated authorization request
            client: Validated OAuth client
            user_id: ID of the user authorizing the request
            entity_id: Entity context
            granted_scopes: List of approved scopes
            
        Returns:
            Tuple[str, Optional[str]]: Final redirect URI and state parameter
        """
        logger.info(
            f"Generating auth code for user '{user_id}', client '{client.client_id}', "
            f"entity '{entity_id}', scopes: {granted_scopes}."
        )

        # Generate cryptographically secure authorization code
        auth_code_str = secrets.token_urlsafe(32)
        code_expires_at = datetime.now(timezone.utc) + timedelta(seconds=AUTH_CODE_LIFETIME_SECONDS)
        
        auth_code_data_obj = AuthCodeData(
            code=auth_code_str,
            client_id=client.client_id,
            redirect_uri=auth_request_model.redirect_uri,
            requested_scopes=granted_scopes,
            user_id=user_id,
            entity_id=entity_id,
            code_challenge=auth_request_model.code_challenge,
            code_challenge_method=auth_request_model.code_challenge_method,
            expires_at=code_expires_at,
        )

        await self.auth_code_store.save_auth_code(auth_code_data_obj)
        logger.info(
            f"Authorization code '{auth_code_str}' generated and stored for "
            f"user '{user_id}', client '{client.client_id}'."
        )

        # Build redirect URI with authorization code
        redirect_params = {"code": auth_code_str}
        if auth_request_model.state:
            redirect_params["state"] = auth_request_model.state
        
        query_string = urlencode(redirect_params)
        final_redirect_uri_str = str(auth_request_model.redirect_uri)
        
        # Append parameters to existing query string or create new one
        separator = "&" if "?" in final_redirect_uri_str else "?"
        final_redirect_uri_str += separator + query_string
            
        return final_redirect_uri_str, auth_request_model.state

    def _build_error_redirect_uri(
        self, 
        redirect_uri_base_str: str, 
        error: str, 
        error_description: Optional[str] = None, 
        state: Optional[str] = None
    ) -> str:
        """
        Builds a redirect URI for OAuth error responses.
        
        Args:
            redirect_uri_base_str: Base redirect URI
            error: OAuth error code
            error_description: Optional error description
            state: State parameter to preserve
            
        Returns:
            str: Complete redirect URI with error parameters
        """
        logger.warning(
            f"Building error redirect to '{redirect_uri_base_str}': "
            f"error='{error}', desc='{error_description}', state='{state}'"
        )
        
        params = {"error": error}
        if error_description:
            params["error_description"] = error_description
        if state:
            params["state"] = state
        
        query_string = urlencode(params)
        
        try:
            # Proper URL manipulation using urllib
            split_url = list(urlsplit(redirect_uri_base_str))
            split_url[3] = query_string
            final_redirect_uri = urlunsplit(split_url)
            return final_redirect_uri
        except Exception as e:
            # Fallback to simple string concatenation if URL parsing fails
            logger.error(
                f"Could not parse redirect_uri_base_str '{redirect_uri_base_str}' "
                f"for error redirect: {e}"
            )
            separator = "&" if "?" in redirect_uri_base_str else "?"
            return f"{redirect_uri_base_str}{separator}{query_string}"

    async def handle_token_request(self, token_request: TokenRequest, entity_id: str) -> TokenResponse:
        """
        Handles OAuth token requests for different grant types.
        
        Args:
            token_request: The token request to process
            entity_id: Entity context for the request
            
        Returns:
            TokenResponse: Token response with access token and optional refresh token
            
        Raises:
            UnsupportedGrantTypeError: For unsupported grant types
            InvalidRequestError: For missing required parameters
        """
        logger.info(
            f"Handling token request for grant_type '{token_request.grant_type}' "
            f"in entity '{entity_id}'."
        )

        if token_request.grant_type == "authorization_code":
            if not token_request.client_id:
                raise InvalidRequestError(
                    "client_id is required in the token request for authorization_code grant."
                )
            return await self._handle_auth_code_grant(token_request, entity_id)
        elif token_request.grant_type == "refresh_token":
            if not token_request.client_id:
                raise InvalidRequestError(
                    "client_id is required in the token request for refresh_token grant."
                )
            return await self._handle_refresh_token_grant(token_request, entity_id)
        else:
            raise UnsupportedGrantTypeError(
                f"Grant type '{token_request.grant_type}' is not supported."
            )

    async def _handle_auth_code_grant(self, token_request: TokenRequest, entity_id: str) -> TokenResponse:
        """
        Processes authorization code grant requests to exchange codes for access tokens.
        
        This method validates the authorization code, verifies PKCE, and issues new tokens.
        """
        if not all([token_request.code, token_request.redirect_uri, token_request.client_id]):
            raise InvalidRequestError(
                "Authorization code, redirect_uri, and client_id are required for authorization_code grant."
            )

        # Validate client and redirect URI
        await self._validate_client(token_request.client_id, str(token_request.redirect_uri))

        # Load and validate authorization code
        auth_code_data = await self.auth_code_store.load_auth_code(token_request.code)
        if not auth_code_data:
            logger.warning("Invalid authorization code (not found).")
            raise InvalidGrantError("Invalid authorization code.")

        # Check code expiration
        if auth_code_data.expires_at < datetime.now(timezone.utc):
            logger.warning("Expired authorization code.")
            await self.auth_code_store.delete_auth_code(token_request.code)
            raise InvalidGrantError("Authorization code has expired.")
        
        # Validate client ID matches
        if token_request.client_id != auth_code_data.client_id:
            logger.warning(
                f"Client ID mismatch. Expected {auth_code_data.client_id}, "
                f"got {token_request.client_id}."
            )
            raise InvalidClientError("Client ID mismatch.")
        
        # Validate redirect URI matches
        if str(token_request.redirect_uri) != str(auth_code_data.redirect_uri):
            logger.warning(
                "Redirect URI mismatch for authorization code. "
                f"Expected {auth_code_data.redirect_uri}, got {token_request.redirect_uri}."
            )
            raise InvalidGrantError("Redirect URI mismatch.")
        
        # Validate entity context
        if auth_code_data.entity_id != entity_id:
            logger.error(
                f"CRITICAL: Auth code entity_id '{auth_code_data.entity_id}' "
                f"mismatch with token request entity_id '{entity_id}'."
            )
            await self.auth_code_store.delete_auth_code(token_request.code)
            raise InvalidGrantError("Authorization code entity mismatch.")

        # Validate PKCE code verifier
        if not token_request.code_verifier:
            raise InvalidRequestError("code_verifier is required for PKCE.")
        if not validate_pkce_code_verifier_format(token_request.code_verifier):
            raise InvalidRequestError("Invalid code_verifier format.")

        # Verify PKCE challenge
        if auth_code_data.code_challenge and auth_code_data.code_challenge_method == "S256":
            expected_challenge = generate_pkce_code_challenge(
                token_request.code_verifier,
                auth_code_data.code_challenge_method
            )
            if expected_challenge != auth_code_data.code_challenge:
                logger.warning("PKCE verification failed for authorization code.")
                await self.auth_code_store.delete_auth_code(token_request.code)
                raise InvalidGrantError("PKCE verification failed: Invalid code_verifier.")
        elif auth_code_data.code_challenge_method == "plain":
            if token_request.code_verifier != auth_code_data.code_challenge:
                logger.warning("PKCE (plain) verification failed for authorization code.")
                await self.auth_code_store.delete_auth_code(token_request.code)
                raise InvalidGrantError("PKCE (plain) verification failed: Invalid code_verifier.")
        else:
            logger.error("Auth code missing valid PKCE challenge data from authorization phase.")
            await self.auth_code_store.delete_auth_code(token_request.code)
            raise ServerError("Internal server error: PKCE data inconsistency.")

        # Authorization code is single-use - delete it immediately after validation
        await self.auth_code_store.delete_auth_code(token_request.code)

        # Generate access token
        access_token_str = secrets.token_urlsafe(32)
        access_token_expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=ACCESS_TOKEN_LIFETIME_SECONDS
        )
        
        access_token_data_obj = AccessTokenData(
            access_token=access_token_str,
            client_id=auth_code_data.client_id,
            user_id=auth_code_data.user_id,
            entity_id=auth_code_data.entity_id,
            issued_scopes=auth_code_data.requested_scopes,
            expires_at=access_token_expires_at
        )
        await self.token_store.save_access_token(access_token_data_obj)

        # Generate refresh token if offline_access scope is granted
        refresh_token_str_to_return: Optional[str] = None
        if ISSUE_REFRESH_TOKENS and "offline_access" in (auth_code_data.requested_scopes or []):
            refresh_token_str = secrets.token_urlsafe(32)
            refresh_token_data_obj = RefreshTokenData(
                refresh_token=refresh_token_str,
                client_id=auth_code_data.client_id,
                user_id=auth_code_data.user_id,
                entity_id=auth_code_data.entity_id,
                issued_scopes=auth_code_data.requested_scopes,
            )
            await self.token_store.save_refresh_token(refresh_token_data_obj)
            refresh_token_str_to_return = refresh_token_str
        
        logger.info(
            f"Access token issued for client '{auth_code_data.client_id}', "
            f"user '{auth_code_data.user_id}' in entity '{entity_id}'."
        )
        return TokenResponse(
            access_token=access_token_str,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_LIFETIME_SECONDS,
            refresh_token=refresh_token_str_to_return,
            scope=" ".join(auth_code_data.requested_scopes) if auth_code_data.requested_scopes else None
        )

    async def _handle_refresh_token_grant(self, token_request: TokenRequest, entity_id: str) -> TokenResponse:
        """
        Processes refresh token grant requests to issue new access tokens.
        
        This method validates the refresh token and optionally allows scope reduction.
        """
        if not token_request.refresh_token or not token_request.client_id:
            raise InvalidRequestError(
                "refresh_token and client_id are required for refresh_token grant."
            )

        # Validate client
        await self._validate_client(token_request.client_id)

        # Load and validate refresh token
        rt_data = await self.token_store.load_refresh_token(token_request.refresh_token)
        if not rt_data:
            logger.warning("Invalid refresh token (not found).")
            raise InvalidGrantError("Invalid refresh token.")
        
        # Validate client ID matches
        if rt_data.client_id != token_request.client_id:
            logger.warning(
                f"Refresh token client_id mismatch. Expected {rt_data.client_id}, "
                f"got {token_request.client_id}."
            )
            raise InvalidClientError("Refresh token was not issued to this client.")

        # Validate entity context
        if rt_data.entity_id != entity_id:
            logger.error(
                f"CRITICAL: Refresh token entity_id '{rt_data.entity_id}' "
                f"mismatch with request entity_id '{entity_id}'."
            )
            await self.token_store.delete_refresh_token(token_request.refresh_token)
            raise InvalidGrantError("Refresh token entity mismatch.")

        # Handle scope reduction if requested
        final_scopes_for_new_at = rt_data.issued_scopes
        if token_request.scope:
            try:
                client_for_scope_check = await self._validate_client(rt_data.client_id)
                requested_new_scopes_list = await self._validate_scopes(
                    token_request.scope, 
                    client_for_scope_check
                )
                # Ensure requested scopes are subset of originally granted scopes
                if all(s in (rt_data.issued_scopes or []) for s in requested_new_scopes_list):
                    final_scopes_for_new_at = requested_new_scopes_list
                else:
                    raise InvalidScopeError(
                        "Requested scopes for refresh exceed original grant or client permissions."
                    )
            except (InvalidClientError, InvalidScopeError) as e_scope:
                logger.warning(f"Scope validation failed during refresh token grant: {e_scope}")
                raise

        # Generate new access token
        access_token_str = secrets.token_urlsafe(32)
        access_token_expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=ACCESS_TOKEN_LIFETIME_SECONDS
        )
        
        new_access_token_data_obj = AccessTokenData(
            access_token=access_token_str,
            client_id=rt_data.client_id,
            user_id=rt_data.user_id,
            entity_id=rt_data.entity_id,
            issued_scopes=final_scopes_for_new_at,
            expires_at=access_token_expires_at
        )
        await self.token_store.save_access_token(new_access_token_data_obj)
        
        logger.info(
            f"Access token refreshed for client '{rt_data.client_id}', "
            f"user '{rt_data.user_id}' in entity '{entity_id}'."
        )
        return TokenResponse(
            access_token=access_token_str,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_LIFETIME_SECONDS,
            refresh_token=rt_data.refresh_token,  # Return the same refresh token
            scope=" ".join(final_scopes_for_new_at) if final_scopes_for_new_at else None
        )