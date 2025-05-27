# tests/test_full_flow.py
import httpx
import asyncio
import json
import logging
import os
from dotenv import load_dotenv
from urllib.parse import urlparse, parse_qs
from uuid import uuid4
from typing import Any, Dict, Optional
from pathlib import Path
import secrets

# Add project root to sys.path for local imports
import sys
project_root_path = Path(__file__).parent.parent.resolve()
if str(project_root_path) not in sys.path:
    sys.path.insert(0, str(project_root_path))

from mcp_plexus.oauth.pkce import generate_pkce_code_verifier, generate_pkce_code_challenge

load_dotenv(dotenv_path=project_root_path / '.env', override=True)

# Configuration constants
BASE_URL = os.getenv("PLEXUS_BASE_URL", "http://127.0.0.1:8080")
E2E_ENTITY_ID = os.getenv("E2E_FULL_FLOW_TEST_ENTITY_ID", "test_tenant_001")

# OAuth client configuration for internal authentication flow
INTERNAL_OAUTH_CLIENT_ID = "plexus-test-client"
INTERNAL_OAUTH_REDIRECT_URI = "http://localhost:8080/callback"
INTERNAL_OAUTH_SCOPES = "openid profile mcp_tool:get_entity_info"

GITHUB_PROVIDER_NAME = "github"
MCP_PROTOCOL_VERSION = "2025-03-26"
HOST_APP_SECRET = os.getenv("HOST_APP_REGISTRATION_SECRET")

# Setup logging configuration
global_test_log_level = os.getenv("E2E_LOG_LEVEL", "DEBUG").upper()
logging.basicConfig(
    level=global_test_log_level,
    format="%(asctime)s - %(name)s - [%(levelname)s] - %(message)s",
    handlers=[logging.StreamHandler()],
    force=True
)
logger = logging.getLogger("FullE2ETest")
logger.setLevel(global_test_log_level)


class MCPTestHelperClient:
    """
    Helper client for testing MCP (Model Context Protocol) interactions.
    
    Manages MCP sessions, authentication tokens, and provides methods for
    testing OAuth flows and tool calls within the MCP Plexus ecosystem.
    """
    
    def __init__(self, base_url: str, entity_id: str):
        self.base_url = base_url
        self.entity_id = entity_id
        self.mcp_endpoint = f"{self.base_url}/{self.entity_id}/mcp/"
        self.plexus_auth_base = f"{self.base_url}/{self.entity_id}/plexus-auth"
        self.internal_oauth_base = f"{self.base_url}/{self.entity_id}/oauth"
        
        # Session and authentication state
        self.mcp_session_id: Optional[str] = None
        self.plexus_user_auth_token: Optional[str] = None
        self.persistent_user_id: Optional[str] = None
        self.internal_access_token: Optional[str] = None
        
        self.request_counter = 0
        self.client_logger = logging.getLogger(f"MCPTestHelperClient.{self.entity_id}")
        self.client_logger.setLevel(logging.DEBUG if global_test_log_level == "DEBUG" else global_test_log_level)

    def _generate_mcp_request_id(self, prefix: str = "e2e-full") -> str:
        """Generate unique request IDs for MCP protocol messages."""
        self.request_counter += 1
        return f"{prefix}-{self.entity_id}-{self.request_counter}"

    async def _make_plexus_http_request(
        self,
        http_client: httpx.AsyncClient,
        method: str,
        url: str,
        json_payload: Optional[Dict[str, Any]] = None,
        data_payload: Optional[Dict[str, Any]] = None,
        expected_status: int = 200,
        extra_headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Make HTTP requests to Plexus endpoints with proper error handling.
        
        Handles both JSON and redirect responses, validates status codes,
        and provides detailed error information for debugging.
        """
        self.client_logger.debug(f"HTTP {method} to {url}")
        
        final_headers = extra_headers or {}

        try:
            if method.upper() == "POST":
                response = await http_client.post(url, json=json_payload, data=data_payload, headers=final_headers)
            elif method.upper() == "GET":
                response = await http_client.get(url, params=data_payload, headers=final_headers)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            self.client_logger.debug(f"HTTP Response Status: {response.status_code}")
            raw_text_for_debug = response.text if response.content else ""
            
            assert response.status_code == expected_status, \
                f"Expected status {expected_status}, got {response.status_code}. Response: {raw_text_for_debug}"
            
            # Handle JSON responses
            if "application/json" in response.headers.get("content-type", "").lower():
                if response.content:
                    return response.json()
                else:
                    self.client_logger.warning(f"Empty JSON response for {url}")
                    return {"_status_code": response.status_code, "_raw_text": "", "_headers": dict(response.headers)}

            # Handle redirect responses (e.g., OAuth flows)
            elif response.status_code == 302 and "location" in response.headers:
                return {"location": response.headers["location"], "_status_code": response.status_code, "_headers": dict(response.headers)}
            
            return {"_status_code": response.status_code, "_raw_text": raw_text_for_debug, "_headers": dict(response.headers)}

        except httpx.HTTPStatusError as e_http:
            self.client_logger.error(f"HTTP Error ({method} {url}): {e_http.response.status_code}")
            self.client_logger.error(f"Error Response Body: {e_http.response.text}")
            raise
        except Exception as e:
            self.client_logger.error(f"Unexpected error ({method} {url}): {e}", exc_info=True)
            raise

    async def _make_mcp_protocol_request(
        self,
        http_client: httpx.AsyncClient,
        mcp_method: str,
        mcp_params: Optional[Dict[str, Any]] = None,
        is_notification: bool = False,
        skip_default_bearer: bool = False
    ) -> Optional[Dict[str, Any]]:
        """
        Send MCP protocol messages to the server.
        
        Handles both regular JSON-RPC requests and notifications,
        manages session IDs, and parses responses from both JSON
        and Server-Sent Events formats.
        """
        request_id = self._generate_mcp_request_id() if not is_notification else None
        payload: Dict[str, Any] = {"jsonrpc": "2.0", "method": mcp_method}
        if mcp_params is not None:
            payload["params"] = mcp_params
        if request_id:
            payload["id"] = request_id
        
        # Prepare headers with session ID and authentication
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if self.mcp_session_id:
            headers["Mcp-Session-Id"] = self.mcp_session_id
        
        # Add Bearer token for authenticated requests
        if self.plexus_user_auth_token and not skip_default_bearer:
            headers["Authorization"] = f"Bearer {self.plexus_user_auth_token}"

        self.client_logger.debug(f"MCP Request: {mcp_method} (ID: {request_id})")
        
        try:
            response = await http_client.post(self.mcp_endpoint, json=payload, headers=headers)
            raw_response_text = response.text
            response_status_code = response.status_code
            response_headers = dict(response.headers)
            
            content_type = response_headers.get("content-type", "").lower()

            # Handle notification acceptance
            if response_status_code == 202 and is_notification:
                self.client_logger.info(f"Notification '{mcp_method}' accepted")
                return {"_mcp_status": "accepted_notification"}

            # Handle HTTP errors
            if response_status_code >= 400:
                self.client_logger.error(f"MCP request {mcp_method} failed with HTTP {response_status_code}")
                try:
                    parsed_error = response.json()
                except json.JSONDecodeError:
                    parsed_error = None
                return {"_http_error": True, "status_code": response_status_code, "detail": parsed_error or raw_response_text}

            # Handle empty responses
            if not response.content:
                self.client_logger.warning(f"Empty response for {mcp_method}")
                # Special case for initialize method with session ID in headers
                if mcp_method == "initialize" and response_status_code == 200 and "mcp-session-id" in response_headers:
                    self.mcp_session_id = response_headers["mcp-session-id"]
                    self.client_logger.info(f"Initialize completed with session ID: {self.mcp_session_id}")
                    return {"_mcp_status": "initialize_empty_body_with_session_id", "id": request_id, "mcp_session_id": self.mcp_session_id}
                return None

            parsed_mcp_json_data = None

            # Parse JSON responses
            if "application/json" in content_type:
                try:
                    parsed_mcp_json_data = response.json()
                    self.client_logger.debug(f"Parsed JSON response for {mcp_method}")
                except json.JSONDecodeError as e:
                    self.client_logger.error(f"JSON decode error for {mcp_method}: {e}")
                    return {"_json_decode_error": True, "raw_text": raw_response_text, "error_str": str(e)}
            
            # Parse Server-Sent Events responses
            elif "text/event-stream" in content_type:
                self.client_logger.debug(f"Parsing SSE response for {mcp_method}")
                for line in response.text.splitlines():
                    if line.startswith("data:"):
                        json_str = line[len("data:"):].strip()
                        try:
                            parsed_mcp_json_data = json.loads(json_str)
                            break
                        except json.JSONDecodeError as e_json_sse:
                            self.client_logger.error(f"SSE JSON decode error: {e_json_sse}")
                            return {"_sse_json_decode_error": True, "line": json_str, "raw_full_sse": raw_response_text, "error_str": str(e_json_sse)}
                
                if not parsed_mcp_json_data and not is_notification:
                    self.client_logger.warning(f"No parsable data in SSE response for {mcp_method}")
            else:
                self.client_logger.warning(f"Unexpected content type '{content_type}' for {mcp_method}")

            # Validate response ID matches request ID
            if parsed_mcp_json_data and not is_notification:
                response_id = parsed_mcp_json_data.get("id")
                if response_id != request_id and not str(response_id).startswith("server-error"):
                    self.client_logger.warning(f"Response ID mismatch: expected {request_id}, got {response_id}")

            # Update session ID if provided in headers
            if "mcp-session-id" in response_headers:
                new_sid = response_headers["mcp-session-id"]
                if self.mcp_session_id != new_sid:
                    self.mcp_session_id = new_sid
                    self.client_logger.info(f"Session ID updated to {new_sid}")
            
            return parsed_mcp_json_data

        except httpx.HTTPStatusError as e_http:
            self.client_logger.error(f"HTTP error for {mcp_method}: {e_http.response.status_code}")
            try:
                return e_http.response.json() if e_http.response.content else {"_http_error_status": True, "status_code": e_http.response.status_code}
            except:
                return {"_http_error_status": True, "status_code": e_http.response.status_code, "detail": e_http.response.text}
        except Exception as exc:
            self.client_logger.error(f"Unexpected error in MCP request {mcp_method}: {exc}", exc_info=True)
        
        return None

    def _extract_tool_call_payload(self, mcp_response_json: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Extract and parse the actual payload from MCP tool call responses.
        
        Handles both error responses and successful tool outputs,
        parsing JSON content from the tool's text response.
        """
        if not mcp_response_json:
            return None
        
        # Check for JSON-RPC protocol errors
        json_rpc_error = mcp_response_json.get("error")
        if json_rpc_error:
            self.client_logger.error(f"MCP protocol error: {json_rpc_error}")
            return {"_mcp_protocol_error": True, "detail": json_rpc_error}

        result = mcp_response_json.get("result")
        if isinstance(result, dict):
            # Handle tool execution errors
            if result.get("isError"):
                self.client_logger.warning("MCP tool execution resulted in error")
                raw_error_content = result.get('content', [])
                parsed_error_detail = None
                if raw_error_content and isinstance(raw_error_content[0], dict) and isinstance(raw_error_content[0].get("text"), str):
                    try:
                        parsed_error_detail = json.loads(raw_error_content[0]["text"])
                    except:
                        pass
                return {"_mcp_tool_error": True, "detail": parsed_error_detail or raw_error_content}

            # Extract successful tool response content
            content_list = result.get("content")
            if content_list and isinstance(content_list[0], dict):
                # Parse JSON from text content
                if isinstance(content_list[0].get("text"), str):
                    try:
                        return json.loads(content_list[0]["text"])
                    except json.JSONDecodeError as e:
                        self.client_logger.error(f"Failed to parse tool response text: {e}")
                        return {"_mcp_tool_payload_parse_error": True, "raw_text": content_list[0]['text']}
                # Handle structured content
                elif isinstance(content_list[0].get("structuredContent"), dict):
                    return content_list[0].get("structuredContent")

            self.client_logger.warning(f"Could not extract payload from tool result: {content_list}")
        else:
            self.client_logger.warning(f"Unexpected result format: {result}")
        
        return None

    async def register_plexus_user(self, http_client: httpx.AsyncClient, host_app_user_id: str) -> bool:
        """
        Register a new user with the Plexus authentication system.
        
        Creates a persistent user ID and auth token for the given host app user ID.
        """
        self.client_logger.info(f"Registering Plexus user '{host_app_user_id}'")
        
        if not HOST_APP_SECRET:
            self.client_logger.error("HOST_APP_SECRET not configured")
            return False

        payload = {"user_id_from_host_app": host_app_user_id}
        url = f"{self.plexus_auth_base}/register-user"
        headers = {"X-Host-App-Secret": HOST_APP_SECRET}
        
        response_data = await self._make_plexus_http_request(
            http_client, "POST", url, json_payload=payload, extra_headers=headers
        )
        
        if response_data and response_data.get("plexus_user_auth_token"):
            self.plexus_user_auth_token = response_data.get("plexus_user_auth_token")
            self.persistent_user_id = response_data.get("persistent_user_id")
            if self.plexus_user_auth_token and self.persistent_user_id:
                self.client_logger.info(f"User registered with ID: {self.persistent_user_id}")
                return True
        
        self.client_logger.error(f"Registration failed: {response_data}")
        return False

    async def initialize_mcp_session(self, http_client: httpx.AsyncClient) -> bool:
        """
        Initialize an MCP session with the server.
        
        Sends the initialize message and notifications/initialized to establish
        a working MCP session with authentication context.
        """
        self.client_logger.info("Initializing MCP session")
        
        client_info_dict = {"name": "FullE2ETestClient", "version": "1.0.0"}
        params = {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": client_info_dict
        }
        
        # Initialize the session
        init_response = await self._make_mcp_protocol_request(
            http_client, "initialize", mcp_params=params, skip_default_bearer=False
        )
        
        # Check if initialization was successful
        if (init_response and 
            not init_response.get("error") and 
            not init_response.get("_http_error") and 
            not init_response.get("_json_decode_error") and 
            not init_response.get("_sse_json_decode_error") and 
            self.mcp_session_id):
            
            self.client_logger.info(f"MCP session initialized: {self.mcp_session_id}")
            
            # Send initialized notification
            notif_response = await self._make_mcp_protocol_request(
                http_client, "notifications/initialized", mcp_params={}, 
                is_notification=True, skip_default_bearer=False
            )
            return bool(notif_response and notif_response.get("_mcp_status") == "accepted_notification")
        
        self.client_logger.error(f"MCP initialization failed: {init_response}")
        return False

    async def call_tool(self, http_client: httpx.AsyncClient, tool_name: str, arguments: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Call an MCP tool with the given arguments.
        
        Returns the parsed tool response payload or None if the call failed.
        """
        if not self.mcp_session_id:
            self.client_logger.error(f"Cannot call tool '{tool_name}': No MCP session")
            return None
        
        mcp_response = await self._make_mcp_protocol_request(
            http_client, "tools/call", 
            mcp_params={"name": tool_name, "arguments": arguments}
        )
        return self._extract_tool_call_payload(mcp_response)
    
    async def perform_internal_oauth_flow(self, http_client: httpx.AsyncClient) -> bool:
        """
        Execute the internal OAuth authorization code flow with PKCE.
        
        Performs the complete OAuth flow including authorization request,
        code exchange, and token retrieval for internal OAuth clients.
        """
        self.client_logger.info("Starting internal OAuth flow")
        
        if not self.mcp_session_id:
            self.client_logger.error("Cannot perform OAuth flow: No MCP session")
            return False

        # Generate PKCE parameters for security
        code_verifier = generate_pkce_code_verifier()
        code_challenge = generate_pkce_code_challenge(code_verifier)
        auth_state = secrets.token_urlsafe(16)

        # Prepare authorization request
        auth_params = {
            "response_type": "code",
            "client_id": INTERNAL_OAUTH_CLIENT_ID,
            "redirect_uri": INTERNAL_OAUTH_REDIRECT_URI,
            "scope": INTERNAL_OAUTH_SCOPES,
            "state": auth_state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256"
        }
        
        auth_url = f"{self.internal_oauth_base}/authorize"
        auth_headers = {"Mcp-Session-Id": self.mcp_session_id}
        
        # Get authorization code via redirect
        auth_response = await self._make_plexus_http_request(
            http_client, "GET", auth_url, data_payload=auth_params,
            expected_status=302, extra_headers=auth_headers
        )
        
        redirect_loc = auth_response.get("location")
        if not redirect_loc:
            self.client_logger.error(f"Authorization did not redirect: {auth_response}")
            return False
        
        # Parse authorization code from redirect
        parsed_redirect = urlparse(redirect_loc)
        query_params = parse_qs(parsed_redirect.query)
        
        auth_code = query_params.get("code", [None])[0]
        received_state = query_params.get("state", [None])[0]

        if not auth_code:
            self.client_logger.error(f"No authorization code received: {query_params}")
            return False
        if received_state != auth_state:
            self.client_logger.error(f"State mismatch: expected {auth_state}, got {received_state}")
            return False

        # Exchange authorization code for access token
        token_url = f"{self.internal_oauth_base}/token"
        token_payload = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": INTERNAL_OAUTH_REDIRECT_URI,
            "client_id": INTERNAL_OAUTH_CLIENT_ID,
            "code_verifier": code_verifier
        }

        token_response = await self._make_plexus_http_request(
            http_client, "POST", token_url, data_payload=token_payload
        )
        
        self.internal_access_token = token_response.get("access_token")
        if self.internal_access_token:
            self.client_logger.info("Internal OAuth flow completed successfully")
            return True
        
        self.client_logger.error(f"Token exchange failed: {token_response}")
        return False


async def test_scenario_full_flow():
    """
    Execute the complete end-to-end test scenario.
    
    Tests user registration, MCP session initialization, tool calls,
    internal OAuth flow, external GitHub OAuth, and token persistence.
    """
    test_host_app_user_id = f"fullflow_user_{secrets.token_hex(8)}"
    logger.info(f"Starting full flow test for user '{test_host_app_user_id}'")
    
    client_helper = MCPTestHelperClient(base_url=BASE_URL, entity_id=E2E_ENTITY_ID)

    async with httpx.AsyncClient(timeout=90.0) as http_client:
        # Step 1: Register Plexus user
        assert await client_helper.register_plexus_user(http_client, test_host_app_user_id), \
            "Plexus user registration failed"
        
        # Store tokens for later session testing
        temp_plexus_token = client_helper.plexus_user_auth_token
        temp_persistent_user_id = client_helper.persistent_user_id

        # Step 2: Initialize MCP session
        assert await client_helper.initialize_mcp_session(http_client), \
            "MCP session initialization failed"
        
        # Step 3: Verify user context in MCP session
        logger.info("Verifying user context in MCP session")
        entity_info = await client_helper.call_tool(http_client, "get_entity_info", {})

        assert entity_info and not entity_info.get("_mcp_tool_error") and not entity_info.get("_mcp_protocol_error"), \
            f"get_entity_info failed: {entity_info}"
        
        if entity_info.get("_mcp_tool_payload_parse_error"):
            logger.error(f"Tool response parsing error: {entity_info.get('raw_text')}")
            assert False, "Failed to parse get_entity_info tool response"

        # Verify persistent user ID is correctly associated with session
        session_info_str = entity_info.get("final_plexus_session_info", "")
        assert f"persistent_user_id={client_helper.persistent_user_id}" in session_info_str, \
            f"User ID mismatch in session. Expected '{client_helper.persistent_user_id}', got: '{session_info_str}'"
        logger.info(f"User context verified: {client_helper.persistent_user_id}")

        # Step 4: Test internal OAuth flow
        logger.info("Testing internal OAuth flow")
        internal_oauth_ok = await client_helper.perform_internal_oauth_flow(http_client)
        assert internal_oauth_ok, "Internal OAuth flow failed"
        logger.info("Internal OAuth flow test PASSED")
        
        # Step 5: Test external GitHub OAuth flow
        logger.info("Testing external GitHub OAuth flow")
        github_tool_name = "fetch_secure_external_data"
        github_item_id = f"gh_item_{uuid4().hex[:6]}"

        # First call may trigger OAuth flow or use existing token
        gh_tool_resp1 = await client_helper.call_tool(http_client, github_tool_name, {"item_id": github_item_id})
        assert gh_tool_resp1, "GitHub tool call received no response"

        if gh_tool_resp1.get("_mcp_tool_error"):
            # OAuth authorization required
            error_detail = gh_tool_resp1.get("detail", {})
            logger.info("GitHub tool requires authorization")
            assert error_detail.get("error") == "external_auth_required", "Expected external_auth_required error"
            assert error_detail.get("provider_name") == GITHUB_PROVIDER_NAME, "Provider name mismatch"
            
            github_auth_url = error_detail.get("authorization_url")
            assert github_auth_url and "github.com/login/oauth/authorize" in github_auth_url, \
                "Invalid GitHub auth URL"

            # Manual intervention required for GitHub OAuth
            logger.info("!!! MANUAL ACTION REQUIRED FOR GITHUB TEST !!!")
            logger.info("Please open the following URL, authenticate with GitHub, and grant consent:")
            logger.info(f"  {github_auth_url}")
            logger.info("After successful authentication, press Enter to continue.")
            await asyncio.to_thread(input, "PRESS ENTER TO CONTINUE... ")

            # Retry tool call after OAuth completion
            gh_tool_resp2 = await client_helper.call_tool(http_client, github_tool_name, {"item_id": github_item_id})
            assert gh_tool_resp2 and not gh_tool_resp2.get("_mcp_tool_error"), \
                f"GitHub tool call failed after auth: {gh_tool_resp2}"
            assert gh_tool_resp2.get("status") == "success_placeholder", \
                f"Unexpected GitHub tool response: {gh_tool_resp2}"
            logger.info("GitHub tool call post-auth SUCCESSFUL")
        else:
            # Token already available from previous runs
            logger.info("GitHub tool call succeeded with existing token")
            assert gh_tool_resp1.get("status") == "success_placeholder", \
                f"Unexpected GitHub tool response: {gh_tool_resp1}"
        
        logger.info("External GitHub OAuth flow test PASSED")

        # Step 6: Test token persistence across MCP sessions
        logger.info("Testing GitHub token persistence with new MCP session")
        client_helper_new_session = MCPTestHelperClient(base_url=BASE_URL, entity_id=E2E_ENTITY_ID)
        client_helper_new_session.plexus_user_auth_token = temp_plexus_token
        client_helper_new_session.persistent_user_id = temp_persistent_user_id

        assert await client_helper_new_session.initialize_mcp_session(http_client), \
            "New MCP session initialization failed"
        assert client_helper_new_session.mcp_session_id != client_helper.mcp_session_id, \
            "New session should have different MCP session ID"
        
        # Test that GitHub token persists across sessions
        gh_tool_resp3 = await client_helper_new_session.call_tool(
            http_client, github_tool_name, {"item_id": github_item_id + "_newsess"}
        )
        assert gh_tool_resp3 and not gh_tool_resp3.get("_mcp_tool_error"), \
            f"GitHub tool call in new session failed: {gh_tool_resp3}"
        assert gh_tool_resp3.get("status") == "success_placeholder", \
            f"Unexpected response in new session: {gh_tool_resp3}"
        assert gh_tool_resp3.get("item_id") == github_item_id + "_newsess", \
            "Tool item_id mismatch in new session"
        logger.info("GitHub token persistence test PASSED")

    logger.info(f"Full E2E test completed successfully for user '{test_host_app_user_id}'")


if __name__ == "__main__":
    logger.info("Starting MCP Plexus E2E test - ensure server is running and configured")
    logger.info(f"Using BASE_URL: {BASE_URL}, E2E_ENTITY_ID: {E2E_ENTITY_ID}")
    
    # Validate required configuration
    if not HOST_APP_SECRET or HOST_APP_SECRET == "default_secret_if_env_missing":
        logger.warning("HOST_APP_REGISTRATION_SECRET not properly configured - check .env file")
    
    if E2E_ENTITY_ID != "test_tenant_001":
        logger.warning(f"E2E_ENTITY_ID is '{E2E_ENTITY_ID}' - GitHub OAuth may fail if not configured for this entity")
    
    if not os.getenv("GITHUB_CLIENT_ID") or not os.getenv("GITHUB_CLIENT_SECRET"):
        logger.warning("GitHub OAuth credentials not configured - OAuth flow may fail")

    asyncio.run(test_scenario_full_flow())