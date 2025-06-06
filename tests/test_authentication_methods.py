# tests/test_authentication_methods.py
import httpx
import asyncio
import json
import logging
import os
from dotenv import load_dotenv
from pathlib import Path
from typing import Any, Dict, Optional
from uuid import uuid4

# Load environment variables from project root
try:
    project_root = Path(__file__).parent.parent
    load_dotenv(dotenv_path=project_root / '.env', override=True)
except Exception:
    load_dotenv()

# Configuration constants
BASE_URL = os.getenv("PLEXUS_BASE_URL", "http://127.0.0.1:8080")
ENTITY_ID_AUTH_TEST = os.getenv("TEST_AUTH_ENTITY_ID", "test_tenant_auth")
HOST_APP_SECRET = os.getenv("HOST_APP_REGISTRATION_SECRET")
MCP_PROTOCOL_VERSION = "2025-03-26"

# Validate required configuration
if not HOST_APP_SECRET:
    print("ERROR: HOST_APP_REGISTRATION_SECRET is not set in your .env file.")
    exit(1)

# Configure logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s - %(name)s - [%(levelname)s] - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("AuthMethodsTestClient")


class AuthTestMCPClient:
    """Client for testing MCP authentication methods."""
    
    def __init__(self, base_url: str, entity_id: str, token: Optional[str] = None):
        self.base_url = base_url
        self.entity_id = entity_id
        self.mcp_endpoint_base = f"{self.base_url}/{self.entity_id}/mcp"
        self.token = token
        self.mcp_session_id: Optional[str] = None
        self.request_counter = 0

    async def _make_raw_http_post(
        self, 
        http_client: httpx.AsyncClient, 
        url: str, 
        payload: Dict[str, Any], 
        headers: Optional[Dict[str, str]] = None
    ) -> httpx.Response:
        """Make HTTP POST request with proper MCP headers and session management."""
        final_headers = headers or {}
        final_headers.setdefault("Content-Type", "application/json")
        final_headers.setdefault("Accept", "application/json, text/event-stream")
        
        # Include session ID in headers if available
        if self.mcp_session_id and "Mcp-Session-Id" not in final_headers:
            final_headers["Mcp-Session-Id"] = self.mcp_session_id
        
        logger.debug(f"HTTP POST to {url}. Headers: {final_headers}. Payload: {json.dumps(payload)}")
        response = await http_client.post(url, json=payload, headers=final_headers)
        logger.debug(f"HTTP Response Status: {response.status_code}. Headers: {dict(response.headers)}. Body: {response.text[:200]}...")
        
        # Update session ID if server provides a new one
        if "mcp-session-id" in response.headers:
            new_sid = response.headers["mcp-session-id"]
            if self.mcp_session_id != new_sid:
                logger.info(f"MCP Session ID updated from {self.mcp_session_id} to {new_sid}")
                self.mcp_session_id = new_sid
        
        return response

    async def mcp_initialize(
        self, 
        http_client: httpx.AsyncClient, 
        custom_headers: Optional[Dict[str, str]] = None,
        use_url_token: bool = False
    ) -> httpx.Response:
        """Initialize MCP session with various authentication methods."""
        self.request_counter += 1
        req_id = f"init-{self.entity_id}-{self.request_counter}"
        
        payload = {
            "jsonrpc": "2.0", 
            "method": "initialize", 
            "id": req_id,
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "AuthTestClient", "version": "1.0"}
            }
        }
        
        # Choose URL based on authentication method
        url_to_use = f"{self.mcp_endpoint_base}/"
        if use_url_token and self.token:
            url_to_use = f"{self.base_url}/{self.entity_id}/mcp/token_auth/{self.token}/"
            logger.info(f"Using URL Token for initialize: {url_to_use}")

        # Set up headers with authentication if not using URL token
        headers_to_use = custom_headers or {}
        if not use_url_token and self.token and "Authorization" not in headers_to_use:
            headers_to_use["Authorization"] = f"Bearer {self.token}"

        return await self._make_raw_http_post(http_client, url_to_use, payload, headers=headers_to_use)

    async def mcp_tool_list(
        self, 
        http_client: httpx.AsyncClient,
        custom_headers: Optional[Dict[str, str]] = None,
        use_url_token: bool = False
    ) -> httpx.Response:
        """Request list of available MCP tools with authentication."""
        self.request_counter += 1
        req_id = f"toolslist-{self.entity_id}-{self.request_counter}"
        
        payload = {"jsonrpc": "2.0", "method": "tools/list", "id": req_id, "params": {}}
        
        # Choose URL based on authentication method
        url_to_use = f"{self.mcp_endpoint_base}/tools/list"
        if use_url_token and self.token:
            url_to_use = f"{self.base_url}/{self.entity_id}/mcp/token_auth/{self.token}/tools/list"

        # Set up headers with authentication if not using URL token
        headers_to_use = custom_headers or {}
        if not use_url_token and self.token and "Authorization" not in headers_to_use:
            headers_to_use["Authorization"] = f"Bearer {self.token}"

        return await self._make_raw_http_post(http_client, url_to_use, payload, headers=headers_to_use)


async def register_test_user_and_get_token(http_client: httpx.AsyncClient) -> Optional[str]:
    """Registers a new user for the test and returns their auth token."""
    host_app_user_id = f"auth-test-user-{uuid4().hex[:8]}"
    logger.info(f"Registering a new Plexus user '{host_app_user_id}' for testing...")
    url = f"{BASE_URL}/{ENTITY_ID_AUTH_TEST}/plexus-auth/register-user"
    payload = {"user_id_from_host_app": host_app_user_id}
    headers = {"X-Host-App-Secret": HOST_APP_SECRET, "Content-Type": "application/json"}
    
    try:
        response = await http_client.post(url, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()
        token = data.get("plexus_user_auth_token")
        if token:
            logger.info(f"Successfully registered user and got token: {token[:10]}...")
            return token
        logger.error(f"Registration response missing token: {data}")
        return None
    except Exception as e:
        logger.error(f"Failed to register test user: {e}", exc_info=True)
        return None


async def test_initialize_no_token(http_client: httpx.AsyncClient):
    """Test MCP initialization without authentication (should fail)."""
    logger.info("\\n--- Test: Initialize with NO token (expect 401) ---")
    client = AuthTestMCPClient(BASE_URL, ENTITY_ID_AUTH_TEST)
    response = await client.mcp_initialize(http_client)
    
    assert response.status_code == 401, f"Expected 401, got {response.status_code}. Body: {response.text}"
    logger.info("Initialize with NO token correctly failed (401).")


async def test_initialize_with_bearer_token(http_client: httpx.AsyncClient, valid_token: str):
    """Test MCP initialization using a standard Bearer token header."""
    logger.info("\\n--- Test: Initialize with Bearer token ---")
    client = AuthTestMCPClient(BASE_URL, ENTITY_ID_AUTH_TEST, token=valid_token)
    response = await client.mcp_initialize(http_client)
    
    assert response.status_code == 200, f"Expected 200, got {response.status_code}. Body: {response.text}"
    assert client.mcp_session_id is not None, "Mcp-Session-Id should be set"
    logger.info("Initialize with Bearer token PASSED.")


async def test_tools_list_with_bearer_token(http_client: httpx.AsyncClient, valid_token: str):
    """Test tools/list endpoint using Bearer token authentication."""
    logger.info("\\n--- Test: tools/list with Bearer token ---")
    
    # Initialize session first
    client = AuthTestMCPClient(BASE_URL, ENTITY_ID_AUTH_TEST, token=valid_token)
    init_response = await client.mcp_initialize(http_client)
    assert init_response.status_code == 200, "Initialization failed for bearer token test"
    assert client.mcp_session_id is not None

    response = await client.mcp_tool_list(http_client)
    
    assert response.status_code == 200, f"Expected 200, got {response.status_code}. Body: {response.text}"
    response_data = response.json()
    assert "result" in response_data and "tools" in response_data["result"], "tools/list response malformed"
    logger.info(f"tools/list with Bearer token PASSED.")


async def test_tools_list_with_url_token(http_client: httpx.AsyncClient, valid_token: str):
    """Test tools/list endpoint using URL-embedded token authentication."""
    logger.info("\\n--- Test: tools/list with URL token ---")
    
    # Initialize session first
    client = AuthTestMCPClient(BASE_URL, ENTITY_ID_AUTH_TEST, token=valid_token)
    init_resp = await client.mcp_initialize(http_client)
    assert init_resp.status_code == 200, f"Expected 200 for initialize, got {init_resp.status_code}."
    
    response = await client.mcp_tool_list(http_client, use_url_token=True)
    
    assert response.status_code == 200, f"Expected 200 for tools/list, got {response.status_code}. Body: {response.text}"
    response_data = response.json()
    assert "result" in response_data and "tools" in response_data["result"], f"tools/list response malformed: {response_data}"
    logger.info(f"tools/list with URL token PASSED.")


async def test_tools_list_no_token(http_client: httpx.AsyncClient, valid_token: str):
    """Test tools/list endpoint without authentication (should fail)."""
    logger.info("\\n--- Test: tools/list with NO token (expect 401) ---")
    
    # First establish a session with valid token
    client_with_session = AuthTestMCPClient(BASE_URL, ENTITY_ID_AUTH_TEST, token=valid_token)
    await client_with_session.mcp_initialize(http_client)
    
    # Then try to use the session without authentication
    client_no_token = AuthTestMCPClient(BASE_URL, ENTITY_ID_AUTH_TEST, token=None)
    client_no_token.mcp_session_id = client_with_session.mcp_session_id
    
    response = await client_no_token.mcp_tool_list(http_client)
    
    assert response.status_code == 401, f"Expected 401, got {response.status_code}. Body: {response.text}"
    logger.info("tools/list with NO token correctly failed (401).")


async def test_multiple_auth_methods_fail(http_client: httpx.AsyncClient, valid_token: str):
    """Test that using multiple authentication methods simultaneously is rejected."""
    logger.info("\\n--- Test: Initialize with Bearer Token AND URL Token (expect 400) ---")
    client = AuthTestMCPClient(BASE_URL, ENTITY_ID_AUTH_TEST, token=valid_token)
    
    # Attempt to use both Bearer token in header and URL token simultaneously
    response = await client.mcp_initialize(
        http_client, 
        custom_headers={"Authorization": f"Bearer {valid_token}"}, 
        use_url_token=True
    )
    assert response.status_code == 400, f"Expected 400, got {response.status_code}. Body: {response.text}"
    logger.info("Initialize with Bearer and URL token correctly failed (400).")


async def main():
    """Run comprehensive authentication methods test suite."""
    logger.info("Starting Authentication Methods Test Suite...")
    
    async with httpx.AsyncClient(timeout=30.0) as http_client:
        # Register a test user and obtain authentication token
        valid_token_for_tests = await register_test_user_and_get_token(http_client)
        assert valid_token_for_tests, "Could not generate a valid token. Halting tests."

        # Run all authentication test scenarios
        await test_initialize_no_token(http_client)
        await test_initialize_with_bearer_token(http_client, valid_token_for_tests)
        
        await test_tools_list_no_token(http_client, valid_token_for_tests)
        await test_tools_list_with_bearer_token(http_client, valid_token_for_tests)
        await test_tools_list_with_url_token(http_client, valid_token_for_tests)
        
        await test_multiple_auth_methods_fail(http_client, valid_token_for_tests)
        
    logger.info("Authentication Methods Test Suite COMPLETED.")


if __name__ == "__main__":
    if not HOST_APP_SECRET:
        logger.error("CRITICAL: Test script cannot run without HOST_APP_REGISTRATION_SECRET.")
    else:
        asyncio.run(main())