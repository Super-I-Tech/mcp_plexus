# test_authentication_methods.py
import httpx
import asyncio
import json
import logging
import os
from dotenv import load_dotenv
from pathlib import Path
from typing import Any, Dict, Optional

# Load environment variables from project root
try:
    project_root = Path(__file__).parent.parent
    load_dotenv(dotenv_path=project_root / '.env')
except Exception:
    load_dotenv()

# Configuration constants
BASE_URL = os.getenv("PLEXUS_BASE_URL", "http://127.0.0.1:8080")
ENTITY_ID_AUTH_TEST = os.getenv("TEST_AUTH_ENTITY_ID", "test_tenant_auth")
HOST_APP_SECRET = os.getenv("HOST_APP_REGISTRATION_SECRET")
MCP_PROTOCOL_VERSION = "2025-03-26"
VALID_PLEXUS_USER_AUTH_TOKEN = "p7UNMJErD38_OWovGb0U79NHHHxVXrN-DgDmxeE_QY4"

# Validate required configuration
if VALID_PLEXUS_USER_AUTH_TOKEN == "YOUR_VALID_AUTHENTICATION_TOKEN_HERE":
    print(f"ERROR: Please set TEST_AUTH_USER_PLEXUS_TOKEN for entity '{ENTITY_ID_AUTH_TEST}' in your .env file or directly in the script.")
    exit(1)
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
        
        # Include session ID if available (allow explicit override for tests)
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
        plexus_token_in_clientinfo: Optional[str] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        use_url_token: bool = False
    ) -> httpx.Response:
        """Initialize MCP session with various authentication methods."""
        self.request_counter += 1
        req_id = f"init-{self.entity_id}-{self.request_counter}"
        
        client_info: Dict[str, Any] = {"name": "AuthTestClient", "version": "1.0"}
        if plexus_token_in_clientinfo:
            client_info["plexusUserAuthToken"] = plexus_token_in_clientinfo
            
        payload = {
            "jsonrpc": "2.0", 
            "method": "initialize", 
            "id": req_id,
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": client_info
            }
        }
        
        # Determine URL based on authentication method
        url_to_use = self.mcp_endpoint_base + "/"
        if use_url_token and self.token:
            url_to_use = f"{self.base_url}/{self.entity_id}/mcp/token_auth/{self.token}/"
            logger.info(f"Using URL Token for initialize: {url_to_use}")

        # Set up authentication headers
        headers_to_use = custom_headers or {}
        if not use_url_token and self.token and not headers_to_use.get("Authorization"):
            if "Authorization" not in headers_to_use:
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
        
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": req_id,
            "params": {} 
        }
        
        # Determine URL based on authentication method
        url_to_use = self.mcp_endpoint_base + "/tools/list"
        if use_url_token and self.token:
            url_to_use = f"{self.base_url}/{self.entity_id}/mcp/token_auth/{self.token}/tools/list"
            logger.info(f"Using URL Token for tools/list: {url_to_use}")

        # Set up authentication headers
        headers_to_use = custom_headers or {}
        if not use_url_token and self.token and not headers_to_use.get("Authorization"):
            if "Authorization" not in headers_to_use:
                headers_to_use["Authorization"] = f"Bearer {self.token}"

        return await self._make_raw_http_post(http_client, url_to_use, payload, headers=headers_to_use)


async def test_initialize_with_clientinfo_token(http_client: httpx.AsyncClient):
    """Test MCP initialization using token embedded in clientInfo."""
    logger.info("\n--- Test: Initialize with plexusUserAuthToken in clientInfo ---")
    client = AuthTestMCPClient(BASE_URL, ENTITY_ID_AUTH_TEST)
    response = await client.mcp_initialize(
        http_client, 
        plexus_token_in_clientinfo=VALID_PLEXUS_USER_AUTH_TOKEN
    )
    
    assert response.status_code == 200, f"Expected 200, got {response.status_code}. Body: {response.text}"
    assert client.mcp_session_id is not None, "Mcp-Session-Id should be set"
    logger.info("Initialize with clientInfo token PASSED.")
    logger.info(f"Session ID: {client.mcp_session_id}")


async def test_initialize_no_token(http_client: httpx.AsyncClient):
    """Test MCP initialization without authentication (should fail)."""
    logger.info("\n--- Test: Initialize with NO token (expect 401) ---")
    client = AuthTestMCPClient(BASE_URL, ENTITY_ID_AUTH_TEST)
    response = await client.mcp_initialize(http_client)
    
    assert response.status_code == 401, f"Expected 401, got {response.status_code}. Body: {response.text}"
    logger.info("Initialize with NO token correctly failed (401).")


async def test_tools_list_with_bearer_token(http_client: httpx.AsyncClient):
    """Test tools/list endpoint using Bearer token authentication."""
    logger.info("\n--- Test: tools/list with Bearer token ---")
    
    # Initialize session first
    client = AuthTestMCPClient(BASE_URL, ENTITY_ID_AUTH_TEST)
    init_response = await client.mcp_initialize(
        http_client, 
        plexus_token_in_clientinfo=VALID_PLEXUS_USER_AUTH_TOKEN
    )
    assert init_response.status_code == 200, "Initialization failed for bearer token test"
    assert client.mcp_session_id is not None

    # Make tools/list call using Bearer token
    client.token = VALID_PLEXUS_USER_AUTH_TOKEN
    response = await client.mcp_tool_list(http_client)
    
    assert response.status_code == 200, f"Expected 200, got {response.status_code}. Body: {response.text}"
    response_data = response.json()
    assert "result" in response_data and "tools" in response_data["result"], "tools/list response malformed"
    logger.info(f"tools/list with Bearer token PASSED. Found {len(response_data['result']['tools'])} tools.")


async def test_tools_list_with_url_token(http_client: httpx.AsyncClient):
    """Test tools/list endpoint using URL-embedded token authentication."""
    logger.info("\n--- Test: tools/list with URL token ---")
    
    # Verify that initialize without token fails as expected
    unauthed_client_for_init = AuthTestMCPClient(BASE_URL, ENTITY_ID_AUTH_TEST)
    init_resp = await unauthed_client_for_init.mcp_initialize(http_client)
    
    assert init_resp.status_code == 401, f"Expected 401 for initialize with no token, got {init_resp.status_code}. Body: {init_resp.text}"
    logger.info("Attempted initialize with no token correctly failed (401) as expected for this test setup.")

    # Test tools/list with URL token
    client_with_url_token = AuthTestMCPClient(BASE_URL, ENTITY_ID_AUTH_TEST, token=VALID_PLEXUS_USER_AUTH_TOKEN)
    client_with_url_token.mcp_session_id = None
    
    response = await client_with_url_token.mcp_tool_list(http_client, use_url_token=True)
    
    assert response.status_code == 200, f"Expected 200 for tools/list with URL token, got {response.status_code}. Body: {response.text}"
    response_data = response.json()
    assert "result" in response_data and "tools" in response_data["result"], f"tools/list response malformed: {response_data}"
    logger.info(f"tools/list with URL token PASSED. Session: {client_with_url_token.mcp_session_id}. Found {len(response_data['result']['tools'])} tools.")
    assert client_with_url_token.mcp_session_id is not None, "Mcp-Session-Id should be set after successful URL token auth and tools/list"


async def test_tools_list_no_token(http_client: httpx.AsyncClient):
    """Test tools/list endpoint without authentication (should fail)."""
    logger.info("\n--- Test: tools/list with NO token (expect 401) ---")
    client = AuthTestMCPClient(BASE_URL, ENTITY_ID_AUTH_TEST)
    response = await client.mcp_tool_list(http_client)
    
    assert response.status_code == 401, f"Expected 401, got {response.status_code}. Body: {response.text}"
    logger.info("tools/list with NO token correctly failed (401).")


async def test_multiple_auth_methods_fail(http_client: httpx.AsyncClient):
    """Test that using multiple authentication methods simultaneously is rejected."""
    logger.info("\n--- Test: Initialize with Bearer Token AND URL Token (expect 400) ---")
    client = AuthTestMCPClient(BASE_URL, ENTITY_ID_AUTH_TEST, token=VALID_PLEXUS_USER_AUTH_TOKEN)
    
    # Test Bearer + URL token combination
    response = await client.mcp_initialize(
        http_client, 
        custom_headers={"Authorization": f"Bearer {VALID_PLEXUS_USER_AUTH_TOKEN}"}, 
        use_url_token=True
    )
    assert response.status_code == 400, f"Expected 400, got {response.status_code}. Body: {response.text}"
    logger.info("Initialize with Bearer and URL token correctly failed (400).")

    # Test Bearer + clientInfo token combination
    logger.info("\n--- Test: Initialize with Bearer Token AND clientInfo Token (expect 400 from our logic) ---")
    response_bearer_and_clientinfo = await client.mcp_initialize(
        http_client,
        plexus_token_in_clientinfo=VALID_PLEXUS_USER_AUTH_TOKEN,
        custom_headers={"Authorization": f"Bearer {VALID_PLEXUS_USER_AUTH_TOKEN}"}
    )
    
    assert response_bearer_and_clientinfo.status_code == 400, \
        f"Expected 400 for Bearer + clientInfo Token, got {response_bearer_and_clientinfo.status_code}. Body: {response_bearer_and_clientinfo.text}"
    logger.info("Initialize with Bearer and ClientInfo Token correctly failed (400).")


async def main():
    """Run comprehensive authentication methods test suite."""
    logger.info("Starting Authentication Methods Test Suite...")
    
    async with httpx.AsyncClient(timeout=30.0) as http_client:
        await test_initialize_no_token(http_client)
        await test_initialize_with_clientinfo_token(http_client)
        
        await test_tools_list_no_token(http_client)
        await test_tools_list_with_bearer_token(http_client)
        await test_tools_list_with_url_token(http_client)
        
        await test_multiple_auth_methods_fail(http_client)
        
    logger.info("Authentication Methods Test Suite COMPLETED.")


if __name__ == "__main__":
    if VALID_PLEXUS_USER_AUTH_TOKEN == "YOUR_VALID_AUTHENTICATION_TOKEN_HERE" or not HOST_APP_SECRET:
        logger.error("CRITICAL: Test script cannot run without valid TEST_AUTH_USER_PLEXUS_TOKEN and HOST_APP_REGISTRATION_SECRET.")
    else:
        asyncio.run(main())