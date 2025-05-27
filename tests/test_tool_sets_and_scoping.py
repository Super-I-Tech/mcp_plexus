# test_tool_sets_and_scoping.py
import httpx
import asyncio
import json
import logging
import os
from dotenv import load_dotenv
from typing import Any, Dict, Optional, List

# Configure logging based on environment variable
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s - %(name)s - [%(levelname)s] - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("ToolScopingSetsTestClient")

# Load environment variables from .env file
try:
    from pathlib import Path
    # Assumes this test script might be in a 'tests' subdirectory of your project root
    project_root = Path(__file__).resolve().parent.parent 
    load_dotenv(dotenv_path=project_root / '.env')
    logger.info(f"Loaded .env from: {project_root / '.env'}")
except Exception as e:
    logger.warning(f"Could not load .env using pathlib from expected project structure: {e}. Falling back to current directory.")
    load_dotenv()

BASE_URL = os.getenv("PLEXUS_BASE_URL", "http://127.0.0.1:8080")
MCP_PROTOCOL_VERSION = "2025-03-26"

# Tenant and User Setup for testing
# These tenants must exist via admin CLI/API before running tests
ENTITY_ID_A = os.getenv("TEST_SCOPING_TENANT_A_ID", "tenant_A_for_scope_test")
ENTITY_ID_B = os.getenv("TEST_SCOPING_TENANT_B_ID", "tenant_B_for_scope_test")
ENTITY_ID_C = os.getenv("TEST_SCOPING_TENANT_C_ID", "tenant_C_for_scope_test") 

# Authentication tokens for each tenant
TOKEN_TENANT_A = os.getenv("TEST_SCOPING_TENANT_A_TOKEN", "YOUR_TENANT_A_TOKEN")
TOKEN_TENANT_B = os.getenv("TEST_SCOPING_TENANT_B_TOKEN", "YOUR_TENANT_B_TOKEN")
TOKEN_TENANT_C = os.getenv("TEST_SCOPING_TENANT_C_TOKEN", "YOUR_TENANT_C_TOKEN")

# Validate that all required tokens are configured
missing_tokens = False
if TOKEN_TENANT_A == "YOUR_TENANT_A_TOKEN":
    logger.error(f"Set TEST_SCOPING_TENANT_A_TOKEN for {ENTITY_ID_A}")
    missing_tokens = True
if TOKEN_TENANT_B == "YOUR_TENANT_B_TOKEN":
    logger.error(f"Set TEST_SCOPING_TENANT_B_TOKEN for {ENTITY_ID_B}")
    missing_tokens = True
if TOKEN_TENANT_C == "YOUR_TENANT_C_TOKEN":
    logger.error(f"Set TEST_SCOPING_TENANT_C_TOKEN for {ENTITY_ID_C}")
    missing_tokens = True
if missing_tokens: 
    logger.critical("Test script cannot run. Please set all required TEST_SCOPING_TENANT_X_TOKEN environment variables.")
    exit(1)

# Tool names used for testing scoping and sets
# These tools must be defined in mcp_plexus/tool_modules/ with appropriate scoping/tags
TOOL_GLOBAL_GENERAL = "get_global_info" 
TOOL_TENANT_A_ONLY = "get_tenant_a_specific_data" 
TOOL_TENANT_B_ONLY = "get_tenant_b_exclusive_feature" 
TOOL_TENANT_A_AND_C = "get_shared_ac_resource" 
TOOL_SET_REPORTING = "generate_report_tool"  # Expected to have tool_sets=["reporting"]
TOOL_SET_ADMIN_TENANT_A = "admin_task_for_tenant_a"  # Expected: tool_sets=["admin_tasks"], allowed_tenant_ids=[ENTITY_ID_A]


class ScopingTestMCPClient:
    """MCP client for testing tool scoping and sets functionality."""
    
    def __init__(self, base_url: str, entity_id: str, token: str):
        self.base_url = base_url
        self.entity_id = entity_id
        self.mcp_endpoint = f"{self.base_url}/{self.entity_id}/mcp/"
        self.token = token 
        self.mcp_session_id: Optional[str] = None
        self.request_counter = 0

    async def _mcp_request(
        self, 
        http_client: httpx.AsyncClient, 
        method: str, 
        params: Optional[Dict[str, Any]] = None,
        is_notification: bool = False,
        skip_default_bearer: bool = False 
    ) -> httpx.Response:
        """Send an MCP request with proper authentication and session handling."""
        self.request_counter += 1
        req_id = f"scope-{self.entity_id}-{self.request_counter}" if not is_notification else None
        payload = {"jsonrpc": "2.0", "method": method, "id": req_id}
        if params:
            payload["params"] = params
        
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        
        # Add authentication header unless explicitly skipped
        if self.token and not skip_default_bearer:
            headers["Authorization"] = f"Bearer {self.token}"
        
        # Include session ID if available
        if self.mcp_session_id:
            headers["Mcp-Session-Id"] = self.mcp_session_id
        
        logger.debug(f"MCP Request to {self.mcp_endpoint}. Method: {method}")
        response = await http_client.post(self.mcp_endpoint, json=payload, headers=headers)
        logger.debug(f"MCP Response Status: {response.status_code}")
        
        # Update session ID if returned in response
        if "mcp-session-id" in response.headers:
            new_sid = response.headers["mcp-session-id"]
            if self.mcp_session_id != new_sid:
                logger.info(f"MCP Session ID for {self.entity_id} is now: {new_sid}")
                self.mcp_session_id = new_sid
        
        return response

    async def initialize_session(self, http_client: httpx.AsyncClient) -> bool:
        """Initialize MCP session for the client."""
        client_info = {"name": "ScopingTestClient", "version": "1.0"}
        params = {
            "protocolVersion": MCP_PROTOCOL_VERSION, 
            "capabilities": {}, 
            "clientInfo": client_info
        }
        
        # Initialize session with authentication
        response = await self._mcp_request(http_client, "initialize", params, skip_default_bearer=False)
        
        if response.status_code == 200 and self.mcp_session_id:
            logger.info(f"Session initialized for {self.entity_id}. Session ID: {self.mcp_session_id}")
            
            # Send required 'initialized' notification
            notif_response = await self._mcp_request(
                http_client, 
                "notifications/initialized", 
                params={}, 
                is_notification=True
            )
            
            if notif_response.status_code == 202:
                logger.info(f"'notifications/initialized' sent and accepted for {self.entity_id}.")
                return True
            
            logger.error(f"'notifications/initialized' failed for {self.entity_id}. Status: {notif_response.status_code}")
            return False
        
        logger.error(f"Failed to initialize session for {self.entity_id}. Status: {response.status_code}")
        return False

    async def list_tools(
        self, 
        http_client: httpx.AsyncClient, 
        tool_set_filter: Optional[str] = None
    ) -> List[str]:
        """List available tools, optionally filtered by tool set."""
        params: Dict[str, Any] = {}
        if tool_set_filter:
            params["tool_set_filter"] = tool_set_filter
        
        response = await self._mcp_request(http_client, "tools/list", params if params else None)
        response.raise_for_status()
        
        data = response.json()
        if "result" in data and "tools" in data["result"] and isinstance(data["result"]["tools"], list):
            return [tool["name"] for tool in data["result"]["tools"] 
                   if isinstance(tool, dict) and "name" in tool]
        
        logger.warning(f"tools/list response for {self.entity_id} malformed or no tools: {data}")
        return []

    async def call_tool(
        self, 
        http_client: httpx.AsyncClient, 
        tool_name: str, 
        arguments: Optional[Dict[str, Any]] = None
    ) -> httpx.Response: 
        """Call a specific tool with given arguments."""
        params = {"name": tool_name, "arguments": arguments or {}}
        return await self._mcp_request(http_client, "tools/call", params)


async def main():
    """Main test suite for tool sets and tenant scoping functionality."""
    logger.info("Starting Tool Sets and Tenant Scoping Test Suite...")
    
    # Initialize clients for each test tenant
    client_a = ScopingTestMCPClient(BASE_URL, ENTITY_ID_A, TOKEN_TENANT_A)
    client_b = ScopingTestMCPClient(BASE_URL, ENTITY_ID_B, TOKEN_TENANT_B)
    client_c = ScopingTestMCPClient(BASE_URL, ENTITY_ID_C, TOKEN_TENANT_C)

    async with httpx.AsyncClient(timeout=30.0) as http_client:
        # Initialize sessions for all test tenants
        logger.info("--- Initializing sessions for all test tenants ---")
        assert await client_a.initialize_session(http_client), f"Failed to init session for {ENTITY_ID_A}"
        assert await client_b.initialize_session(http_client), f"Failed to init session for {ENTITY_ID_B}"
        assert await client_c.initialize_session(http_client), f"Failed to init session for {ENTITY_ID_C}"

        # Test Tenant Scoping via tools/list
        logger.info("--- Test: Tenant A tools/list (no filter) ---")
        tools_a = await client_a.list_tools(http_client)
        logger.info(f"Tenant A sees tools: {tools_a}")
        assert TOOL_GLOBAL_GENERAL in tools_a
        assert TOOL_TENANT_A_ONLY in tools_a
        assert TOOL_TENANT_A_AND_C in tools_a
        assert TOOL_TENANT_B_ONLY not in tools_a 
        assert TOOL_SET_ADMIN_TENANT_A in tools_a

        logger.info("--- Test: Tenant B tools/list (no filter) ---")
        tools_b = await client_b.list_tools(http_client)
        logger.info(f"Tenant B sees tools: {tools_b}")
        assert TOOL_GLOBAL_GENERAL in tools_b
        assert TOOL_TENANT_A_ONLY not in tools_b
        assert TOOL_TENANT_B_ONLY in tools_b
        assert TOOL_TENANT_A_AND_C not in tools_b
        assert TOOL_SET_ADMIN_TENANT_A not in tools_b

        # Test Tool Set Filtering
        logger.info("--- Test: Tenant A tools/list, filter by tool_set 'reporting' ---")
        tools_a_reporting = await client_a.list_tools(http_client, tool_set_filter="reporting")
        logger.info(f"Tenant A sees 'reporting' tools: {tools_a_reporting}")
        assert TOOL_SET_REPORTING in tools_a_reporting
        assert TOOL_GLOBAL_GENERAL not in tools_a_reporting
        assert TOOL_SET_ADMIN_TENANT_A not in tools_a_reporting
        
        logger.info("--- Test: Tenant A tools/list, filter by tool_set 'admin_tasks' ---")
        tools_a_admin = await client_a.list_tools(http_client, tool_set_filter="admin_tasks")
        logger.info(f"Tenant A sees 'admin_tasks' tools: {tools_a_admin}")
        assert TOOL_SET_ADMIN_TENANT_A in tools_a_admin
        assert TOOL_SET_REPORTING not in tools_a_admin 

        logger.info("--- Test: Tenant B tools/list, filter by tool_set 'reporting' ---")
        tools_b_reporting = await client_b.list_tools(http_client, tool_set_filter="reporting")
        logger.info(f"Tenant B sees 'reporting' tools: {tools_b_reporting}")
        
        # Check if reporting tool is visible to tenant B based on its availability
        if TOOL_SET_REPORTING in await client_b.list_tools(http_client):
            assert TOOL_SET_REPORTING in tools_b_reporting, "If TOOL_SET_REPORTING is visible to B, it should be found by filter"
        else:
            assert TOOL_SET_REPORTING not in tools_b_reporting, "If TOOL_SET_REPORTING is not visible to B, filter shouldn't find it"

        # Test Tenant Call Permissions
        logger.info(f"--- Test: Tenant A calls its own scoped tool ({TOOL_TENANT_A_ONLY}) ---")
        response_call_a_own = await client_a.call_tool(http_client, TOOL_TENANT_A_ONLY)
        assert response_call_a_own.status_code == 200, (
            f"Tenant A failed to call its own tool. Status: {response_call_a_own.status_code}, "
            f"Body: {response_call_a_own.text}"
        )
        logger.info(f"Tenant A successfully called '{TOOL_TENANT_A_ONLY}'.")

        logger.info(f"--- Test: Tenant A calls Tenant B's scoped tool ({TOOL_TENANT_B_ONLY}) - expect failure (403) ---")
        response_call_a_for_b = await client_a.call_tool(http_client, TOOL_TENANT_B_ONLY)
        assert response_call_a_for_b.status_code == 403, (
            f"Tenant A should NOT call B's tool. Expected 403, got {response_call_a_for_b.status_code}. "
            f"Body: {response_call_a_for_b.text}"
        )
        logger.info(f"Tenant A correctly prevented from calling '{TOOL_TENANT_B_ONLY}'.")
        
        logger.info(f"--- Test: Tenant A calls Global tool ({TOOL_GLOBAL_GENERAL}) ---")
        response_call_a_global = await client_a.call_tool(http_client, TOOL_GLOBAL_GENERAL)
        assert response_call_a_global.status_code == 200, (
            f"Tenant A failed to call global tool. Status: {response_call_a_global.status_code}, "
            f"Body: {response_call_a_global.text}"
        )
        logger.info(f"Tenant A successfully called global tool '{TOOL_GLOBAL_GENERAL}'.")

        logger.info(f"--- Test: Tenant C calls shared tool ({TOOL_TENANT_A_AND_C}) ---")
        response_call_c_shared = await client_c.call_tool(http_client, TOOL_TENANT_A_AND_C)
        assert response_call_c_shared.status_code == 200, (
            f"Tenant C failed to call shared tool ACD. Status: {response_call_c_shared.status_code}, "
            f"Body: {response_call_c_shared.text}"
        )
        logger.info(f"Tenant C successfully called shared tool '{TOOL_TENANT_A_AND_C}'.")

        logger.info(f"--- Test: Tenant B tries to call shared tool ({TOOL_TENANT_A_AND_C}) - expect failure (403) ---")
        response_call_b_shared_fail = await client_b.call_tool(http_client, TOOL_TENANT_A_AND_C)
        assert response_call_b_shared_fail.status_code == 403, (
            f"Tenant B should NOT call AC shared tool. Expected 403, got {response_call_b_shared_fail.status_code}. "
            f"Body: {response_call_b_shared_fail.text}"
        )
        logger.info(f"Tenant B correctly prevented from calling '{TOOL_TENANT_A_AND_C}'.")

    logger.info("Tool Sets and Tenant Scoping Test Suite COMPLETED.")


if __name__ == "__main__":
    if not missing_tokens:
        asyncio.run(main())