# tests/test_tool_requires_api_key.py
import httpx
import asyncio
import json
import logging
import os
from dotenv import load_dotenv
from uuid import uuid4
from typing import Any, Dict, Optional
from pathlib import Path

# Load environment variables from .env file if available
try:
    project_root = Path(__file__).resolve().parent.parent 
    dotenv_path = project_root / '.env'
    if dotenv_path.exists():
        load_dotenv(dotenv_path=dotenv_path, override=True)
    else:
        load_dotenv(override=True) 
except Exception:
    load_dotenv(override=True)

# Configuration constants from environment variables
BASE_URL = os.getenv("PLEXUS_BASE_URL", "http://127.0.0.1:8080") 
ENTITY_ID_FOR_TOOL_KEY_TEST = os.getenv("TEST_TOOL_API_KEY_ENTITY_ID", "test_tenant_tool_api_key") 
HOST_APP_SECRET = os.getenv("HOST_APP_REGISTRATION_SECRET")
MCP_PROTOCOL_VERSION = "2025-03-26"

# Test target configuration
TARGET_TOOL_NAME = "use_alpha_service_key_tool"
TARGET_PROVIDER_NAME = "my_test_service_alpha" 
TARGET_KEY_DISPLAY_NAME = "My Alpha Test Service Key"

SERVER_ENCRYPTION_KEY_SET = bool(os.getenv("PLEXUS_ENCRYPTION_KEY"))

# Configure logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s - %(name)s - [%(levelname)s] - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("ToolRequiresApiKeyTest") 

class FullFlowTestClient:
    """
    Test client that handles the complete flow of:
    1. User registration with Plexus
    2. MCP session initialization
    3. API key submission
    4. Tool execution that requires API keys
    """
    
    def __init__(self, base_url: str, entity_id: str):
        self.base_url = base_url
        self.entity_id = entity_id
        self.mcp_endpoint = f"{self.base_url}/{self.entity_id}/mcp/"
        self.services_endpoint_base = f"{self.base_url}/{self.entity_id}/plexus-services"
        self.plexus_auth_base = f"{self.base_url}/{self.entity_id}/plexus-auth"
        
        # Session state
        self.mcp_session_id: Optional[str] = None
        self.plexus_user_auth_token: Optional[str] = None
        self.persistent_user_id: Optional[str] = None
        self.request_counter = 0
        
        self.client_logger = logging.getLogger(f"ToolRequiresApiKeyTest.Client.{self.entity_id}")

    async def _make_generic_http_request(
        self, 
        http_client: httpx.AsyncClient, 
        method: str, 
        url: str, 
        json_payload: Optional[Dict[str, Any]] = None,
        data_payload: Optional[Dict[str, Any]] = None,
        expected_status: int = 200,
        extra_headers: Optional[Dict[str,str]] = None
    ) -> Optional[Dict[str, Any]]:
        """Generic HTTP request handler with error handling and response parsing"""
        final_headers = extra_headers or {}
        if 'Content-Type' not in final_headers and json_payload:
            final_headers.setdefault("Content-Type", "application/json")

        self.client_logger.debug(f"HTTP {method} to {url}. Headers: {final_headers}")
        
        try:
            response = await http_client.request(
                method, url, json=json_payload, data=data_payload, headers=final_headers
            )
            self.client_logger.debug(f"HTTP Response Status: {response.status_code}")
            
            assert response.status_code == expected_status, \
                f"Expected {expected_status}, got {response.status_code}. Response: {response.text}"
            
            if response.content:
                try:
                    return response.json()
                except json.JSONDecodeError:
                    self.client_logger.warning(f"Response for {url} not JSON, returning raw text container.")
                    return {
                        "_status_code": response.status_code, 
                        "_raw_text": response.text, 
                        "_headers": dict(response.headers)
                    }
            return {
                "_status_code": response.status_code, 
                "_raw_text": "", 
                "_headers": dict(response.headers)
            }
            
        except httpx.HTTPStatusError as e_http:
            self.client_logger.error(
                f"HTTP Error ({method} {url}): {e_http.response.status_code} - {e_http.response.text}"
            )
            try: 
                return e_http.response.json()
            except: 
                return {
                    "error": "http_status_error_no_json_body", 
                    "status_code": e_http.response.status_code, 
                    "detail": e_http.response.text
                }
        except Exception as e:
            self.client_logger.error(f"Unexpected error ({method} {url}): {e}", exc_info=True)
            return {"error": "unexpected_exception", "detail": str(e)}

    async def register_plexus_user(self, http_client: httpx.AsyncClient, host_app_user_id: str) -> bool:
        """Register a new user with the Plexus authentication system"""
        self.client_logger.info(f"Registering Plexus user '{host_app_user_id}' for entity '{self.entity_id}'...")
        
        payload = {"user_id_from_host_app": host_app_user_id}
        url = f"{self.plexus_auth_base}/register-user"
        headers = {"Content-Type": "application/json"} 
        
        if HOST_APP_SECRET:
            headers["X-Host-App-Secret"] = HOST_APP_SECRET
        else:
            self.client_logger.error("HOST_APP_SECRET not set for user registration.")
            return False
        
        response_data = await self._make_generic_http_request(
            http_client, "POST", url, json_payload=payload, extra_headers=headers
        )
        
        if response_data and response_data.get("plexus_user_auth_token"): 
            self.plexus_user_auth_token = response_data.get("plexus_user_auth_token")
            self.persistent_user_id = response_data.get("persistent_user_id")
            
            if self.plexus_user_auth_token and self.persistent_user_id:
                self.client_logger.info(
                    f"Plexus user '{self.persistent_user_id}' registered. Token: {self.plexus_user_auth_token[:10]}..."
                )
                return True
                
        self.client_logger.error(f"Plexus registration failed. Response: {response_data}")
        return False

    async def _make_mcp_protocol_request(
        self, 
        http_client: httpx.AsyncClient, 
        mcp_method: str, 
        mcp_params: Optional[Dict[str, Any]] = None,
        is_notification: bool = False,
        skip_default_bearer: bool = False 
    ) -> Optional[Dict[str, Any]]:
        """
        Handle MCP protocol requests with support for both JSON and SSE responses.
        Manages session IDs and authentication tokens automatically.
        """
        self.request_counter += 1
        req_id = f"mcp-fullflow-{self.entity_id}-{self.request_counter}" if not is_notification else None
        
        # Build MCP request payload according to JSON-RPC 2.0 specification
        payload: Dict[str, Any] = {"jsonrpc": "2.0", "method": mcp_method}
        if mcp_params: 
            payload["params"] = mcp_params
        if req_id: 
            payload["id"] = req_id
        
        # Set up headers with session and auth info
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if self.mcp_session_id: 
            headers["Mcp-Session-Id"] = self.mcp_session_id
        if self.plexus_user_auth_token and not skip_default_bearer: 
            headers["Authorization"] = f"Bearer {self.plexus_user_auth_token}"
        
        self.client_logger.info(f"MCP Request: ID={req_id}, Method={mcp_method}")
        
        try:
            response = await http_client.post(self.mcp_endpoint, json=payload, headers=headers)
            raw_response_text = response.text 
            response_status_code = response.status_code
            response_headers = dict(response.headers)
            
            self.client_logger.info(
                f"MCP Response for {mcp_method}(ID:{req_id}) - Status: {response_status_code}"
            )
            
            content_type = response_headers.get("content-type", "").lower()

            # Handle notification acceptance (HTTP 202)
            if response_status_code == 202 and is_notification:
                self.client_logger.info(f"Received HTTP 202 for notification '{mcp_method}'.")
                return {"_mcp_status": "accepted_notification"}

            # Handle HTTP errors
            if response_status_code >= 400:
                self.client_logger.error(
                    f"MCP request {mcp_method} (ID:{req_id}) failed with HTTP status: {response_status_code}"
                )
                try: 
                    parsed_mcp_json_data = response.json()
                except json.JSONDecodeError: 
                    parsed_mcp_json_data = None
                return {
                    "_http_error": True, 
                    "status_code": response_status_code, 
                    "detail": parsed_mcp_json_data or raw_response_text
                }

            # Handle empty responses (special case for initialize)
            if not response.content:
                if mcp_method == "initialize" and response_status_code == 200 and "mcp-session-id" in response_headers:
                    self.mcp_session_id = response_headers["mcp-session-id"]
                    self.client_logger.info(
                        f"initialize call had empty body but Mcp-Session-Id '{self.mcp_session_id}' was received."
                    )
                    return {
                        "_mcp_status": "initialize_empty_body_with_session_id", 
                        "id": req_id, 
                        "mcp_session_id": self.mcp_session_id
                    }
                return None

            # Parse response based on content type
            parsed_mcp_json_data = None
            
            if "application/json" in content_type:
                try: 
                    parsed_mcp_json_data = response.json()
                    self.client_logger.debug(f"Parsed application/json for {mcp_method} (ID:{req_id})")
                except json.JSONDecodeError as e: 
                    self.client_logger.error(
                        f"Failed to decode application/json response for {mcp_method} (ID:{req_id}). Err: {e}"
                    )
                    return {
                        "_json_decode_error": True, 
                        "raw_text": raw_response_text, 
                        "error_str": str(e)
                    }
                    
            elif "text/event-stream" in content_type:
                # Parse SSE format looking for 'data:' field
                self.client_logger.debug(f"Received text/event-stream for {mcp_method} (ID:{req_id})")
                for line in response.text.splitlines():
                     if line.startswith("data:"):
                        json_str = line[len("data:"):].strip()
                        try: 
                            parsed_mcp_json_data = json.loads(json_str)
                            self.client_logger.debug(
                                f"Successfully parsed JSON from SSE 'data:' for {mcp_method} (ID:{req_id})"
                            )
                            break 
                        except json.JSONDecodeError as e_json_sse:
                            self.client_logger.error(
                                f"Could not decode JSON from SSE 'data:' line for {mcp_method} (ID:{req_id}). Error: {e_json_sse}"
                            )
                            return {
                                "_sse_json_decode_error": True, 
                                "line": json_str, 
                                "raw_full_sse": raw_response_text, 
                                "error_str": str(e_json_sse)
                            }

            # Update session ID if provided in response headers
            if response_headers and "mcp-session-id" in response_headers:
                new_sid = response_headers["mcp-session-id"]
                if self.mcp_session_id != new_sid: 
                    self.mcp_session_id = new_sid
                    self.client_logger.info(f"MCP Session ID ('{mcp_method}') updated to {new_sid}")
            
            return parsed_mcp_json_data
            
        except httpx.HTTPStatusError as e_http: 
            self.client_logger.error(
                f"HTTPStatusError ({mcp_method} ID:{req_id}): {e_http.response.status_code}"
            )
            try: 
                return e_http.response.json() if e_http.response.content else {
                    "_http_error_status": True, 
                    "status_code": e_http.response.status_code, 
                    "detail": e_http.response.text
                }
            except: 
                return {
                    "_http_error_status": True, 
                    "status_code": e_http.response.status_code, 
                    "detail": e_http.response.text
                }
        except Exception as exc: 
            self.client_logger.error(
                f"Unexpected exception in _make_mcp_protocol_request for {mcp_method} (ID:{req_id}): {exc}", 
                exc_info=True
            )
        return None

    async def initialize_mcp_session(self, http_client: httpx.AsyncClient) -> bool:
        """Initialize MCP session with the server and send required notification"""
        if not self.plexus_user_auth_token: 
            self.client_logger.error("Cannot init MCP: Plexus user auth token missing on client instance.")
            return False
            
        client_info: Dict[str, Any] = {"name": "FullFlowTestClient", "version": "1.0.1"}
        params = {
            "protocolVersion": MCP_PROTOCOL_VERSION, 
            "capabilities": {}, 
            "clientInfo": client_info
        }

        # Initialize session
        init_response_json = await self._make_mcp_protocol_request(
            http_client, "initialize", mcp_params=params, skip_default_bearer=False
        )
        
        if (init_response_json and 
            not init_response_json.get("error") and 
            not init_response_json.get("_http_error") and 
            not init_response_json.get("_json_decode_error") and 
            not init_response_json.get("_sse_json_decode_error") and 
            self.mcp_session_id):
            
            self.client_logger.info(f"MCP session initialized with server. Session ID: {self.mcp_session_id}")
            
            # Send required initialized notification per MCP protocol
            notif_response = await self._make_mcp_protocol_request(
                http_client, "notifications/initialized", mcp_params={}, 
                is_notification=True, skip_default_bearer=False
            ) 
            return bool(notif_response and notif_response.get("_mcp_status") == "accepted_notification")
            
        self.client_logger.error(f"Failed to initialize MCP session. Current Session ID: {self.mcp_session_id}")
        return False

    async def submit_api_key(self, http_client: httpx.AsyncClient, provider: str, key_value: str) -> bool:
        """Submit an API key for a specific provider to the Plexus services"""
        if not self.plexus_user_auth_token: 
            self.client_logger.error("Cannot submit API key: Plexus user not authenticated on client instance.")
            return False
            
        url = f"{self.services_endpoint_base}/api-keys"
        payload = {"provider_name": provider, "api_key_value": key_value}
        headers = {"Authorization": f"Bearer {self.plexus_user_auth_token}"}
        
        response_data = await self._make_generic_http_request(
            http_client, "POST", url, json_payload=payload, extra_headers=headers
        )
        return bool(response_data and "message" in response_data and provider in response_data["message"])

    async def call_mcp_tool(self, http_client: httpx.AsyncClient, tool_name: str, arguments: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Call an MCP tool and extract the result payload"""
        if not self.mcp_session_id: 
            self.client_logger.error(f"Tool '{tool_name}': No MCP session ID.")
            return None
        
        full_mcp_response_json = await self._make_mcp_protocol_request(
            http_client, 
            "tools/call", 
            mcp_params={"name": tool_name, "arguments": arguments},
            skip_default_bearer=False
        )
        return self._extract_tool_result_payload(full_mcp_response_json)
    
    def _extract_tool_result_payload(self, mcp_response_json: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Extract the actual tool result payload from MCP response format.
        Handles both successful results and error conditions.
        """
        if not mcp_response_json: 
            return None
        
        # Check for request/parsing errors
        if (mcp_response_json.get("_http_error") or 
            mcp_response_json.get("_json_decode_error") or 
            mcp_response_json.get("_sse_json_decode_error")):
            return mcp_response_json

        # Check for MCP protocol errors
        if mcp_response_json.get("error"): 
            self.client_logger.error(f"MCP Protocol Error received: {mcp_response_json['error']}")
            return {"_mcp_protocol_error": True, "detail": mcp_response_json['error']}
        
        result = mcp_response_json.get("result")
        
        # Handle tool execution errors (isError=True)
        if isinstance(result, dict) and result.get("isError"):
            error_content_list = result.get('content', [])
            if (error_content_list and 
                isinstance(error_content_list[0], dict) and 
                isinstance(error_content_list[0].get("text"), str)):
                try: 
                    # Parse JSON from error text (expected for plexus_api_key_required)
                    return json.loads(error_content_list[0]["text"]) 
                except json.JSONDecodeError as e: 
                    self.client_logger.error(
                        f"Could not parse JSON from 'isError' tool error text. Error: {e}"
                    )
                    return {
                        "_mcp_tool_error_unparsed_text": error_content_list[0]["text"], 
                        "detail": str(e)
                    } 
            return {"_mcp_tool_error_raw_content": error_content_list}
        
        # Handle successful tool results
        if (isinstance(result, dict) and 
            result.get("content") and 
            isinstance(result["content"], list) and 
            result["content"]):
            
            first_content = result["content"][0]
            if (isinstance(first_content, dict) and 
                "text" in first_content and 
                isinstance(first_content["text"], str)):
                try: 
                    return json.loads(first_content["text"])
                except json.JSONDecodeError as e: 
                    self.client_logger.error(f"Failed to parse successful tool result text. Error: {e}")
                    return {"_payload_is_raw_text": True, "text": first_content['text']}
            elif isinstance(first_content, dict) and "structuredContent" in first_content:
                return first_content["structuredContent"]
        
        self.client_logger.warning(f"Could not extract expected tool payload from result: {result}")
        return None

async def run_api_key_tool_test_flow():
    """
    Execute the complete test flow:
    1. Register user and initialize MCP session
    2. Call tool without API key (expect error)
    3. Submit API key
    4. Call tool again (expect success)
    """
    logger.info(f"--- Test: Tool requiring API Key for Entity: {ENTITY_ID_FOR_TOOL_KEY_TEST} ---")
    test_user_id = f"fullflow_user_{uuid4().hex[:6]}"
    dummy_api_key_value = f"test_key_val_for_{test_user_id}_{uuid4().hex[:8]}"

    client = FullFlowTestClient(base_url=BASE_URL, entity_id=ENTITY_ID_FOR_TOOL_KEY_TEST)

    async with httpx.AsyncClient(timeout=30.0) as http_client:
        # Setup: Register user and initialize MCP session
        assert await client.register_plexus_user(http_client, test_user_id), "User registration failed"
        assert client.plexus_user_auth_token, "Plexus Auth Token not set after registration"
        assert await client.initialize_mcp_session(http_client), "MCP session initialization failed"
        assert client.mcp_session_id, "MCP Session ID not set after initialization"

        # Test 1: Call tool without API key (should fail with specific error)
        logger.info(f"Attempting to call '{TARGET_TOOL_NAME}' (expecting API key required error)...")
        tool_args = {"some_other_param": f"run_value_1_{uuid4().hex[:4]}"} 
        
        extracted_payload_1 = await client.call_mcp_tool(http_client, TARGET_TOOL_NAME, tool_args)
        
        assert extracted_payload_1 is not None, "First tool call did not return an extractable payload"
        assert isinstance(extracted_payload_1, dict), \
            f"extracted_payload_1 is not a dict. Got type: {type(extracted_payload_1)}"
        
        # Verify we get the expected API key required error
        assert extracted_payload_1.get("error") == "plexus_api_key_required", \
            f"Expected 'plexus_api_key_required' error. Got: {json.dumps(extracted_payload_1, indent=2)}"
        assert extracted_payload_1.get("provider_name") == TARGET_PROVIDER_NAME
        assert extracted_payload_1.get("key_name_display") == TARGET_KEY_DISPLAY_NAME
        assert "instructions" in extracted_payload_1
        
        logger.info(f"Correctly received PlexusApiKeyRequiredError for provider '{TARGET_PROVIDER_NAME}'.")

        # Submit the required API key
        logger.info(f"Submitting API key for '{TARGET_PROVIDER_NAME}'...")
        submit_ok = await client.submit_api_key(http_client, TARGET_PROVIDER_NAME, dummy_api_key_value)
        assert submit_ok, "API Key submission failed"
        logger.info(f"API Key for '{TARGET_PROVIDER_NAME}' submitted successfully.")
        
        # Brief pause to allow key processing
        await asyncio.sleep(0.3) 

        # Test 2: Call tool with API key (should succeed)
        logger.info(f"Attempting to call '{TARGET_TOOL_NAME}' again (expecting success this time)...")
        tool_args_2 = {"some_other_param": f"run_value_2_{uuid4().hex[:4]}"} 
        extracted_payload_2 = await client.call_mcp_tool(http_client, TARGET_TOOL_NAME, tool_args_2)
        
        assert extracted_payload_2 is not None, "Second tool call did not return an extractable payload"
        
        if isinstance(extracted_payload_2, dict):
            assert extracted_payload_2.get("error") != "plexus_api_key_required", \
                f"Second tool call STILL resulted in 'plexus_api_key_required' error: {json.dumps(extracted_payload_2, indent=2)}"
            assert "_mcp_protocol_error" not in extracted_payload_2, \
                f"Second tool call resulted in an MCP protocol error: {extracted_payload_2.get('detail')}"
        
        # Verify successful tool execution results
        assert isinstance(extracted_payload_2, dict), \
            f"Expected dict payload from successful second call, got {type(extracted_payload_2)}"
        assert "retrieved_api_key_fragment" in extracted_payload_2, \
            f"Tool response missing 'retrieved_api_key_fragment'"
        assert extracted_payload_2["retrieved_api_key_fragment"].startswith(dummy_api_key_value[:10]), \
            f"Retrieved API key fragment does not match submitted key"
        assert extracted_payload_2.get("provider_name_used") == TARGET_PROVIDER_NAME, \
            f"provider_name_used mismatch. Expected '{TARGET_PROVIDER_NAME}'"
        assert extracted_payload_2.get("received_other_param") == tool_args_2["some_other_param"], \
            f"received_other_param mismatch"
        
        logger.info(f"Tool '{TARGET_TOOL_NAME}' successfully called with API key for '{TARGET_PROVIDER_NAME}'.")
    
    logger.info(f"--- Test: Tool requiring API Key for Entity '{ENTITY_ID_FOR_TOOL_KEY_TEST}' PASSED ---")

async def main():
    """Main test execution function"""
    logger.info(f"Starting Full API Key Test Flow for entity: {ENTITY_ID_FOR_TOOL_KEY_TEST}")
    
    if not HOST_APP_SECRET:
        logger.error("CRITICAL: HOST_APP_REGISTRATION_SECRET must be set in .env for registration.")
        return
    if not SERVER_ENCRYPTION_KEY_SET:
         logger.warning("PLEXUS_ENCRYPTION_KEY check: Not set in client's env. Ensure it's set on SERVER SIDE.")
    
    await run_api_key_tool_test_flow()

if __name__ == "__main__":
    asyncio.run(main())