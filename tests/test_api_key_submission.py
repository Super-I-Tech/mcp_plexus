# tests/test_api_key_submission.py
import httpx
import asyncio
import logging
import os
from dotenv import load_dotenv
from uuid import uuid4
from typing import Optional, Tuple
from pathlib import Path

# Load environment variables from project root .env file
try:
    project_root = Path(__file__).resolve().parent.parent 
    dotenv_path = project_root / '.env'
    if dotenv_path.exists():
        load_dotenv(dotenv_path=dotenv_path, override=True)
        logging.info(f"Loaded .env from: {dotenv_path}")
    else:
        logging.warning(f".env file not found at {dotenv_path}. Relying on OS environment variables.")
        load_dotenv(override=True)
except Exception as e_load:
    logging.error(f"Error loading .env: {e_load}. Relying on OS environment variables if set.")
    load_dotenv(override=True)

# Configuration from environment variables
BASE_URL = os.getenv("PLEXUS_BASE_URL", "http://127.0.0.1:8080")
ENTITY_ID_FOR_API_KEY_TEST = os.getenv("TEST_API_KEY_ENTITY_ID", "test_tenant_api_key") 
HOST_APP_SECRET = os.getenv("HOST_APP_REGISTRATION_SECRET")
SERVER_ENCRYPTION_KEY_SET = bool(os.getenv("PLEXUS_ENCRYPTION_KEY"))

if not HOST_APP_SECRET:
    print("CRITICAL ERROR: HOST_APP_REGISTRATION_SECRET is not set in environment. Test cannot effectively run user registration.")

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s - %(name)s - [%(levelname)s] - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("ApiKeySubmissionTest")

async def register_plexus_user_for_test(
    http_client: httpx.AsyncClient, entity_id: str, host_app_user_id: str
) -> Optional[Tuple[str, str]]:
    """
    Register a test user with Plexus to obtain authentication credentials.
    
    Returns:
        Tuple of (plexus_user_auth_token, persistent_user_id) if successful, None otherwise
    """
    logger.info(f"Registering Plexus user '{host_app_user_id}' for entity '{entity_id}' for API key test...")
    url = f"{BASE_URL}/{entity_id}/plexus-auth/register-user"
    payload = {"user_id_from_host_app": host_app_user_id}
    
    if not HOST_APP_SECRET:
        logger.error(f"Cannot register user: HOST_APP_REGISTRATION_SECRET is not set. Cannot proceed with registration for user '{host_app_user_id}'.")
        return None
        
    headers = {"X-Host-App-Secret": HOST_APP_SECRET, "Content-Type": "application/json"}
    
    try:
        response = await http_client.post(url, json=payload, headers=headers)
        logger.debug(f"User Reg Resp Status: {response.status_code}, Body: {response.text[:200]}")
        response.raise_for_status() 
        data = response.json()
        token = data.get("plexus_user_auth_token")
        p_user_id = data.get("persistent_user_id")
        if token and p_user_id:
            logger.info(f"Successfully registered Plexus user '{p_user_id}'. Token: {token[:10]}...")
            return token, p_user_id
        else:
            logger.error(f"Plexus user registration response missing token or persistent_user_id: {data}")
            return None
    except httpx.HTTPStatusError as e_http:
        logger.error(f"HTTP error during Plexus User Registration for '{host_app_user_id}': {e_http.response.status_code} - {e_http.response.text}")
        return None
    except Exception as e:
        logger.error(f"Exception during Plexus User Registration for '{host_app_user_id}': {e}", exc_info=True)
        return None

async def test_submit_api_key():
    """
    Test the complete flow of registering a user and submitting an API key.
    
    This test verifies that:
    1. A user can be registered with Plexus
    2. The registered user can successfully submit an API key
    3. The API key submission returns appropriate success response
    """
    logger.info(f"--- Test: API Key Submission for Entity: {ENTITY_ID_FOR_API_KEY_TEST} ---")
    host_app_user_id = f"apikey_submit_user_{uuid4().hex[:8]}"
    
    provider_name_to_test = "my_test_service_alpha"
    api_key_to_submit = f"dummy_secret_key_for_{provider_name_to_test}_{uuid4().hex[:6]}"

    async with httpx.AsyncClient(timeout=30.0) as client:
        # Register a user to get authentication token
        auth_info = await register_plexus_user_for_test(client, ENTITY_ID_FOR_API_KEY_TEST, host_app_user_id)
        if not auth_info:
            logger.error("Test Prerequisite FAILED: Plexus user registration failed. Cannot proceed with API key submission test.")
            assert False, "Plexus user registration prerequisite failed for API key submission test."
            return
            
        plexus_user_auth_token, persistent_user_id = auth_info
        logger.info(f"Using Plexus User Auth Token: {plexus_user_auth_token[:10]}... for Persistent User ID: {persistent_user_id}")

        # Submit the API Key using the authenticated user
        submit_url = f"{BASE_URL}/{ENTITY_ID_FOR_API_KEY_TEST}/plexus-services/api-keys"
        submit_payload = {
            "provider_name": provider_name_to_test,
            "api_key_value": api_key_to_submit
        }
        submit_headers = {
            "Authorization": f"Bearer {plexus_user_auth_token}",
            "Content-Type": "application/json"
        }
        
        logger.info(f"Attempting to submit API key for provider '{provider_name_to_test}' to {submit_url}...")
        try:
            submit_response = await client.post(submit_url, json=submit_payload, headers=submit_headers)
            
            logger.info(f"Submit API Key Response Status: {submit_response.status_code}")
            logger.info(f"Submit API Key Response Headers: {dict(submit_response.headers)}")
            if submit_response.content:
                 logger.info(f"Submit API Key Response Body: {submit_response.text}")

            assert submit_response.status_code == 200, \
                f"Expected 200 OK for API key submission, got {submit_response.status_code}. Body: {submit_response.text}"
            
            response_data = submit_response.json()
            assert "message" in response_data, "Success message missing in response."
            assert provider_name_to_test in response_data["message"], \
                f"Provider name '{provider_name_to_test}' not found in success message: {response_data['message']}"
            
            logger.info(f"API Key Submission successful: {response_data['message']}")

        except httpx.HTTPStatusError as e_submit:
            logger.error(f"HTTP error during API key submission: {e_submit.response.status_code} - {e_submit.response.text}")
            assert False, f"API Key submission failed with HTTP error: {e_submit.response.status_code}"
        except Exception as e_submit_other:
            logger.error(f"Unexpected error during API key submission: {e_submit_other}", exc_info=True)
            assert False, f"API Key submission failed with unexpected error: {e_submit_other}"

    logger.info("--- API Key Submission Test PASSED ---")
    
    # Provide manual verification instructions for database state
    logger.info("IMPORTANT: Please manually verify the 'user_external_api_keys' table in your database:")
    logger.info(f"  1. A row exists for entity_id='{ENTITY_ID_FOR_API_KEY_TEST}', persistent_user_id='{persistent_user_id}', provider_name='{provider_name_to_test}'.")
    logger.info(f"  2. The 'encrypted_api_key_value' column IS NOT '{api_key_to_submit}' (it MUST be encrypted).")
    logger.info("  3. 'registered_at' and 'last_updated_at' timestamps are valid.")
    if not SERVER_ENCRYPTION_KEY_SET:
        logger.warning("  CRITICAL WARNING: PLEXUS_ENCRYPTION_KEY was NOT detected in client's environment. If also not set on server, encryption WILL NOT occur and keys will be stored in plaintext!")
    else:
        logger.info("  (PLEXUS_ENCRYPTION_KEY was detected in client's env, assume server also has it correctly for actual encryption.)")

async def main():
    """
    Main entry point for the API key submission test.
    
    Performs environment validation and executes the test suite.
    """
    logger.info(f"Starting API Key Submission Test for entity: {ENTITY_ID_FOR_API_KEY_TEST}")
    logger.info(f"Ensure this tenant '{ENTITY_ID_FOR_API_KEY_TEST}' exists. CLI: plexus admin tenant create --entity-id {ENTITY_ID_FOR_API_KEY_TEST} --name 'API Key Test Tenant'")
    
    # Validate required environment configuration
    if not HOST_APP_SECRET:
        logger.error("HOST_APP_REGISTRATION_SECRET must be set in .env for user registration to work in this test.")
    if not SERVER_ENCRYPTION_KEY_SET:
        logger.warning("PLEXUS_ENCRYPTION_KEY is not set in this test script's environment. Please ensure it's set on the SERVER for encryption to actually occur.")
    
    await test_submit_api_key()

if __name__ == "__main__":
    asyncio.run(main())