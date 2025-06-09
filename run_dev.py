import uvicorn
from dotenv import load_dotenv
import os
from pathlib import Path 
import logging

# Configure logging before any application imports to ensure visibility
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s RUN_DEV.PY - [%(levelname)s] - %(message)s'
)
logger = logging.getLogger("run_dev_script")

if __name__ == "__main__":
    # Determine project root and .env file location
    project_root = Path(__file__).parent.resolve()
    dotenv_path_explicit = project_root / ".env"
    
    logger.info(f"Current working directory: {os.getcwd()}")
    logger.info(f"Project root (derived from __file__): {project_root}")
    logger.info(f"Expected .env path for load_dotenv: {dotenv_path_explicit}")
    
    # Load environment variables from .env file if it exists
    if dotenv_path_explicit.exists():
        logger.info(f".env file FOUND at: {dotenv_path_explicit}")
        # Override existing OS environment variables with .env values
        load_dotenv(dotenv_path=dotenv_path_explicit, override=True)
        logger.info(f"python-dotenv: Attempted to load .env from {dotenv_path_explicit}")
    else:
        logger.warning(f".env file NOT FOUND at: {dotenv_path_explicit}. "
                      "Will rely on OS environment variables or pydantic-settings defaults.")

    # Log key environment variables for verification
    _secret_val = os.getenv('HOST_APP_REGISTRATION_SECRET')
    logger.info(f"HOST_APP_REGISTRATION_SECRET: {'********' if _secret_val else 'None'}")
    logger.info(f"DEBUG_MODE: {os.getenv('DEBUG_MODE')}")
    logger.info(f"STORAGE_BACKEND: {os.getenv('STORAGE_BACKEND')}")
    logger.info(f"REDIS_HOST: {os.getenv('REDIS_HOST')}")
    logger.info(f"PLEXUS_FASTMCP_LOG_LEVEL: {os.getenv('PLEXUS_FASTMCP_LOG_LEVEL')}")

    # Configure development server settings
    host = os.getenv("DEV_SERVER_HOST", "127.0.0.1")
    port = int(os.getenv("DEV_SERVER_PORT", "8000"))
    uvicorn_log_level = os.getenv("DEV_SERVER_LOG_LEVEL", "info").lower()
    
    # Convert string environment variables to boolean values
    debug_mode_env_val = os.getenv("DEBUG_MODE", "False").lower()
    debug_mode_bool_for_reload = debug_mode_env_val in ["true", "1", "yes", "on", "t"]
    
    # Determine reload setting, defaulting to debug mode value
    default_reload = debug_mode_bool_for_reload
    reload_env_val = os.getenv("DEV_SERVER_RELOAD", str(default_reload)).lower()
    reload_bool = reload_env_val in ["true", "1", "yes", "on", "t"]

    logger.info(f"Starting Uvicorn server on {host}:{port}")
    logger.info(f"Uvicorn log level: {uvicorn_log_level}")
    logger.info(f"Reload: {reload_bool} (Debug Mode from env: '{debug_mode_env_val}' -> "
               f"interpreted as {debug_mode_bool_for_reload}, "
               f"DEV_SERVER_RELOAD: '{os.getenv('DEV_SERVER_RELOAD')}')")
    logger.info(f"App module: mcp_plexus.main:app")
    
    # Start the development server
    uvicorn.run(
        "mcp_plexus.main:app", 
        host=host,
        port=port,
        log_level=uvicorn_log_level,
        reload=reload_bool
    )