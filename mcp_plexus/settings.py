# mcp_plexus/settings.py
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from typing import List, Optional
import logging
from pathlib import Path

# Configure logging for settings module
logger = logging.getLogger(__name__)
if not logging.getLogger().hasHandlers():
    logging.basicConfig(
        level=logging.INFO, 
        format='%(asctime)s SETTINGS.PY - [%(levelname)s] - %(message)s'
    )

# Determine the project root dynamically from this file's location
# This settings.py file is at MCP_Plexus/mcp_plexus/settings.py
# Two .parent calls will get to MCP_Plexus/ directory
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
DOTENV_PATH = PROJECT_ROOT / ".env"

logger.info(f"SETTINGS.PY: Determined PROJECT_ROOT as: {PROJECT_ROOT}")
logger.info(f"SETTINGS.PY: Explicit .env path for pydantic-settings: {DOTENV_PATH}")

if DOTENV_PATH.exists():
    logger.info(f"SETTINGS.PY: .env file FOUND at explicit path: {DOTENV_PATH}")
else:
    logger.warning(
        f"SETTINGS.PY: .env file NOT FOUND at explicit path: {DOTENV_PATH}. "
        "Will rely on OS env vars or defaults."
    )


class Settings(BaseSettings):
    """Application settings with environment variable support."""
    
    app_name: str = "MCP Plexus"
    debug_mode: bool = False
    storage_backend: str = "sqlite"
    
    # Redis configuration
    # Note: MCP Session Management currently defaults to and requires Redis
    # This will be made more configurable in the future
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: Optional[str] = None
    redis_ssl: bool = False
    
    # SQLite configuration
    sqlite_db_path: str = "./mcp_plexus_data.sqlite3"
    
    # Logging and authentication settings
    plexus_fastmcp_log_level: str = "INFO"
    plexus_user_auth_token_bytes_length: int = 32
    plexus_user_auth_token_lifetime_days: Optional[int] = 90
    
    # Security settings
    host_app_registration_secret: Optional[str] = "default_secret_if_env_missing"
    admin_api_key: Optional[str] = Field(
        default=None, 
        description="API Key for accessing admin routes."
    )
    plexus_encryption_key: Optional[str] = Field(
        default=None, 
        description="Key for encrypting sensitive data like external API keys. MUST be set for production."
    )

    model_config = SettingsConfigDict(
        env_file=DOTENV_PATH if DOTENV_PATH.exists() else None,
        extra="ignore",
        env_file_encoding='utf-8'
    )


# Initialize settings instance
settings = Settings()

# Log configuration values for debugging (sensitive values are masked)
logger.info(
    f"SETTINGS.PY: Post-Settings() settings.host_app_registration_secret: "
    f"{'********' if settings.host_app_registration_secret else 'None'} (Type: {type(settings.host_app_registration_secret)})"
)
logger.info(
    f"SETTINGS.PY: Post-Settings() settings.debug_mode: "
    f"{settings.debug_mode} (Type: {type(settings.debug_mode)})"
)
logger.info(
    f"SETTINGS.PY: Post-Settings() settings.storage_backend: "
    f"'{settings.storage_backend}' (Type: {type(settings.storage_backend)})"
)
logger.info(
    f"SETTINGS.PY: Post-Settings() settings.redis_host: "
    f"'{settings.redis_host}' (Type: {type(settings.redis_host)})"
)
logger.info(
    f"SETTINGS.PY: Post-Settings() settings.plexus_fastmcp_log_level: "
    f"'{settings.plexus_fastmcp_log_level}' (Type: {type(settings.plexus_fastmcp_log_level)})"
)
logger.info(
    f"SETTINGS.PY: Post-Settings() settings.admin_api_key: "
    f"{'********' if settings.admin_api_key else 'None'} (Type: {type(settings.admin_api_key)})"
)