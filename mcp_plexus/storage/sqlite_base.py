# mcp_plexus/storage/sqlite_base.py
import sqlite3
import logging
from pathlib import Path
from typing import Optional

from ..settings import settings

logger = logging.getLogger(__name__)

# Global connection instance to ensure single connection per application lifecycle
_db_connection: Optional[sqlite3.Connection] = None


async def get_sqlite_db_connection() -> sqlite3.Connection:
    """
    Get or create a SQLite database connection with proper initialization.
    
    Uses a singleton pattern to maintain a single connection throughout
    the application lifecycle. Ensures the database directory exists
    and initializes the schema on first connection.
    
    Returns:
        sqlite3.Connection: The database connection instance
        
    Raises:
        sqlite3.Error: If database connection fails
    """
    global _db_connection
    if _db_connection is None:
        try:
            db_path = Path(settings.sqlite_db_path).resolve()
            # Ensure the database directory structure exists
            db_path.parent.mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Attempting to connect to SQLite DB at: {db_path}")
            
            # Enable thread-safe access for async/FastAPI compatibility
            _db_connection = sqlite3.connect(str(db_path), check_same_thread=False)
            # Enable column access by name instead of index
            _db_connection.row_factory = sqlite3.Row
            
            logger.info(f"Successfully connected to SQLite DB: {db_path}")
            
            # Initialize database schema if tables don't exist
            await init_sqlite_db(_db_connection)
        except sqlite3.Error as e:
            logger.error(
                f"Error connecting to SQLite database at {settings.sqlite_db_path}: {e}",
                exc_info=True
            )
            raise
    return _db_connection


async def init_sqlite_db(conn: Optional[sqlite3.Connection] = None):
    """
    Initialize the SQLite database schema by creating all required tables.
    
    Creates tables for authentication tokens, OAuth configurations, tenant
    management, and API key storage. Uses IF NOT EXISTS to safely handle
    repeated initialization calls.
    
    Args:
        conn: Optional database connection. If None, uses the global connection.
    """
    db_conn = conn or await get_sqlite_db_connection()
    cursor = db_conn.cursor()
    
    # Plexus internal authentication tokens for users
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS plexus_user_auth_tokens (
        entity_id TEXT NOT NULL,
        persistent_user_id TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL,
        last_used_at TEXT,
        PRIMARY KEY (entity_id, persistent_user_id)
    )
    ''')
    logger.info("Ensured 'plexus_user_auth_tokens' table exists.")

    # User-specific OAuth tokens from external providers
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user_external_oauth_tokens (
        entity_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        provider_name TEXT NOT NULL,
        token_data TEXT NOT NULL,
        PRIMARY KEY (entity_id, user_id, provider_name)
    )
    ''')
    logger.info("Ensured 'user_external_oauth_tokens' table exists.")

    # Configuration settings for external OAuth providers
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS external_oauth_provider_configs (
        entity_id TEXT NOT NULL,
        provider_name TEXT NOT NULL,
        config_data TEXT NOT NULL,
        PRIMARY KEY (entity_id, provider_name)
    )
    ''')
    logger.info("Ensured 'external_oauth_provider_configs' table exists.")
    
    # Authorization codes when Plexus acts as OAuth Authorization Server
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS internal_oauth_auth_codes (
        code TEXT PRIMARY KEY,
        auth_code_data TEXT NOT NULL,
        expires_at TEXT NOT NULL
    )
    ''')
    logger.info("Ensured 'internal_oauth_auth_codes' table exists.")
    
    # Access tokens issued by Plexus OAuth server
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS internal_oauth_access_tokens (
        access_token TEXT PRIMARY KEY,
        access_token_data TEXT NOT NULL,
        expires_at TEXT NOT NULL
    )
    ''')
    logger.info("Ensured 'internal_oauth_access_tokens' table exists.")

    # Refresh tokens for token renewal
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS internal_oauth_refresh_tokens (
        refresh_token TEXT PRIMARY KEY,
        refresh_token_data TEXT NOT NULL
    )
    ''')
    logger.info("Ensured 'internal_oauth_refresh_tokens' table exists.")

    # OAuth client registry for applications using Plexus as OAuth server
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS internal_oauth_clients (
        client_id TEXT PRIMARY KEY,
        entity_id TEXT NOT NULL,
        client_data TEXT NOT NULL
    )
    ''')
    logger.info("Ensured 'internal_oauth_clients' table exists.")

    # Multi-tenant support - tenant configuration and management
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS plexus_tenants (
        entity_id TEXT PRIMARY KEY,
        tenant_name TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        created_at TEXT NOT NULL,
        settings_json TEXT
    )
    ''')
    logger.info("Ensured 'plexus_tenants' table exists.")

    # User API keys for non-OAuth external services
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user_external_api_keys (
        entity_id TEXT NOT NULL,
        persistent_user_id TEXT NOT NULL,
        provider_name TEXT NOT NULL,
        encrypted_api_key_value TEXT NOT NULL,
        registered_at TEXT NOT NULL,
        last_updated_at TEXT NOT NULL,
        PRIMARY KEY (entity_id, persistent_user_id, provider_name)
    )
    ''')
    logger.info("Ensured 'user_external_api_keys' table exists.")
    
    db_conn.commit()
    logger.info("SQLite database schema initialized/verified.")


async def close_sqlite_db_connection():
    """
    Properly close the global SQLite database connection.
    
    Should be called during application shutdown to ensure
    proper cleanup of database resources.
    """
    global _db_connection
    if _db_connection is not None:
        logger.info("Closing SQLite DB connection.")
        _db_connection.close()
        _db_connection = None
        logger.info("SQLite DB connection closed.")