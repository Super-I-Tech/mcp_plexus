import sqlite3
import logging
from typing import Optional
from datetime import datetime

from ..oauth.storage_interfaces import AbstractUserExternalApiKeyStore 
from .models import StoredUserExternalApiKey
from ..storage.sqlite_base import get_sqlite_db_connection
from ..utils.security import FernetEncryptor
from ..settings import settings

logger = logging.getLogger(__name__)


class SQLiteUserExternalApiKeyStore(AbstractUserExternalApiKeyStore):
    """SQLite implementation for storing and managing user external API keys with encryption."""
    
    def __init__(self):
        """Initialize the store with encryption capabilities."""
        self._encryptor = FernetEncryptor(settings.plexus_encryption_key)
        if not self._encryptor.key_valid:
            logger.critical(
                "SQLiteUserExternalApiKeyStore: PLEXUS_ENCRYPTION_KEY is invalid or not set. "
                "API key storage will be compromised or fail."
            )

    async def initialize(self) -> None:
        """Initialize the database connection and ensure tables exist."""
        await get_sqlite_db_connection() 
        logger.info("SQLiteUserExternalApiKeyStore initialized (tables ensured by sqlite_base).")

    async def teardown(self) -> None:
        """Clean up resources during shutdown."""
        logger.info("SQLiteUserExternalApiKeyStore teardown (connection managed globally).")

    async def _execute_query(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        """Execute a write query with proper error handling and transaction management."""
        conn = await get_sqlite_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(query, params)
            conn.commit()
        except sqlite3.Error as e:
            logger.error(f"SQLite error executing query '{query}': {e}", exc_info=True)
            conn.rollback()
            raise
        return cursor

    async def _fetchone(self, query: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        """Execute a read query and return a single row."""
        conn = await get_sqlite_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(query, params)
            return cursor.fetchone()
        except sqlite3.Error as e:
            logger.error(f"SQLite error during fetchone for query '{query}': {e}", exc_info=True)
            raise 
            
    def _row_to_stored_key_data(self, row: Optional[sqlite3.Row]) -> Optional[StoredUserExternalApiKey]:
        """Convert a database row to a StoredUserExternalApiKey model instance."""
        if not row:
            return None
        try:
            return StoredUserExternalApiKey(
                entity_id=row["entity_id"],
                persistent_user_id=row["persistent_user_id"],
                provider_name=row["provider_name"],
                encrypted_api_key_value=row["encrypted_api_key_value"],
                registered_at=datetime.fromisoformat(
                    row["registered_at"].replace("Z", "+00:00")
                ) if isinstance(row["registered_at"], str) else row["registered_at"],
                last_updated_at=datetime.fromisoformat(
                    row["last_updated_at"].replace("Z", "+00:00")
                ) if isinstance(row["last_updated_at"], str) else row["last_updated_at"],
            )
        except Exception as e:
            logger.error(
                f"Error converting row to StoredUserExternalApiKey: {row}. Error: {e}", 
                exc_info=True
            )
            return None

    async def save_api_key(self, api_key_data: StoredUserExternalApiKey) -> None:
        """Save or update an encrypted API key in the database."""
        if not self._encryptor.key_valid or not self._encryptor.fernet_instance:
            logger.error("Cannot save API key: Encryption service is not properly configured.")
            raise RuntimeError("Encryption service unavailable for saving API key.")

        # Use UPSERT to handle both insert and update scenarios
        query = """
            INSERT INTO user_external_api_keys 
            (entity_id, persistent_user_id, provider_name, encrypted_api_key_value, registered_at, last_updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(entity_id, persistent_user_id, provider_name) DO UPDATE SET
                encrypted_api_key_value=excluded.encrypted_api_key_value,
                last_updated_at=excluded.last_updated_at
        """
        
        params = (
            api_key_data.entity_id,
            api_key_data.persistent_user_id,
            api_key_data.provider_name,
            api_key_data.encrypted_api_key_value, 
            api_key_data.registered_at.isoformat(),
            api_key_data.last_updated_at.isoformat()
        )
        
        await self._execute_query(query, params)
        logger.info(
            f"Saved user external API key for E:{api_key_data.entity_id}, "
            f"U:{api_key_data.persistent_user_id}, P:{api_key_data.provider_name}."
        )

    async def load_api_key_data(
        self, 
        entity_id: str, 
        persistent_user_id: str, 
        provider_name: str
    ) -> Optional[StoredUserExternalApiKey]:
        """Load encrypted API key data from the database."""
        query = """
            SELECT * FROM user_external_api_keys 
            WHERE entity_id = ? AND persistent_user_id = ? AND provider_name = ?
        """
        
        row = await self._fetchone(query, (entity_id, persistent_user_id, provider_name))
        return self._row_to_stored_key_data(row)

    async def delete_api_key(
        self, 
        entity_id: str, 
        persistent_user_id: str, 
        provider_name: str
    ) -> bool:
        """Delete an API key from the database and return whether deletion was successful."""
        query = """
            DELETE FROM user_external_api_keys 
            WHERE entity_id = ? AND persistent_user_id = ? AND provider_name = ?
        """
        
        cursor = await self._execute_query(query, (entity_id, persistent_user_id, provider_name))
        deleted = cursor.rowcount > 0
        
        if deleted:
            logger.info(
                f"Deleted user external API key for E:{entity_id}, "
                f"U:{persistent_user_id}, P:{provider_name}."
            )
        else:
            logger.info(
                f"No API key found to delete for E:{entity_id}, "
                f"U:{persistent_user_id}, P:{provider_name}."
            )
        
        return deleted


# Global singleton instance management
_sqlite_user_external_api_key_store_instance: Optional[SQLiteUserExternalApiKeyStore] = None


async def get_sqlite_user_external_api_key_store() -> SQLiteUserExternalApiKeyStore:
    """Get or create the global SQLiteUserExternalApiKeyStore instance."""
    global _sqlite_user_external_api_key_store_instance
    if _sqlite_user_external_api_key_store_instance is None:
        _sqlite_user_external_api_key_store_instance = SQLiteUserExternalApiKeyStore()
        await _sqlite_user_external_api_key_store_instance.initialize()
    return _sqlite_user_external_api_key_store_instance