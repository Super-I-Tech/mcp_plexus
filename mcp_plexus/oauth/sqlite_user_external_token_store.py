# mcp_plexus/oauth/sqlite_user_external_token_store.py
import sqlite3
import logging
import json
from typing import Optional, Dict, Any

from .storage_interfaces import AbstractUserExternalTokenStore 
from ..storage.sqlite_base import get_sqlite_db_connection

logger = logging.getLogger(__name__)


class SQLiteUserExternalTokenStore(AbstractUserExternalTokenStore):
    """SQLite implementation for storing user external OAuth tokens."""
    
    async def initialize(self) -> None:
        """Initialize the token store by ensuring database connection and tables exist."""
        await get_sqlite_db_connection() 
        logger.info("SQLiteUserExternalTokenStore initialized (tables ensured by sqlite_base).")

    async def teardown(self) -> None:
        """Clean up resources. Connection is managed globally, so no action needed."""
        logger.info("SQLiteUserExternalTokenStore teardown (connection managed globally).")

    async def _execute_query(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        """
        Execute a SQL query with proper error handling and transaction management.
        Commits on success, rolls back on error.
        """
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
        """Execute a SELECT query and return a single row result."""
        conn = await get_sqlite_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(query, params)
            return cursor.fetchone()
        except sqlite3.Error as e:
            logger.error(f"SQLite error during fetchone for query '{query}': {e}", exc_info=True)
            raise

    async def save_user_external_token(
        self, entity_id: str, user_id: str, provider_name: str, token_data: Dict[str, Any]
    ) -> None:
        """
        Save or update user external OAuth token data.
        Uses UPSERT pattern to handle both insert and update scenarios.
        """
        query = '''
            INSERT INTO user_external_oauth_tokens (entity_id, user_id, provider_name, token_data)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(entity_id, user_id, provider_name) DO UPDATE SET
                token_data=excluded.token_data
        '''
        token_data_json = json.dumps(token_data)
        params = (entity_id, user_id, provider_name, token_data_json)
        await self._execute_query(query, params)
        logger.info(f"Saved user external token for E:{entity_id}, U:{user_id}, P:{provider_name}.")

    async def load_user_external_token(
        self, entity_id: str, user_id: str, provider_name: str
    ) -> Optional[Dict[str, Any]]:
        """
        Load user external OAuth token data for the specified entity, user, and provider.
        Returns None if token doesn't exist or JSON deserialization fails.
        """
        query = """
            SELECT token_data 
            FROM user_external_oauth_tokens 
            WHERE entity_id = ? AND user_id = ? AND provider_name = ?
        """
        row = await self._fetchone(query, (entity_id, user_id, provider_name))
        if row and row["token_data"]:
            try:
                return json.loads(row["token_data"])
            except json.JSONDecodeError as e:
                logger.error(
                    f"Error deserializing user external token for "
                    f"E:{entity_id}, U:{user_id}, P:{provider_name}: {e}", 
                    exc_info=True
                )
                return None
        return None

    async def delete_user_external_token(
        self, entity_id: str, user_id: str, provider_name: str
    ) -> None:
        """Delete user external OAuth token for the specified entity, user, and provider."""
        query = """
            DELETE FROM user_external_oauth_tokens 
            WHERE entity_id = ? AND user_id = ? AND provider_name = ?
        """
        await self._execute_query(query, (entity_id, user_id, provider_name))
        logger.info(f"Deleted user external token for E:{entity_id}, U:{user_id}, P:{provider_name}.")


# Global singleton instance management
_sqlite_user_external_token_store_instance: Optional[SQLiteUserExternalTokenStore] = None


async def get_sqlite_user_external_token_store() -> SQLiteUserExternalTokenStore:
    """
    Get or create the singleton SQLiteUserExternalTokenStore instance.
    Ensures only one instance exists throughout the application lifecycle.
    """
    global _sqlite_user_external_token_store_instance
    if _sqlite_user_external_token_store_instance is None:
        _sqlite_user_external_token_store_instance = SQLiteUserExternalTokenStore()
        await _sqlite_user_external_token_store_instance.initialize()
    return _sqlite_user_external_token_store_instance