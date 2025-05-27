# mcp_plexus/plexus_auth/sqlite_user_auth_token_store.py
import sqlite3
import logging
from typing import Optional
from datetime import datetime, timezone

from .storage_interfaces import AbstractPlexusUserAuthTokenStore
from .models import PlexusUserAuthTokenData
from ..storage.sqlite_base import get_sqlite_db_connection

logger = logging.getLogger(__name__)


class SQLitePlexusUserAuthTokenStore(AbstractPlexusUserAuthTokenStore):
    """SQLite implementation for storing and managing user authentication tokens."""
    
    async def initialize(self) -> None:
        """Initialize the token store by ensuring database connection."""
        await get_sqlite_db_connection()
        logger.info("SQLitePlexusUserAuthTokenStore initialized (tables ensured by sqlite_base).")

    async def teardown(self) -> None:
        """Clean up resources - connection is managed globally."""
        logger.info("SQLitePlexusUserAuthTokenStore teardown (connection managed globally).")

    async def _execute_query(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        """Execute a SQL query with proper error handling and transaction management."""
        conn = await get_sqlite_db_connection()
        cursor = conn.cursor()
        try:
            logger.debug(f"Executing SQL: {query} with params: {params}")
            cursor.execute(query, params)
            conn.commit()
        except sqlite3.Error as e:
            logger.error(f"SQLite error executing query '{query}': {e}", exc_info=True)
            conn.rollback()
            raise
        return cursor

    async def _fetchone(self, query: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        """Execute a SELECT query and return a single row."""
        conn = await get_sqlite_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(query, params)
            return cursor.fetchone()
        except sqlite3.Error as e:
            logger.error(f"SQLite error during fetchone for query '{query}': {e}", exc_info=True)
            raise 

    def _row_to_token_data(self, row: Optional[sqlite3.Row]) -> Optional[PlexusUserAuthTokenData]:
        """Convert a database row to a PlexusUserAuthTokenData object."""
        if not row:
            return None
        try:
            return PlexusUserAuthTokenData(
                entity_id=row["entity_id"],
                persistent_user_id=row["persistent_user_id"],
                token_hash=row["token_hash"],
                created_at=row["created_at"],
                last_used_at=row["last_used_at"]
            )
        except Exception as e:
            logger.error(f"Error converting row to PlexusUserAuthTokenData: {row}. Error: {e}", exc_info=True)
            return None

    async def save_token_data(self, token_data: PlexusUserAuthTokenData) -> None:
        """
        Save token data with upsert behavior.
        Handles conflicts on both (entity_id, persistent_user_id) and token_hash uniqueness.
        """
        query = '''
            INSERT INTO plexus_user_auth_tokens (entity_id, persistent_user_id, token_hash, created_at, last_used_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(entity_id, persistent_user_id) DO UPDATE SET
                token_hash=excluded.token_hash,
                created_at=excluded.created_at,
                last_used_at=excluded.last_used_at
            ON CONFLICT(token_hash) DO UPDATE SET 
                entity_id=excluded.entity_id,
                persistent_user_id=excluded.persistent_user_id,
                created_at=excluded.created_at,
                last_used_at=excluded.last_used_at
        '''
        params = (
            token_data.entity_id,
            token_data.persistent_user_id,
            token_data.token_hash,
            token_data.created_at,
            token_data.last_used_at if token_data.last_used_at else datetime.now(timezone.utc).isoformat()
        )
        await self._execute_query(query, params)
        logger.info(f"Saved PlexusUserAuthTokenData for user '{token_data.persistent_user_id}' in entity '{token_data.entity_id}'.")

    async def get_token_data_by_hash(self, token_hash: str) -> Optional[PlexusUserAuthTokenData]:
        """Retrieve token data by token hash."""
        query = "SELECT * FROM plexus_user_auth_tokens WHERE token_hash = ?"
        row = await self._fetchone(query, (token_hash,))
        return self._row_to_token_data(row)

    async def get_token_data_by_user_id(self, entity_id: str, persistent_user_id: str) -> Optional[PlexusUserAuthTokenData]:
        """Retrieve token data by entity ID and user ID combination."""
        query = "SELECT * FROM plexus_user_auth_tokens WHERE entity_id = ? AND persistent_user_id = ?"
        row = await self._fetchone(query, (entity_id, persistent_user_id))
        return self._row_to_token_data(row)

    async def delete_token_data_by_hash(self, token_hash: str) -> None:
        """Delete token data by token hash."""
        query = "DELETE FROM plexus_user_auth_tokens WHERE token_hash = ?"
        await self._execute_query(query, (token_hash,))
        logger.info(f"Deleted PlexusUserAuthTokenData by hash: {token_hash[:10]}...")

    async def delete_token_data_by_user_id(self, entity_id: str, persistent_user_id: str) -> None:
        """Delete token data by entity ID and user ID combination."""
        query = "DELETE FROM plexus_user_auth_tokens WHERE entity_id = ? AND persistent_user_id = ?"
        await self._execute_query(query, (entity_id, persistent_user_id))
        logger.info(f"Deleted PlexusUserAuthTokenData for user '{persistent_user_id}' in entity '{entity_id}'.")

    async def update_token_last_used(self, token_hash: str) -> None:
        """Update the last used timestamp for a token to track activity."""
        query = "UPDATE plexus_user_auth_tokens SET last_used_at = ? WHERE token_hash = ?"
        now_iso = datetime.now(timezone.utc).isoformat()
        await self._execute_query(query, (now_iso, token_hash))
        logger.debug(f"Updated last_used_at for token hash {token_hash[:10]}...")


# Global singleton instance management
_sqlite_plexus_user_auth_token_store_instance: Optional[SQLitePlexusUserAuthTokenStore] = None


async def get_sqlite_plexus_user_auth_token_store() -> SQLitePlexusUserAuthTokenStore:
    """Get or create the singleton SQLite token store instance."""
    global _sqlite_plexus_user_auth_token_store_instance
    if _sqlite_plexus_user_auth_token_store_instance is None:
        _sqlite_plexus_user_auth_token_store_instance = SQLitePlexusUserAuthTokenStore()
        await _sqlite_plexus_user_auth_token_store_instance.initialize()
    return _sqlite_plexus_user_auth_token_store_instance