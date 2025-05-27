# mcp_plexus/oauth/sqlite_oauth_internal_token_store.py
import sqlite3
import logging
from typing import Optional
from datetime import datetime, timezone

from .storage_interfaces import AbstractOAuthTokenStore 
from .models import AccessTokenData, RefreshTokenData
from ..storage.sqlite_base import get_sqlite_db_connection

logger = logging.getLogger(__name__)


class SQLiteOAuthTokenStore(AbstractOAuthTokenStore):
    """SQLite implementation of OAuth token storage for internal authentication."""
    
    async def initialize(self) -> None:
        """Initialize the SQLite connection and ensure database is ready."""
        await get_sqlite_db_connection()
        logger.info("SQLiteOAuthTokenStore initialized.")

    async def teardown(self) -> None:
        """Clean up resources during shutdown."""
        logger.info("SQLiteOAuthTokenStore teardown.")

    async def _execute_query(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        """Execute a write query with automatic commit/rollback handling."""
        conn = await get_sqlite_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(query, params)
            conn.commit()
        except sqlite3.Error as e:
            logger.error(f"SQLite error: {e}", exc_info=True)
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
            logger.error(f"SQLite error: {e}", exc_info=True)
            raise

    def _row_to_access_token_data(self, row: Optional[sqlite3.Row]) -> Optional[AccessTokenData]:
        """Convert database row to AccessTokenData object with error handling."""
        if not row:
            return None
        try:
            return AccessTokenData.model_validate_json(row["access_token_data"])
        except Exception as e:
            logger.error(f"Error deserializing AccessTokenData: {e}", exc_info=True)
            return None

    def _row_to_refresh_token_data(self, row: Optional[sqlite3.Row]) -> Optional[RefreshTokenData]:
        """Convert database row to RefreshTokenData object with error handling."""
        if not row:
            return None
        try:
            return RefreshTokenData.model_validate_json(row["refresh_token_data"])
        except Exception as e:
            logger.error(f"Error deserializing RefreshTokenData: {e}", exc_info=True)
            return None

    async def save_access_token(self, access_token_data: AccessTokenData) -> None:
        """Store or update an access token with upsert logic."""
        query = '''
            INSERT INTO internal_oauth_access_tokens (access_token, access_token_data, expires_at)
            VALUES (?, ?, ?)
            ON CONFLICT(access_token) DO UPDATE SET
                access_token_data=excluded.access_token_data,
                expires_at=excluded.expires_at
        '''
        expires_at_iso = access_token_data.expires_at.isoformat()
        params = (
            access_token_data.access_token,
            access_token_data.model_dump_json(),
            expires_at_iso
        )
        await self._execute_query(query, params)

    async def load_access_token(self, access_token: str) -> Optional[AccessTokenData]:
        """Retrieve an access token only if it hasn't expired."""
        query = '''
            SELECT access_token_data 
            FROM internal_oauth_access_tokens 
            WHERE access_token = ? AND expires_at > ?
        '''
        now_iso = datetime.now(timezone.utc).isoformat()
        row = await self._fetchone(query, (access_token, now_iso))
        return self._row_to_access_token_data(row)

    async def delete_access_token(self, access_token: str) -> None:
        """Remove an access token from storage."""
        query = "DELETE FROM internal_oauth_access_tokens WHERE access_token = ?"
        await self._execute_query(query, (access_token,))

    async def save_refresh_token(self, refresh_token_data: RefreshTokenData) -> None:
        """Store or update a refresh token with upsert logic."""
        query = '''
            INSERT INTO internal_oauth_refresh_tokens (refresh_token, refresh_token_data)
            VALUES (?, ?)
            ON CONFLICT(refresh_token) DO UPDATE SET
                refresh_token_data=excluded.refresh_token_data
        '''
        params = (
            refresh_token_data.refresh_token,
            refresh_token_data.model_dump_json()
        )
        await self._execute_query(query, params)

    async def load_refresh_token(self, refresh_token: str) -> Optional[RefreshTokenData]:
        """Retrieve a refresh token from storage."""
        query = "SELECT refresh_token_data FROM internal_oauth_refresh_tokens WHERE refresh_token = ?"
        row = await self._fetchone(query, (refresh_token,))
        return self._row_to_refresh_token_data(row)

    async def delete_refresh_token(self, refresh_token: str) -> None:
        """Remove a refresh token from storage."""
        query = "DELETE FROM internal_oauth_refresh_tokens WHERE refresh_token = ?"
        await self._execute_query(query, (refresh_token,))


# Global singleton instance for the OAuth token store
_sqlite_oauth_token_store_instance: Optional[SQLiteOAuthTokenStore] = None


async def get_sqlite_oauth_internal_token_store() -> SQLiteOAuthTokenStore:
    """Get or create the singleton SQLite OAuth token store instance."""
    global _sqlite_oauth_token_store_instance
    if _sqlite_oauth_token_store_instance is None:
        _sqlite_oauth_token_store_instance = SQLiteOAuthTokenStore()
        await _sqlite_oauth_token_store_instance.initialize()
    return _sqlite_oauth_token_store_instance