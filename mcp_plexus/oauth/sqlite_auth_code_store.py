# mcp_plexus/oauth/sqlite_auth_code_store.py
import sqlite3
import logging
from typing import Optional
from datetime import datetime, timezone

from .storage_interfaces import AbstractAuthCodeStore 
from .models import AuthCodeData
from ..storage.sqlite_base import get_sqlite_db_connection

logger = logging.getLogger(__name__)


class SQLiteAuthCodeStore(AbstractAuthCodeStore):
    """SQLite implementation of the abstract auth code store for OAuth flow."""

    async def initialize(self) -> None:
        """Initialize the SQLite auth code store by ensuring database connection."""
        await get_sqlite_db_connection()
        logger.info("SQLiteAuthCodeStore initialized.")

    async def teardown(self) -> None:
        """Clean up resources when shutting down the auth code store."""
        logger.info("SQLiteAuthCodeStore teardown.")

    async def _execute_query(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        """
        Execute a database query with proper error handling and transaction management.
        
        Args:
            query: SQL query string to execute
            params: Parameters to bind to the query
            
        Returns:
            Database cursor after query execution
            
        Raises:
            sqlite3.Error: If database operation fails
        """
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
        """
        Execute a SELECT query and return a single row.
        
        Args:
            query: SQL SELECT query string
            params: Parameters to bind to the query
            
        Returns:
            Single database row or None if no results
            
        Raises:
            sqlite3.Error: If database operation fails
        """
        conn = await get_sqlite_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(query, params)
            return cursor.fetchone()
        except sqlite3.Error as e:
            logger.error(f"SQLite error: {e}", exc_info=True)
            raise

    def _row_to_auth_code_data(self, row: Optional[sqlite3.Row]) -> Optional[AuthCodeData]:
        """
        Convert a database row to an AuthCodeData object.
        
        Args:
            row: Database row containing serialized auth code data
            
        Returns:
            Deserialized AuthCodeData object or None if conversion fails
        """
        if not row:
            return None
        try:
            return AuthCodeData.model_validate_json(row["auth_code_data"])
        except Exception as e:
            logger.error(f"Error deserializing AuthCodeData: {e}", exc_info=True)
            return None

    async def save_auth_code(self, auth_code_data: AuthCodeData) -> None:
        """
        Store an authorization code in the database.
        
        Args:
            auth_code_data: Authorization code data to store
        """
        query = '''
            INSERT INTO internal_oauth_auth_codes (code, auth_code_data, expires_at)
            VALUES (?, ?, ?)
        '''
        expires_at_iso = auth_code_data.expires_at.isoformat()
        params = (auth_code_data.code, auth_code_data.model_dump_json(), expires_at_iso)
        await self._execute_query(query, params)

    async def load_auth_code(self, code: str) -> Optional[AuthCodeData]:
        """
        Retrieve an authorization code from the database if it exists and hasn't expired.
        
        Args:
            code: Authorization code string to look up
            
        Returns:
            AuthCodeData if found and valid, None otherwise
        """
        query = "SELECT auth_code_data FROM internal_oauth_auth_codes WHERE code = ? AND expires_at > ?"
        now_iso = datetime.now(timezone.utc).isoformat()
        row = await self._fetchone(query, (code, now_iso))
        return self._row_to_auth_code_data(row)

    async def delete_auth_code(self, code: str) -> None:
        """
        Remove an authorization code from the database.
        
        Args:
            code: Authorization code string to delete
        """
        query = "DELETE FROM internal_oauth_auth_codes WHERE code = ?"
        await self._execute_query(query, (code,))


# Global singleton instance for the auth code store
_sqlite_auth_code_store_instance: Optional[SQLiteAuthCodeStore] = None


async def get_sqlite_auth_code_store() -> SQLiteAuthCodeStore:
    """
    Get or create a singleton instance of the SQLite auth code store.
    
    Returns:
        Initialized SQLiteAuthCodeStore instance
    """
    global _sqlite_auth_code_store_instance
    if _sqlite_auth_code_store_instance is None:
        _sqlite_auth_code_store_instance = SQLiteAuthCodeStore()
        await _sqlite_auth_code_store_instance.initialize()
    return _sqlite_auth_code_store_instance