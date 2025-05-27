# mcp_plexus/oauth/sqlite_oauth_internal_client_store.py
import sqlite3
import logging
from typing import Optional, List

from .storage_interfaces import AbstractOAuthClientStore
from .models import OAuthClient
from ..storage.sqlite_base import get_sqlite_db_connection

logger = logging.getLogger(__name__)


class SQLiteOAuthClientStore(AbstractOAuthClientStore):
    """SQLite implementation of OAuth client storage for internal clients."""
    
    async def initialize(self) -> None:
        """Initialize the SQLite database connection and ensure tables exist."""
        await get_sqlite_db_connection()
        logger.info("SQLiteOAuthClientStore initialized.")

    async def teardown(self) -> None:
        """Clean up resources. Connection is managed globally."""
        logger.info("SQLiteOAuthClientStore teardown (connection managed globally).")

    async def _execute_query(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        """Execute a SQL query with error handling and transaction management."""
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
        """Execute a SELECT query and return a single row."""
        conn = await get_sqlite_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(query, params)
            return cursor.fetchone()
        except sqlite3.Error as e:
            logger.error(f"SQLite error during fetchone for query '{query}': {e}", exc_info=True)
            raise
            
    def _row_to_oauth_client(self, row: Optional[sqlite3.Row]) -> Optional[OAuthClient]:
        """Convert a database row to an OAuthClient object."""
        if not row or "client_data" not in row.keys() or not row["client_data"]:
            return None
        try:
            return OAuthClient.model_validate_json(row["client_data"])
        except Exception as e:
            logger.error(f"Error deserializing OAuthClient from row {row}: {e}", exc_info=True)
            return None

    async def save_client(self, client: OAuthClient) -> None:
        """Save or update an OAuth client in the database."""
        query = '''
            INSERT INTO internal_oauth_clients (client_id, entity_id, client_data)
            VALUES (?, ?, ?)
            ON CONFLICT(client_id) DO UPDATE SET
                entity_id=excluded.entity_id,
                client_data=excluded.client_data
        '''
        # Using "global" as default entity_id since current OAuthClient model doesn't include entity_id
        entity_id_for_storage = "global"
        
        params = (client.client_id, entity_id_for_storage, client.model_dump_json())
        await self._execute_query(query, params)
        logger.info(f"Saved internal OAuth client '{client.client_id}'.")

    async def load_client(self, client_id: str) -> Optional[OAuthClient]:
        """Load an OAuth client by client ID."""
        query = "SELECT client_data FROM internal_oauth_clients WHERE client_id = ?"
        row = await self._fetchone(query, (client_id,))
        return self._row_to_oauth_client(row)

    async def delete_client(self, client_id: str) -> None:
        """Delete an OAuth client by client ID."""
        query = "DELETE FROM internal_oauth_clients WHERE client_id = ?"
        await self._execute_query(query, (client_id,))
        logger.info(f"Deleted internal OAuth client '{client_id}'.")

    async def list_clients_for_entity(self, entity_id: str) -> List[OAuthClient]:
        """List all OAuth clients for a specific entity ID."""
        conn = await get_sqlite_db_connection()
        cursor = conn.cursor()
        query = "SELECT client_data FROM internal_oauth_clients WHERE entity_id = ?"
        try:
            cursor.execute(query, (entity_id,))
            rows = cursor.fetchall()
            clients = [
                self._row_to_oauth_client(row) 
                for row in rows 
                if self._row_to_oauth_client(row) is not None
            ]
            return clients
        except sqlite3.Error as e:
            logger.error(f"SQLite error listing clients for entity '{entity_id}': {e}", exc_info=True)
            return []


# Global singleton instance
_sqlite_oauth_client_store_instance: Optional[SQLiteOAuthClientStore] = None


async def get_sqlite_internal_oauth_client_store() -> SQLiteOAuthClientStore:
    """Get the singleton instance of SQLiteOAuthClientStore."""
    global _sqlite_oauth_client_store_instance
    if _sqlite_oauth_client_store_instance is None:
        _sqlite_oauth_client_store_instance = SQLiteOAuthClientStore()
        await _sqlite_oauth_client_store_instance.initialize()
    return _sqlite_oauth_client_store_instance