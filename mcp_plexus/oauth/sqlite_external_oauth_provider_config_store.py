# mcp_plexus/oauth/sqlite_external_oauth_provider_config_store.py
import sqlite3
import logging
from typing import Optional, List

from .storage_interfaces import AbstractExternalOAuthProviderConfigStore 
from .models import OAuthProviderSettings
from ..storage.sqlite_base import get_sqlite_db_connection

logger = logging.getLogger(__name__)


class SQLiteExternalOAuthProviderConfigStore(AbstractExternalOAuthProviderConfigStore):
    """SQLite implementation for storing external OAuth provider configurations."""
    
    async def initialize(self) -> None:
        """Initialize the store by ensuring database connection is available."""
        await get_sqlite_db_connection()
        logger.info("SQLiteExternalOAuthProviderConfigStore initialized.")

    async def teardown(self) -> None:
        """Teardown the store. Connection is managed globally, so no cleanup needed."""
        logger.info("SQLiteExternalOAuthProviderConfigStore teardown (connection managed globally).")

    async def _execute_query(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        """Execute a query that modifies data with proper transaction handling."""
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
        """Execute a query and return a single row result."""
        conn = await get_sqlite_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(query, params)
            return cursor.fetchone()
        except sqlite3.Error as e:
            logger.error(f"SQLite error during fetchone for query '{query}': {e}", exc_info=True)
            raise
            
    async def _fetchall(self, query: str, params: tuple = ()) -> List[sqlite3.Row]:
        """Execute a query and return all matching rows."""
        conn = await get_sqlite_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(query, params)
            return cursor.fetchall()
        except sqlite3.Error as e:
            logger.error(f"SQLite error during fetchall for query '{query}': {e}", exc_info=True)
            raise

    def _row_to_provider_settings(self, row: Optional[sqlite3.Row]) -> Optional[OAuthProviderSettings]:
        """Convert a database row to OAuthProviderSettings object with error handling."""
        if not row or "config_data" not in row.keys() or not row["config_data"]:
            return None
        try:
            return OAuthProviderSettings.model_validate_json(row["config_data"])
        except Exception as e:
            logger.error(f"Error deserializing OAuthProviderSettings from row {row}: {e}", exc_info=True)
            return None

    async def save_provider_config(self, entity_id: str, provider_config: OAuthProviderSettings) -> None:
        """Save or update a provider configuration using upsert pattern."""
        query = '''
            INSERT INTO external_oauth_provider_configs (entity_id, provider_name, config_data)
            VALUES (?, ?, ?)
            ON CONFLICT(entity_id, provider_name) DO UPDATE SET
                config_data=excluded.config_data
        '''
        config_data_json = provider_config.model_dump_json()
        params = (entity_id, provider_config.provider_name, config_data_json)
        await self._execute_query(query, params)
        logger.info(f"Saved external provider config '{provider_config.provider_name}' for entity '{entity_id}'.")

    async def load_provider_config(self, entity_id: str, provider_name: str) -> Optional[OAuthProviderSettings]:
        """Load a specific provider configuration for an entity."""
        query = "SELECT config_data FROM external_oauth_provider_configs WHERE entity_id = ? AND provider_name = ?"
        row = await self._fetchone(query, (entity_id, provider_name))
        return self._row_to_provider_settings(row)

    async def delete_provider_config(self, entity_id: str, provider_name: str) -> None:
        """Delete a specific provider configuration for an entity."""
        query = "DELETE FROM external_oauth_provider_configs WHERE entity_id = ? AND provider_name = ?"
        await self._execute_query(query, (entity_id, provider_name))
        logger.info(f"Deleted external provider config '{provider_name}' for entity '{entity_id}'.")

    async def load_all_provider_configs_for_entity(self, entity_id: str) -> List[OAuthProviderSettings]:
        """Load all provider configurations for a specific entity, filtering out invalid ones."""
        query = "SELECT config_data FROM external_oauth_provider_configs WHERE entity_id = ?"
        rows = await self._fetchall(query, (entity_id,))
        configs = []
        for row in rows:
            cfg = self._row_to_provider_settings(row)
            if cfg:
                configs.append(cfg)
        return configs


# Global singleton instance for the store
_sqlite_ext_oauth_provider_config_store_instance: Optional[SQLiteExternalOAuthProviderConfigStore] = None


async def get_sqlite_external_oauth_provider_config_store() -> SQLiteExternalOAuthProviderConfigStore:
    """Get or create a singleton instance of the SQLite external OAuth provider config store."""
    global _sqlite_ext_oauth_provider_config_store_instance
    if _sqlite_ext_oauth_provider_config_store_instance is None:
        _sqlite_ext_oauth_provider_config_store_instance = SQLiteExternalOAuthProviderConfigStore()
        await _sqlite_ext_oauth_provider_config_store_instance.initialize()
    return _sqlite_ext_oauth_provider_config_store_instance