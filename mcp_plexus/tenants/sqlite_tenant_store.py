# mcp_plexus/tenants/sqlite_tenant_store.py
import sqlite3
import logging
import json
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

from .storage_interfaces import AbstractTenantStore
from .models import TenantInDB, TenantCreate, TenantUpdate
from ..storage.sqlite_base import get_sqlite_db_connection

logger = logging.getLogger(__name__)


class SQLiteTenantStore(AbstractTenantStore):
    """SQLite implementation of the tenant storage interface."""

    async def initialize(self) -> None:
        """Initialize the tenant store by ensuring database and table exist."""
        await get_sqlite_db_connection()
        logger.info("SQLiteTenantStore initialized.")

    async def teardown(self) -> None:
        """Clean up resources. Connection is managed globally so no action needed."""
        logger.info("SQLiteTenantStore teardown (connection managed globally).")

    async def _execute_query(self, query: str, params: tuple = (), commit: bool = True) -> sqlite3.Cursor:
        """
        Execute a SQL query with proper error handling and transaction management.
        
        Args:
            query: SQL query string
            params: Query parameters tuple
            commit: Whether to commit the transaction
            
        Returns:
            sqlite3.Cursor: The cursor after query execution
            
        Raises:
            sqlite3.Error: If query execution fails
        """
        conn = await get_sqlite_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(query, params)
            if commit:
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"SQLite error executing query '{query}': {e}", exc_info=True)
            if commit:
                conn.rollback()
            raise
        return cursor

    async def _fetchone(self, query: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        """Execute a query and return a single row."""
        cursor = await self._execute_query(query, params, commit=False)
        return cursor.fetchone()

    async def _fetchall(self, query: str, params: tuple = ()) -> List[sqlite3.Row]:
        """Execute a query and return all matching rows."""
        cursor = await self._execute_query(query, params, commit=False)
        return cursor.fetchall()

    def _row_to_tenant_in_db(self, row: Optional[sqlite3.Row]) -> Optional[TenantInDB]:
        """
        Convert a database row to a TenantInDB object.
        
        Handles datetime parsing and JSON deserialization with error recovery.
        """
        if not row:
            return None
        
        try:
            # Handle datetime conversion - SQLite may store as string or datetime
            created_at = row["created_at"]
            if isinstance(created_at, str):
                created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            
            return TenantInDB(
                entity_id=row["entity_id"],
                tenant_name=row["tenant_name"],
                status=row["status"],
                created_at=created_at,
                settings_json=json.loads(row["settings_json"]) if row["settings_json"] else {}
            )
        except Exception as e:
            logger.error(f"Error converting row to TenantInDB: {row}. Error: {e}", exc_info=True)
            return None

    async def create_tenant(self, tenant_create: TenantCreate) -> TenantInDB:
        """
        Create a new tenant in the database.
        
        Args:
            tenant_create: Tenant creation data
            
        Returns:
            TenantInDB: The created tenant with generated timestamp
            
        Raises:
            ValueError: If tenant with same entity_id already exists
        """
        # Check for existing tenant to prevent duplicates
        existing = await self.get_tenant_by_entity_id(tenant_create.entity_id)
        if existing:
            raise ValueError(f"Tenant with entity_id '{tenant_create.entity_id}' already exists.")

        created_at_dt = datetime.now(timezone.utc)
        created_at_iso = created_at_dt.isoformat()
        settings_str = json.dumps(tenant_create.settings_json or {})

        query = """
            INSERT INTO plexus_tenants (entity_id, tenant_name, status, created_at, settings_json)
            VALUES (?, ?, ?, ?, ?)
        """
        params = (
            tenant_create.entity_id,
            tenant_create.tenant_name,
            tenant_create.status,
            created_at_iso,
            settings_str
        )
        
        await self._execute_query(query, params)
        
        return TenantInDB(
            entity_id=tenant_create.entity_id,
            tenant_name=tenant_create.tenant_name,
            status=tenant_create.status,
            created_at=created_at_dt,
            settings_json=tenant_create.settings_json or {}
        )

    async def get_tenant_by_entity_id(self, entity_id: str) -> Optional[TenantInDB]:
        """Retrieve a tenant by its entity ID."""
        query = """
            SELECT entity_id, tenant_name, status, created_at, settings_json 
            FROM plexus_tenants 
            WHERE entity_id = ?
        """
        row = await self._fetchone(query, (entity_id,))
        return self._row_to_tenant_in_db(row)

    async def list_tenants(self, skip: int = 0, limit: int = 100) -> List[TenantInDB]:
        """
        Retrieve a paginated list of tenants ordered by creation date (newest first).
        
        Args:
            skip: Number of records to skip for pagination
            limit: Maximum number of records to return
            
        Returns:
            List of TenantInDB objects, excluding any that failed to parse
        """
        query = """
            SELECT entity_id, tenant_name, status, created_at, settings_json 
            FROM plexus_tenants 
            ORDER BY created_at DESC 
            LIMIT ? OFFSET ?
        """
        rows = await self._fetchall(query, (limit, skip))
        
        # Filter out None values from failed conversions
        return [
            tenant for row in rows 
            if (tenant := self._row_to_tenant_in_db(row)) is not None
        ]

    async def update_tenant(self, entity_id: str, tenant_update: TenantUpdate) -> Optional[TenantInDB]:
        """
        Update an existing tenant with partial data.
        
        Args:
            entity_id: The tenant's entity ID
            tenant_update: Partial update data (only set fields will be updated)
            
        Returns:
            Updated TenantInDB object or None if tenant not found
        """
        current_tenant = await self.get_tenant_by_entity_id(entity_id)
        if not current_tenant:
            return None

        # Extract only the fields that were explicitly set
        update_fields: Dict[str, Any] = tenant_update.model_dump(exclude_unset=True)
        if not update_fields:
            return current_tenant

        # Build dynamic UPDATE query based on provided fields
        set_clauses = []
        params = []
        for key, value in update_fields.items():
            set_clauses.append(f"{key} = ?")
            if key == "settings_json":
                params.append(json.dumps(value or {}))
            else:
                params.append(value)

        query = f"UPDATE plexus_tenants SET {', '.join(set_clauses)} WHERE entity_id = ?"
        params.append(entity_id)

        await self._execute_query(query, tuple(params))
        return await self.get_tenant_by_entity_id(entity_id)

    async def delete_tenant(self, entity_id: str) -> bool:
        """
        Delete a tenant by entity ID.
        
        Returns:
            bool: True if a tenant was deleted, False if no tenant found
        """
        query = "DELETE FROM plexus_tenants WHERE entity_id = ?"
        cursor = await self._execute_query(query, (entity_id,))
        return cursor.rowcount > 0


# Singleton instance management
_sqlite_tenant_store_instance: Optional[SQLiteTenantStore] = None


async def get_sqlite_tenant_store() -> SQLiteTenantStore:
    """
    Get or create the singleton SQLiteTenantStore instance.
    
    Ensures only one instance exists and is properly initialized.
    """
    global _sqlite_tenant_store_instance
    if _sqlite_tenant_store_instance is None:
        _sqlite_tenant_store_instance = SQLiteTenantStore()
        await _sqlite_tenant_store_instance.initialize()
    return _sqlite_tenant_store_instance