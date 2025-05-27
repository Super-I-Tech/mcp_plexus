# mcp_plexus/storage/__init__.py

"""Storage module initialization.

This module provides a unified interface for database operations,
currently supporting SQLite database connections and initialization.
"""

from .sqlite_base import (
    get_sqlite_db_connection,
    init_sqlite_db,
    close_sqlite_db_connection
)

# Export public API for database operations
__all__ = [
    "get_sqlite_db_connection",
    "init_sqlite_db", 
    "close_sqlite_db_connection"
]