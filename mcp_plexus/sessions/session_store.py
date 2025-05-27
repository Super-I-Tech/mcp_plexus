# mcp_plexus/sessions/session_store.py
import logging
from abc import ABC, abstractmethod
from typing import Optional
import redis.asyncio as aioredis

from ..settings import settings as plexus_global_settings
from .session_data import SessionData

# Global logger instance to avoid repeated initialization
_session_store_logger_instance = None


def _get_session_store_logger():
    """
    Returns a singleton logger instance for session store operations.
    Sets appropriate log level based on debug mode and global settings.
    """
    global _session_store_logger_instance
    if _session_store_logger_instance is None:
        _session_store_logger_instance = logging.getLogger(__name__)
        effective_level = (
            logging.DEBUG 
            if plexus_global_settings.debug_mode 
            else plexus_global_settings.plexus_fastmcp_log_level.upper()
        )
        _session_store_logger_instance.setLevel(effective_level)
    return _session_store_logger_instance


class AbstractSessionStore(ABC):
    """
    Abstract base class defining the interface for session storage implementations.
    """
    
    @abstractmethod
    async def load_session(self, session_key: str) -> Optional[SessionData]:
        """Load session data by session key."""
        pass
    
    @abstractmethod
    async def save_session(self, session_data: SessionData) -> None:
        """Save session data to storage."""
        pass
    
    @abstractmethod
    async def delete_session(self, session_key: str) -> None:
        """Delete session data by session key."""
        pass
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the session store."""
        pass
    
    @abstractmethod
    async def teardown(self) -> None:
        """Clean up session store resources."""
        pass

    def _construct_redis_key(self, entity_id: str, mcp_session_id: str) -> str:
        """
        Constructs a standardized Redis key for session storage.
        Format: plexus:session:{entity_id}:{mcp_session_id}
        """
        if not entity_id or not mcp_session_id:
            raise ValueError(
                "entity_id and mcp_session_id are required to construct a session key."
            )
        return f"plexus:session:{entity_id}:{mcp_session_id}"


class RedisPlexusSessionStore(AbstractSessionStore):
    """
    Redis-based implementation of session storage with automatic TTL management.
    """
    
    _redis_client: Optional[aioredis.Redis] = None
    SESSION_TTL_SECONDS: int = 3600 * 24  # Default 24 hours

    def __init__(self, session_ttl_seconds: Optional[int] = None):
        """
        Initialize Redis session store with optional custom TTL.
        
        Args:
            session_ttl_seconds: Custom TTL for sessions, defaults to 24 hours
        """
        if session_ttl_seconds is not None:
            self.SESSION_TTL_SECONDS = session_ttl_seconds
        _get_session_store_logger().info(
            f"RedisPlexusSessionStore initialized. Session TTL: {self.SESSION_TTL_SECONDS}s"
        )

    async def initialize(self) -> None:
        """
        Establishes connection to Redis server using global settings.
        Skips initialization if client already exists.
        """
        if self._redis_client:
            _get_session_store_logger().warning(
                "Redis client already initialized. Skipping re-initialization."
            )
            return

        # Build connection parameters from global settings
        connection_params = {
            "host": plexus_global_settings.redis_host,
            "port": plexus_global_settings.redis_port,
            "db": plexus_global_settings.redis_db,
            "decode_responses": False,  # Keep as bytes for explicit encoding control
        }
        if plexus_global_settings.redis_password:
            connection_params["password"] = plexus_global_settings.redis_password
        
        logger = _get_session_store_logger()
        logger.info(
            f"Connecting to Redis at {connection_params['host']}:"
            f"{connection_params['port']}, DB: {connection_params['db']}"
        )
        
        try:
            self._redis_client = aioredis.Redis(**connection_params)
            await self._redis_client.ping()
            logger.info("Successfully connected to Redis and pinged.")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}", exc_info=True)
            self._redis_client = None
            raise

    async def teardown(self) -> None:
        """
        Properly closes Redis connection and cleans up resources.
        """
        logger = _get_session_store_logger()
        if self._redis_client:
            logger.info("Closing Redis connection.")
            await self._redis_client.close()
            self._redis_client = None
            logger.info("Redis connection closed.")
        else:
            logger.info("No active Redis connection to close.")

    async def _get_client(self) -> aioredis.Redis:
        """
        Returns the Redis client, ensuring it's properly initialized.
        
        Raises:
            RuntimeError: If client is not initialized
        """
        if not self._redis_client:
            _get_session_store_logger().error(
                "Redis client not initialized. Call initialize() first."
            )
            raise RuntimeError(
                "RedisPlexusSessionStore not initialized. Call initialize() first."
            )
        return self._redis_client

    async def load_session(self, session_key: str) -> Optional[SessionData]:
        """
        Loads session data from Redis by key.
        
        Args:
            session_key: The Redis key to load session data from
            
        Returns:
            SessionData object if found and valid, None otherwise
        """
        client = await self._get_client()
        logger = _get_session_store_logger()
        logger.debug(f"Attempting to load session for key: '{session_key}'")
        
        try:
            session_json_bytes = await client.get(session_key)
            
            if session_json_bytes:
                try:
                    session_json_str = session_json_bytes.decode("utf-8")
                    session_data_obj = SessionData.model_validate_json(session_json_str)
                    logger.debug(f"Successfully loaded session for key: '{session_key}'")
                    return session_data_obj
                except Exception as e:
                    logger.error(
                        f"Error deserializing session for key {session_key}: {e}", 
                        exc_info=True
                    )
                    return None
            else:
                logger.debug(f"No session found for key: '{session_key}'")
                return None
        except Exception as e:
            logger.error(f"Error loading session for key {session_key}: {e}", exc_info=True)
            return None

    async def save_session(self, session_data: SessionData) -> None:
        """
        Saves session data to Redis with automatic TTL.
        
        Args:
            session_data: SessionData object to save
        """
        if not isinstance(session_data, SessionData):
            logger = _get_session_store_logger()
            logger.error("Invalid session_data type provided to save_session")
            return

        client = await self._get_client()
        logger = _get_session_store_logger()
        
        session_key = self._construct_redis_key(
            session_data.entity_id, session_data.mcp_session_id
        )
        
        logger.debug(f"Attempting to save session for key: '{session_key}'")
        
        try:
            # Update last accessed timestamp
            session_data.touch()
            
            # Serialize to JSON and encode for Redis storage
            session_json_str = session_data.model_dump_json()
            
            set_result = await client.set(
                session_key,
                session_json_str.encode("utf-8"),
                ex=self.SESSION_TTL_SECONDS,
            )
            
            # Verify the save operation was successful
            exists_after_set = await client.exists(session_key)
            
            if set_result and exists_after_set:
                logger.debug(
                    f"Successfully saved session for key: '{session_key}', "
                    f"TTL: {self.SESSION_TTL_SECONDS}s"
                )
            else:
                logger.error(
                    f"Failed to save session for key: '{session_key}'. "
                    f"SET result: {set_result}, EXISTS: {exists_after_set}"
                )

        except Exception as e:
            logger.error(f"Error saving session for key {session_key}: {e}", exc_info=True)

    async def delete_session(self, session_key: str) -> None:
        """
        Deletes session data from Redis by key.
        
        Args:
            session_key: The Redis key to delete
        """
        client = await self._get_client()
        logger = _get_session_store_logger()
        logger.debug(f"Deleting session for key: {session_key}")
        
        try:
            deleted_count = await client.delete(session_key)
            if deleted_count > 0:
                logger.info(f"Session deleted successfully for key: {session_key}")
            else:
                logger.info(f"No session found to delete for key: {session_key}")
        except Exception as e:
            logger.error(f"Error deleting session for key {session_key}: {e}", exc_info=True)