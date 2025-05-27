# mcp_plexus/oauth/user_token_store.py
import logging
from typing import Optional, Dict, Any
import json

import redis.asyncio as aioredis

from ..settings import settings as plexus_global_settings
from .storage_interfaces import AbstractUserExternalTokenStore
from .sqlite_user_external_token_store import get_sqlite_user_external_token_store

logger = logging.getLogger(__name__)


class RedisUserExternalTokenStore(AbstractUserExternalTokenStore):
    """Redis implementation for storing user external OAuth tokens."""
    
    _redis_client: Optional[aioredis.Redis] = None
    USER_EXTERNAL_TOKEN_BUNDLE_TTL_SECONDS: Optional[int] = 3600 * 24 * 90  # 90 days default

    def __init__(self, token_bundle_ttl_seconds: Optional[int] = None):
        """Initialize Redis token store with optional custom TTL."""
        if token_bundle_ttl_seconds is not None:
            self.USER_EXTERNAL_TOKEN_BUNDLE_TTL_SECONDS = token_bundle_ttl_seconds
        logger.info(
            f"RedisUserExternalTokenStore initialized. TTL: {self.USER_EXTERNAL_TOKEN_BUNDLE_TTL_SECONDS}s."
        )

    async def initialize(self) -> None:
        """Establish Redis connection using global settings."""
        if self._redis_client:
            return
            
        connection_params = {
            "host": plexus_global_settings.redis_host,
            "port": plexus_global_settings.redis_port,
            "db": plexus_global_settings.redis_db,
            "decode_responses": False,
        }
        
        if plexus_global_settings.redis_password:
            connection_params["password"] = plexus_global_settings.redis_password
            
        try:
            self._redis_client = aioredis.Redis(**connection_params)  # type: ignore
            await self._redis_client.ping()
            logger.info("RedisUserExternalTokenStore: Connected.")
        except Exception as e:
            logger.error(f"RedisUserExternalTokenStore: Connect failed: {e}", exc_info=True)
            self._redis_client = None
            raise

    async def teardown(self) -> None:
        """Close Redis connection and cleanup resources."""
        if self._redis_client:
            await self._redis_client.close()
            self._redis_client = None
            logger.info("RedisUserExternalTokenStore: Closed.")

    async def _get_client(self) -> aioredis.Redis:
        """Get Redis client, initializing connection if needed."""
        if not self._redis_client:
            await self.initialize()
            if not self._redis_client:
                raise RuntimeError("RedisUserExternalTokenStore not initialized or connection failed.")
        return self._redis_client

    def _get_key(self, entity_id: str, user_id: str, provider_name: str) -> str:
        """Generate Redis key for user external token storage."""
        return f"plexus:user_ext_oauth:{entity_id}:{user_id}:{provider_name}"

    async def save_user_external_token(
        self, entity_id: str, user_id: str, provider_name: str, token_data: Dict[str, Any]
    ) -> None:
        """Save user external token data with automatic expiration."""
        client = await self._get_client()
        key = self._get_key(entity_id, user_id, provider_name)
        
        await client.set(
            key,
            json.dumps(token_data).encode("utf-8"),
            ex=self.USER_EXTERNAL_TOKEN_BUNDLE_TTL_SECONDS
        )
        logger.info(f"Saved Redis user ext token for E:{entity_id}, U:{user_id}, P:{provider_name}.")

    async def load_user_external_token(
        self, entity_id: str, user_id: str, provider_name: str
    ) -> Optional[Dict[str, Any]]:
        """Load user external token data, returning None if not found or corrupted."""
        client = await self._get_client()
        key = self._get_key(entity_id, user_id, provider_name)
        
        data_bytes = await client.get(key)
        if data_bytes:
            try:
                return json.loads(data_bytes.decode("utf-8"))
            except Exception as e:
                logger.error(
                    f"Error deserializing Redis user ext token E:{entity_id},U:{user_id},P:{provider_name}: {e}"
                )
                return None
        return None

    async def delete_user_external_token(
        self, entity_id: str, user_id: str, provider_name: str
    ) -> None:
        """Remove user external token from Redis storage."""
        client = await self._get_client()
        key = self._get_key(entity_id, user_id, provider_name)
        
        await client.delete(key)
        logger.info(f"Deleted Redis user ext token for E:{entity_id}, U:{user_id}, P:{provider_name}.")


# Global singleton instance for token store
_user_ext_token_store_instance: Optional[AbstractUserExternalTokenStore] = None


async def get_user_external_token_store() -> AbstractUserExternalTokenStore:
    """
    Factory function that returns the appropriate token store implementation
    based on global storage backend configuration. Ensures singleton pattern.
    """
    global _user_ext_token_store_instance
    
    if _user_ext_token_store_instance is None:
        if plexus_global_settings.storage_backend == "sqlite":
            logger.info("Using SQLiteUserExternalTokenStore for user-specific external tokens.")
            _user_ext_token_store_instance = await get_sqlite_user_external_token_store()
        elif plexus_global_settings.storage_backend == "redis":
            logger.info("Using RedisUserExternalTokenStore for user-specific external tokens.")
            _user_ext_token_store_instance = RedisUserExternalTokenStore()
            await _user_ext_token_store_instance.initialize()
        else:
            raise ValueError(
                f"Unsupported storage_backend for user external tokens: {plexus_global_settings.storage_backend}"
            )
    
    return _user_ext_token_store_instance