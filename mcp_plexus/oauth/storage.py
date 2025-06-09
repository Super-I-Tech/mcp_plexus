# mcp_plexus/oauth/storage.py
import logging
from typing import Optional, List, Union

import redis.asyncio as aioredis
from datetime import datetime, timezone

from ..settings import settings as plexus_global_settings
from .storage_interfaces import (
    AbstractAuthCodeStore, 
    AbstractOAuthTokenStore, 
    AbstractExternalOAuthProviderConfigStore, 
    AbstractOAuthClientStore
)
from .models import (
    AuthCodeData, 
    AccessTokenData, 
    RefreshTokenData, 
    OAuthProviderSettings, 
    OAuthClient
)

# SQLite implementations and their factory functions
from .sqlite_oauth_internal_token_store import (
    SQLiteOAuthTokenStore, 
    get_sqlite_oauth_internal_token_store
)
from .sqlite_auth_code_store import (
    SQLiteAuthCodeStore, 
    get_sqlite_auth_code_store
)
from .sqlite_external_oauth_provider_config_store import (
    SQLiteExternalOAuthProviderConfigStore, 
    get_sqlite_external_oauth_provider_config_store
)
from .sqlite_oauth_internal_client_store import (
    SQLiteOAuthClientStore, 
    get_sqlite_internal_oauth_client_store
)

logger = logging.getLogger(__name__)


class RedisAuthCodeStore(AbstractAuthCodeStore):
    """
    Redis-based storage for OAuth authorization codes with automatic expiration.
    
    Auth codes are temporary tokens with a short TTL for security purposes.
    """
    _redis_client: Optional[aioredis.Redis] = None
    AUTH_CODE_TTL_SECONDS: int = 600  # 10 minutes default TTL

    def __init__(self, auth_code_ttl_seconds: Optional[int] = None):
        if auth_code_ttl_seconds is not None:
            self.AUTH_CODE_TTL_SECONDS = auth_code_ttl_seconds
        logger.info(f"RedisAuthCodeStore initialized. TTL: {self.AUTH_CODE_TTL_SECONDS}s.")

    async def initialize(self) -> None:
        """Establish Redis connection with configured parameters."""
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
            self._redis_client = aioredis.Redis(**connection_params)
            await self._redis_client.ping()
            logger.info("RedisAuthCodeStore: Successfully connected to Redis.")
        except Exception as e:
            logger.error(f"RedisAuthCodeStore: Failed to connect: {e}", exc_info=True)
            self._redis_client = None
            raise
            
    async def teardown(self) -> None:
        """Clean up Redis connection."""
        if self._redis_client:
            await self._redis_client.close()
            self._redis_client = None
            logger.info("RedisAuthCodeStore: Connection closed.")

    async def _get_client(self) -> aioredis.Redis:
        """Get initialized Redis client or raise error if not ready."""
        if not self._redis_client:
            raise RuntimeError("RedisAuthCodeStore not initialized.")
        return self._redis_client

    def _get_key(self, code: str) -> str:
        """Generate Redis key for auth code storage."""
        return f"plexus:oauth:auth_code:{code}"

    async def save_auth_code(self, auth_code_data: AuthCodeData) -> None:
        """Save auth code with automatic expiration."""
        client = await self._get_client()
        await client.set(
            self._get_key(auth_code_data.code),
            auth_code_data.model_dump_json().encode("utf-8"),
            ex=self.AUTH_CODE_TTL_SECONDS
        )

    async def load_auth_code(self, code: str) -> Optional[AuthCodeData]:
        """Load and deserialize auth code data."""
        client = await self._get_client()
        data_bytes = await client.get(self._get_key(code))
        
        if data_bytes:
            try:
                return AuthCodeData.model_validate_json(data_bytes.decode("utf-8"))
            except Exception as e:
                logger.error(f"Error deserializing auth_code '{code}': {e}")
                return None
        return None

    async def delete_auth_code(self, code: str) -> None:
        """Remove auth code from storage."""
        client = await self._get_client()
        await client.delete(self._get_key(code))


class RedisOAuthTokenStore(AbstractOAuthTokenStore):
    """
    Redis-based storage for OAuth access and refresh tokens.
    
    Access tokens use their expiration time as TTL, while refresh tokens
    have a configurable storage TTL (default 90 days).
    """
    _redis_client: Optional[aioredis.Redis] = None
    REFRESH_TOKEN_STORAGE_TTL_SECONDS: Optional[int] = 3600 * 24 * 90  # 90 days

    def __init__(self, refresh_token_ttl: Optional[int] = None):
        if refresh_token_ttl is not None:
            self.REFRESH_TOKEN_STORAGE_TTL_SECONDS = refresh_token_ttl
        logger.info(f"RedisOAuthTokenStore initialized. Refresh TTL: {self.REFRESH_TOKEN_STORAGE_TTL_SECONDS}s.")

    async def initialize(self) -> None:
        """Establish Redis connection with configured parameters."""
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
            self._redis_client = aioredis.Redis(**connection_params)
            await self._redis_client.ping()
            logger.info("RedisOAuthTokenStore: Connected.")
        except Exception as e:
            logger.error(f"RedisOAuthTokenStore: Connect failed: {e}", exc_info=True)
            self._redis_client = None
            raise

    async def teardown(self) -> None:
        """Clean up Redis connection."""
        if self._redis_client:
            await self._redis_client.close()
            self._redis_client = None
            logger.info("RedisOAuthTokenStore: Connection closed.")

    async def _get_client(self) -> aioredis.Redis:
        """Get initialized Redis client or raise error if not ready."""
        if not self._redis_client:
            raise RuntimeError("RedisOAuthTokenStore not initialized.")
        return self._redis_client

    def _get_access_token_key(self, token: str) -> str:
        """Generate Redis key for access token storage."""
        return f"plexus:oauth:access_token:{token}"

    def _get_refresh_token_key(self, token: str) -> str:
        """Generate Redis key for refresh token storage."""
        return f"plexus:oauth:refresh_token:{token}"

    async def save_access_token(self, token_data: AccessTokenData) -> None:
        """Save access token with TTL based on its expiration time."""
        ttl = int((token_data.expires_at - datetime.now(timezone.utc)).total_seconds())
        
        if ttl <= 0:
            logger.warning("Access token expired. Not saving.")
            return
            
        client = await self._get_client()
        await client.set(
            self._get_access_token_key(token_data.access_token),
            token_data.model_dump_json().encode("utf-8"),
            ex=ttl
        )

    async def load_access_token(self, token: str) -> Optional[AccessTokenData]:
        """Load and deserialize access token data."""
        client = await self._get_client()
        data_bytes = await client.get(self._get_access_token_key(token))
        
        if data_bytes:
            try:
                return AccessTokenData.model_validate_json(data_bytes.decode("utf-8"))
            except Exception as e:
                logger.error(f"Error deserializing access token: {e}")
                return None
        return None

    async def delete_access_token(self, token: str) -> None:
        """Remove access token from storage."""
        client = await self._get_client()
        await client.delete(self._get_access_token_key(token))

    async def save_refresh_token(self, token_data: RefreshTokenData) -> None:
        """Save refresh token with configured storage TTL."""
        client = await self._get_client()
        await client.set(
            self._get_refresh_token_key(token_data.refresh_token),
            token_data.model_dump_json().encode("utf-8"),
            ex=self.REFRESH_TOKEN_STORAGE_TTL_SECONDS
        )

    async def load_refresh_token(self, token: str) -> Optional[RefreshTokenData]:
        """Load and deserialize refresh token data."""
        client = await self._get_client()
        data_bytes = await client.get(self._get_refresh_token_key(token))
        
        if data_bytes:
            try:
                return RefreshTokenData.model_validate_json(data_bytes.decode("utf-8"))
            except Exception as e:
                logger.error(f"Error deserializing refresh token: {e}")
                return None
        return None

    async def delete_refresh_token(self, token: str) -> None:
        """Remove refresh token from storage."""
        client = await self._get_client()
        await client.delete(self._get_refresh_token_key(token))


class RedisExternalOAuthProviderConfigStore(AbstractExternalOAuthProviderConfigStore):
    """
    Redis-based storage for external OAuth provider configurations.
    
    Stores provider settings per entity (tenant) for multi-tenant support.
    """
    _redis_client: Optional[aioredis.Redis] = None

    def __init__(self):
        logger.info("RedisExternalOAuthProviderConfigStore initialized.")

    async def initialize(self) -> None:
        """Establish Redis connection with configured parameters."""
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
            self._redis_client = aioredis.Redis(**connection_params)
            await self._redis_client.ping()
            logger.info("RedisExternalOAuthProviderConfigStore: Connected.")
        except Exception as e:
            logger.error(f"RedisExternalOAuthProviderConfigStore: Connect failed: {e}", exc_info=True)
            self._redis_client = None
            raise

    async def teardown(self) -> None:
        """Clean up Redis connection."""
        if self._redis_client:
            await self._redis_client.close()
            self._redis_client = None
            logger.info("RedisExternalOAuthProviderConfigStore: Closed.")

    async def _get_client(self) -> aioredis.Redis:
        """Get initialized Redis client or raise error if not ready."""
        if not self._redis_client:
            raise RuntimeError("RedisExternalOAuthProviderConfigStore not initialized.")
        return self._redis_client

    def _get_config_key(self, entity_id: str, provider_name: str) -> str:
        """Generate Redis key for provider configuration storage."""
        return f"plexus:tenant:{entity_id}:ext_oauth_cfg:{provider_name}"

    def _get_entity_configs_pattern(self, entity_id: str) -> str:
        """Generate Redis key pattern for scanning all provider configs for an entity."""
        return f"plexus:tenant:{entity_id}:ext_oauth_cfg:*"

    async def save_provider_config(self, entity_id: str, config: OAuthProviderSettings) -> None:
        """Save OAuth provider configuration for a specific entity."""
        client = await self._get_client()
        await client.set(
            self._get_config_key(entity_id, config.provider_name),
            config.model_dump_json().encode("utf-8")
        )

    async def load_provider_config(self, entity_id: str, provider_name: str) -> Optional[OAuthProviderSettings]:
        """Load OAuth provider configuration for a specific entity and provider."""
        client = await self._get_client()
        data_bytes = await client.get(self._get_config_key(entity_id, provider_name))
        
        if data_bytes:
            try:
                return OAuthProviderSettings.model_validate_json(data_bytes.decode("utf-8"))
            except Exception as e:
                logger.error(f"Error deserializing provider config '{provider_name}' for entity {entity_id}: {e}")
                return None
        return None

    async def delete_provider_config(self, entity_id: str, provider_name: str) -> None:
        """Remove OAuth provider configuration."""
        client = await self._get_client()
        await client.delete(self._get_config_key(entity_id, provider_name))

    async def load_all_provider_configs_for_entity(self, entity_id: str) -> list[OAuthProviderSettings]:
        """Load all OAuth provider configurations for a specific entity."""
        client = await self._get_client()
        
        # Scan for all keys matching the entity's provider config pattern
        keys = [
            k.decode("utf-8") 
            async for k in client.scan_iter(match=self._get_entity_configs_pattern(entity_id))
        ]
        
        configs: list[OAuthProviderSettings] = []
        if not keys:
            return configs
            
        for key_str in keys:
            data_bytes = await client.get(key_str)
            if data_bytes:
                try:
                    configs.append(OAuthProviderSettings.model_validate_json(data_bytes.decode("utf-8")))
                except Exception as e:
                    logger.error(f"Error deserializing config from key '{key_str}': {e}")
                    
        return configs


# Global store instances for singleton pattern
_token_store_instance: Optional[AbstractOAuthTokenStore] = None
_auth_code_store_instance: Optional[AbstractAuthCodeStore] = None
_external_oauth_provider_config_store_instance: Optional[AbstractExternalOAuthProviderConfigStore] = None
_internal_oauth_client_store_instance: Optional[AbstractOAuthClientStore] = None


async def get_oauth_token_store() -> AbstractOAuthTokenStore:
    """
    Factory function to get the configured OAuth token store instance.
    
    Returns a singleton instance based on the storage_backend setting.
    """
    global _token_store_instance
    
    if _token_store_instance is None:
        if plexus_global_settings.storage_backend == "sqlite":
            logger.info("Using SQLiteOAuthTokenStore for internal OAuth tokens.")
            _token_store_instance = await get_sqlite_oauth_internal_token_store()
        elif plexus_global_settings.storage_backend == "redis":
            logger.info("Using RedisOAuthTokenStore for internal OAuth tokens.")
            _token_store_instance = RedisOAuthTokenStore()
            await _token_store_instance.initialize()
        else:
            raise ValueError(f"Unsupported storage_backend for internal OAuth tokens: {plexus_global_settings.storage_backend}")
            
    return _token_store_instance


async def get_auth_code_store() -> AbstractAuthCodeStore:
    """
    Factory function to get the configured auth code store instance.
    
    Returns a singleton instance based on the storage_backend setting.
    """
    global _auth_code_store_instance
    
    if _auth_code_store_instance is None:
        if plexus_global_settings.storage_backend == "sqlite":
            logger.info("Using SQLiteAuthCodeStore for internal OAuth auth codes.")
            _auth_code_store_instance = await get_sqlite_auth_code_store()
        elif plexus_global_settings.storage_backend == "redis":
            logger.info("Using RedisAuthCodeStore for internal OAuth auth codes.")
            _auth_code_store_instance = RedisAuthCodeStore()
            await _auth_code_store_instance.initialize()
        else:
            raise ValueError(f"Unsupported storage_backend for internal OAuth auth codes: {plexus_global_settings.storage_backend}")
            
    return _auth_code_store_instance


async def get_external_oauth_provider_config_store() -> AbstractExternalOAuthProviderConfigStore:
    """
    Factory function to get the configured external OAuth provider config store instance.
    
    Returns a singleton instance based on the storage_backend setting.
    """
    global _external_oauth_provider_config_store_instance
    
    if _external_oauth_provider_config_store_instance is None:
        if plexus_global_settings.storage_backend == "sqlite":
            logger.info("Using SQLiteExternalOAuthProviderConfigStore for external provider configs.")
            _external_oauth_provider_config_store_instance = await get_sqlite_external_oauth_provider_config_store()
        elif plexus_global_settings.storage_backend == "redis":
            logger.info("Using RedisExternalOAuthProviderConfigStore for external provider configs.")
            _external_oauth_provider_config_store_instance = RedisExternalOAuthProviderConfigStore()
            await _external_oauth_provider_config_store_instance.initialize()
        else:
            raise ValueError(f"Unsupported storage_backend for external provider configs: {plexus_global_settings.storage_backend}")
            
    return _external_oauth_provider_config_store_instance


async def get_internal_oauth_client_store() -> AbstractOAuthClientStore:
    """
    Factory function to get the configured internal OAuth client store instance.
    
    Returns a singleton instance based on the storage_backend setting.
    Note: Redis implementation is not yet available, falls back to SQLite.
    """
    global _internal_oauth_client_store_instance
    
    if _internal_oauth_client_store_instance is None:
        if plexus_global_settings.storage_backend == "sqlite":
            logger.info("Using SQLiteOAuthClientStore for internal OAuth clients.")
            _internal_oauth_client_store_instance = await get_sqlite_internal_oauth_client_store()
        elif plexus_global_settings.storage_backend == "redis":
            # Redis implementation not yet available, fallback to SQLite
            logger.error("RedisOAuthClientStore is not yet implemented. Falling back to SQLite for internal clients.")
            _internal_oauth_client_store_instance = await get_sqlite_internal_oauth_client_store()
        else:
            raise ValueError(f"Unsupported storage_backend for internal OAuth clients: {plexus_global_settings.storage_backend}")
            
    return _internal_oauth_client_store_instance