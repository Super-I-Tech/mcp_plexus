# mcp_plexus/tenants/service.py
import logging
from typing import Optional, List
from .models import Tenant, TenantCreate, TenantUpdate, TenantInDB
from .storage_interfaces import AbstractTenantStore

logger = logging.getLogger(__name__)


class TenantService:
    """
    Service layer for tenant management operations.
    
    Handles business logic and orchestrates interactions with the tenant storage layer.
    Acts as an intermediary between the API layer and the data persistence layer.
    """
    
    def __init__(self, tenant_store: AbstractTenantStore):
        """Initialize the service with a tenant storage implementation."""
        self.tenant_store = tenant_store

    async def create_tenant(self, tenant_create: TenantCreate) -> TenantInDB:
        """
        Create a new tenant in the system.
        
        Logs the creation attempt and propagates any validation errors
        from the storage layer to maintain data integrity.
        """
        logger.info(f"Service: Attempting to create tenant with entity_id: {tenant_create.entity_id}")
        try:
            return await self.tenant_store.create_tenant(tenant_create)
        except ValueError as ve:
            logger.warning(f"Service: Tenant creation failed for entity_id '{tenant_create.entity_id}': {ve}")
            raise

    async def get_tenant(self, entity_id: str) -> Optional[TenantInDB]:
        """Retrieve a specific tenant by their entity identifier."""
        logger.info(f"Service: Getting tenant with entity_id: {entity_id}")
        return await self.tenant_store.get_tenant_by_entity_id(entity_id)

    async def list_tenants(self, skip: int = 0, limit: int = 100) -> List[TenantInDB]:
        """
        Retrieve a paginated list of tenants.
        
        Supports pagination to handle large datasets efficiently.
        """
        logger.info(f"Service: Listing tenants with skip: {skip}, limit: {limit}")
        return await self.tenant_store.list_tenants(skip=skip, limit=limit)

    async def update_tenant(self, entity_id: str, tenant_update: TenantUpdate) -> Optional[TenantInDB]:
        """
        Update an existing tenant's information.
        
        Future business logic such as status transition validation
        should be implemented here before delegating to storage.
        """
        logger.info(f"Service: Updating tenant with entity_id: {entity_id}")
        return await self.tenant_store.update_tenant(entity_id, tenant_update)

    async def delete_tenant(self, entity_id: str) -> bool:
        """
        Remove a tenant from the system.
        
        Future business logic such as dependency checks or soft delete policies
        should be implemented here before delegating to storage.
        """
        logger.info(f"Service: Deleting tenant with entity_id: {entity_id}")
        return await self.tenant_store.delete_tenant(entity_id)