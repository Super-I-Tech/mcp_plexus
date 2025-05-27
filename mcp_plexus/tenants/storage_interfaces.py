# mcp_plexus/tenants/storage_interfaces.py
from abc import ABC, abstractmethod
from typing import Optional, List
from .models import TenantInDB, TenantCreate, TenantUpdate


class AbstractTenantStore(ABC):
    """
    Abstract base class defining the interface for tenant storage operations.
    
    This interface provides a contract for implementing different storage backends
    (e.g., database, file system, in-memory) while maintaining consistent behavior
    across the application.
    """

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the storage backend and prepare it for operations."""
        pass

    @abstractmethod
    async def teardown(self) -> None:
        """Clean up resources and properly close the storage backend."""
        pass

    @abstractmethod
    async def create_tenant(self, tenant_create: TenantCreate) -> TenantInDB:
        """
        Create a new tenant in the storage backend.
        
        Args:
            tenant_create: Tenant creation data containing required fields
            
        Returns:
            The created tenant with generated fields (ID, timestamps, etc.)
        """
        pass

    @abstractmethod
    async def get_tenant_by_entity_id(self, entity_id: str) -> Optional[TenantInDB]:
        """
        Retrieve a tenant by its unique entity identifier.
        
        Args:
            entity_id: The unique identifier for the tenant
            
        Returns:
            The tenant if found, None otherwise
        """
        pass

    @abstractmethod
    async def list_tenants(self, skip: int = 0, limit: int = 100) -> List[TenantInDB]:
        """
        Retrieve a paginated list of tenants from storage.
        
        Args:
            skip: Number of records to skip for pagination
            limit: Maximum number of records to return
            
        Returns:
            List of tenants within the specified range
        """
        pass

    @abstractmethod
    async def update_tenant(self, entity_id: str, tenant_update: TenantUpdate) -> Optional[TenantInDB]:
        """
        Update an existing tenant's information.
        
        Args:
            entity_id: The unique identifier of the tenant to update
            tenant_update: Data containing the fields to be updated
            
        Returns:
            The updated tenant if found and modified, None if tenant doesn't exist
        """
        pass

    @abstractmethod
    async def delete_tenant(self, entity_id: str) -> bool:
        """
        Remove a tenant from storage.
        
        Args:
            entity_id: The unique identifier of the tenant to delete
            
        Returns:
            True if the tenant was successfully deleted, False if not found
        """
        pass