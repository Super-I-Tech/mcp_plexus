# mcp_plexus/tenants/endpoints.py
import logging
from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from typing import List, Annotated

from .models import Tenant, TenantCreate, TenantUpdate
from .service import TenantService
from .sqlite_tenant_store import get_sqlite_tenant_store
from .storage_interfaces import AbstractTenantStore
from ..dependencies import get_admin_api_key

logger = logging.getLogger(__name__)

# Admin router for tenant management - requires admin API key authentication
tenants_admin_router = APIRouter(
    prefix="/admin/tenants", 
    tags=["Admin - Tenants"],
    dependencies=[Depends(get_admin_api_key)]
)


async def get_tenant_service(
    tenant_store: Annotated[AbstractTenantStore, Depends(get_sqlite_tenant_store)]
) -> TenantService:
    """Factory function to create TenantService with injected store dependency."""
    return TenantService(tenant_store)


@tenants_admin_router.post("/", response_model=Tenant, status_code=status.HTTP_201_CREATED)
async def create_tenant_endpoint(
    tenant_create: TenantCreate,
    service: Annotated[TenantService, Depends(get_tenant_service)]
):
    """Create a new tenant. Returns 409 if tenant with entity_id already exists."""
    logger.info(f"API: Received request to create tenant: {tenant_create.model_dump()}")
    try:
        # Service returns TenantInDB model, convert to API response model
        created_tenant_in_db = await service.create_tenant(tenant_create)
        return Tenant.model_validate(created_tenant_in_db)
    except ValueError as e: 
        logger.warning(f"API: Tenant creation failed for entity_id '{tenant_create.entity_id}': {e}")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except Exception as e:
        logger.error(f"API: Unexpected error creating tenant '{tenant_create.entity_id}': {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not create tenant.")


@tenants_admin_router.get("/{entity_id}", response_model=Tenant)
async def get_tenant_endpoint(
    entity_id: Annotated[str, Path(description="The ID of the tenant to retrieve")],
    service: Annotated[TenantService, Depends(get_tenant_service)]
):
    """Retrieve a specific tenant by entity_id."""
    tenant_in_db = await service.get_tenant(entity_id)
    if not tenant_in_db:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    return Tenant.model_validate(tenant_in_db)


@tenants_admin_router.get("/", response_model=List[Tenant])
@tenants_admin_router.get("", response_model=List[Tenant], include_in_schema=False)
async def list_tenants_endpoint(
    service: Annotated[TenantService, Depends(get_tenant_service)],
    skip: Annotated[int, Query(ge=0, description="Number of tenants to skip.")] = 0,
    limit: Annotated[int, Query(ge=1, le=100, description="Maximum number of tenants to return.")] = 100
):
    """List all tenants with pagination support. Handles both trailing slash variants."""
    tenants_in_db = await service.list_tenants(skip=skip, limit=limit)
    return [Tenant.model_validate(t) for t in tenants_in_db]


@tenants_admin_router.put("/{entity_id}", response_model=Tenant)
async def update_tenant_endpoint(
    entity_id: Annotated[str, Path(description="The ID of the tenant to update")],
    tenant_update: TenantUpdate,
    service: Annotated[TenantService, Depends(get_tenant_service)]
):
    """Update an existing tenant. Returns 404 if tenant does not exist."""
    updated_tenant_in_db = await service.update_tenant(entity_id, tenant_update)
    if not updated_tenant_in_db:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    return Tenant.model_validate(updated_tenant_in_db)


@tenants_admin_router.delete("/{entity_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tenant_endpoint(
    entity_id: Annotated[str, Path(description="The ID of the tenant to delete")],
    service: Annotated[TenantService, Depends(get_tenant_service)]
):
    """Delete a tenant by entity_id. Returns 404 if tenant does not exist."""
    deleted = await service.delete_tenant(entity_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found or could not be deleted.")
    return None