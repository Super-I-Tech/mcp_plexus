import logging
from typing import Dict, Any
from ..core.global_registry import PLEXUS_SERVER_INSTANCE
from fastmcp import Context as FastMCPBaseContext

logger = logging.getLogger(__name__)

# Ensure the Plexus server instance is properly initialized before registering tools
if PLEXUS_SERVER_INSTANCE is None:
    raise RuntimeError("PLEXUS_SERVER_INSTANCE not initialized for example_scope_tools.")


@PLEXUS_SERVER_INSTANCE.tool(name="get_global_info")
async def get_global_info_tool(ctx: FastMCPBaseContext) -> Dict[str, Any]:
    """Global tool available to all tenants without restrictions."""
    return {"message": "This is a global tool.", "info": "Available to all"}


@PLEXUS_SERVER_INSTANCE.tool(
    name="get_tenant_a_specific_data",
    allowed_tenant_ids=["tenant_A_for_scope_test"]
)
async def get_tenant_a_tool(ctx: FastMCPBaseContext) -> Dict[str, Any]:
    """Tool restricted to tenant A for accessing tenant-specific data."""
    return {"message": "This tool is specific to Tenant A.", "data_for": "tenant_A"}


@PLEXUS_SERVER_INSTANCE.tool(
    name="get_tenant_b_exclusive_feature",
    allowed_tenant_ids=["tenant_B_for_scope_test"]
)
async def get_tenant_b_tool(ctx: FastMCPBaseContext) -> Dict[str, Any]:
    """Exclusive feature tool available only to tenant B."""
    return {"message": "Exclusive feature for Tenant B."}


@PLEXUS_SERVER_INSTANCE.tool(
    name="get_shared_ac_resource",
    allowed_tenant_ids=["tenant_A_for_scope_test", "tenant_C_for_scope_test"]
)
async def get_shared_ac_tool(ctx: FastMCPBaseContext) -> Dict[str, Any]:
    """Shared resource tool accessible by both tenant A and tenant C."""
    return {"message": "Shared resource for Tenant A and Tenant C."}


@PLEXUS_SERVER_INSTANCE.tool(
    name="generate_report_tool",
    tool_sets=["reporting"]
)
async def generate_report(ctx: FastMCPBaseContext) -> Dict[str, Any]:
    """Reporting tool categorized under the 'reporting' tool set."""
    return {"report_type": "sales_summary", "status": "generated"}


@PLEXUS_SERVER_INSTANCE.tool(
    name="admin_task_for_tenant_a",
    tool_sets=["admin_tasks"],
    allowed_tenant_ids=["tenant_A_for_scope_test"]
)
async def admin_task_a(ctx: FastMCPBaseContext) -> Dict[str, Any]:
    """Administrative task tool restricted to tenant A and categorized under admin tasks."""
    return {"task": "user_cleanup", "tenant": "tenant_A", "status": "simulated_complete"}


logger.info("Example scope and set tools registered by example_scope_tools.py")