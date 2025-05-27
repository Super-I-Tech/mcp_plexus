from fastapi import APIRouter
import logging

logger = logging.getLogger(__name__)
router = APIRouter()

# This router is intentionally empty for Phase 0 MCP handling
# Raw ASGI routes for /<entity_id>/mcp are added directly to the main FastAPI app
# This file is maintained for potential future non-MCP routes under /mcp_handlers

logger.info("MCP Plexus mcp_router initialized (currently no MCP routes here).")