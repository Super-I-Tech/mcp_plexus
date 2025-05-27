# mcp_plexus/cli/config.py
import os
from dotenv import load_dotenv
from pathlib import Path

# Determine the project root dynamically from this file's location
# This cli/config.py file is at MCP_Plexus/mcp_plexus/cli/config.py
# Three .parent calls navigate to the project root directory
project_root = Path(__file__).parent.parent.parent.resolve()

# Load environment variables from .env file, overriding system environment variables
load_dotenv(dotenv_path=project_root / '.env', override=True)

# API configuration for CLI client communication
PLEXUS_CLI_API_BASE_URL = os.getenv("PLEXUS_CLI_API_BASE_URL", "http://127.0.0.1:8000")

# Admin API key for authenticated operations
PLEXUS_CLI_ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")