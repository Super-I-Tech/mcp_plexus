# mcp_plexus/tool_loader.py
import importlib.util
import logging
from pathlib import Path
from typing import TYPE_CHECKING
import sys 

if TYPE_CHECKING:
    from mcp_plexus.core.server import MCPPlexusServer 

logger = logging.getLogger(__name__)
if not logger.hasHandlers():
    logging.basicConfig(
        level=logging.DEBUG, 
        format='%(asctime)s TOOL_LOADER - [%(levelname)s] - %(message)s'
    )
    logger.setLevel(logging.DEBUG)


def load_tools_from_directory(directory_path: Path):
    """
    Dynamically loads tool modules from a specified directory and registers them
    with the global PLEXUS_SERVER_INSTANCE. This function must be called after
    the server instance has been initialized to ensure proper tool registration.
    """
    logger.info(f"Initiating tool loading from directory: {directory_path.resolve()}")
    
    # Import server instance inside function to ensure it's available after initialization
    try:
        from mcp_plexus.core.global_registry import PLEXUS_SERVER_INSTANCE 
        
        if PLEXUS_SERVER_INSTANCE is None:
            logger.error(
                "PLEXUS_SERVER_INSTANCE is None at the time of tool loading. "
                "Tools cannot be registered. Check initialization order."
            )
            return
        
        # Validate the server instance has the required FastMCP backend
        if hasattr(PLEXUS_SERVER_INSTANCE, '_fastmcp_instance') and PLEXUS_SERVER_INSTANCE._fastmcp_instance:
            logger.info(f"Server instance validated with FastMCP backend ID: {id(PLEXUS_SERVER_INSTANCE._fastmcp_instance)}")
        else:
            logger.warning("Server instance does not have a _fastmcp_instance or it is None.")

    except ImportError:
        logger.error("Could not import PLEXUS_SERVER_INSTANCE from global_registry. Tool loading aborted.")
        return
    except Exception as e_registry:
        logger.error(f"Error accessing PLEXUS_SERVER_INSTANCE: {e_registry}", exc_info=True)
        return

    if not directory_path.is_dir():
        logger.warning(f"Tool modules directory '{directory_path}' not found or not a directory. Skipping tool loading.")
        return

    logger.info(f"Scanning for tool modules in: {directory_path.resolve()}")
    found_files_count = 0
    loaded_modules_count = 0
    
    for file_path in directory_path.glob("*.py"):
        found_files_count += 1
        logger.debug(f"Found file: {file_path.name}")
        
        # Skip __init__.py files as they are not tool modules
        if file_path.name == "__init__.py":
            logger.debug(f"Skipping __init__.py: {file_path}")
            continue

        module_name_stem = file_path.stem
        # Use consistent module naming convention for tool modules
        module_spec_name = f"mcp_plexus.tool_modules.{module_name_stem}" 
        
        logger.info(f"Attempting to import tool module: '{module_name_stem}' from '{file_path}' as '{module_spec_name}'")
        
        try:
            # Handle module reloading for development scenarios (e.g., Uvicorn auto-reload)
            if module_spec_name in sys.modules:
                logger.info(f"Module '{module_spec_name}' already in sys.modules. Reloading...")
                module = importlib.reload(sys.modules[module_spec_name])
                logger.info(f"Reloaded module: {module_spec_name}")
                loaded_modules_count += 1
            else:
                # Create and execute new module specification
                spec = importlib.util.spec_from_file_location(module_spec_name, str(file_path))
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[module_spec_name] = module 
                    # Execute module - this triggers tool registration via decorators
                    spec.loader.exec_module(module)
                    logger.info(f"Successfully imported and executed tool module: '{module_spec_name}' (from {file_path})")
                    loaded_modules_count += 1
                else:
                    logger.error(f"Could not create module spec or loader for '{file_path}'. Skipping.")
                    continue
                    
        except ImportError as e_imp:
            logger.error(f"ImportError loading module {module_name_stem} ({module_spec_name}): {e_imp}", exc_info=True)
        except Exception as e:
            logger.error(f"Error importing/processing tool module {module_name_stem} ({module_spec_name}): {e}", exc_info=True)
    
    if found_files_count == 0:
        logger.warning(f"No Python files found in tool modules directory: {directory_path.resolve()}")
    
    logger.info(
        f"Tool loading process finished. Found {found_files_count} .py files. "
        f"Successfully loaded/reloaded {loaded_modules_count} tool modules."
    )