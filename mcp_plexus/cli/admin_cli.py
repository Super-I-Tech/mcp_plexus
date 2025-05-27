# mcp_plexus/cli/admin_cli.py
import typer
from . import tenant_cli 
from . import ext_oauth_cli

# Main admin CLI application with helpful configuration
app = typer.Typer(
    name="admin", 
    help="MCP Plexus Administrative Commands.", 
    no_args_is_help=True
)

# Register sub-command modules for administrative operations
app.add_typer(tenant_cli.app, name="tenant")
app.add_typer(ext_oauth_cli.app, name="ext-oauth")


@app.callback()
def admin_callback():
    """
    MCP Plexus Admin CLI entry point callback.
    
    This callback is executed before any admin subcommand runs,
    providing a hook for global admin CLI initialization if needed.
    """
    pass


if __name__ == "__main__":
    app()