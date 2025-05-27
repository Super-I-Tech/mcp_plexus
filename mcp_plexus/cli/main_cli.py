# mcp_plexus/cli/main_cli.py
import typer
from . import admin_cli

# Main CLI application with help enabled when no arguments are provided
app = typer.Typer(
    name="plexus", 
    help="MCP Plexus Command Line Interface.", 
    no_args_is_help=True
)

# Register admin commands under 'admin' subcommand
app.add_typer(admin_cli.app, name="admin")


@app.callback()
def main_callback():
    """
    MCP Plexus main CLI application.
    Use 'plexus admin --help' for admin commands.
    """
    pass


def cli_entry_point():
    """Entry point function for console script registration in pyproject.toml"""
    app()


if __name__ == "__main__":
    cli_entry_point()