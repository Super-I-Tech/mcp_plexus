# mcp_plexus/cli/tenant_cli.py
import typer
from typing import Optional
from typing_extensions import Annotated  # For older Python compatibility
import json

from .utils_cli import make_api_request

app = typer.Typer(
    name="tenant", 
    help="Manage Plexus Tenants via Admin API.", 
    no_args_is_help=True
)


@app.command("create")
def create_tenant(
    entity_id: Annotated[
        str, 
        typer.Option(
            prompt="Tenant Entity ID (e.g., my-company)", 
            help="Unique identifier for the tenant."
        )
    ],
    name: Annotated[
        str, 
        typer.Option(prompt="Tenant Name", help="Display name for the tenant.")
    ],
    status: str = typer.Option("active", help="Status (e.g., active, inactive)."),
    settings_json_str: Annotated[
        Optional[str], 
        typer.Option(
            "--settings-json", 
            help="JSON string for tenant-specific settings (e.g., '{\"feature_x\": true}')"
        )
    ] = None
):
    """Create a new Plexus Tenant."""
    payload = {"entity_id": entity_id, "tenant_name": name, "status": status}
    
    # Parse and validate JSON settings if provided
    if settings_json_str:
        try:
            payload["settings_json"] = json.loads(settings_json_str)
        except json.JSONDecodeError:
            typer.secho(
                f"Error: Invalid JSON string provided for settings: {settings_json_str}", 
                fg=typer.colors.RED
            )
            raise typer.Exit(code=1)
    
    make_api_request("POST", "/admin/tenants/", json_payload=payload, expected_status=201)


@app.command("get")
def get_tenant(
    entity_id: Annotated[
        str, 
        typer.Argument(help="The Entity ID of the tenant to retrieve.")
    ]
):
    """Get details for a specific Plexus Tenant."""
    make_api_request("GET", f"/admin/tenants/{entity_id}")


@app.command("list")
def list_tenants(
    skip: Annotated[
        int, 
        typer.Option("--skip", help="Number of tenants to skip.", min=0)
    ] = 0,
    limit: Annotated[
        int, 
        typer.Option("--limit", help="Maximum number of tenants to return.", min=1, max=100)
    ] = 100
):
    """List Plexus Tenants."""
    params = {"skip": skip, "limit": limit}
    make_api_request("GET", "/admin/tenants/", params_payload=params)


@app.command("update")
def update_tenant(
    entity_id: Annotated[
        str, 
        typer.Argument(help="The Entity ID of the tenant to update.")
    ],
    new_name: Annotated[
        Optional[str], 
        typer.Option("--name", help="New display name for the tenant.")
    ] = None,
    new_status: Optional[str] = typer.Option(
        None, 
        "--status", 
        help="New status (e.g., active, inactive)."
    ),
    new_settings_json_str: Annotated[
        Optional[str], 
        typer.Option(
            "--settings-json", 
            help="NEW JSON string for tenant settings. This will REPLACE all existing settings for this tenant."
        )
    ] = None
):
    """Update an existing Plexus Tenant. Only provided fields will be updated."""
    payload = {}
    
    # Build payload with only the fields that need to be updated
    if new_name is not None:
        payload["tenant_name"] = new_name
    if new_status is not None:
        payload["status"] = new_status
    if new_settings_json_str is not None:
        try:
            payload["settings_json"] = json.loads(new_settings_json_str)
        except json.JSONDecodeError:
            typer.secho(
                f"Error: Invalid JSON string provided for new settings: {new_settings_json_str}", 
                fg=typer.colors.RED
            )
            raise typer.Exit(code=1)

    # Exit early if no update parameters were provided
    if not payload:
        typer.echo("No update parameters provided. Nothing to do.")
        raise typer.Exit()

    make_api_request("PUT", f"/admin/tenants/{entity_id}", json_payload=payload)


@app.command("delete")
def delete_tenant(
    entity_id: Annotated[
        str, 
        typer.Argument(help="The Entity ID of the tenant to delete.")
    ]
):
    """Delete a Plexus Tenant."""
    make_api_request(
        "DELETE", 
        f"/admin/tenants/{entity_id}", 
        expected_status=204, 
        expect_json_response=False
    )


if __name__ == "__main__":
    app()