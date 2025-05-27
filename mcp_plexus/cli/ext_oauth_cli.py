# mcp_plexus/cli/ext_oauth_cli.py
import typer
from typing import Optional, List as PyList
from typing_extensions import Annotated
import json

from .utils_cli import make_api_request
from ..oauth.models import OAuthProviderSettings

app = typer.Typer(
    name="ext-oauth",
    help="Manage External OAuth Provider configurations for Tenants.",
    no_args_is_help=True
)


@app.command("create")
def create_ext_oauth_provider(
    entity_id: Annotated[str, typer.Argument(help="The Entity ID for which to register this provider.")],
    provider_name: Annotated[str, typer.Option(prompt=True, help="Unique name for the provider (e.g., 'github', 'google').")],
    client_id: Annotated[str, typer.Option(prompt=True, help="Client ID from the external provider.")],
    client_secret: Annotated[str, typer.Option(prompt=True, help="Client Secret from the external provider.", hide_input=True)],
    authorization_url: Annotated[str, typer.Option(prompt=True, help="Authorization URL of the external provider.")],
    token_url: Annotated[str, typer.Option(prompt=True, help="Token URL of the external provider.")],
    default_scopes_str: Annotated[str, typer.Option("--scopes", prompt=True, help="Comma-separated list of default scopes (e.g., 'read:user,repo').")],
    userinfo_url: Annotated[Optional[str], typer.Option(help="Userinfo URL of the external provider (optional).")] = None,
):
    """Register a new External OAuth Provider configuration for a specific Tenant."""
    # Parse comma-separated scopes and filter out empty strings
    scopes_list = [s.strip() for s in default_scopes_str.split(',') if s.strip()]
    if not scopes_list:
        typer.secho("Error: Scopes cannot be empty. Please provide a comma-separated list.", fg=typer.colors.RED)
        raise typer.Exit(code=1)
        
    payload = {
        "provider_name": provider_name,
        "client_id": client_id,
        "client_secret": client_secret,
        "authorization_url": authorization_url,
        "token_url": token_url,
        "default_scopes": scopes_list,
    }
    if userinfo_url:
        payload["userinfo_url"] = userinfo_url
    
    # Validate payload against Pydantic model before sending to API
    try:
        OAuthProviderSettings(**payload)  # type: ignore
    except Exception as e:
        typer.secho(f"CLI Error: Invalid provider settings data: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
        
    make_api_request(
        "POST",
        f"/{entity_id}/admin/external-oauth-providers/",
        json_payload=payload,
        expected_status=201
    )


@app.command("get")
def get_ext_oauth_provider(
    entity_id: Annotated[str, typer.Argument(help="The Entity ID.")],
    provider_name: Annotated[str, typer.Argument(help="The name of the provider configuration to retrieve.")]
):
    """Get a specific External OAuth Provider configuration for a Tenant."""
    make_api_request("GET", f"/{entity_id}/admin/external-oauth-providers/{provider_name}")


@app.command("list")
def list_ext_oauth_providers(
    entity_id: Annotated[str, typer.Argument(help="The Entity ID for which to list provider configurations.")]
):
    """List all External OAuth Provider configurations for a Tenant."""
    make_api_request("GET", f"/{entity_id}/admin/external-oauth-providers/")


@app.command("update")
def update_ext_oauth_provider(
    entity_id: Annotated[str, typer.Argument(help="The Entity ID.")],
    provider_name_path: Annotated[str, typer.Argument(help="Name of the provider config to update.")],
    client_id: Annotated[Optional[str], typer.Option(help="New Client ID (if changing).")] = None,
    client_secret: Annotated[Optional[str], typer.Option(help="New Client Secret (if changing).", hide_input=True)] = None,
    authorization_url: Annotated[Optional[str], typer.Option(help="New Authorization URL (if changing).")] = None,
    token_url: Annotated[Optional[str], typer.Option(help="New Token URL (if changing).")] = None,
    default_scopes_str: Annotated[Optional[str], typer.Option("--scopes", help="New comma-separated default scopes (if changing).")] = None,
    userinfo_url: Annotated[Optional[str], typer.Option(help="New Userinfo URL (if changing, or set to 'REMOVE' to clear).")] = None,
):
    """Update an External OAuth Provider configuration for a Tenant.
    
    All current values must be re-provided for fields you wish to keep or change.
    Omitted optional fields (like userinfo_url) will be cleared if originally set.
    Provider name in path is used; provider_name in body must match if a full new payload is sent.
    """
    typer.secho("Update command currently requires re-entering all fields for the new configuration.", fg=typer.colors.YELLOW)
    typer.secho(f"Updating provider: {provider_name_path} for entity: {entity_id}", fg=typer.colors.YELLOW)

    final_payload = {}
    
    # Provider name in request body must match the path parameter
    final_payload["provider_name"] = provider_name_path

    # Collect all required fields, prompting for missing ones
    if client_id is not None:
        final_payload["client_id"] = client_id
    else:
        client_id_prompt = typer.prompt(f"Client ID for {provider_name_path}")
        final_payload["client_id"] = client_id_prompt
    
    if client_secret is not None:
        final_payload["client_secret"] = client_secret
    else:
        client_secret_prompt = typer.prompt(f"Client Secret for {provider_name_path}", hide_input=True)
        final_payload["client_secret"] = client_secret_prompt

    if authorization_url is not None:
        final_payload["authorization_url"] = authorization_url
    else:
        auth_url_prompt = typer.prompt(f"Authorization URL for {provider_name_path}")
        final_payload["authorization_url"] = auth_url_prompt

    if token_url is not None:
        final_payload["token_url"] = token_url
    else:
        token_url_prompt = typer.prompt(f"Token URL for {provider_name_path}")
        final_payload["token_url"] = token_url_prompt

    # Handle scopes parsing and validation
    if default_scopes_str is not None:
        scopes_list = [s.strip() for s in default_scopes_str.split(',') if s.strip()]
    else:
        scopes_prompt = typer.prompt(f"Default Scopes (comma-separated) for {provider_name_path}")
        scopes_list = [s.strip() for s in scopes_prompt.split(',') if s.strip()]
    
    if not scopes_list:
        typer.secho("Error: Scopes cannot be empty for update.", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    final_payload["default_scopes"] = scopes_list

    # Handle optional userinfo_url with special 'REMOVE' keyword
    if userinfo_url is not None:
        if userinfo_url.upper() == 'REMOVE':
            final_payload["userinfo_url"] = None
        else:
            final_payload["userinfo_url"] = userinfo_url
    else:
        userinfo_url_prompt = typer.prompt(
            f"Userinfo URL for {provider_name_path} (optional, press Enter to skip)",
            default="",
            show_default=False
        )
        if userinfo_url_prompt:
            final_payload["userinfo_url"] = userinfo_url_prompt
        else:
            final_payload["userinfo_url"] = None

    # Validate the complete payload before sending
    try:
        OAuthProviderSettings(**final_payload)  # type: ignore
    except Exception as e:
        typer.secho(f"CLI Error: Invalid provider settings data for update: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    make_api_request(
        "PUT",
        f"/{entity_id}/admin/external-oauth-providers/{provider_name_path}",
        json_payload=final_payload
    )


@app.command("delete")
def delete_ext_oauth_provider(
    entity_id: Annotated[str, typer.Argument(help="The Entity ID.")],
    provider_name: Annotated[str, typer.Argument(help="The name of the provider configuration to delete.")],
    force: Annotated[bool, typer.Option("--force", prompt="Are you sure you want to delete this provider config?", help="Confirm deletion.", show_default=False)] = False
):
    """Delete an External OAuth Provider configuration for a Tenant."""
    if not force:
        typer.echo("Deletion cancelled.")
        raise typer.Abort()
    
    make_api_request(
        "DELETE",
        f"/{entity_id}/admin/external-oauth-providers/{provider_name}",
        expected_status=204,
        expect_json_response=False
    )
    typer.secho(
        f"External OAuth provider config '{provider_name}' for entity '{entity_id}' deleted.",
        fg=typer.colors.GREEN
    )


if __name__ == "__main__":
    app()