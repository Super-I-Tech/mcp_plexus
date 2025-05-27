# mcp_plexus/cli/utils_cli.py
import requests
import typer
import json
from typing import Optional, Dict, Any, Union, List

from .config import PLEXUS_CLI_API_BASE_URL


def make_api_request(
    method: str,
    endpoint: str,
    json_payload: Optional[Dict[str, Any]] = None,
    params_payload: Optional[Dict[str, Any]] = None,
    expected_status: Union[int, List[int]] = 200,
    expect_json_response: bool = True
) -> Any:
    """
    Makes an HTTP API request with comprehensive logging and error handling.
    
    Handles authentication via admin API key when available and provides
    detailed console output for debugging purposes.
    """
    # Import here to avoid circular imports
    from .config import PLEXUS_CLI_API_BASE_URL, PLEXUS_CLI_ADMIN_API_KEY

    full_url = f"{PLEXUS_CLI_API_BASE_URL}{endpoint}"
    headers: Dict[str, str] = {} 

    # Add admin authentication header if available
    if PLEXUS_CLI_ADMIN_API_KEY:
        headers["X-Admin-API-Key"] = PLEXUS_CLI_ADMIN_API_KEY
    else:
        # Warn user if attempting admin endpoint without proper credentials
        if "/admin/" in endpoint:
            typer.secho(
                "CLI: Warning - ADMIN_API_KEY not set in .env for CLI. Admin API calls might fail.", 
                fg=typer.colors.YELLOW
            )

    # Log request details for debugging
    typer.echo(f"CLI: {method.upper()} {full_url}")
    if json_payload:
        typer.echo(f"CLI: JSON Payload: {json.dumps(json_payload, indent=2)}")
    if params_payload:
         typer.echo(f"CLI: Query Params: {params_payload}")
    if headers:
        # Mask sensitive API key in logs
        log_headers = headers.copy()
        if "X-Admin-API-Key" in log_headers:
            log_headers["X-Admin-API-Key"] = "*******"
        typer.echo(f"CLI: Headers: {log_headers}")

    try:
        response = requests.request(
            method, 
            full_url, 
            json=json_payload, 
            params=params_payload, 
            headers=headers, 
            timeout=30
        )
        typer.echo(f"CLI: Response Status: {response.status_code}")

        # Normalize expected status to list for consistent checking
        expected_statuses = [expected_status] if isinstance(expected_status, int) else expected_status

        if response.status_code in expected_statuses:
            # Handle 204 No Content responses
            if not response.content and response.status_code == 204:
                 typer.echo(typer.style(
                     f"CLI: Success (Status {response.status_code}, No Content).", 
                     fg=typer.colors.GREEN
                 ))
                 return None
            
            if expect_json_response:
                try:
                    data = response.json()
                    typer.echo(typer.style("CLI: Response JSON:", fg=typer.colors.CYAN))
                    typer.echo(json.dumps(data, indent=2))
                    return data
                except json.JSONDecodeError:
                    typer.secho(
                        f"CLI: Error - Could not decode JSON response. Raw text: {response.text}", 
                        fg=typer.colors.RED
                    )
                    raise typer.Exit(code=1)
            else:
                # Handle non-JSON responses (e.g., plain text, 204 responses)
                typer.echo(typer.style(
                    f"CLI: Success (Status {response.status_code}). Raw text: {response.text[:200]}...", 
                    fg=typer.colors.GREEN
                ))
                return response.text
        else:
            # Handle API error responses
            err_msg = f"CLI: API Error - Expected status {expected_status}, got {response.status_code}."
            try:
                err_data = response.json()
                err_msg += f" Detail: {err_data.get('detail', response.text)}"
            except json.JSONDecodeError:
                err_msg += f" Raw response: {response.text}"
            typer.secho(err_msg, fg=typer.colors.RED)
            raise typer.Exit(code=1)

    except requests.exceptions.ConnectionError as e:
        typer.secho(
            f"CLI: Connection Error - Could not connect to API at {full_url}. Is the server running? Error: {e}", 
            fg=typer.colors.RED
        )
        raise typer.Exit(code=1)
    except requests.exceptions.RequestException as e:
        typer.secho(f"CLI: Request Error - {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)