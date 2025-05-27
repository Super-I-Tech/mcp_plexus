# mcp_plexus/oauth/pkce.py
import secrets
import hashlib
import base64
import re

# RFC 7636 specifies length between 43 and 128 characters
CODE_VERIFIER_LENGTH = 64


def generate_pkce_code_verifier(length: int = CODE_VERIFIER_LENGTH) -> str:
    """
    Generates a cryptographically random PKCE code verifier.
    The verifier is an unreserved string with a minimum length of 43 characters
    and a maximum length of 128 characters. (RFC 7636 - Section 4.1)
    Allowed characters: A-Z, a-z, 0-9, '-', '.', '_', '~'
    """
    if not (43 <= length <= 128):
        raise ValueError("PKCE code verifier length must be between 43 and 128 characters.")
    
    # Generate random bytes and base64url encode them
    # Base64 expands data size by 4/3, so we generate 3/4 of desired length
    verifier = secrets.token_urlsafe(int(length * 3 / 4))
    
    # Truncate to exact desired length
    return verifier[:length]


def generate_pkce_code_challenge(code_verifier: str, method: str = "S256") -> str:
    """
    Generates a PKCE code challenge from a code verifier.
    Supports "S256" (SHA256) and "plain" methods. (RFC 7636 - Section 4.2)
    "S256" is REQUIRED for MCP Plexus unless a client cannot support it.
    """
    if method == "S256":
        # Hash the verifier using SHA256
        hashed_verifier = hashlib.sha256(code_verifier.encode('ascii')).digest()
        
        # Base64url encode the hash and remove padding
        challenge = base64.urlsafe_b64encode(hashed_verifier).rstrip(b'=').decode('ascii')
        return challenge
    elif method == "plain":
        # Plain method returns verifier as-is - only used if S256 not supported
        return code_verifier
    else:
        raise ValueError(f"Unsupported PKCE code challenge method: {method}. Must be 'S256' or 'plain'.")


def validate_pkce_code_verifier_format(code_verifier: str) -> bool:
    """
    Validates the format of a PKCE code_verifier as per RFC 7636.
    Checks length and allowed characters (A-Z, a-z, 0-9, '-', '.', '_', '~').
    """
    # Check length requirements
    if not (43 <= len(code_verifier) <= 128):
        return False
    
    # Check allowed character set
    if not re.match(r"^[A-Za-z0-9\-._~]+$", code_verifier):
        return False
    
    return True