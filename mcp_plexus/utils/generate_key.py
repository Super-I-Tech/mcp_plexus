# generate_key.py
from mcp_plexus.utils.security import generate_fernet_key

# Generate a new Fernet encryption key for secure data encryption
key = generate_fernet_key()
print("Generated Fernet Key:")
print(key)
print("Add this to your .env file as PLEXUS_ENCRYPTION_KEY")